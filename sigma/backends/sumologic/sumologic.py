from sigma.conversion.state import ConversionState
from sigma.conversion.base import TextQueryBackend
from sigma.conditions import ConditionItem, ConditionAND, ConditionOR, ConditionNOT
from sigma.types import (
    SigmaCompareExpression,
    SigmaRegularExpression,
    SigmaRegularExpressionFlag,
)
from sigma.rule import SigmaRule
import re
import json
from typing import ClassVar, Dict, Tuple, Pattern, List, Any, Optional


class SumoLogicCSEBackend(TextQueryBackend):
    """
    Sumo Logic Cloud SIEM (CSE) backend for converting Sigma rules to CSE Rule JSON format.

    This backend converts Sigma rules into Sumo Logic Cloud SIEM Rule JSON format with:
    - CSE-compatible query expressions
    - MITRE ATT&CK technique and tactic mapping
    - Risk score calculation based on severity
    - Full rule metadata including name, description, and category
    """

    name: ClassVar[str] = "Sumo Logic Cloud SIEM (CSE) Backend"
    formats: Dict[str, str] = {
        "default": "Sumo Logic CSE Rule JSON format",
        "cse_rule": "CSE Rule JSON with full metadata",
    }
    requires_pipeline: bool = True

    # CSE uses lowercase boolean operators
    precedence: ClassVar[Tuple[ConditionItem, ConditionItem, ConditionItem]] = (
        ConditionNOT,
        ConditionAND,
        ConditionOR,
    )
    group_expression: ClassVar[str] = "({expr})"

    # CSE Query tokens - uppercase for CSE
    token_separator: str = " "
    or_token: ClassVar[str] = "OR"
    and_token: ClassVar[str] = "AND"
    not_token: ClassVar[str] = "!"
    eq_token: ClassVar[str] = "="

    # String output
    field_quote: ClassVar[str] = ""  # CSE doesn't quote field names
    field_quote_pattern: ClassVar[Optional[Pattern]] = None
    field_quote_pattern_negation: ClassVar[bool] = True

    # Field escaping
    field_escape: ClassVar[str] = "\\"
    field_escape_quote: ClassVar[bool] = False
    field_escape_pattern: ClassVar[Optional[Pattern]] = None

    # Values - no quoting, we'll handle it in convert_value_str
    str_quote: ClassVar[str] = ""
    escape_char: ClassVar[str] = "\\"
    wildcard_multi: ClassVar[str] = "*"
    wildcard_single: ClassVar[str] = "*"
    add_escaped: ClassVar[str] = ""  # Don't add extra escaping
    filter_chars: ClassVar[str] = ""
    bool_values: ClassVar[Dict[bool, str]] = {
        True: "true",
        False: "false",
    }

    # String matching operators - use wildcards with matches
    startswith_expression: ClassVar[str] = "{field} matches /{value}.*/"
    endswith_expression: ClassVar[str] = "{field} matches /.*{value}/"
    contains_expression: ClassVar[str] = "{field} matches /{value}/"
    wildcard_match_expression: ClassVar[str] = "{field} matches /{value}/"

    # Regular expressions - CSE uses 'matches' with regex
    re_expression: ClassVar[str] = "{field} matches /{regex}/"
    re_escape_char: ClassVar[str] = "\\"
    re_escape: ClassVar[Tuple[str, ...]] = ()
    re_escape_escape_char: bool = True
    re_flag_prefix: bool = False  # CSE doesn't use flag prefixes in regex
    re_flags: Dict[SigmaRegularExpressionFlag, str] = {
        SigmaRegularExpressionFlag.IGNORECASE: "i",
    }

    # Numeric comparison operators
    compare_op_expression: ClassVar[str] = "{field} {operator} {value}"
    compare_operators: ClassVar[Dict[SigmaCompareExpression.CompareOperators, str]] = {
        SigmaCompareExpression.CompareOperators.LT: "<",
        SigmaCompareExpression.CompareOperators.LTE: "<=",
        SigmaCompareExpression.CompareOperators.GT: ">",
        SigmaCompareExpression.CompareOperators.GTE: ">=",
    }

    # Null/None expressions
    field_null_expression: ClassVar[str] = "isEmpty({field})"

    # Field existence
    field_exists_expression: ClassVar[str] = "!isEmpty({field})"
    field_not_exists_expression: ClassVar[str] = "isEmpty({field})"

    # Field value in list
    convert_or_as_in: ClassVar[bool] = True
    convert_and_as_in: ClassVar[bool] = False
    in_expressions_allow_wildcards: ClassVar[bool] = False
    field_in_list_expression: ClassVar[str] = "{field} in ({list})"
    or_in_operator: ClassVar[str] = "in"
    list_separator: ClassVar[str] = ", "

    # MITRE ATT&CK categories allowed in CSE
    ALLOWED_CATEGORIES: ClassVar[List[str]] = [
        "Threat Intelligence",
        "Initial Access",
        "Execution",
        "Persistence",
        "Privilege Escalation",
        "Defense Evasion",
        "Credential Access",
        "Discovery",
        "Lateral Movement",
        "Collection",
        "Command and Control",
        "Exfiltration",
        "Impact",
    ]

    DEFAULT_CATEGORY: ClassVar[str] = "Unknown/Other"

    def __init__(
        self,
        processing_pipeline: Optional[Any] = None,
        collect_errors: bool = False,
        **kwargs,
    ):
        super().__init__(processing_pipeline, collect_errors, **kwargs)
        self.rule_metadata = []

    def convert_value_str(self, s, state: ConversionState) -> str:
        """
        Convert string value - add quotes for use in expressions.
        CSE needs quoted strings for equality but unquoted for regex.
        """
        # Convert to string if it's a SigmaString object
        if not isinstance(s, str):
            s = str(s)

        # Escape backslashes and quotes
        s = s.replace("\\", "\\\\")
        s = s.replace('"', '\\"')
        return f'"{s}"'

    def finalize_query_default(
        self, rule: SigmaRule, query: str, index: int, state: ConversionState
    ) -> str:
        """
        Finalize query and create rule JSON metadata.
        Also clean up unnecessary quotes in regex expressions.
        """
        # Remove quotes from values inside regex patterns
        # Pattern: matches /"value"/ should become matches /value/
        query = re.sub(
            r'matches /(\.\*)?\"([^"]+)\"(\.\*)?/', r"matches /\1\2\3/", query
        )

        # Create rule JSON and store it
        rule_json = self.create_rule_json(rule, query)
        self.rule_metadata.append(rule_json)

        # Return JSON string for this single rule
        return json.dumps(rule_json, indent=4, sort_keys=False)

    def finalize_output_default(self, queries: List[str]) -> Any:
        """
        Finalize output by returning list of JSON strings.
        """
        return queries

    def finalize(self, queries: List[Any], output_format: str) -> Any:
        """
        Finalize output in the specified format.

        Args:
            queries: List of query results from finalize_query_*
            output_format: Output format name

        Returns:
            Finalized output (list of JSON strings for multiple rules, single JSON string for one rule)
        """
        # Call the format-specific finalize_output method
        result = self.__getattribute__("finalize_output_" + output_format)(queries)

        # Apply any pipeline finalizers if present
        if self.last_processing_pipeline:
            return self.last_processing_pipeline.finalize(result)

        return result

    def create_rule_json(self, rule: SigmaRule, query: str) -> Dict[str, Any]:
        """
        Create CSE Rule JSON structure from Sigma rule and query.

        Args:
            rule: Sigma rule object
            query: Generated CSE query expression

        Returns:
            Dictionary representing CSE rule JSON
        """
        # Extract MITRE ATT&CK tactics and techniques from tags
        tactics, techniques, mitre_tags = self._extract_attack_tags(rule.tags)

        # Map severity to risk score
        risk_score = self._map_risk_score(rule.level)

        # Determine category from tactics
        category = self._determine_category(tactics)

        # Build comprehensive description
        description = self._build_description(rule, techniques)

        # Map status to enabled and prototype
        enabled, prototype = self._map_status(rule.status)

        # Get entity selectors based on logsource
        entity_selectors = self._get_entity_selectors(rule.logsource)

        # Create rule JSON
        rule_json = {
            "name": rule.title,
            "description": description,
            "enabled": enabled,
            "prototype": prototype,
            "expression": query,
        }

        # Add entity selectors if available
        if entity_selectors:
            rule_json["entity_selectors"] = entity_selectors

        # Add score
        rule_json["score"] = risk_score

        # Add tags array with normalized MITRE tags
        if mitre_tags:
            rule_json["tags"] = mitre_tags

        return rule_json

    def _extract_attack_tags(
        self, tags: List[Any]
    ) -> Tuple[List[str], List[str], List[str]]:
        """
        Extract MITRE ATT&CK tactics and techniques from Sigma rule tags.

        Args:
            tags: List of tags from Sigma rule (SigmaRuleTag objects or strings)

        Returns:
            Tuple of (tactics, techniques, mitre_tags) where mitre_tags are normalized
            in the format _mitreAttackTactic:TA#### or _mitreAttackTechnique:T####
        """
        tactics = []
        techniques = []
        mitre_tags = []

        # Tactic ID mapping for MITRE ATT&CK
        tactic_id_map = {
            "reconnaissance": "TA0043",
            "resource development": "TA0042",
            "initial access": "TA0001",
            "execution": "TA0002",
            "persistence": "TA0003",
            "privilege escalation": "TA0004",
            "defense evasion": "TA0005",
            "credential access": "TA0006",
            "discovery": "TA0007",
            "lateral movement": "TA0008",
            "collection": "TA0009",
            "command and control": "TA0011",
            "exfiltration": "TA0010",
            "impact": "TA0040",
        }

        for tag in tags:
            # Handle SigmaRuleTag objects
            if hasattr(tag, "name"):
                tag_name = tag.name
            else:
                tag_name = str(tag)

            tag_lower = tag_name.lower()

            # Skip attack namespace prefix (already in tag_name without it)
            # Check if it's a technique (T####)
            if re.match(r"^t\d{4}(\.\d{3})?$", tag_name, re.IGNORECASE):
                technique_upper = tag_name.upper()
                techniques.append(technique_upper)
                mitre_tags.append(f"_mitreAttackTechnique:{technique_upper}")
            # Skip software/groups (S#### or G####)
            elif re.match(r"^[sg]\d{4}$", tag_name, re.IGNORECASE):
                continue
            # Otherwise it's a tactic
            else:
                # Convert underscore/dash to space and title case
                tactic = tag_name.replace("_", " ").replace("-", " ").title()
                tactics.append(tactic)

                # Add normalized tactic tag with ID
                tactic_key = tactic.lower()
                if tactic_key in tactic_id_map:
                    mitre_tags.append(f"_mitreAttackTactic:{tactic_id_map[tactic_key]}")

        return tactics, techniques, mitre_tags

    def _map_risk_score(self, level: Any) -> int:
        """
        Map Sigma rule severity level to CSE risk score (0-10 scale).
        Args:
            level: Sigma rule level (critical, high, medium, low, informational)

        Returns:
            Risk score integer from 0 to 10
        """
        if level is None:
            return 3

        level_str = str(level).lower()

        score_mapping = {
            "critical": 8,
            "high": 6,
            "medium": 3,
            "low": 1,
            "informational": 1,
            "info": 1,
        }

        return score_mapping.get(level_str, 3)

    def _map_status(self, status: Any) -> Tuple[bool, bool]:
        """
        Map Sigma status to CSIEM enabled and prototype booleans.

        Mapping:
        - stable: enabled=True, prototype=False
        - test: enabled=True, prototype=True
        - experimental: enabled=True, prototype=True
        - deprecated: enabled=False, prototype=False
        - unsupported: enabled=False, prototype=False

        Args:
            status: Sigma rule status

        Returns:
            Tuple of (enabled, prototype)
        """
        if status is None:
            return True, False

        status_str = str(status).lower()

        status_mapping = {
            "stable": (True, False),
            "test": (True, True),
            "experimental": (True, True),
            "deprecated": (False, False),
            "unsupported": (False, False),
        }

        return status_mapping.get(status_str, (True, False))

    def _build_description(self, rule: SigmaRule, techniques: List[str]) -> str:
        """
        Build comprehensive description from Sigma rule metadata.

        Includes:
        - Original description
        - Author (if available)
        - Created and Modified dates
        - References
        - Log source information
        - False positives

        Args:
            rule: Sigma rule object
            techniques: List of MITRE technique IDs

        Returns:
            Formatted description string
        """
        parts = []

        # Main description
        if rule.description:
            parts.append(rule.description)

        # Author and dates on same line section
        metadata_lines = []
        if rule.author:
            metadata_lines.append(f"Author: {rule.author}")
        if hasattr(rule, "date") and rule.date:
            metadata_lines.append(f"Created: {rule.date}")
        if hasattr(rule, "modified") and rule.modified:
            metadata_lines.append(f"Modified: {rule.modified}")

        if metadata_lines:
            parts.append("\n\n" + "\n".join(metadata_lines))

        # References
        if rule.references:
            parts.append("\n\nReferences:")
            for ref in rule.references:
                parts.append(f"\n- {ref}")

        # Log source with bullet points
        if rule.logsource:
            logsource_items = []
            if hasattr(rule.logsource, "category") and rule.logsource.category:
                logsource_items.append(f"- Category: {rule.logsource.category}")
            if hasattr(rule.logsource, "product") and rule.logsource.product:
                logsource_items.append(f"- Product: {rule.logsource.product}")
            if hasattr(rule.logsource, "service") and rule.logsource.service:
                logsource_items.append(f"- Service: {rule.logsource.service}")

            if logsource_items:
                parts.append("\n\nLog Source:")
                for item in logsource_items:
                    parts.append(f"\n{item}")

        # False positives
        if hasattr(rule, "falsepositives") and rule.falsepositives:
            parts.append("\n\nFalse Positives:")
            for fp in rule.falsepositives:
                parts.append(f"\n- {fp}")

        return "".join(parts)

    def _get_entity_selectors(self, logsource: Any) -> List[Dict[str, str]]:
        """
        Get entity selectors based on logsource category.

        Args:
            logsource: Sigma rule logsource object

        Returns:
            List of entity selector dictionaries
        """
        entity_selectors = []

        if not logsource:
            return entity_selectors

        category = None
        if hasattr(logsource, "category"):
            category = logsource.category

        # Map categories to entity selectors based on feedback
        if category == "process_creation":
            entity_selectors = [
                {"entity_type": "_hostname", "expression": "device_hostname"},
                {"entity_type": "_username", "expression": "user_username"},
                {"entity_type": "_process", "expression": "baseImage"},
            ]
        elif category in ["network_connection", "firewall"]:
            entity_selectors = [
                {"entity_type": "_hostname", "expression": "device_hostname"},
                {"entity_type": "_ip", "expression": "srcDevice_ip"},
            ]
        elif category == "file_event":
            entity_selectors = [
                {"entity_type": "_hostname", "expression": "device_hostname"},
                {"entity_type": "_file", "expression": "user_username"},
            ]
        elif category == "dns_query":
            entity_selectors = [
                {"entity_type": "_hostname", "expression": "device_hostname"},
                {"entity_type": "_domain", "expression": "http_url_fqdn"},
            ]
        elif category == "authentication":
            entity_selectors = [
                {"entity_type": "_hostname", "expression": "device_hostname"},
                {"entity_type": "_ip", "expression": "device_ip"},
                {"entity_type": "_username", "expression": "user_username"},
            ]
        elif category == "registry_event":
            entity_selectors = [
                {"entity_type": "_hostname", "expression": "device_hostname"},
                {"entity_type": "_username", "expression": "user_username"},
            ]
        else:
            # Default to hostname for unknown categories
            entity_selectors = [
                {"entity_type": "_hostname", "expression": "device_hostname"}
            ]

        return entity_selectors

    def _determine_category(self, tactics: List[str]) -> str:
        """
        Determine CSE rule category from MITRE tactics.

        Args:
            tactics: List of MITRE ATT&CK tactics

        Returns:
            Category string
        """
        if not tactics:
            return self.DEFAULT_CATEGORY

        # Use first tactic that matches allowed categories
        for tactic in tactics:
            # Remove spaces for comparison
            tactic_normalized = tactic.replace(" ", "")
            for allowed_cat in self.ALLOWED_CATEGORIES:
                if tactic_normalized.lower() == allowed_cat.replace(" ", "").lower():
                    return allowed_cat

        return self.DEFAULT_CATEGORY


class SumoLogicCSERuleBackend(SumoLogicCSEBackend):
    """
    Sumo Logic CSE Rule Backend that outputs complete JSON rules.

    This backend extends SumoLogicCSEBackend to provide full CSE Rule JSON
    output suitable for direct import via CSE API or UI.
    """

    name: ClassVar[str] = "Sumo Logic CSE Rule JSON Backend"

    def finalize_query_cse_rule(
        self, rule: SigmaRule, query: str, index: int, state: ConversionState
    ) -> str:
        """
        Finalize query as CSE Rule JSON for cse_rule format.
        """
        rule_json = self.create_rule_json(rule, query)
        self.rule_metadata.append(rule_json)
        return json.dumps(rule_json, indent=4, sort_keys=False)

    def finalize_output_cse_rule(self, queries: List[Any]) -> Any:
        """
        Output collected rules as JSON array or single JSON.
        """
        return queries
