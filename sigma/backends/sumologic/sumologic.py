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

    Based on legacy implementation: https://github.com/SigmaHQ/legacy-sigmatools/blob/master/tools/sigma/backends/sumologic.py
    Reference: https://help.sumologic.com/docs/cse/
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

    # CSE Query tokens - lowercase for CSE
    token_separator: str = " "
    or_token: ClassVar[str] = "or"
    and_token: ClassVar[str] = "and"
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

    # Values
    str_quote: ClassVar[str] = '"'
    escape_char: ClassVar[str] = "\\"
    wildcard_multi: ClassVar[str] = "*"
    wildcard_single: ClassVar[str] = "*"
    add_escaped: ClassVar[str] = "\\"
    filter_chars: ClassVar[str] = ""
    bool_values: ClassVar[Dict[bool, str]] = {
        True: "true",
        False: "false",
    }

    # String matching operators
    startswith_expression: ClassVar[str] = '{field} matches "{value}*"'
    endswith_expression: ClassVar[str] = '{field} matches "*{value}"'
    contains_expression: ClassVar[str] = '{field} matches "*{value}*"'
    wildcard_match_expression: ClassVar[str] = '{field} matches "{value}"'

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

    def finalize_query_default(
        self, rule: SigmaRule, query: str, index: int, state: ConversionState
    ) -> str:
        """
        Finalize query and create rule JSON metadata.
        """
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
        tactics, techniques = self._extract_attack_tags(rule.tags)

        # Map severity to risk score
        risk_score = self._map_risk_score(rule.level)

        # Determine category from tactics
        category = self._determine_category(tactics)

        # Build technique string for description
        technique_str = ""
        if techniques:
            technique_str = f" Technique: {', '.join(techniques)}."

        # Create rule JSON
        rule_json = {
            "name": f"{rule.title} by {rule.author if rule.author else 'Unknown'}",
            "description": f"{rule.description}{technique_str}",
            "enabled": True,
            "expression": query,
            "assetField": "device_hostname",
            "score": risk_score,
            "stream": "record",
            "category": category,
        }

        # Add optional fields if available
        if rule.references:
            rule_json["reference"] = rule.references

        if techniques:
            rule_json["techniques"] = techniques

        if tactics:
            rule_json["tactics"] = tactics

        return rule_json

    def _extract_attack_tags(self, tags: List[Any]) -> Tuple[List[str], List[str]]:
        """
        Extract MITRE ATT&CK tactics and techniques from Sigma rule tags.

        Args:
            tags: List of tags from Sigma rule (SigmaRuleTag objects or strings)

        Returns:
            Tuple of (tactics, techniques)
        """
        tactics = []
        techniques = []

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
                techniques.append(tag_name.upper())
            # Skip software/groups (S#### or G####)
            elif re.match(r"^[sg]\d{4}$", tag_name, re.IGNORECASE):
                continue
            # Otherwise it's a tactic
            else:
                # Convert underscore to space and title case
                tactic = tag_name.replace("_", " ").title()
                tactics.append(tactic)

        return tactics, techniques

    def _map_risk_score(self, level: Any) -> int:
        """
        Map Sigma rule severity level to CSE risk score (1-5).

        Args:
            level: Sigma rule level (critical, high, medium, low, informational)

        Returns:
            Risk score integer from 1 to 5
        """
        if level is None:
            return 3

        level_str = str(level).lower()

        score_mapping = {
            "critical": 5,
            "high": 4,
            "medium": 3,
            "low": 2,
            "informational": 1,
            "info": 1,
        }

        return score_mapping.get(level_str, 3)

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
