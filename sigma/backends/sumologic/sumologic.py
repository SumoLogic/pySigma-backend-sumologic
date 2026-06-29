from sigma.conversion.state import ConversionState
from sigma.conversion.base import TextQueryBackend
from sigma.conditions import ConditionItem, ConditionAND, ConditionOR, ConditionNOT
from sigma.types import (
    SigmaCompareExpression,
    SigmaRegularExpression,
    SigmaRegularExpressionFlag,
)
from sigma.rule import SigmaRule
from sigma.processing.pipeline import ProcessingPipeline
import re
import json
import yaml
from typing import ClassVar, Dict, Tuple, Pattern, List, Any, Optional


class SumoLogicCSEBackend(TextQueryBackend):
    """
    Sumo Logic Cloud SIEM backend for converting Sigma rules to CSIEM Rule JSON format.

    This backend converts Sigma rules into Sumo Logic CSIEM Rule JSON format with:
    - Cloud SIEM-compatible query expressions
    - MITRE ATT&CK technique and tactic mapping
    - Risk score calculation based on severity
    - Full rule metadata including name, description, and category
    """

    name: ClassVar[str] = "Sumo Logic Cloud SIEM Backend"
    identifier: ClassVar[str] = "sumologic_cse"
    formats: Dict[str, str] = {  # type: ignore[misc]
        "default": "Sumo Logic CSIEM Rule JSON format",
        "cse_rule": "CSIEM Rule JSON with full metadata",
    }
    requires_pipeline: bool = True  # type: ignore[misc]

    # Cloud SIEM uses uppercase boolean operators
    precedence: ClassVar[Tuple[ConditionItem, ConditionItem, ConditionItem]] = (  # type: ignore[assignment]
        ConditionNOT,
        ConditionAND,
        ConditionOR,
    )
    group_expression: ClassVar[str] = "({expr})"

    # Cloud SIEM Query tokens - uppercase operators
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
    bool_values: ClassVar[Dict[bool, str]] = {  # type: ignore[assignment]
        True: "true",
        False: "false",
    }

    # String matching operators - use wildcards with matches
    startswith_expression: ClassVar[str] = "{field} matches /{value}.*/"
    endswith_expression: ClassVar[str] = "{field} matches /.*{value}/"
    contains_expression: ClassVar[str] = "{field} matches /.*{value}.*/"
    wildcard_match_expression: ClassVar[str] = "{field} matches /{value}/"

    # Regular expressions - CSE uses 'matches' with regex
    # Must escape / (delimiter), and common regex metacharacters when used as literals
    re_expression: ClassVar[str] = "{field} matches /{regex}/"
    re_escape_char: ClassVar[str] = "\\"
    re_escape: ClassVar[Tuple[str, ...]] = ("/", ".")  # type: ignore[assignment]
    re_escape_escape_char: bool = True
    re_flag_prefix: bool = False  # CSE doesn't use flag prefixes in regex
    re_flags: Dict[SigmaRegularExpressionFlag, str] = {
        SigmaRegularExpressionFlag.IGNORECASE: "i",
    }

    # Numeric comparison operators
    compare_op_expression: ClassVar[str] = "{field} {operator} {value}"
    compare_operators: ClassVar[Dict[SigmaCompareExpression.CompareOperators, str]] = {  # type: ignore[valid-type]
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
        min_confidence: float = 0.25,
        schema_path: Optional[str] = None,
        include_confidence_metadata: bool = True,
        fail_on_unmapped_logsource: bool = False,
        include_full_sigma_rule: bool = False,
        **kwargs,
    ):
        super().__init__(processing_pipeline, collect_errors, **kwargs)
        self.rule_metadata: List[Dict[str, Any]] = []
        self.min_confidence = float(min_confidence)
        self.schema_path = schema_path
        self.include_confidence_metadata = include_confidence_metadata
        self.fail_on_unmapped_logsource = fail_on_unmapped_logsource
        if isinstance(include_full_sigma_rule, str):
            self.include_full_sigma_rule = include_full_sigma_rule.lower() in ("true", "1", "yes")
        else:
            self.include_full_sigma_rule = bool(include_full_sigma_rule)

        # Load CSE schema for field type checking
        from sigma.pipelines.sumologic.schema_loader import SchemaLoader

        self.schema = SchemaLoader.load(
            schema_path
        )  # Uses bundled schema if path is None

    def convert_rule(self, rule: SigmaRule, output_format=None, callback=None):
        if self.include_full_sigma_rule:
            rule._original_yaml = yaml.dump(  # type: ignore[attr-defined]
                rule.to_dict(), default_flow_style=False, sort_keys=False
            )
        return super().convert_rule(rule, output_format, callback)

    def escape_and_quote_field(self, field_name: str) -> str:
        """
        Escape and quote field names with CSE fields[] syntax for vendor-specific fields.

        CSE has two ways to reference fields:
        1. Normalized CSE schema fields: Direct reference (e.g., action, user_username)
        2. Vendor-specific/raw fields: Must use fields['fieldname'] syntax

        This method wraps vendor-specific fields (unmapped fields not in CSE schema)
        in the fields[] syntax.

        Args:
            field_name: Field name to escape/quote

        Returns:
            Escaped field name, wrapped in fields[] if vendor-specific

        Example:
            user_username → user_username (CSE schema field)
            auditType.category → fields['auditType.category'] (vendor-specific)
        """
        if not field_name:
            return field_name

        # Check if this is a CSE schema field (normalized field)
        if self.schema and self.schema.field_exists(field_name):
            # This is a known CSE schema field - use direct reference
            return field_name

        # Check if this looks like a vendor-specific field
        # Indicators: contains dots (nested structure), camelCase with dots, etc.
        is_vendor_specific = (
            "." in field_name  # Nested structure: auditType.category
            or field_name.startswith("EventData.")  # Windows EventData
            or field_name.startswith("fields.")  # Already wrapped
        )

        if is_vendor_specific:
            # Wrap in fields[] syntax
            # Remove 'fields.' prefix if already present
            if field_name.startswith("fields."):
                field_name = field_name[7:]  # Remove "fields."

            return f"fields['{field_name}']"

        # Default: use field name as-is (might be CSE schema field not in our schema file)
        return field_name

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

    def convert_condition_field_eq_val_num(self, cond, state: ConversionState) -> str:
        """
        Convert field=number condition with CSE schema type awareness.

        CSE schema has many fields that are logically numeric but typed as strings
        (e.g., logonType="3", metadata_deviceEventId="Security-4624").

        This method checks the target field's type in the schema and quotes numeric
        values if the field is a string type.
        """
        from sigma.conditions import ConditionFieldEqualsValueExpression

        if not isinstance(cond, ConditionFieldEqualsValueExpression):
            # Fallback to parent implementation
            return super().convert_condition_field_eq_val_num(cond, state)  # type: ignore[return-value]

        field_name = cond.field
        numeric_value = cond.value.to_plain()

        # Apply vendor-specific field wrapping
        escaped_field = self.escape_and_quote_field(field_name)

        # Check if field exists in schema and is a string type
        if self.schema and field_name:
            field_schema = self.schema.get_field(field_name)
            if field_schema and field_schema.field_type == "string":
                # Field is a string type - quote the numeric value
                return f'{escaped_field}="{numeric_value}"'

        # Field is numeric type or not in schema - use unquoted number
        return f"{escaped_field}={numeric_value}"

    def convert_condition_as_in_expression(self, cond, state: ConversionState) -> str:
        """
        Convert field in (value_list) with CSE schema type awareness.

        Overrides base class to quote numeric values when target field is a string type.
        """
        from sigma.conditions import ConditionFieldEqualsValueExpression
        from sigma.types import SigmaString
        from typing import cast

        if not all(
            isinstance(arg, ConditionFieldEqualsValueExpression) for arg in cond.args
        ):
            return super().convert_condition_as_in_expression(cond, state)  # type: ignore[return-value]

        field_name = cast(ConditionFieldEqualsValueExpression, cond.args[0]).field

        # Check if field is a string type in schema
        field_is_string = False
        if self.schema and field_name:
            field_schema = self.schema.get_field(field_name)
            if field_schema and field_schema.field_type == "string":
                field_is_string = True

        # Build the value list with proper quoting based on field type
        values = []
        for arg in cond.args:
            val = cast(ConditionFieldEqualsValueExpression, arg).value
            if isinstance(val, SigmaString):
                # String value - use standard string conversion (always quoted)
                values.append(self.convert_value_str(val, state))
            else:
                # Numeric value
                if field_is_string:
                    # Field is string type - quote the number
                    values.append(f'"{val.to_plain()}"')
                else:
                    # Field is numeric type - no quotes
                    values.append(str(val.to_plain()))

        return self.field_in_list_expression.format(
            field=self.escape_and_quote_field(field_name),
            list=self.list_separator.join(values),
        )

    def convert_condition_field_eq_field(self, cond, state: ConversionState):
        from sigma.exceptions import SigmaFeatureNotSupportedByBackendError

        raise SigmaFeatureNotSupportedByBackendError(
            "Field reference expressions (field-to-field comparisons) are not supported by the Sumo Logic CSE backend."
        )

    def convert_condition_val_str(self, cond, state: ConversionState) -> str:
        """
        Override to provide better error messages for unsupported unbound value patterns.

        Unbound values are values without field names (e.g., keywords lists).
        CSE requires field-based queries, so we provide helpful context about what failed.
        """
        from sigma.exceptions import SigmaFeatureNotSupportedByBackendError

        # Get the value being converted
        cond_value = cond.value

        # Build error message with context
        error_msg = "Conversion failed: Unbound value expressions (keywords) are not supported.\n\n"

        # Show the Sigma detection pattern
        error_msg += "Unsupported Sigma pattern:\n"
        error_msg += "  detection:\n"

        # Try to extract the detection item name from the parent chain
        detection_name = "keywords"  # default
        if hasattr(cond, "parent") and cond.parent:
            parent = cond.parent
            # Walk up to find the detection name
            while parent:
                if hasattr(parent, "parent") and hasattr(parent.parent, "detections"):
                    # Found the SigmaDetections object, search for this detection
                    for name, detection in parent.parent.detections.items():
                        if detection == parent:
                            detection_name = name
                            break
                    break
                parent = getattr(parent, "parent", None)

        error_msg += f"    {detection_name}:\n"

        # Show all values - walk up the parent chain to find the detection item
        values_to_show = [cond_value]  # Default to current value

        # Walk up parent chain: ConditionValueExpression -> ConditionOR -> SigmaDetection -> detection_items
        if hasattr(cond, "parent") and cond.parent:
            parent = cond.parent
            # If parent is ConditionOR/ConditionAND, go up one more level to SigmaDetection
            if hasattr(parent, "parent") and parent.parent:
                sigma_detection = parent.parent
                # SigmaDetection has detection_items
                if (
                    hasattr(sigma_detection, "detection_items")
                    and sigma_detection.detection_items
                ):
                    # Get the first (usually only) detection item
                    detection_item = sigma_detection.detection_items[0]
                    if hasattr(detection_item, "value") and isinstance(
                        detection_item.value, list
                    ):
                        values_to_show = detection_item.value

        for val in values_to_show:
            error_msg += f"      - '{val}'\n"

        error_msg += f"    condition: {detection_name}\n"
        error_msg += "\n"

        error_msg += (
            "Reason: CSE requires field-based queries. Keywords (unbound values) search across "
            "all fields, which is not supported in CSE's structured query language.\n\n"
            "Solution: Rewrite the rule to specify which fields to search.\n\n"
            "Example rewrite:\n"
            "  Before:\n"
            "    detection:\n"
            "      keywords:\n"
            "        - 'suspicious'\n"
            "        - 'malware'\n"
            "      condition: keywords\n\n"
            "  After:\n"
            "    detection:\n"
            "      selection:\n"
            "        commandLine|contains:\n"
            "          - 'suspicious'\n"
            "          - 'malware'\n"
            "      condition: selection\n\n"
            "Common searchable fields:\n"
            "  - commandLine (process commands)\n"
            "  - file_path (file paths)\n"
            "  - http_url (URLs)\n"
            "  - description (event descriptions)\n"
            "  - See CSE schema for field-specific searches"
        )

        raise SigmaFeatureNotSupportedByBackendError(error_msg)

    def _transform_windows_eventid(self, rule: SigmaRule, query: str) -> str:
        """
        Transform Windows EventID values to include service prefix.

        CSE uses format: {{service}}-{{EventID}} (e.g., "Security-4624")
        Sigma rules just have EventID numbers (e.g., "4624")

        This transforms:
          metadata_deviceEventId=4624 → metadata_deviceEventId="security-4624"

        The service prefix comes directly from the Sigma rule's logsource.service
        field for any rule where product=windows.

        Args:
            rule: Sigma rule object
            query: Generated CSE query expression

        Returns:
            Query with transformed EventID values
        """
        if "metadata_deviceEventId" not in query:
            return query

        if not rule.logsource or not hasattr(rule.logsource, "service"):
            return query

        service = rule.logsource.service
        if not service:
            return query

        SERVICE_TO_CHANNEL = {
            "sysmon": "Microsoft-Windows-Sysmon/Operational",
            "powershell": "PowerShell",
            "powershell-classic": "PowerShell",
            "taskscheduler": "Microsoft-Windows-TaskScheduler/Operational",
        }
        channel = SERVICE_TO_CHANNEL.get(service.lower(), service.capitalize())

        # Transform EventID values: metadata_deviceEventId="4624" → metadata_deviceEventId="Security-4624"
        # Also handle EventID in lists: metadata_deviceEventId in ("4624", "4625") → metadata_deviceEventId in ("Security-4624", "Security-4625")

        # Pattern 1: Single value (metadata_deviceEventId="4624" or metadata_deviceEventId=4624)
        def replace_single_quoted(match):
            event_id = match.group(1)
            return f'metadata_deviceEventId="{channel}-{event_id}"'

        # First handle quoted values
        query = re.sub(r'metadata_deviceEventId="(\d+)"', replace_single_quoted, query)
        # Then handle unquoted values (for backwards compatibility)
        query = re.sub(r"metadata_deviceEventId=(\d+)", replace_single_quoted, query)

        # Pattern 2: In list (metadata_deviceEventId in ("4624", "4625") or in (4624, 4625))
        def replace_list(match):
            list_content = match.group(1)
            # Extract all quoted or unquoted numbers
            event_ids = re.findall(r'"?(\d+)"?', list_content)
            # Add channel prefix to each
            transformed_ids = [f'"{channel}-{eid}"' for eid in event_ids]
            return f'metadata_deviceEventId in ({", ".join(transformed_ids)})'

        query = re.sub(r"metadata_deviceEventId in \(([^)]+)\)", replace_list, query)

        return query

    def _inject_vendor_product_metadata(self, rule: SigmaRule, query: str) -> str:
        """
        Inject metadata_vendor and metadata_product filters based on Sigma logsource.

        CSE parsers are vendor/product-specific, and queries should filter by these
        fields for proper log source targeting.

        Based on CSE Parser EventID Analysis (April 2026):
        - 252 parsers analyzed
        - Each parser has specific vendor/product combination
        - Proper filtering ensures query runs against correct log source

        Args:
            rule: Sigma rule object
            query: Generated CSE query expression

        Returns:
            Query with vendor/product metadata prepended

        Example:
            Input:  baseImage="powershell.exe"
            Output: metadata_vendor="Microsoft" AND metadata_product="Windows"
                    AND baseImage="powershell.exe"
        """
        from sigma.pipelines.sumologic.vendor_product_mapping import VendorProductMapper

        if not rule.logsource:
            return query

        # Get vendor/product mapping
        mapping = VendorProductMapper.get_vendor_product(
            product=(
                rule.logsource.product if hasattr(rule.logsource, "product") else None
            ),
            service=(
                rule.logsource.service if hasattr(rule.logsource, "service") else None
            ),
            category=(
                rule.logsource.category if hasattr(rule.logsource, "category") else None
            ),
        )

        vendor, product, pattern_type, classification = mapping

        # Check if we got a valid mapping (not all Nones)
        if vendor is None or product is None:
            # Track unmapped logsource for confidence metadata
            self._unmapped_logsource = {
                "product": (
                    rule.logsource.product
                    if hasattr(rule.logsource, "product")
                    else None
                ),
                "service": getattr(rule.logsource, "service", None),
                "category": getattr(rule.logsource, "category", None),
            }
            # Return query without metadata filters - don't inject invalid metadata_vendor="None"
            return query

        # Clear any previous unmapped logsource tracking (we have a valid mapping)
        self._unmapped_logsource = None  # type: ignore[assignment]

        # Skip "Generic" vendor/product metadata - these are fallback categories
        # not actual vendor/product filters in Cloud SIEM
        if vendor == "Generic":
            return query

        # For Windows: only inject vendor/product when the rule references vendor-specific
        # fields (EventID, EventData.*, Channel, etc.). Rules using only normalized Sigma
        # taxonomy fields rely on normalized sources and don't need vendor/product scoping.
        if vendor == "Microsoft" and product == "Windows":
            has_vendor_fields = "metadata_deviceEventId" in query or "fields[" in query
            if not has_vendor_fields:
                return query

        # Prepend vendor/product filters to the query
        metadata_filter = f'metadata_vendor="{vendor}" AND metadata_product="{product}"'

        # Combine with existing query
        if query.strip():
            return f"{metadata_filter} AND {query}"
        else:
            return metadata_filter

    def _transform_windows_metadata_fields(self, rule: SigmaRule, query: str) -> str:
        """
        Transform Windows metadata fields to CSE fields[] syntax.

        Windows event metadata fields in Sigma use underscore notation:
          - Provider_Name
          - Computer
          - Channel
          - etc.

        CSE stores these in the fields object with dot notation:
          - fields['Provider.Name']
          - fields['Computer']
          - fields['Channel']

        This transforms:
          Provider_Name="value" → fields['Provider.Name']="value"

        Args:
            rule: Sigma rule object
            query: Generated CSE query expression

        Returns:
            Query with transformed metadata fields
        """
        # Only apply to Windows rules
        if not rule.logsource or not hasattr(rule.logsource, "product"):
            return query

        if rule.logsource.product and rule.logsource.product.lower() != "windows":
            return query

        # Map Windows metadata fields (Sigma underscore → CSE dot notation in fields[])
        # Based on Windows Event Log XML schema
        metadata_fields = {
            "Provider_Name": "fields['Provider.Name']",
            "Provider_Guid": "fields['Provider.Guid']",
            "Channel": "fields['Channel']",
            "Computer": "fields['Computer']",
            "EventRecordID": "fields['EventRecordID']",
            "ProcessID": "fields['Execution.ProcessID']",
            "ThreadID": "fields['Execution.ThreadID']",
            "Keywords": "fields['Keywords']",
            "Level": "fields['Level']",
            "Task": "fields['Task']",
            "Opcode": "fields['Opcode']",
            "Version": "fields['Version']",
        }

        # Transform each metadata field in the query
        for sigma_field, cse_field in metadata_fields.items():
            # Replace field name in various contexts:
            # 1. Equality: Provider_Name="value"
            query = re.sub(rf"\b{sigma_field}=", f"{cse_field}=", query)

            # 2. In operator: Provider_Name in (...)
            query = re.sub(rf"\b{sigma_field}\s+in\s+", f"{cse_field} in ", query)

            # 3. Matches operator: Provider_Name matches /pattern/
            query = re.sub(
                rf"\b{sigma_field}\s+matches\s+", f"{cse_field} matches ", query
            )

        return query

    def _wrap_vendor_specific_fields(self, rule: SigmaRule, query: str) -> str:
        """
        Wrap vendor-specific fields in fields[] syntax based on logsource context.

        Rules with specific product/service are vendor-specific and their unmapped fields
        should use fields[] syntax. Rules with only category use normalized field names.

        For Windows logsources, unmapped fields are automatically prefixed with EventData.
        to match Cloud SIEM's structure (e.g., TargetImage → EventData.TargetImage).

        Args:
            rule: Sigma rule object with logsource information
            query: Generated CSIEM query expression

        Returns:
            Query with vendor-specific fields wrapped in fields[] syntax
        """
        if not rule.logsource:
            return query

        # Determine if this is a vendor-specific logsource
        has_product = rule.logsource.product is not None
        has_service = rule.logsource.service is not None
        has_only_category = (
            rule.logsource.category is not None and not has_product and not has_service
        )

        # Only process vendor-specific logsources (not generic categories)
        if not (has_product or has_service) or has_only_category:
            return query

        # Check if this is a Windows logsource
        is_windows = (
            rule.logsource.product and rule.logsource.product.lower() == "windows"
        )

        # Windows Event Log header/system fields that should NOT get EventData. prefix
        # These appear before the EventData body in Windows Event Logs
        WINDOWS_HEADER_FIELDS = {
            "Channel",
            "Computer",
            "EventID",
            "EventRecordID",
            "Execution",
            "Keywords",
            "Level",
            "Opcode",
            "Provider",
            "Security",
            "Task",
            "TimeCreated",
            "Version",
        }

        # Find all bare field names (not already in fields[] syntax, not metadata fields)
        # Pattern: field name at word boundary, followed by operator (=, in, matches, etc.)
        # Exclude: metadata_, fields[, already wrapped fields
        field_pattern = r"\b(?!metadata_|fields\[)([a-zA-Z_][a-zA-Z0-9_\.]*)\b(?=\s*(?:=|!=|in\s|matches\s|<|>|<=|>=))"

        def wrap_if_not_in_schema(match):
            field_name = match.group(1)

            # Don't wrap if field is in CSIEM schema
            if self.schema and self.schema.field_exists(field_name):
                return field_name

            # Don't wrap boolean operators
            if field_name.upper() in ("AND", "OR", "NOT"):
                return field_name

            # Don't wrap CSIEM functions
            if field_name in ("isEmpty",):
                return field_name

            # For Windows logsources, check if it's a header field
            if is_windows:
                # Check if this is a Windows header field (base name or dotted like Provider.Name)
                base_field = field_name.split(".")[0]
                if base_field in WINDOWS_HEADER_FIELDS:
                    # Windows header field - wrap as-is without EventData prefix
                    return f"fields['{field_name}']"
                else:
                    # Windows EventData field - prefix with EventData.
                    return f"fields['EventData.{field_name}']"

            # For other vendors, just wrap the field name
            return f"fields['{field_name}']"

        # Split query into quoted and unquoted segments to avoid wrapping
        # words inside string values (e.g., "sign" in "Max sign in attempts")
        # Matches: "quoted strings", /regex patterns/, and everything else
        segments = re.split(r'("(?:[^"\\]|\\.)*"|/(?:[^/\\]|\\.)*?/)', query)
        result_parts = []
        for i, segment in enumerate(segments):
            if i % 2 == 1:
                # Inside a quoted string or regex — leave untouched
                result_parts.append(segment)
            else:
                # Outside quotes — apply field wrapping
                result_parts.append(
                    re.sub(field_pattern, wrap_if_not_in_schema, segment)
                )

        return "".join(result_parts)

    def finalize_query_default(
        self, rule: SigmaRule, query: str, index: int, state: ConversionState
    ) -> str:
        """
        Finalize query and create rule JSON metadata.
        Also clean up unnecessary quotes in regex expressions and escape special chars.
        """

        # Escape special regex characters in values before removing quotes
        # CSE uses / as regex delimiter, so literal / must be escaped as \/
        # Also escape . to match literal dots, not "any character"
        def escape_regex_value(match):
            prefix = match.group(1) or ""  # Leading .*
            value = match.group(2)  # The quoted value
            suffix = match.group(3) or ""  # Trailing .*

            # Escape forward slashes (regex delimiter)
            value = value.replace("/", "\\/")
            # Escape dots to match literal dots
            value = value.replace(".", "\\.")
            # Escape other regex metacharacters that should be literal
            value = value.replace("(", "\\(").replace(")", "\\)")
            value = value.replace("[", "\\[").replace("]", "\\]")
            value = value.replace("{", "\\{").replace("}", "\\}")
            value = value.replace("^", "\\^").replace("$", "\\$")
            value = value.replace("+", "\\+").replace("?", "\\?")
            value = value.replace("|", "\\|")

            return f"matches /{prefix}{value}{suffix}/"

        # Remove quotes and escape special characters in regex patterns
        query = re.sub(
            r'matches /(\.\*)?\"([^"]+)\"(\.\*)?/', escape_regex_value, query
        )

        # Fix NOT operator formatting - remove space after !
        # Cloud SIEM requires !(expr) or !field, not ! (expr) or ! field
        query = re.sub(r"!\s+", "!", query)

        # Fix comparison operator spacing for consistency
        # Standardize to no spaces around operators: field=value, field>=value
        # This matches the = operator formatting and keeps expressions compact
        # Only apply outside regex literals (matches /.../) to avoid corrupting patterns
        def _strip_operator_spaces(q: str) -> str:
            parts = re.split(r"(matches\s*/[^/]*/)", q)
            for i, part in enumerate(parts):
                if not part.startswith("matches"):
                    part = re.sub(r"\s*>=\s*", ">=", part)
                    part = re.sub(r"\s*<=\s*", "<=", part)
                    part = re.sub(r"\s*!=\s*", "!=", part)
                    part = re.sub(r"\s*>\s*", ">", part)
                    part = re.sub(r"\s*<\s*", "<", part)
                    parts[i] = part
            return "".join(parts)

        query = _strip_operator_spaces(query)

        # Transform Windows EventID values to include channel prefix
        query = self._transform_windows_eventid(rule, query)

        # Transform Windows metadata fields to fields[] syntax
        query = self._transform_windows_metadata_fields(rule, query)

        # Wrap vendor-specific fields based on logsource context
        query = self._wrap_vendor_specific_fields(rule, query)

        # Inject vendor/product metadata based on logsource
        query = self._inject_vendor_product_metadata(rule, query)

        # Create rule JSON and store it
        rule_json = self.create_rule_json(rule, query)
        self.rule_metadata.append(rule_json)

        # Return JSON string for this single rule
        return json.dumps(rule_json, indent=4, sort_keys=False)

    def finalize_output_default(self, queries: List[str]) -> Any:
        """
        Finalize output by wrapping in rules array structure.
        """
        # Parse JSON strings back to objects
        rule_objects = [json.loads(q) for q in queries]

        # Wrap in rules structure and return as list
        return [json.dumps({"rules": rule_objects}, indent=4, sort_keys=False)]

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

        # Determine category from MITRE tactic tags
        category = self._determine_category_from_tags(mitre_tags)

        # Build comprehensive description
        description = self._build_description(rule, techniques)

        # Map status to enabled and prototype
        enabled, prototype = self._map_status(rule.status)

        # Get entity selectors based on logsource
        entity_selectors = self._get_entity_selectors(rule.logsource)

        # Create rule JSON
        rule_json = {
            "content_type": "RULE",
            "sigma_uid": str(rule.id) if rule.id else None,
            "enabled": enabled,
            "is_prototype": prototype,
            "name": rule.title,
            "name_expression": rule.title,
            "rule_source": "user",
            "summary_expression": "",
            "pattern_type": "templated_match",
            "stream": "record",
            "description_expression": description,
            "expression": query,
        }

        # Add entity selectors if available
        if entity_selectors:
            rule_json["entity_selectors"] = entity_selectors  # type: ignore[assignment]
        # Add score mapping
        rule_json["score_mapping"] = {  # type: ignore[assignment]
            "default": risk_score,
            "type": "constant",
            "field": None,
            "mapping": [],
        }

        # Add tags array with normalized MITRE tags
        if mitre_tags:
            rule_json["tags"] = mitre_tags  # type: ignore[assignment]
        # Add category (derived from MITRE tactic tags)
        rule_json["category"] = category

        # Collect and inject confidence metadata
        if self.include_confidence_metadata:
            confidence_metadata = self._collect_confidence_metadata(rule)

            # Check confidence threshold
            if (
                confidence_metadata["overall_score"]
                < confidence_metadata["threshold_used"]
            ):
                from sigma.exceptions import SigmaFeatureNotSupportedByBackendError

                error_msg = self._build_confidence_error_message(confidence_metadata)
                raise SigmaFeatureNotSupportedByBackendError(error_msg)

            # Check for unmapped logsource if strict mode enabled
            if self.fail_on_unmapped_logsource and not confidence_metadata.get(
                "has_vendor_mapping", True
            ):
                from sigma.exceptions import SigmaFeatureNotSupportedByBackendError

                unmapped = confidence_metadata.get("unmapped_logsource", {})
                raise SigmaFeatureNotSupportedByBackendError(
                    f"Conversion blocked: No vendor/product mapping found for logsource "
                    f"(product={unmapped.get('product')}, service={unmapped.get('service')}, "
                    f"category={unmapped.get('category')}). "
                    f"Use -O fail_on_unmapped_logsource=false to allow conversion without metadata filters."
                )

            # Add confidence metadata to rule JSON
            rule_json["mapping_confidence"] = confidence_metadata  # type: ignore[assignment]

        if self.include_full_sigma_rule:
            rule_json["full_sigma_rule"] = getattr(  # type: ignore[assignment]
                rule, "_original_yaml", ""
            )

        return rule_json

    def _get_used_fields(self, rule: SigmaRule) -> set:
        """
        Extract the set of field names actually used in the rule's detection logic.

        Args:
            rule: Sigma rule being analyzed

        Returns:
            Set of field names used in detection
        """
        used_fields = set()

        # Traverse detection items to collect field names
        if (
            hasattr(rule, "detection")
            and rule.detection
            and hasattr(rule.detection, "detections")
        ):
            for detection_name, detection in rule.detection.detections.items():
                if hasattr(detection, "detection_items"):
                    for item in detection.detection_items:
                        if hasattr(item, "field") and item.field:
                            used_fields.add(item.field)

        return used_fields

    def _compute_entity_confidence(self, rule: SigmaRule) -> Dict[str, Any]:
        """
        Compute entity selection confidence for a rule.

        Checks if the rule has entity selectors defined, and whether they are expected
        based on the logsource category.

        Args:
            rule: Sigma rule being converted

        Returns:
            Dictionary with entity confidence metadata:
            {
                "has_selectors": bool,
                "expected": bool,
                "category": str,
                "expected_entities": list,
                "actual_entities": list
            }
        """
        from sigma.pipelines.sumologic.category_entity_mapping import (
            get_entities_for_category,
            has_entity_mapping,
        )

        # Get entity selectors that were actually assigned
        actual_selectors = self._get_entity_selectors(rule.logsource)
        has_selectors = len(actual_selectors) > 0

        # Determine if entities are expected based on category
        category = None
        if rule.logsource and hasattr(rule.logsource, "category"):
            category = rule.logsource.category

        expected = False
        expected_entity_types = []

        if category:
            expected = has_entity_mapping(category)
            if expected:
                expected_selectors = get_entities_for_category(category)
                expected_entity_types = [e["entity_type"] for e in expected_selectors]

        actual_entity_types = [e["entity_type"] for e in actual_selectors]

        return {
            "has_selectors": has_selectors,
            "expected": expected,
            "category": category or "unknown",
            "expected_entities": expected_entity_types,
            "actual_entities": actual_entity_types,
        }

    def _collect_confidence_metadata(self, rule: SigmaRule) -> Dict[str, Any]:
        """
        Collect confidence metadata from pipeline transformations.

        Args:
            rule: Sigma rule being converted

        Returns:
            Confidence metadata dictionary for injection into rule JSON
        """
        from sigma.pipelines.sumologic.sumologic import ConfidenceAwareFieldMapping
        from sigma.pipelines.sumologic.confidence import get_category_threshold

        all_field_mappings = []
        all_confidences = []
        logsource_category = "unknown"
        warnings_list = []

        # Get the set of fields actually used in the rule's detection logic (already transformed)
        used_cse_fields = self._get_used_fields(rule)

        # Build reverse mapping from CSE field → Sigma field
        cse_to_sigma = {}
        if self.last_processing_pipeline and hasattr(
            self.last_processing_pipeline, "items"
        ):
            for item in self.last_processing_pipeline.items:
                if (
                    hasattr(rule, "applied_processing_items")
                    and item.identifier not in rule.applied_processing_items
                ):
                    continue
                transformation = item.transformation
                if isinstance(transformation, ConfidenceAwareFieldMapping):
                    # Build reverse mapping
                    for sigma_field, cse_field in transformation.mapping.items():
                        cse_to_sigma[cse_field] = sigma_field

        # Extract confidence from pipeline transformations
        # IMPORTANT: Only include transformations that were actually applied to this rule
        if self.last_processing_pipeline and hasattr(
            self.last_processing_pipeline, "items"
        ):
            for item in self.last_processing_pipeline.items:
                # Skip transformations that weren't applied to this specific rule
                if (
                    hasattr(rule, "applied_processing_items")
                    and item.identifier not in rule.applied_processing_items
                ):
                    continue

                transformation = item.transformation
                if isinstance(transformation, ConfidenceAwareFieldMapping):
                    # Get confidence metadata from transformation
                    metadata = transformation.get_confidence_metadata()
                    logsource_category = metadata["logsource_category"]

                    # Filter to only include fields that are actually used in the rule
                    for mapping in metadata["field_mappings"]:
                        sigma_field = mapping["sigma_field"]
                        cse_field = mapping["cse_field"]

                        # Check if this CSE field was used in the detection logic
                        if cse_field in used_cse_fields:
                            all_field_mappings.append(mapping)
                            all_confidences.append(mapping["confidence"])
                            warnings_list.extend(mapping.get("warnings", []))

        # Detect unmapped fields (fields used in the rule but not in any ConfidenceAwareFieldMapping)
        # These are fields that passed through the pipeline unchanged
        mapped_fields = {mapping["cse_field"] for mapping in all_field_mappings}
        unmapped_fields = used_cse_fields - mapped_fields

        # Determine if this is a vendor-specific logsource where pass-through is expected
        is_vendor_specific = rule.logsource and (
            rule.logsource.product is not None or rule.logsource.service is not None
        )

        if unmapped_fields:
            for field in sorted(unmapped_fields):
                if is_vendor_specific:
                    # Vendor-specific pass-through: field goes to fields['x'] — correct behavior
                    all_confidences.append(0.8)
                    all_field_mappings.append(
                        {
                            "sigma_field": field,
                            "cse_field": field,
                            "confidence": 0.8,
                            "factors": {
                                "semantic_similarity": 1.0,
                                "data_preservation": 1.0,
                                "type_compatibility": 1.0,
                                "field_specificity": 0.8,
                            },
                            "warnings": [
                                "Vendor-specific pass-through (fields[] wrapped)"
                            ],
                        }
                    )
                else:
                    # Generic logsource with unmapped field — genuinely uncertain
                    warning = f"Field '{field}' is not mapped to CSE schema and may not exist in Cloud SIEM logs"
                    warnings_list.append(warning)
                    all_confidences.append(0.0)
                    all_field_mappings.append(
                        {
                            "sigma_field": field,
                            "cse_field": field,
                            "confidence": 0.0,
                            "factors": {
                                "semantic_similarity": 0.0,
                                "data_preservation": 0.0,
                                "type_compatibility": 0.0,
                                "field_specificity": 0.0,
                            },
                            "warnings": [
                                f"UNMAPPED: Field '{field}' is not in any CSE schema mapping"
                            ],
                        }
                    )

        # Compute overall confidence (weighted average)
        if all_confidences:
            overall_score = sum(all_confidences) / len(all_confidences)
        else:
            overall_score = (
                1.0  # No mappings = full confidence (rule has no field filters)
            )

        # Check entity selector coverage
        # Rules should have entity selectors when they have meaningful log source context
        entity_confidence = self._compute_entity_confidence(rule)
        entity_has_selectors = entity_confidence.get("has_selectors", False)
        entity_expected = entity_confidence.get("expected", False)

        # If entities are expected but missing, add warning and adjust confidence
        if entity_expected and not entity_has_selectors:
            warning = (
                f"No entity selectors defined for category '{entity_confidence.get('category', 'unknown')}'. "
                f"Expected entities: {', '.join(entity_confidence.get('expected_entities', []))}. "
                f"Entity selection helps Cloud SIEM correlate alerts and track entity behavior."
            )
            warnings_list.append(warning)

            # Reduce confidence by 10% for missing entities (not as critical as unmapped fields)
            overall_score = overall_score * 0.9

        # Check for unmapped logsource (no vendor/product mapping found)
        unmapped_logsource = getattr(self, "_unmapped_logsource", None)
        if unmapped_logsource:
            logsource_str = (
                f"product={unmapped_logsource['product']}, "
                f"service={unmapped_logsource['service']}, "
                f"category={unmapped_logsource['category']}"
            )
            warnings_list.append(
                f"No vendor/product mapping for logsource ({logsource_str}). "
                f"Rule will not have metadata_vendor/metadata_product filters and may not match expected logs."
            )
            # Reset for next rule
            self._unmapped_logsource = None  # type: ignore[assignment]
        # Get threshold for this category
        category_threshold = get_category_threshold(logsource_category)

        # User-configured min_confidence overrides category threshold
        # Special case: min_confidence=0.0 disables all threshold checking
        if self.min_confidence == 0.0:
            threshold_used = 0.0
        else:
            threshold_used = self.min_confidence

        return {
            "overall_score": round(overall_score, 3),
            "threshold_used": round(threshold_used, 3),
            "category_threshold": round(category_threshold, 3),
            "logsource_category": logsource_category,
            "field_mappings": all_field_mappings,
            "warnings": warnings_list,
            "blocked": overall_score < threshold_used,
            "entity_selection": entity_confidence,
            "has_vendor_mapping": unmapped_logsource is None,
            "unmapped_logsource": unmapped_logsource,
        }

    def _build_confidence_error_message(
        self, confidence_metadata: Dict[str, Any]
    ) -> str:
        """
        Build detailed error message for confidence threshold failures.

        Args:
            confidence_metadata: Confidence metadata collected from pipeline

        Returns:
            Formatted error message explaining why conversion was blocked
        """
        overall = confidence_metadata["overall_score"]
        threshold = confidence_metadata["threshold_used"]
        category = confidence_metadata["logsource_category"]

        msg = [
            f"Conversion blocked: Confidence score {overall:.3f} below threshold {threshold:.3f}",
            f"Log source category: {category}",
            "",
            "Low-confidence field mappings:",
        ]

        # List field mappings below threshold
        for mapping in confidence_metadata["field_mappings"]:
            if mapping["confidence"] < threshold:
                sigma_field = mapping["sigma_field"]
                cse_field = mapping["cse_field"]
                conf = mapping["confidence"]
                factors = mapping["factors"]

                msg.append(f"  - {sigma_field} → {cse_field}: {conf:.3f}")
                msg.append(
                    f"    Factors: semantic={factors['semantic_similarity']:.2f}, "
                    f"data_pres={factors['data_preservation']:.2f}, "
                    f"type={factors['type_compatibility']:.2f}, "
                    f"specificity={factors['field_specificity']:.2f}"
                )

        # Add warnings if any
        if confidence_metadata["warnings"]:
            msg.append("")
            msg.append("Warnings:")
            for warning in confidence_metadata["warnings"]:
                msg.append(f"  - {warning}")

        msg.append("")
        msg.append(
            f"To allow this conversion: Use -O min_confidence={overall - 0.05:.2f} or lower"
        )

        return "\n".join(msg)

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
        Get entity selectors based on logsource using 3-tier priority:
        1. Category-based (highest specificity - from Sigma taxonomy)
        2. Classification-based (product pattern from vendor_product_mapping)
        3. Product-based (legacy fallback)

        Args:
            logsource: Sigma rule logsource object

        Returns:
            List of entity selector dictionaries (empty if cannot determine confidently)
        """
        from sigma.pipelines.sumologic.vendor_product_mapping import VendorProductMapper
        from sigma.pipelines.sumologic.entity_classification import (
            get_entities_for_classification,
        )
        from sigma.pipelines.sumologic.category_entity_mapping import (
            get_entities_for_category,
        )

        entity_selectors: List[Dict[str, str]] = []

        if not logsource:
            return entity_selectors

        # Extract category, product, and service
        category = None
        product = None
        service = None
        if hasattr(logsource, "category"):
            category = logsource.category
        if hasattr(logsource, "product"):
            product = logsource.product
        if hasattr(logsource, "service"):
            service = logsource.service

        # Priority 1: Category-based (from comprehensive Sigma taxonomy mapping)
        if category:
            entities = get_entities_for_category(category)
            if entities:
                return entities

        # Priority 2: Classification-based (uses metadata from vendor_product_mapping)
        classification = VendorProductMapper.get_source_classification(
            product, service, category
        )
        if classification:
            return get_entities_for_classification(classification)

        # Priority 3: Product-based fallback (legacy - for backward compatibility)
        if product:
            product_lower = product.lower()

            # Windows, Linux, macOS: hostname + username
            if product_lower in ["windows", "linux", "macos"]:
                return [
                    {"entity_type": "_hostname", "expression": "device_hostname"},
                    {"entity_type": "_username", "expression": "user_username"},
                ]

            # Cloud providers: source IP + username
            elif product_lower in ["azure", "aws"]:
                return [
                    {"entity_type": "_ip", "expression": "srcDevice_ip"},
                    {"entity_type": "_username", "expression": "user_username"},
                ]

            # GitHub: username (user-driven actions)
            elif product_lower == "github":
                return [
                    {"entity_type": "_username", "expression": "user_username"},
                ]

            # Office 365 / M365: username
            elif product_lower in ["office365", "m365"]:
                return [
                    {"entity_type": "_username", "expression": "user_username"},
                ]

        # Fail safely - return empty list
        # Better to have no entity selectors than wrong ones
        # Rule will need manual review for entity selection
        return entity_selectors

    def _determine_category_from_tags(self, mitre_tags: List[str]) -> str:
        """
        Determine CSE rule category from MITRE tactic tags.

        Per platform implementation: Category is derived from the first MITRE tactic tag
        by looking up the tactic ID and using its label as the category.

        Args:
            mitre_tags: List of normalized MITRE tags (e.g., ["_mitreAttackTactic:TA0002"])

        Returns:
            Category string (tactic label or "Unknown/Other")
        """
        # Mapping of MITRE tactic IDs to their labels (which are the categories)
        TACTIC_ID_TO_CATEGORY = {
            "TA0001": "Initial Access",
            "TA0002": "Execution",
            "TA0003": "Persistence",
            "TA0004": "Privilege Escalation",
            "TA0005": "Defense Evasion",
            "TA0006": "Credential Access",
            "TA0007": "Discovery",
            "TA0008": "Lateral Movement",
            "TA0009": "Collection",
            "TA0010": "Exfiltration",
            "TA0011": "Command and Control",
            "TA0040": "Impact",
            "TA0042": "Resource Development",
            "TA0043": "Reconnaissance",
        }

        # Find the first MITRE tactic tag and extract its ID
        for tag in mitre_tags:
            if tag.startswith("_mitreAttackTactic:"):
                tactic_id = tag.split(":", 1)[
                    1
                ]  # Extract "TA0002" from "_mitreAttackTactic:TA0002"
                return TACTIC_ID_TO_CATEGORY.get(tactic_id, self.DEFAULT_CATEGORY)

        # No tactic tag found
        return self.DEFAULT_CATEGORY


class SumoLogicCSERuleBackend(SumoLogicCSEBackend):
    """
    Sumo Logic Cloud SIEM Rule Backend that outputs complete JSON rules.

    This backend extends SumoLogicCSEBackend to provide full CSIEM Rule JSON
    output suitable for direct import via Cloud SIEM API or UI.
    """

    name: ClassVar[str] = "Sumo Logic Cloud SIEM Rule JSON Backend"
    identifier: ClassVar[str] = "sumologic_cse_rule"

    def finalize_query_cse_rule(
        self, rule: SigmaRule, query: str, index: int, state: ConversionState
    ) -> str:
        """
        Finalize query as CSIEM Rule JSON for cse_rule format.
        """
        rule_json = self.create_rule_json(rule, query)
        self.rule_metadata.append(rule_json)
        return json.dumps(rule_json, indent=4, sort_keys=False)

    def finalize_output_cse_rule(self, queries: List[Any]) -> Any:
        """
        Output collected rules as JSON with rules wrapper.
        """
        # Parse JSON strings back to objects
        rule_objects = [json.loads(q) for q in queries]

        # Wrap in rules structure and return as list
        return [json.dumps({"rules": rule_objects}, indent=4, sort_keys=False)]
