from sigma.processing.transformations import (
    AddConditionTransformation,
    FieldMappingTransformation,
    DetectionItemFailureTransformation,
    RuleFailureTransformation,
)
from sigma.processing.conditions import (
    LogsourceCondition,
    IncludeFieldCondition,
    ExcludeFieldCondition,
)
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from typing import Dict, Any, Optional
from .schema_loader import SchemaIndex, SchemaLoader
from .confidence import compute_confidence, ConfidenceScore


class ConfidenceAwareFieldMapping(FieldMappingTransformation):
    """
    Enhanced FieldMappingTransformation that computes and stores confidence scores.

    This subclass computes confidence scores for all field mappings at initialization
    and provides access to this metadata for the backend to inject into rule JSON.
    """

    def __init__(
        self,
        mapping: Dict[str, str],
        logsource_category: str,
        schema: Optional[SchemaIndex] = None
    ):
        """
        Initialize confidence-aware field mapping.

        Args:
            mapping: Dictionary of Sigma field → CSE field mappings
            logsource_category: Sigma logsource category (e.g., "process_creation")
            schema: CSE schema index for validation (None if schema not loaded)
        """
        super().__init__(mapping)
        self.logsource_category = logsource_category
        self.schema = schema

        # Compute confidence for all mappings at initialization
        self.confidence_scores: Dict[str, ConfidenceScore] = {}
        for sigma_field, cse_field in mapping.items():
            score = compute_confidence(
                sigma_field=sigma_field,
                cse_field=cse_field,
                logsource_category=logsource_category,
                schema=schema
            )
            self.confidence_scores[sigma_field] = score

    def get_confidence_metadata(self) -> Dict[str, Any]:
        """
        Get confidence metadata for backend to inject into rule JSON.

        Returns:
            Dictionary with field mapping confidence information
        """
        return {
            "logsource_category": self.logsource_category,
            "field_mappings": [
                score.to_dict()
                for score in self.confidence_scores.values()
            ]
        }

    def get_overall_confidence(self) -> float:
        """
        Compute overall confidence for this mapping transformation.

        Uses weighted average of individual field mapping confidences.
        """
        if not self.confidence_scores:
            return 1.0

        total_confidence = sum(score.overall for score in self.confidence_scores.values())
        return total_confidence / len(self.confidence_scores)


class DataFieldTransformation(DetectionItemFailureTransformation):
    """
    Smart transformation for Windows 'Data' field that handles structured patterns.

    Windows Event Log Data field usage falls into three categories:
    1. Key=Value patterns (e.g., 'EngineVersion=2.') → Transform to EventData.EngineVersion
    2. Key:Value patterns (e.g., 'statement:DROP TABLE') → Transform to EventData.statement
    3. Arbitrary strings (e.g., 'Net.WebClient') → Block with helpful error

    This transformation automatically handles categories 1 and 2, only failing on category 3.
    """

    def __init__(self):
        # Initialize with a default error message (will be customized per detection item)
        super().__init__(
            "Field 'Data' contains arbitrary string patterns that cannot be converted.\n\n"
            "See error details for specific values that failed conversion."
        )

    def apply_detection_item(self, detection_item):
        """
        Transform Data field to EventData.* fields when possible.

        Detects and transforms structured patterns:
        - Data|contains: 'FieldName=Value' → EventData.FieldName|contains: 'Value'
        - Data|contains: 'FieldName:Value' → EventData.FieldName|contains: 'Value'

        Raises error for arbitrary strings that can't be parsed.
        """
        import re
        from sigma.rule import SigmaDetectionItem
        from sigma.exceptions import SigmaTransformationError
        from sigma.types import SigmaString

        # Only process if this is the Data field
        if detection_item.field != "Data":
            return

        # Get detection values (handle both single values and lists)
        values = detection_item.value if isinstance(detection_item.value, list) else [detection_item.value]

        # Track which values can be transformed vs. which fail
        structured_patterns = []
        arbitrary_strings = []

        for value in values:
            # Convert SigmaString to plain string for pattern matching
            if hasattr(value, 'to_plain'):
                value_str = value.to_plain()
            else:
                value_str = str(value)

            # Strip wildcards added by |contains modifier (e.g., '*EngineVersion=2.*' → 'EngineVersion=2.')
            # This lets us detect structured patterns even when wrapped with wildcards
            value_str_clean = value_str.strip('*')

            # Try to parse structured patterns: FieldName=Value or FieldName:Value
            # Match word characters for field name, then = or :, then capture the rest
            match = re.match(r'^(\w+)[:=](.+)$', value_str_clean)

            if match:
                field_name = match.group(1)
                field_value = match.group(2)
                structured_patterns.append((field_name, field_value, value))
            else:
                # Not a structured pattern - arbitrary string
                arbitrary_strings.append(value_str)

        # If any arbitrary strings found, fail with helpful error
        if arbitrary_strings:
            # Build error message showing original Sigma criteria and what failed
            error_msg = "Field 'Data' contains arbitrary string patterns that cannot be converted.\n\n"

            # Show the original Sigma detection criteria
            error_msg += "Original Sigma detection:\n"
            error_msg += f"  Data|contains:\n"
            for value in values:
                value_str = value.to_plain() if hasattr(value, 'to_plain') else str(value)
                # Highlight unsupported values with ✗, supported with ✓
                if value_str.strip('*') in [s.strip('*') for s in arbitrary_strings]:
                    error_msg += f"    ✗ '{value_str.strip('*')}'  ← UNSUPPORTED (arbitrary string)\n"
                else:
                    error_msg += f"    ✓ '{value_str.strip('*')}'  ← OK (structured pattern)\n"

            error_msg += (
                "\nReason: CSE parses Windows Event Log Data into structured EventData.* fields. "
                "Arbitrary string matching against the Data blob is not supported because "
                "we cannot determine which EventData field contains the string.\n\n"
            )

            # Show what was successfully converted (if any)
            if structured_patterns:
                error_msg += "Successfully converted:\n"
                for field_name, field_value, _ in structured_patterns:
                    error_msg += f"  ✓ '{field_name}={field_value}' → EventData.{field_name}|contains: '{field_value}'\n"
                error_msg += "\n"

            error_msg += "Failed to convert:\n"
            for s in arbitrary_strings:
                error_msg += f"  ✗ '{s.strip('*')}' - No field name found (arbitrary string)\n"

            error_msg += (
                "\nSupported patterns:\n"
                "  ✓ Key=Value: 'EngineVersion=2.' → Converts to EventData.EngineVersion\n"
                "  ✓ Key:Value: 'statement:DROP' → Converts to EventData.statement\n"
                "  ✗ Arbitrary: 'Net.WebClient' → Cannot determine which field contains this\n\n"
                "Solution: Rewrite to use specific EventData field names.\n"
                "Example:\n"
                "  Before: Data|contains: 'Net.WebClient'\n"
                "  After:  EventData.ContextInfo|contains: 'Net.WebClient'\n\n"
                "Common EventData fields:\n"
                "  - EventData.ContextInfo (PowerShell command/script content)\n"
                "  - EventData.CommandLine (process commands)\n"
                "  - EventData.Message (generic message text)\n"
                "  - See Windows Event Log documentation for event-specific fields"
            )
            raise SigmaTransformationError(error_msg)

        # All values are structured patterns - transform them
        # For now, take the first pattern and transform the detection item
        # (Multiple fields would need multiple detection items, which is complex)
        if len(structured_patterns) == 1:
            field_name, field_value, original_value = structured_patterns[0]

            # Transform the field name to EventData.FieldName
            detection_item.field = f"EventData.{field_name}"

            # Update the value to just the value part (removing the field name prefix)
            # Preserve wildcard structure from the original SigmaString
            plain = original_value.to_plain() if hasattr(original_value, 'to_plain') else str(original_value)
            prefix = '*' if plain.startswith('*') else ''
            suffix = '*' if plain.endswith('*') else ''
            detection_item.value = [SigmaString(f"{prefix}{field_value}{suffix}")]

        elif len(structured_patterns) > 1:
            # Multiple structured fields - this is complex, need to create multiple detection items
            # For now, fail with a helpful message explaining manual rewrite is needed

            error_msg = "Field 'Data' contains multiple structured field patterns.\n\n"

            # Show the original Sigma detection criteria
            error_msg += "Original Sigma detection:\n"
            error_msg += f"  Data|contains|all:\n"
            for field_name, field_value, original_value in structured_patterns:
                value_str = original_value.to_plain() if hasattr(original_value, 'to_plain') else str(original_value)
                error_msg += f"    - '{value_str.strip('*')}'  → Would convert to EventData.{field_name}\n"

            error_msg += (
                "\nReason: Automatic conversion of multiple fields is not yet supported. "
                "Each Data field can only be transformed to one EventData field.\n\n"
                "Solution: Rewrite the rule to use multiple EventData.* field conditions.\n\n"
                "Example rewrite:\n"
                "  Before:\n"
                "    detection:\n"
                "      selection:\n"
                "        Data|contains|all:\n"
            )

            # Show the original patterns
            for field_name, field_value, _ in structured_patterns:
                error_msg += f"          - '{field_name}={field_value}'\n"

            error_msg += "\n  After:\n    detection:\n      selection:\n"

            # Show how to rewrite each field
            for field_name, field_value, _ in structured_patterns:
                error_msg += f"        EventData.{field_name}: '{field_value}'\n"

            error_msg += "      condition: selection"

            raise SigmaTransformationError(error_msg)


def sumologic_cse_pipeline() -> ProcessingPipeline:
    """
    Processing pipeline for Sumo Logic Cloud SIEM (CSE).

    This pipeline transforms Sigma rules into Sumo Logic Cloud SIEM compatible queries by:
    - Mapping Sigma field names to CSIEM schema field names
    - Handling Windows event logs, Sysmon, security logs
    - Supporting process creation, network connection, DNS queries, file operations
    - Providing proper field mappings for authentication, user activity, and system events
    - Computing confidence scores for field mappings (requires CSE schema)
    """
    # Load CSE schema for confidence scoring and validation
    # This is cached and only loaded once per process
    schema = SchemaLoader.load()

    from sigma.pipelines.sumologic.logsource_config import get_field_mappings

    items = []
    for entry in get_field_mappings():
        logsource = entry.get("logsource", {})
        condition_kwargs = {}
        if "product" in logsource:
            condition_kwargs["product"] = logsource["product"]
        if "service" in logsource:
            condition_kwargs["service"] = logsource["service"]
        if "category" in logsource:
            condition_kwargs["category"] = logsource["category"]

        item_kwargs = {
            "identifier": f"sumologic_cse_{entry['name']}",
            "transformation": ConfidenceAwareFieldMapping(
                mapping=entry["fields"],
                logsource_category=entry.get("logsource_category", entry["name"]),
                schema=schema,
            ),
        }
        if condition_kwargs:
            item_kwargs["rule_conditions"] = [LogsourceCondition(**condition_kwargs)]

        items.append(ProcessingItem(**item_kwargs))

    items.append(
        ProcessingItem(
            identifier="sumologic_cse_transform_data_field",
            transformation=DataFieldTransformation(),
            field_name_conditions=[
                IncludeFieldCondition(fields=["Data"])
            ],
        )
    )

    return ProcessingPipeline(
        name="Sumo Logic Cloud SIEM (CSE) Pipeline",
        allowed_backends=frozenset(["sumo_logic_cse", "sumo_logic_cse_rule"]),
        priority=20,
        items=items,
    )
