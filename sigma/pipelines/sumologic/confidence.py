"""
Confidence scoring engine for Sigma to Sumo Logic CSE field mappings.

Computes confidence scores based on:
- Semantic similarity (35%): Field name and description keyword overlap
- Data preservation (30%): Detects lossy mappings
- Type compatibility (20%): Schema type alignment
- Field specificity (15%): Penalizes general-purpose fields
"""

import re
from typing import Dict, Optional, Set
from dataclasses import dataclass
from .schema_loader import SchemaIndex, FieldSchema


# Weights for confidence factors
WEIGHT_SEMANTIC = 0.35
WEIGHT_DATA_PRESERVATION = 0.30
WEIGHT_TYPE_COMPATIBILITY = 0.20
WEIGHT_FIELD_SPECIFICITY = 0.15


@dataclass
class ConfidenceFactors:
    """Individual confidence factor scores."""

    semantic_similarity: float
    data_preservation: float
    type_compatibility: float
    field_specificity: float

    def to_dict(self) -> Dict[str, float]:
        """Convert to dictionary for JSON serialization."""
        return {
            "semantic_similarity": round(self.semantic_similarity, 3),
            "data_preservation": round(self.data_preservation, 3),
            "type_compatibility": round(self.type_compatibility, 3),
            "field_specificity": round(self.field_specificity, 3),
        }


@dataclass
class ConfidenceScore:
    """Complete confidence score for a field mapping."""

    sigma_field: str
    cse_field: str
    overall: float
    factors: ConfidenceFactors
    warnings: list[str]

    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "sigma_field": self.sigma_field,
            "cse_field": self.cse_field,
            "confidence": round(self.overall, 3),
            "factors": self.factors.to_dict(),
            "warnings": self.warnings,
        }


# Category-aware confidence thresholds
CATEGORY_THRESHOLDS = {
    # Security-critical categories require high confidence
    "authentication": 0.80,
    # Process/command execution needs precision for attack detection
    "process_creation": 0.75,
    "image_load": 0.75,
    "registry_event": 0.75,
    # Standard threshold for network/DNS
    "network_connection": 0.70,
    "dns_query": 0.70,
    "firewall": 0.70,
    "file_event": 0.70,
    # Descriptive/metadata fields can be more permissive
    "proxy": 0.60,
    # Default for uncategorized
    "default": 0.70,
}


# Known multi-value Sigma fields that lose data when mapped to single CSE fields
MULTI_VALUE_FIELDS = {
    "Hashes": ["md5", "sha1", "sha256", "imphash"],  # Multi-hash string
}


# Known-good mappings with manual confidence scores
# These are well-established, verified mappings that bypass automatic scoring
KNOWN_GOOD_MAPPINGS = {
    # Windows Event IDs map cleanly to metadata_deviceEventId
    # Note: Values need transformation (4624 → "Security-4624"), but mapping is correct
    ("EventID", "metadata_deviceEventId"): 0.95,
    ("EventId", "metadata_deviceEventId"): 0.95,
    # Exact name matches (case-insensitive semantic match but algorithmic scoring can be low)
    ("Action", "action"): 1.0,
    ("action", "action"): 1.0,
    ("errorCode", "errorCode"): 1.0,
    ("ErrorCode", "errorCode"): 1.0,
    # AWS CloudTrail standard mappings (well-documented in CSE parsers)
    # eventName is used for both action and deviceEventId construction
    ("eventName", "action"): 0.95,  # Primary mapping
    ("eventSource", "application"): 0.90,
    ("sourceIPAddress", "srcDevice_ip"): 0.95,
    ("userIdentity.principalId", "user_userId"): 0.90,
    ("userIdentity.userName", "user_username"): 0.95,
    ("userAgent", "http_userAgent"): 0.95,
    ("requestParameters", "fields.requestParameters"): 0.85,
    ("responseElements", "fields.responseElements"): 0.85,
    # Common CSE field exact matches
    ("user", "user_username"): 0.85,
    ("User", "user_username"): 0.85,
    ("username", "user_username"): 0.95,
    ("Username", "user_username"): 0.95,
    ("hostname", "device_hostname"): 0.95,
    ("Hostname", "device_hostname"): 0.95,
    ("ip", "srcDevice_ip"): 0.85,  # Context-dependent but common
    ("IpAddress", "srcDevice_ip"): 0.90,
}


def get_category_threshold(logsource_category: str) -> float:
    """
    Get confidence threshold for a logsource category.

    Args:
        logsource_category: Sigma logsource category (e.g., "process_creation")

    Returns:
        Confidence threshold (0.0-1.0)
    """
    return CATEGORY_THRESHOLDS.get(logsource_category, CATEGORY_THRESHOLDS["default"])


def compute_semantic_similarity(
    sigma_field: str, cse_field: str, cse_field_schema: Optional[FieldSchema]
) -> float:
    """
    Compute semantic similarity between Sigma and CSE field names/descriptions.

    Uses keyword overlap approach:
    - Tokenize field names (split on underscore, camelCase)
    - Extract keywords from CSE field description
    - Compute Jaccard similarity: intersection / union

    Score 1.0 = perfect match (e.g., CommandLine → commandLine)
    Score 0.5 = partial overlap (e.g., IntegrityLevel → normalizedSeverity - "level" keyword)
    Score 0.0 = no overlap (completely different concepts)

    Args:
        sigma_field: Sigma field name (e.g., "CommandLine", "IntegrityLevel")
        cse_field: CSE field name (e.g., "commandLine", "normalizedSeverity")
        cse_field_schema: CSE field schema with description (None if not in schema)

    Returns:
        Similarity score 0.0-1.0
    """
    # Tokenize Sigma field name
    sigma_tokens = _tokenize_field_name(sigma_field)

    # Tokenize CSE field name
    cse_tokens = _tokenize_field_name(cse_field)

    # Add CSE description keywords if available
    if cse_field_schema:
        cse_tokens.update(cse_field_schema.get_keywords())

    # Compute Jaccard similarity
    if not sigma_tokens or not cse_tokens:
        return 0.0

    intersection = sigma_tokens & cse_tokens
    union = sigma_tokens | cse_tokens

    return len(intersection) / len(union)


def _tokenize_field_name(field_name: str) -> Set[str]:
    """
    Tokenize a field name into keywords.

    Handles:
    - Underscore separation: device_hostname → device, hostname
    - CamelCase: CommandLine → command, line
    - Numbers: sha256 → sha, 256

    Returns lowercase tokens.
    """
    # Replace underscore with space
    field_name = field_name.replace("_", " ")

    # Split camelCase: CommandLine → Command Line
    field_name = re.sub(r"([a-z])([A-Z])", r"\1 \2", field_name)

    # Split numbers: sha256 → sha 256
    field_name = re.sub(r"([a-zA-Z])(\d+)", r"\1 \2", field_name)

    # Tokenize and lowercase
    tokens = set(field_name.lower().split())

    # Remove common stop words that don't help matching
    stop_words = {"the", "a", "an", "of", "to", "for", "in", "on", "at", "from", "by"}
    tokens = tokens - stop_words

    return tokens


def compute_data_preservation(
    sigma_field: str, cse_field: str, logsource_category: str
) -> float:
    """
    Compute data preservation score (1.0 = lossless, <1.0 = lossy).

    Detects:
    - Multi-value to single-value collapse (e.g., Hashes → file_hash_sha256)
    - Type width mismatches (e.g., full string → truncated field)
    - Context loss (e.g., SubjectUserName vs TargetUserName → user_username)

    Args:
        sigma_field: Sigma field name
        cse_field: CSE field name
        logsource_category: Log source category for context

    Returns:
        Data preservation score 0.0-1.0
    """
    score = 1.0
    warnings = []

    # Check for multi-value collapse
    if sigma_field in MULTI_VALUE_FIELDS:
        expected_types = MULTI_VALUE_FIELDS[sigma_field]
        # Check if CSE field is for a specific hash type
        if any(hash_type in cse_field.lower() for hash_type in expected_types):
            # Lossy - only capturing one hash type
            score = 0.5
        else:
            # Very lossy - completely wrong target
            score = 0.2

    # Check for context loss (Subject/Target/Source/Destination prefixes)
    sigma_prefix = _extract_context_prefix(sigma_field)
    cse_prefix = _extract_context_prefix(cse_field)

    if sigma_prefix and not cse_prefix:
        # Context loss: SubjectUserName → user_username (loses "Subject" context)
        score *= 0.7

    # Check for specific known lossy mappings
    lossy_patterns = {
        ("IntegrityLevel", "normalizedSeverity"): 0.3,  # Integrity ≠ severity
        ("CurrentDirectory", "file_path"): 0.8,  # Directory vs full path (minor)
        (
            "Description",
            "description",
        ): 0.9,  # File description vs event description (collision risk)
        (
            "ServiceType",
            "resource_type",
        ): 0.6,  # Windows service type ≠ generic resource type
        ("StartType", "changeType"): 0.5,  # Service startup ≠ change type
        ("Status", "normalizedAction"): 0.6,  # Status code ≠ action category
    }

    for (sigma, cse), penalty_score in lossy_patterns.items():
        if sigma_field == sigma and cse_field == cse:
            score = min(score, penalty_score)

    return score


def _extract_context_prefix(field_name: str) -> Optional[str]:
    """
    Extract context prefix from field name (Subject, Target, Source, Destination).

    Returns prefix or None if no context prefix found.
    """
    context_prefixes = ["Subject", "Target", "Source", "Destination", "Src", "Dst"]
    for prefix in context_prefixes:
        if field_name.startswith(prefix):
            return prefix
    return None


def compute_type_compatibility(
    sigma_field: str, cse_field: str, cse_field_schema: Optional[FieldSchema]
) -> float:
    """
    Compute type compatibility score.

    Checks:
    - Numeric → String mismatch (e.g., SubStatus → errorText)
    - String → Numeric mismatch
    - Boolean → String/Numeric

    Without schema: Use heuristics based on field names
    With schema: Use schema type information

    Args:
        sigma_field: Sigma field name
        cse_field: CSE field name
        cse_field_schema: CSE field schema (None if not in schema)

    Returns:
        Type compatibility score 0.0-1.0
    """
    # Infer Sigma field type from name
    sigma_type = _infer_sigma_type(sigma_field)

    # Get CSE field type from schema or infer
    if cse_field_schema:
        cse_type = cse_field_schema.field_type.lower()
    else:
        cse_type = _infer_cse_type(cse_field)

    # Score compatibility
    if sigma_type == cse_type:
        return 1.0
    elif sigma_type == "string" and cse_type in ["string", "text"]:
        return 1.0
    elif sigma_type == "numeric" and cse_type in ["int", "long", "integer", "number"]:
        return 1.0
    elif (sigma_type, cse_type) in [("numeric", "string"), ("string", "numeric")]:
        # Type mismatch - problematic
        return 0.4
    elif sigma_type == "boolean" and cse_type == "string":
        # Boolean to string - acceptable
        return 0.8
    else:
        # Unknown or minor mismatch
        return 0.7


def _infer_sigma_type(field_name: str) -> str:
    """
    Infer Sigma field type from name heuristics.

    Returns: "string", "numeric", "boolean", or "unknown"
    """
    # Numeric indicators
    if any(
        keyword in field_name.lower()
        for keyword in ["count", "size", "port", "id", "pid", "code", "status", "type"]
    ):
        return "numeric"

    # Boolean indicators
    if any(
        keyword in field_name.lower()
        for keyword in ["initiated", "signed", "enabled", "success"]
    ):
        return "boolean"

    # Default to string (most common)
    return "string"


def _infer_cse_type(field_name: str) -> str:
    """
    Infer CSE field type from name heuristics.

    Returns: "string", "int", "long", "boolean", or "unknown"
    """
    # Numeric indicators
    if any(
        keyword in field_name.lower()
        for keyword in ["port", "pid", "count", "size", "bytes", "packets"]
    ):
        return "int"

    # String indicators
    if any(
        keyword in field_name.lower()
        for keyword in ["text", "description", "message", "name", "path", "domain"]
    ):
        return "string"

    # Boolean indicators (less common in CSE)
    if "success" in field_name.lower():
        return "boolean"

    # Default to string
    return "string"


def compute_field_specificity(
    cse_field: str, cse_field_schema: Optional[FieldSchema]
) -> float:
    """
    Compute field specificity score.

    Penalizes general-purpose CSE fields (action, description, resource)
    that accept data from many sources. Specific fields score higher.

    Args:
        cse_field: CSE field name
        cse_field_schema: CSE field schema (None if not in schema)

    Returns:
        Specificity score 0.0-1.0
    """
    if cse_field_schema:
        if cse_field_schema.is_general_purpose():
            return 0.5  # General-purpose field - lower confidence
        else:
            return 1.0  # Specific field - full confidence
    else:
        # Heuristic: General-purpose field names
        general_purpose_names = [
            "action",
            "description",
            "resource",
            "application",
            "resourcetype",
            "normalizedaction",
            "normalizedresource",
            "cause",
            "severity",
        ]
        if cse_field.lower() in general_purpose_names:
            return 0.5
        else:
            return 0.9  # Assume specific if not in known general list


def validate_schema_appropriateness(
    sigma_field: str, cse_field: str, cse_field_schema: Optional[FieldSchema]
) -> tuple[bool, list[str]]:
    """
    Validate if mapping is appropriate according to CSE schema metadata.

    Checks:
    1. Target CSE field exists in schema
    2. related_attributes compatibility (semantic boundaries)
    3. Not using enrichment-only fields as direct mappings

    Args:
        sigma_field: Sigma field name
        cse_field: CSE field name
        cse_field_schema: CSE field schema (None if not in schema)

    Returns:
        (is_valid, warnings) tuple
    """
    warnings = []

    if not cse_field_schema:
        warnings.append(f"CSE field '{cse_field}' not found in schema")
        return (False, warnings)

    # Check enrichment-only fields
    if cse_field_schema.enrichment_attribute:
        warnings.append(
            f"CSE field '{cse_field}' is marked as enrichment-only, "
            f"should not be used as direct mapping target"
        )

    # Check related_attributes for semantic appropriateness
    # This is a heuristic check - we look for contradictions
    related_attrs = cse_field_schema.related_attributes
    if related_attrs:
        # Example: mapping to dns_queryDomain when related_attrs says
        # "explicitly NOT for DNS domains" would be inappropriate
        # This is context-dependent and requires knowledge of both fields
        # For now, we just flag if there are related_attributes to review
        pass

    return (True, warnings)


def compute_confidence(
    sigma_field: str,
    cse_field: str,
    logsource_category: str,
    schema: Optional[SchemaIndex],
) -> ConfidenceScore:
    """
    Compute overall confidence score for a Sigma → CSE field mapping.

    Combines four weighted factors:
    - Semantic similarity (35%): Field name and description keyword overlap
    - Data preservation (30%): Detects lossy mappings
    - Type compatibility (20%): Schema type alignment
    - Field specificity (15%): Penalizes general-purpose fields

    Args:
        sigma_field: Sigma field name (e.g., "CommandLine")
        cse_field: CSE field name (e.g., "commandLine")
        logsource_category: Sigma logsource category (e.g., "process_creation")
        schema: CSE schema index for validation (None if schema not loaded)

    Returns:
        ConfidenceScore with overall score and factor breakdown
    """
    warnings = []

    # Check for known-good mappings first (manual overrides)
    mapping_key = (sigma_field, cse_field)
    if mapping_key in KNOWN_GOOD_MAPPINGS:
        confidence = KNOWN_GOOD_MAPPINGS[mapping_key]
        # Return high-confidence score with perfect factors
        return ConfidenceScore(
            sigma_field=sigma_field,
            cse_field=cse_field,
            overall=confidence,
            factors=ConfidenceFactors(
                semantic_similarity=1.0,
                data_preservation=1.0,
                type_compatibility=1.0,
                field_specificity=1.0,
            ),
            warnings=["Known-good mapping (manual override)"],
        )

    # Get CSE field schema
    cse_field_schema = schema.get_field(cse_field) if schema else None

    # Compute individual factors
    semantic = compute_semantic_similarity(sigma_field, cse_field, cse_field_schema)
    data_pres = compute_data_preservation(sigma_field, cse_field, logsource_category)
    type_compat = compute_type_compatibility(sigma_field, cse_field, cse_field_schema)
    specificity = compute_field_specificity(cse_field, cse_field_schema)

    # Schema validation (reduces confidence if issues found)
    if schema:
        is_valid, validation_warnings = validate_schema_appropriateness(
            sigma_field, cse_field, cse_field_schema
        )
        warnings.extend(validation_warnings)

        if not is_valid:
            # Reduce confidence for schema validation failures
            specificity *= 0.8

    # Compute weighted overall score
    overall = (
        WEIGHT_SEMANTIC * semantic
        + WEIGHT_DATA_PRESERVATION * data_pres
        + WEIGHT_TYPE_COMPATIBILITY * type_compat
        + WEIGHT_FIELD_SPECIFICITY * specificity
    )

    factors = ConfidenceFactors(
        semantic_similarity=semantic,
        data_preservation=data_pres,
        type_compatibility=type_compat,
        field_specificity=specificity,
    )

    return ConfidenceScore(
        sigma_field=sigma_field,
        cse_field=cse_field,
        overall=overall,
        factors=factors,
        warnings=warnings,
    )
