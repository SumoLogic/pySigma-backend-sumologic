"""
Entity classification taxonomy for metadata-driven entity selection.

This module defines source classifications (endpoint, identity, cloud_audit, etc.)
and maps them to appropriate entity selection patterns for Cloud SIEM rules.

Entity selectors tell Cloud SIEM which entities (hostnames, users, IPs, processes, etc.)
should be associated with alerts generated from a rule. This enables:
- Entity behavior tracking over time
- Alert correlation across rules
- Entity timelines and profiles
- Entity-based investigations

Source classifications provide a systematic way to assign entity selectors based on
product type, eliminating the need for per-product hardcoded logic.
"""

from typing import Dict, List

# Classification → Entity pattern mapping
# Each classification defines which entity types are appropriate for that source category
CLASSIFICATION_ENTITY_PATTERNS: Dict[str, List[str]] = {
    "endpoint": [
        "_hostname",  # device_hostname (primary - the endpoint itself)
        "_username",  # user_username (user logged into endpoint)
        "_process",  # baseImage (if process activity is captured)
    ],
    "identity": [
        "_username",  # user_username (primary - the authenticating user)
        "_ip",  # srcDevice_ip (client IP address)
    ],
    "cloud_audit": [
        "_username",  # user_username (primary - IAM principal/service account)
        "_ip",  # srcDevice_ip (API call origin IP)
    ],
    "network": [
        "_hostname",  # device_hostname (firewall/network device itself)
        "_ip",  # srcDevice_ip (source of traffic)
    ],
    "application": [
        "_username",  # user_username (primary - application user)
        "_ip",  # srcDevice_ip (optional - client IP if available)
    ],
    "cloud_infrastructure": [
        "_ip",  # srcDevice_ip or device_ip (primary - resource IP)
    ],
    "security_tool": [
        "_hostname",  # device_hostname (protected endpoint)
        "_username",  # user_username (user context if available)
        "_file",  # file_path (malware/threat file context)
    ],
}

# Entity type → CSIEM field mapping
# Maps abstract entity types (_hostname, _username, etc.) to actual CSIEM schema field names
ENTITY_TYPE_TO_FIELD: Dict[str, str] = {
    "_hostname": "device_hostname",
    "_username": "user_username",
    "_ip": "srcDevice_ip",
    "_process": "baseImage",
    "_file": "file_path",
    "_domain": "dns_queryDomain",
    "_mac": "device_mac",
}


def get_entities_for_classification(classification: str) -> List[Dict[str, str]]:
    """
    Get entity selectors for a source classification.

    Returns entity selectors appropriate for the given classification type.
    For example, "identity" sources return username + IP entities, while
    "endpoint" sources return hostname + username + process entities.

    Args:
        classification: Source classification (e.g., "identity", "endpoint", "cloud_audit")

    Returns:
        List of entity selector dicts with entity_type and expression:
        [
            {"entity_type": "_username", "expression": "user_username"},
            {"entity_type": "_ip", "expression": "srcDevice_ip"},
            ...
        ]
        Returns empty list if classification is unknown.

    Examples:
        >>> get_entities_for_classification("identity")
        [
            {"entity_type": "_username", "expression": "user_username"},
            {"entity_type": "_ip", "expression": "srcDevice_ip"}
        ]

        >>> get_entities_for_classification("endpoint")
        [
            {"entity_type": "_hostname", "expression": "device_hostname"},
            {"entity_type": "_username", "expression": "user_username"},
            {"entity_type": "_process", "expression": "baseImage"}
        ]
    """
    if classification not in CLASSIFICATION_ENTITY_PATTERNS:
        return []

    entity_types = CLASSIFICATION_ENTITY_PATTERNS[classification]
    return [
        {"entity_type": entity_type, "expression": ENTITY_TYPE_TO_FIELD[entity_type]}
        for entity_type in entity_types
        if entity_type in ENTITY_TYPE_TO_FIELD
    ]


def get_available_classifications() -> List[str]:
    """
    Get list of all available source classifications.

    Returns:
        List of classification names: ["endpoint", "identity", "cloud_audit", ...]
    """
    return list(CLASSIFICATION_ENTITY_PATTERNS.keys())
