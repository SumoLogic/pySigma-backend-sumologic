"""
Category-to-entity mapping for Sigma rule categories.

Maps Sigma logsource categories to appropriate entity selectors based on the
Sigma specification taxonomy (v2.1.0).

This provides systematic entity selection for all documented Sigma categories,
eliminating the need for per-category hardcoded logic in the backend.
"""

from typing import Dict, List, Optional, Tuple

# Category → Entity pattern mapping
# Each category defines which entity types are appropriate based on the activity type
# Format: category → (entity_types_list, rationale)
CATEGORY_ENTITY_PATTERNS: Dict[str, Tuple[List[str], str]] = {
    # ===== Process/Execution Categories =====
    "process_creation": (
        ["_hostname", "_username", "_process"],
        "Process creation events identify which user on which host executed which process"
    ),
    "process_termination": (
        ["_hostname", "_process"],
        "Process termination tracks which processes ended on which hosts"
    ),
    "process_access": (
        ["_hostname", "_username", "_process"],
        "Process access events track which processes are being accessed and by whom"
    ),
    "process_tampering": (
        ["_hostname", "_username", "_process"],
        "Process tampering indicates which processes are being modified"
    ),
    "create_remote_thread": (
        ["_hostname", "_username", "_process"],
        "Remote thread creation identifies process injection attempts"
    ),

    # ===== File System Categories =====
    "file_event": (
        ["_hostname", "_file"],
        "File operations identify which files are being acted upon and where"
    ),
    "file_change": (
        ["_hostname", "_file"],
        "File modifications track which files are changed on which hosts"
    ),
    "file_delete": (
        ["_hostname", "_file"],
        "File deletions identify which files are removed from which hosts"
    ),
    "file_delete_detected": (
        ["_hostname", "_file"],
        "Detected file deletions track suspicious file removal"
    ),
    "file_access": (
        ["_hostname", "_file"],
        "File access events track which files are accessed"
    ),
    "file_rename": (
        ["_hostname", "_file"],
        "File renames track file name changes"
    ),
    "file_block_executable": (
        ["_hostname", "_file"],
        "Blocked executable files indicate prevented execution attempts"
    ),
    "file_block_shredding": (
        ["_hostname", "_file"],
        "Blocked file shredding attempts"
    ),
    "file_executable_detected": (
        ["_hostname", "_file"],
        "Executable file detection events"
    ),

    # ===== Network Categories =====
    "network_connection": (
        ["_hostname", "_ip"],
        "Network events track which hosts/IPs are communicating"
    ),
    "dns_query": (
        ["_hostname", "_domain"],
        "DNS queries track which hosts are resolving which domains"
    ),
    "dns": (
        ["_hostname", "_domain"],
        "Generic DNS activity tracks domain resolution"
    ),
    "firewall": (
        ["_hostname", "_ip"],
        "Firewall events track network traffic and blocking decisions"
    ),
    "proxy": (
        ["_ip", "_domain"],
        "Proxy logs track client IPs accessing domains through the proxy"
    ),
    "webserver": (
        ["_ip", "_hostname"],
        "Web server logs track client IPs accessing server hosts"
    ),

    # ===== Registry Categories =====
    "registry_event": (
        ["_hostname", "_username"],
        "Registry modifications track which user on which host made changes"
    ),
    "registry_add": (
        ["_hostname", "_username"],
        "Registry key additions"
    ),
    "registry_delete": (
        ["_hostname", "_username"],
        "Registry key deletions"
    ),
    "registry_set": (
        ["_hostname", "_username"],
        "Registry value modifications"
    ),
    "registry_rename": (
        ["_hostname", "_username"],
        "Registry key renames"
    ),

    # ===== Authentication/Identity Categories =====
    "authentication": (
        ["_hostname", "_ip", "_username"],
        "Authentication events track which users are logging in from where"
    ),

    # ===== DLL/Driver Categories =====
    "image_load": (
        ["_hostname", "_username"],
        "DLL/image loading tracks which user on which host loaded libraries"
    ),
    "driver_load": (
        ["_hostname", "_file"],
        "Driver loading events track which drivers are loaded on which hosts"
    ),

    # ===== WMI/PowerShell Categories =====
    "wmi_event": (
        ["_hostname", "_username"],
        "WMI events track which users execute WMI operations on which hosts"
    ),
    "ps_script": (
        ["_hostname", "_username"],
        "PowerShell script execution tracking"
    ),
    "ps_module": (
        ["_hostname", "_username"],
        "PowerShell module loading tracking"
    ),
    "ps_classic_script": (
        ["_hostname", "_username"],
        "Classic PowerShell script execution"
    ),
    "ps_classic_start": (
        ["_hostname", "_username"],
        "Classic PowerShell process start"
    ),
    "ps_classic_provider_start": (
        ["_hostname", "_username"],
        "Classic PowerShell provider initialization"
    ),

    # ===== Pipe/IPC Categories =====
    "pipe_created": (
        ["_hostname", "_username"],
        "Named pipe creation for IPC tracking"
    ),

    # ===== Clipboard/Data Categories =====
    "clipboard_capture": (
        ["_hostname", "_username"],
        "Clipboard capture events track data exfiltration attempts"
    ),

    # ===== Security/AV Categories =====
    "antivirus": (
        ["_hostname", "_file"],
        "Antivirus detections identify threats on specific hosts"
    ),

    # ===== Application Categories =====
    "application": (
        ["_username"],
        "Application logs track user actions in SaaS/application environments"
    ),

    # ===== Database Categories =====
    "database": (
        ["_hostname", "_username"],
        "Database query logs track which users execute queries on which DB servers"
    ),

    # ===== Sysmon Status Categories =====
    "sysmon_status": (
        ["_hostname"],
        "Sysmon operational status events"
    ),
    "sysmon_error": (
        ["_hostname"],
        "Sysmon error events"
    ),

    # ===== Stream/Alternate Data Categories =====
    "create_stream_hash": (
        ["_hostname", "_file"],
        "Alternate data stream creation tracking"
    ),

    # ===== Raw Access Categories =====
    "raw_access_thread": (
        ["_hostname", "_username"],
        "Raw disk access attempts tracking"
    ),
}

# Entity type → CSIEM field mapping
# Note: dns_queryDomain is NOT in entity_fields.json, so we use http_url_fqdn for _domain
# This is a known limitation of CSE - only HTTP domain fields are recognized as entity fields
ENTITY_TYPE_TO_FIELD: Dict[str, str] = {
    "_hostname": "device_hostname",
    "_username": "user_username",
    "_ip": "srcDevice_ip",
    "_process": "baseImage",
    "_file": "file_path",
    "_domain": "http_url_fqdn",  # CSE limitation: dns_queryDomain is not an entity field
    "_mac": "device_mac",
}


def get_entities_for_category(category: str) -> List[Dict[str, str]]:
    """
    Get entity selectors for a Sigma logsource category.

    Returns entity selectors appropriate for the given category type based on
    the Sigma specification taxonomy.

    Args:
        category: Sigma logsource category (e.g., "process_creation", "dns_query")

    Returns:
        List of entity selector dicts with entity_type and expression:
        [
            {"entity_type": "_hostname", "expression": "device_hostname"},
            {"entity_type": "_username", "expression": "user_username"},
            ...
        ]
        Returns empty list if category is unknown.

    Examples:
        >>> get_entities_for_category("process_creation")
        [
            {"entity_type": "_hostname", "expression": "device_hostname"},
            {"entity_type": "_username", "expression": "user_username"},
            {"entity_type": "_process", "expression": "baseImage"}
        ]

        >>> get_entities_for_category("dns")
        [
            {"entity_type": "_hostname", "expression": "device_hostname"},
            {"entity_type": "_domain", "expression": "http_url_fqdn"}
        ]
    """
    if category not in CATEGORY_ENTITY_PATTERNS:
        return []

    entity_types, _rationale = CATEGORY_ENTITY_PATTERNS[category]
    return [
        {
            "entity_type": entity_type,
            "expression": ENTITY_TYPE_TO_FIELD[entity_type]
        }
        for entity_type in entity_types
        if entity_type in ENTITY_TYPE_TO_FIELD
    ]


def get_category_rationale(category: str) -> Optional[str]:
    """
    Get rationale for why specific entities are selected for a category.

    Args:
        category: Sigma logsource category

    Returns:
        Rationale string or None if category is unknown
    """
    if category not in CATEGORY_ENTITY_PATTERNS:
        return None

    _entity_types, rationale = CATEGORY_ENTITY_PATTERNS[category]
    return rationale


def get_available_categories() -> List[str]:
    """
    Get list of all available Sigma categories with entity mappings.

    Returns:
        List of category names sorted alphabetically
    """
    return sorted(CATEGORY_ENTITY_PATTERNS.keys())


def has_entity_mapping(category: str) -> bool:
    """
    Check if a category has entity mappings defined.

    Args:
        category: Sigma logsource category

    Returns:
        True if mapping exists, False otherwise
    """
    return category in CATEGORY_ENTITY_PATTERNS
