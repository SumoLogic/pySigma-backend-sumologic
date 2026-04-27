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
        schema: Optional[SchemaIndex] = None,
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
                schema=schema,
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
                score.to_dict() for score in self.confidence_scores.values()
            ],
        }

    def get_overall_confidence(self) -> float:
        """
        Compute overall confidence for this mapping transformation.

        Uses weighted average of individual field mapping confidences.
        """
        if not self.confidence_scores:
            return 1.0

        total_confidence = sum(
            score.overall for score in self.confidence_scores.values()
        )
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
        values = (
            detection_item.value
            if isinstance(detection_item.value, list)
            else [detection_item.value]
        )

        # Track which values can be transformed vs. which fail
        structured_patterns = []
        arbitrary_strings = []

        for value in values:
            # Convert SigmaString to plain string for pattern matching
            if hasattr(value, "to_plain"):
                value_str = value.to_plain()
            else:
                value_str = str(value)

            # Strip wildcards added by |contains modifier (e.g., '*EngineVersion=2.*' → 'EngineVersion=2.')
            # This lets us detect structured patterns even when wrapped with wildcards
            value_str_clean = value_str.strip("*")

            # Try to parse structured patterns: FieldName=Value or FieldName:Value
            # Match word characters for field name, then = or :, then capture the rest
            match = re.match(r"^(\w+)[:=](.+)$", value_str_clean)

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
                value_str = (
                    value.to_plain() if hasattr(value, "to_plain") else str(value)
                )
                # Highlight unsupported values with ✗, supported with ✓
                if value_str.strip("*") in [s.strip("*") for s in arbitrary_strings]:
                    error_msg += f"    ✗ '{value_str.strip('*')}'  ← UNSUPPORTED (arbitrary string)\n"
                else:
                    error_msg += (
                        f"    ✓ '{value_str.strip('*')}'  ← OK (structured pattern)\n"
                    )

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
                error_msg += (
                    f"  ✗ '{s.strip('*')}' - No field name found (arbitrary string)\n"
                )

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
            # Need to preserve SigmaString structure with wildcards if present
            if hasattr(original_value, "s"):
                # It's a SigmaString - reconstruct with just the value part
                # The original structure is like: [SpecialChars.WILDCARD_MULTI, 'EngineVersion=2.', SpecialChars.WILDCARD_MULTI]
                # We want: [SpecialChars.WILDCARD_MULTI, '2.', SpecialChars.WILDCARD_MULTI]

                # Find the wildcards/special chars from original
                from sigma.types import SpecialChars

                original_parts = original_value.s

                # Reconstruct with value part only, keeping wildcards
                new_parts = []
                for part in original_parts:
                    if isinstance(part, SpecialChars):
                        # Keep special chars (wildcards)
                        new_parts.append(part)
                    elif isinstance(part, str):
                        # Replace the string part with just the value
                        new_parts.append(field_value)

                # Create new SigmaString directly from internal structure
                new_sigma_string = SigmaString.__new__(SigmaString)
                new_sigma_string.s = new_parts
                new_sigma_string.original = field_value

                detection_item.value = [new_sigma_string]
            else:
                # Plain string - wrap in SigmaString
                detection_item.value = [SigmaString(field_value)]

        elif len(structured_patterns) > 1:
            # Multiple structured fields - this is complex, need to create multiple detection items
            # For now, fail with a helpful message explaining manual rewrite is needed

            error_msg = "Field 'Data' contains multiple structured field patterns.\n\n"

            # Show the original Sigma detection criteria
            error_msg += "Original Sigma detection:\n"
            error_msg += f"  Data|contains|all:\n"
            for field_name, field_value, original_value in structured_patterns:
                value_str = (
                    original_value.to_plain()
                    if hasattr(original_value, "to_plain")
                    else str(original_value)
                )
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

    return ProcessingPipeline(
        name="Sumo Logic Cloud SIEM (CSE) Pipeline",
        allowed_backends=frozenset(["sumo_logic_cse", "sumo_logic_cse_rule"]),
        priority=20,
        items=[
            # Windows Process Creation (Sysmon Event ID 1, Security Event ID 4688)
            ProcessingItem(
                identifier="sumologic_cse_process_creation",
                transformation=ConfidenceAwareFieldMapping(
                    mapping={
                        # Process fields
                        "CommandLine": "commandLine",
                        "Image": "baseImage",
                        "ParentImage": "parentBaseImage",
                        "ParentCommandLine": "parentCommandLine",
                        "ProcessId": "pid",
                        "ParentProcessId": "parentPid",
                        "CurrentDirectory": "file_path",
                        "OriginalFileName": "file_basename",
                        # User fields
                        "User": "user_username",
                        "LogonId": "user_userId",
                        "IntegrityLevel": "normalizedSeverity",
                        # Hash fields
                        "md5": "file_hash_md5",
                        "MD5": "file_hash_md5",
                        "sha1": "file_hash_sha1",
                        "SHA1": "file_hash_sha1",
                        "sha256": "file_hash_sha256",
                        "SHA256": "file_hash_sha256",
                        "Hashes": "file_hash_sha256",
                        # File metadata
                        "Company": "file_company",
                        "Product": "file_product",
                        "Description": "description",
                        "FileVersion": "file_version",
                    },
                    logsource_category="process_creation",
                    schema=schema,
                ),
                rule_conditions=[LogsourceCondition(category="process_creation")],
            ),
            # Windows Network Connection (Sysmon Event ID 3)
            ProcessingItem(
                identifier="sumologic_cse_network_connection",
                transformation=ConfidenceAwareFieldMapping(
                    mapping={
                        "SourceIp": "srcDevice_ip",
                        "SourcePort": "srcPort",
                        "DestinationIp": "dstDevice_ip",
                        "DestinationPort": "dstPort",
                        "Protocol": "ipProtocol",
                        "Image": "baseImage",
                        "User": "user_username",
                        "ProcessId": "pid",
                        "Initiated": "action",
                        "DestinationHostname": "dstDevice_hostname",
                        "SourceHostname": "srcDevice_hostname",
                    },
                    logsource_category="network_connection",
                    schema=schema,
                ),
                rule_conditions=[LogsourceCondition(category="network_connection")],
            ),
            # DNS Query (Sysmon Event ID 22)
            ProcessingItem(
                identifier="sumologic_cse_dns_query",
                transformation=ConfidenceAwareFieldMapping(
                    mapping={
                        "QueryName": "dns_query",
                        "QueryResults": "dns_reply",
                        "QueryStatus": "dns_replyCode",
                        "Image": "baseImage",
                        "ProcessId": "pid",
                        "record_type": "dns_queryType",
                    },
                    logsource_category="dns_query",
                    schema=schema,
                ),
                rule_conditions=[LogsourceCondition(category="dns_query")],
            ),
            # File Creation/Modification (Sysmon Event ID 11, 23)
            ProcessingItem(
                identifier="sumologic_cse_file_event",
                transformation=ConfidenceAwareFieldMapping(
                    mapping={
                        "TargetFilename": "file_path",
                        "Image": "baseImage",
                        "User": "user_username",
                        "ProcessId": "pid",
                        "md5": "file_hash_md5",
                        "sha1": "file_hash_sha1",
                        "sha256": "file_hash_sha256",
                    },
                    logsource_category="file_event",
                    schema=schema,
                ),
                rule_conditions=[LogsourceCondition(category="file_event")],
            ),
            # Image/Module Load (Sysmon Event ID 6, 7)
            ProcessingItem(
                identifier="sumologic_cse_image_load",
                transformation=ConfidenceAwareFieldMapping(
                    mapping={
                        "ImageLoaded": "file_path",
                        "Signature": "file_signature",
                        "SignatureStatus": "file_signatureStatus",
                        "Signed": "file_signatureStatus",
                        "Image": "baseImage",
                        "md5": "file_hash_md5",
                        "sha1": "file_hash_sha1",
                        "sha256": "file_hash_sha256",
                    },
                    logsource_category="image_load",
                    schema=schema,
                ),
                rule_conditions=[LogsourceCondition(category="image_load")],
            ),
            # Registry Events (Sysmon Event ID 12, 13, 14)
            ProcessingItem(
                identifier="sumologic_cse_registry_event",
                transformation=ConfidenceAwareFieldMapping(
                    mapping={
                        "TargetObject": "changeTarget",
                        "Details": "changeResult",
                        "EventType": "changeType",
                        "Image": "baseImage",
                        "User": "user_username",
                    },
                    logsource_category="registry_event",
                    schema=schema,
                ),
                rule_conditions=[LogsourceCondition(category="registry_event")],
            ),
            # Windows Security Events - Authentication
            ProcessingItem(
                identifier="sumologic_cse_windows_authentication",
                transformation=ConfidenceAwareFieldMapping(
                    mapping={
                        "TargetUserName": "user_username",
                        "TargetDomainName": "user_authDomain",
                        "SubjectUserName": "user_username",
                        "SubjectDomainName": "user_authDomain",
                        "LogonType": "logonType",
                        "IpAddress": "srcDevice_ip",
                        "WorkstationName": "srcDevice_hostname",
                        "Status": "errorCode",
                        "SubStatus": "errorText",
                        "SourceNetworkAddress": "srcDevice_ip",
                        "TargetLogonId": "user_userId",
                        "LogonProcessName": "application",
                        "AuthenticationPackageName": "authProvider",
                    },
                    logsource_category="authentication",
                    schema=schema,
                ),
                rule_conditions=[
                    LogsourceCondition(product="windows", service="security")
                ],
            ),
            # Windows System Events
            ProcessingItem(
                identifier="sumologic_cse_windows_system",
                transformation=ConfidenceAwareFieldMapping(
                    mapping={
                        "ServiceName": "application",
                        "ImagePath": "file_path",
                        "ServiceType": "resource_type",
                        "StartType": "changeType",
                    },
                    logsource_category="windows_system",
                    schema=schema,
                ),
                rule_conditions=[
                    LogsourceCondition(product="windows", service="system")
                ],
            ),
            # PowerShell Logs
            ProcessingItem(
                identifier="sumologic_cse_powershell",
                transformation=ConfidenceAwareFieldMapping(
                    mapping={
                        "ScriptBlockText": "commandLine",
                        "Path": "file_path",
                        "HostApplication": "commandLine",
                        "ContextInfo": "description",
                    },
                    logsource_category="windows_powershell",
                    schema=schema,
                ),
                rule_conditions=[
                    LogsourceCondition(product="windows", service="powershell")
                ],
            ),
            # Web/Proxy Logs
            ProcessingItem(
                identifier="sumologic_cse_proxy",
                transformation=ConfidenceAwareFieldMapping(
                    mapping={
                        "c-uri": "http_url",
                        "cs-uri-query": "http_url_query",
                        "cs-method": "http_method",
                        "cs-host": "http_hostname",
                        "c-useragent": "http_userAgent",
                        "sc-status": "http_response_statusCode",
                        "cs-username": "user_username",
                        "c-ip": "srcDevice_ip",
                        "r-ip": "dstDevice_ip",
                        "cs-bytes": "bytesOut",
                        "sc-bytes": "bytesIn",
                        "url": "http_url",
                    },
                    logsource_category="proxy",
                    schema=schema,
                ),
                rule_conditions=[LogsourceCondition(category="proxy")],
            ),
            # Firewall Logs
            ProcessingItem(
                identifier="sumologic_cse_firewall",
                transformation=ConfidenceAwareFieldMapping(
                    mapping={
                        "src_ip": "srcDevice_ip",
                        "dst_ip": "dstDevice_ip",
                        "src_port": "srcPort",
                        "dst_port": "dstPort",
                        "protocol": "ipProtocol",
                        "action": "action",
                    },
                    logsource_category="firewall",
                    schema=schema,
                ),
                rule_conditions=[LogsourceCondition(category="firewall")],
            ),
            # AWS CloudTrail
            ProcessingItem(
                identifier="sumologic_cse_aws_cloudtrail",
                transformation=ConfidenceAwareFieldMapping(
                    mapping={
                        "eventName": "action",
                        "eventSource": "application",
                        "userIdentity.principalId": "user_username",
                        "userIdentity.arn": "user_userId",
                        "sourceIPAddress": "srcDevice_ip",
                        "userAgent": "http_userAgent",
                        "errorCode": "errorCode",
                        "errorMessage": "errorText",
                        "requestParameters.instanceId": "resourceId",
                        "responseElements.instanceId": "resourceId",
                    },
                    logsource_category="aws_cloudtrail",
                    schema=schema,
                ),
                rule_conditions=[
                    LogsourceCondition(product="aws", service="cloudtrail")
                ],
            ),
            # Azure Activity Logs
            ProcessingItem(
                identifier="sumologic_cse_azure_activity",
                transformation=ConfidenceAwareFieldMapping(
                    mapping={
                        "operationName": "action",
                        "caller": "user_username",
                        "callerIpAddress": "srcDevice_ip",
                        "resourceId": "resourceId",
                        "status": "normalizedAction",
                        "properties.message": "description",
                    },
                    logsource_category="azure_activitylogs",
                    schema=schema,
                ),
                rule_conditions=[
                    LogsourceCondition(product="azure", service="activitylogs")
                ],
            ),
            # Office 365
            ProcessingItem(
                identifier="sumologic_cse_office365",
                transformation=ConfidenceAwareFieldMapping(
                    mapping={
                        "Operation": "action",
                        "UserId": "user_username",
                        "ClientIP": "srcDevice_ip",
                        "UserAgent": "http_userAgent",
                        "ObjectId": "resourceId",
                    },
                    logsource_category="office365",
                    schema=schema,
                ),
                rule_conditions=[LogsourceCondition(service="office365")],
            ),
            # Linux/Unix authentication
            ProcessingItem(
                identifier="sumologic_cse_linux_auth",
                transformation=ConfidenceAwareFieldMapping(
                    mapping={
                        "user": "user_username",
                        "srcip": "srcDevice_ip",
                        "hostname": "device_hostname",
                        "addr": "srcDevice_ip",
                    },
                    logsource_category="linux_auth",
                    schema=schema,
                ),
                rule_conditions=[LogsourceCondition(product="linux", service="auth")],
            ),
            # Windows Event Log - Common EventData fields (cross-event)
            ProcessingItem(
                identifier="sumologic_cse_windows_eventdata_common",
                transformation=ConfidenceAwareFieldMapping(
                    mapping={
                        # User identification (Target)
                        "TargetUserName": "user_username",
                        "TargetUserSid": "user_userId",
                        "TargetDomainName": "user_authDomain",
                        # User identification (Subject)
                        "SubjectUserName": "user_username",
                        "SubjectUserSid": "user_userId",
                        "SubjectDomainName": "user_authDomain",
                        # Process identification
                        "ProcessId": "pid",
                        "ProcessGuid": "fields.EventData.ProcessGuid",
                        # Network fields
                        "IpAddress": "srcDevice_ip",
                        "IpPort": "srcPort",
                        "SourceIp": "srcDevice_ip",
                        "SourcePort": "srcPort",
                        "SourceAddress": "srcDevice_ip",
                        "DestinationIp": "dstDevice_ip",
                        "DestinationPort": "dstPort",
                        "DestAddress": "dstDevice_ip",
                        "DestPort": "dstPort",
                        # Authentication
                        "LogonType": "logonType",
                        "AuthenticationPackageName": "authProvider",
                        "LogonProcessName": "application",
                        # Process/Image
                        "Image": "baseImage",
                        "User": "user_username",
                        # Timestamps
                        "UtcTime": "fields.EventData.UtcTime",
                    },
                    logsource_category="windows_eventdata",
                    schema=schema,
                ),
                rule_conditions=[LogsourceCondition(product="windows")],
            ),
            # Windows Sysmon - All events (common fields + event-specific fields)
            ProcessingItem(
                identifier="sumologic_cse_sysmon",
                transformation=ConfidenceAwareFieldMapping(
                    mapping={
                        # Process Creation (Event ID 1)
                        "CommandLine": "commandLine",
                        "ParentImage": "parentBaseImage",
                        "ParentProcessId": "fields.EventData.ParentProcessId",
                        "ParentCommandLine": "parentCommandLine",
                        "ParentProcessGuid": "fields.EventData.ParentProcessGuid",
                        "CurrentDirectory": "fields.EventData.CurrentDirectory",
                        "IntegrityLevel": "fields.EventData.IntegrityLevel",
                        "LogonGuid": "fields.EventData.LogonGuid",
                        "LogonId": "fields.EventData.LogonId",
                        "TerminalSessionId": "fields.EventData.TerminalSessionId",
                        "Hashes": "fields.EventData.Hashes",
                        # Network Connection (Event ID 3)
                        "Protocol": "fields.EventData.Protocol",
                        "SourceHostname": "srcDevice_hostname",
                        "SourceIsIpv6": "fields.EventData.SourceIsIpv6",
                        "DestinationHostname": "dstDevice_hostname",
                        "DestinationPortName": "fields.EventData.DestinationPortName",
                        "DestinationIsIpv6": "fields.EventData.DestinationIsIpv6",
                        "Initiated": "fields.EventData.Initiated",
                        # File Operations (Event ID 2, 11, 15, 23, 26)
                        "TargetFilename": "file_path",
                        "CreationUtcTime": "fields.EventData.CreationUtcTime",
                        "PreviousCreationUtcTime": "fields.EventData.PreviousCreationUtcTime",
                        "Hash": "fields.EventData.Hash",
                        "Contents": "fields.EventData.Contents",
                        # Image/Driver Load (Event ID 6, 7)
                        "ImageLoaded": "file_path",
                        "Signed": "fields.EventData.Signed",
                        "Signature": "fields.EventData.Signature",
                        "SignatureStatus": "fields.EventData.SignatureStatus",
                        # Registry Events (Event ID 12, 13, 14)
                        "EventType": "changeType",
                        "TargetObject": "changeTarget",
                        "Details": "fields.EventData.Details",
                        "NewName": "fields.EventData.NewName",
                        # Remote Thread (Event ID 8)
                        "SourceImage": "baseImage",
                        "SourceProcessGuid": "fields.EventData.SourceProcessGuid",
                        "SourceProcessId": "pid",
                        "TargetImage": "file_path",
                        "TargetProcessGuid": "fields.EventData.TargetProcessGuid",
                        "TargetProcessId": "fields.EventData.TargetProcessId",
                        "NewThreadId": "fields.EventData.NewThreadId",
                        "StartAddress": "fields.EventData.StartAddress",
                        "StartModule": "fields.EventData.StartModule",
                        "StartFunction": "fields.EventData.StartFunction",
                        # Pipe Events (Event ID 17, 18)
                        "PipeName": "changeTarget",
                        # Raw Access Read (Event ID 9)
                        "Device": "changeTarget",
                    },
                    logsource_category="sysmon",
                    schema=schema,
                ),
                rule_conditions=[
                    LogsourceCondition(product="windows", service="sysmon")
                ],
            ),
            # Windows Security - Additional fields beyond common
            ProcessingItem(
                identifier="sumologic_cse_security",
                transformation=ConfidenceAwareFieldMapping(
                    mapping={
                        # Process Creation (Event ID 4688)
                        "NewProcessName": "baseImage",
                        "NewProcessId": "fields.EventData.NewProcessId",
                        "ParentProcessName": "parentBaseImage",
                        "CommandLine": "commandLine",
                        "MandatoryLabel": "fields.EventData.MandatoryLabel",
                        "TokenElevationType": "fields.EventData.TokenElevationType",
                        # Authentication (Event ID 4624, 4625, 4648)
                        "WorkstationName": "srcDevice_hostname",
                        "TargetServerName": "dstDevice_hostname",
                        "TargetInfo": "fields.EventData.TargetInfo",
                        "Status": "errorCode",
                        "SubStatus": "fields.EventData.SubStatus",
                        "FailureReason": "cause",
                        "LogonGuid": "fields.EventData.LogonGuid",
                        "KeyLength": "fields.EventData.KeyLength",
                        "ElevatedToken": "fields.EventData.ElevatedToken",
                        "ImpersonationLevel": "fields.EventData.ImpersonationLevel",
                        "VirtualAccount": "fields.EventData.VirtualAccount",
                        # Network (Event ID 5156)
                        "Application": "application",
                        "Direction": "fields.EventData.Direction",
                        "FilterRTID": "fields.EventData.FilterRTID",
                        "LayerName": "fields.EventData.LayerName",
                        "RemoteMachineID": "fields.EventData.RemoteMachineID",
                        "RemoteUserID": "fields.EventData.RemoteUserID",
                    },
                    logsource_category="security",
                    schema=schema,
                ),
                rule_conditions=[
                    LogsourceCondition(product="windows", service="security")
                ],
            ),
            # Windows PowerShell - All versions
            ProcessingItem(
                identifier="sumologic_cse_powershell",
                transformation=ConfidenceAwareFieldMapping(
                    mapping={
                        # Script Block Logging (Event ID 4104)
                        "ScriptBlockText": "commandLine",
                        "ScriptBlockId": "fields.EventData.ScriptBlockId",
                        "Path": "file_path",
                        "MessageNumber": "fields.EventData.MessageNumber",
                        "MessageTotal": "fields.EventData.MessageTotal",
                        # Classic/Module Logging (Event ID 400, 403, 600, 800)
                        "HostApplication": "commandLine",
                        "EngineVersion": "fields.EngineVersion",
                        "HostVersion": "fields.HostVersion",
                        "HostName": "srcDevice_hostname",
                        "Payload": "fields.EventData.Payload",
                        "RunspaceId": "fields.EventData.RunspaceId",
                    },
                    logsource_category="powershell",
                    schema=schema,
                ),
                rule_conditions=[
                    LogsourceCondition(product="windows", service="powershell")
                ],
            ),
            # Generic field mapping for common fields
            ProcessingItem(
                identifier="sumologic_cse_generic_fields",
                transformation=ConfidenceAwareFieldMapping(
                    mapping={
                        # Event IDs
                        "EventID": "metadata_deviceEventId",
                        "EventId": "metadata_deviceEventId",
                        # User fields
                        "User": "user_username",
                        "Username": "user_username",
                        "UserName": "user_username",
                        "SourceUser": "user_username",
                        "TargetUser": "targetUser_username",
                        "SubjectUserName": "user_username",
                        # IP addresses
                        "IpAddress": "srcDevice_ip",
                        "SourceIp": "srcDevice_ip",
                        "SourceIpAddress": "srcDevice_ip",
                        "DestinationIp": "dstDevice_ip",
                        "DestinationIpAddress": "dstDevice_ip",
                        # Hostnames
                        "ComputerName": "device_hostname",
                        "Computer": "device_hostname",
                        "Workstation": "srcDevice_hostname",
                        "DestinationHostname": "dstDevice_hostname",
                        # File fields
                        "FileName": "file_basename",
                        "FilePath": "file_path",
                        "FileHash": "file_hash_sha256",
                        # Process fields
                        "ProcessName": "baseImage",
                        "ParentProcessName": "parentBaseImage",
                        # Network fields
                        "DestinationPort": "dstPort",
                        "SourcePort": "srcPort",
                        # Action/Status
                        "Action": "action",
                        "Status": "normalizedAction",
                    },
                    logsource_category="generic",
                    schema=schema,
                ),
            ),
            # Smart handling of "Data" field - transforms structured patterns, blocks arbitrary strings
            ProcessingItem(
                identifier="sumologic_cse_transform_data_field",
                transformation=DataFieldTransformation(),
                field_name_conditions=[IncludeFieldCondition(fields=["Data"])],
            ),
        ],
    )
