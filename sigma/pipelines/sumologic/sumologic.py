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


def sumologic_cse_pipeline() -> ProcessingPipeline:
    """
    Processing pipeline for Sumo Logic Cloud SIEM (CSE).

    This pipeline transforms Sigma rules into Sumo Logic Cloud SIEM compatible queries by:
    - Mapping Sigma field names to Cloud SIEM schema field names
    - Handling Windows event logs, Sysmon, security logs
    - Supporting process creation, network connection, DNS queries, file operations
    - Providing proper field mappings for authentication, user activity, and system events

    Based on legacy implementation and CSE schema.
    Reference:
    - https://github.com/SigmaHQ/legacy-sigmatools/blob/master/tools/sigma/backends/sumologic.py
    - https://github.com/SumoLogic/cloud-siem-content-catalog/blob/master/schema/full_schema.md
    """
    return ProcessingPipeline(
        name="Sumo Logic Cloud SIEM (CSE) Pipeline",
        allowed_backends=frozenset(["sumologic-cse", "sumologic-cse-rule"]),
        priority=20,
        items=[
            # Windows Process Creation (Sysmon Event ID 1, Security Event ID 4688)
            ProcessingItem(
                identifier="sumologic_cse_process_creation",
                transformation=FieldMappingTransformation(
                    {
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
                    }
                ),
                rule_conditions=[LogsourceCondition(category="process_creation")],
            ),
            # Windows Network Connection (Sysmon Event ID 3)
            ProcessingItem(
                identifier="sumologic_cse_network_connection",
                transformation=FieldMappingTransformation(
                    {
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
                    }
                ),
                rule_conditions=[LogsourceCondition(category="network_connection")],
            ),
            # DNS Query (Sysmon Event ID 22)
            ProcessingItem(
                identifier="sumologic_cse_dns_query",
                transformation=FieldMappingTransformation(
                    {
                        "QueryName": "dns_query",
                        "QueryResults": "dns_reply",
                        "QueryStatus": "dns_replyCode",
                        "Image": "baseImage",
                        "ProcessId": "pid",
                        "record_type": "dns_queryType",
                    }
                ),
                rule_conditions=[LogsourceCondition(category="dns_query")],
            ),
            # File Creation/Modification (Sysmon Event ID 11, 23)
            ProcessingItem(
                identifier="sumologic_cse_file_event",
                transformation=FieldMappingTransformation(
                    {
                        "TargetFilename": "file_path",
                        "Image": "baseImage",
                        "User": "user_username",
                        "ProcessId": "pid",
                        "md5": "file_hash_md5",
                        "sha1": "file_hash_sha1",
                        "sha256": "file_hash_sha256",
                    }
                ),
                rule_conditions=[LogsourceCondition(category="file_event")],
            ),
            # Image/Module Load (Sysmon Event ID 6, 7)
            ProcessingItem(
                identifier="sumologic_cse_image_load",
                transformation=FieldMappingTransformation(
                    {
                        "ImageLoaded": "file_path",
                        "Signature": "file_signature",
                        "SignatureStatus": "file_signatureStatus",
                        "Signed": "file_signatureStatus",
                        "Image": "baseImage",
                        "md5": "file_hash_md5",
                        "sha1": "file_hash_sha1",
                        "sha256": "file_hash_sha256",
                    }
                ),
                rule_conditions=[LogsourceCondition(category="image_load")],
            ),
            # Registry Events (Sysmon Event ID 12, 13, 14)
            ProcessingItem(
                identifier="sumologic_cse_registry_event",
                transformation=FieldMappingTransformation(
                    {
                        "TargetObject": "changeTarget",
                        "Details": "changeResult",
                        "EventType": "changeType",
                        "Image": "baseImage",
                        "User": "user_username",
                    }
                ),
                rule_conditions=[LogsourceCondition(category="registry_event")],
            ),
            # Windows Security Events - Authentication
            ProcessingItem(
                identifier="sumologic_cse_windows_authentication",
                transformation=FieldMappingTransformation(
                    {
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
                    }
                ),
                rule_conditions=[
                    LogsourceCondition(product="windows", service="security")
                ],
            ),
            # Windows System Events
            ProcessingItem(
                identifier="sumologic_cse_windows_system",
                transformation=FieldMappingTransformation(
                    {
                        "ServiceName": "application",
                        "ImagePath": "file_path",
                        "ServiceType": "resource_type",
                        "StartType": "changeType",
                    }
                ),
                rule_conditions=[
                    LogsourceCondition(product="windows", service="system")
                ],
            ),
            # PowerShell Logs
            ProcessingItem(
                identifier="sumologic_cse_powershell",
                transformation=FieldMappingTransformation(
                    {
                        "ScriptBlockText": "commandLine",
                        "Path": "file_path",
                        "HostApplication": "commandLine",
                        "ContextInfo": "description",
                    }
                ),
                rule_conditions=[
                    LogsourceCondition(product="windows", service="powershell")
                ],
            ),
            # Web/Proxy Logs
            ProcessingItem(
                identifier="sumologic_cse_proxy",
                transformation=FieldMappingTransformation(
                    {
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
                    }
                ),
                rule_conditions=[LogsourceCondition(category="proxy")],
            ),
            # Firewall Logs
            ProcessingItem(
                identifier="sumologic_cse_firewall",
                transformation=FieldMappingTransformation(
                    {
                        "src_ip": "srcDevice_ip",
                        "dst_ip": "dstDevice_ip",
                        "src_port": "srcPort",
                        "dst_port": "dstPort",
                        "protocol": "ipProtocol",
                        "action": "action",
                    }
                ),
                rule_conditions=[LogsourceCondition(category="firewall")],
            ),
            # AWS CloudTrail
            ProcessingItem(
                identifier="sumologic_cse_aws_cloudtrail",
                transformation=FieldMappingTransformation(
                    {
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
                    }
                ),
                rule_conditions=[
                    LogsourceCondition(product="aws", service="cloudtrail")
                ],
            ),
            # Azure Activity Logs
            ProcessingItem(
                identifier="sumologic_cse_azure_activity",
                transformation=FieldMappingTransformation(
                    {
                        "operationName": "action",
                        "caller": "user_username",
                        "callerIpAddress": "srcDevice_ip",
                        "resourceId": "resourceId",
                        "status": "normalizedAction",
                        "properties.message": "description",
                    }
                ),
                rule_conditions=[
                    LogsourceCondition(product="azure", service="activitylogs")
                ],
            ),
            # Office 365
            ProcessingItem(
                identifier="sumologic_cse_office365",
                transformation=FieldMappingTransformation(
                    {
                        "Operation": "action",
                        "UserId": "user_username",
                        "ClientIP": "srcDevice_ip",
                        "UserAgent": "http_userAgent",
                        "ObjectId": "resourceId",
                    }
                ),
                rule_conditions=[LogsourceCondition(service="office365")],
            ),
            # Linux/Unix authentication
            ProcessingItem(
                identifier="sumologic_cse_linux_auth",
                transformation=FieldMappingTransformation(
                    {
                        "user": "user_username",
                        "srcip": "srcDevice_ip",
                        "hostname": "device_hostname",
                        "addr": "srcDevice_ip",
                    }
                ),
                rule_conditions=[LogsourceCondition(product="linux", service="auth")],
            ),
            # Generic field mapping for common fields
            ProcessingItem(
                identifier="sumologic_cse_generic_fields",
                transformation=FieldMappingTransformation(
                    {
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
                    }
                ),
            ),
        ],
    )
