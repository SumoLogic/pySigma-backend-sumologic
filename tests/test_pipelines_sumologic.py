import pytest
from sigma.backends.sumologic import SumoLogicCSERuleBackend
from sigma.pipelines.sumologic import sumologic_cse_pipeline
from sigma.collection import SigmaCollection


def test_sumologic_cse_pipeline_initialization():
    """Test that CSE pipeline initializes correctly"""
    pipeline = sumologic_cse_pipeline()

    assert pipeline is not None
    assert pipeline.name == "Sumo Logic Cloud SIEM (CSE) Pipeline"
    assert "sumologic_cse" in pipeline.allowed_backends
    assert "sumologic_cse_rule" in pipeline.allowed_backends
    assert pipeline.priority == 20


def test_sumologic_cse_pipeline_process_creation_mapping():
    """Test process creation field mappings"""
    backend = SumoLogicCSERuleBackend(
        processing_pipeline=sumologic_cse_pipeline(), min_confidence=0.0
    )

    result = backend.convert(
        SigmaCollection.from_yaml(
            """
            title: Process Creation Field Mapping Test
            id: 00000000-0000-0000-0001-000000000001
            status: test
            logsource:
                category: process_creation
                product: windows
            detection:
                sel:
                    CommandLine: "test.exe"
                    Image: "C:\\\\test.exe"
                    ParentImage: "C:\\\\parent.exe"
                    ProcessId: "1234"
                    User: "SYSTEM"
                condition: sel
        """
        )
    )

    # Verify field mapping occurred
    assert "commandLine" in result[0]
    assert "baseImage" in result[0]
    assert "parentBaseImage" in result[0]
    assert "pid" in result[0]
    assert "user_username" in result[0]


def test_sumologic_cse_pipeline_network_connection_mapping():
    """Test network connection field mappings"""
    backend = SumoLogicCSERuleBackend(
        processing_pipeline=sumologic_cse_pipeline(), min_confidence=0.0
    )

    result = backend.convert(
        SigmaCollection.from_yaml(
            """
            title: Network Connection Field Mapping Test
            id: 00000000-0000-0000-0001-000000000002
            status: test
            logsource:
                category: network_connection
                product: windows
            detection:
                sel:
                    SourceIp: "192.168.1.100"
                    DestinationIp: "10.0.0.1"
                    SourcePort: 12345
                    DestinationPort: 443
                condition: sel
        """
        )
    )

    # Verify field mapping occurred
    assert "srcDevice_ip" in result[0]
    assert "dstDevice_ip" in result[0]
    assert "srcPort" in result[0]
    assert "dstPort" in result[0]


def test_sumologic_cse_pipeline_dns_query_mapping():
    """Test DNS query field mappings"""
    backend = SumoLogicCSERuleBackend(
        processing_pipeline=sumologic_cse_pipeline(), min_confidence=0.0
    )

    result = backend.convert(
        SigmaCollection.from_yaml(
            """
            title: DNS Query Field Mapping Test
            id: 00000000-0000-0000-0001-000000000003
            status: test
            logsource:
                category: dns_query
                product: windows
            detection:
                sel:
                    QueryName: "malicious.com"
                    QueryResults: "1.2.3.4"
                condition: sel
        """
        )
    )

    # Verify field mapping occurred
    assert "dns_query" in result[0]
    assert "dns_reply" in result[0]


def test_sumologic_cse_pipeline_file_event_mapping():
    """Test file event field mappings"""
    backend = SumoLogicCSERuleBackend(
        processing_pipeline=sumologic_cse_pipeline(), min_confidence=0.0
    )

    result = backend.convert(
        SigmaCollection.from_yaml(
            """
            title: File Event Field Mapping Test
            id: 00000000-0000-0000-0001-000000000004
            status: test
            logsource:
                category: file_event
                product: windows
            detection:
                sel:
                    TargetFilename: "C:\\\\malicious.exe"
                    md5: "abc123"
                condition: sel
        """
        )
    )

    # Verify field mapping occurred
    assert "file_path" in result[0]
    assert "file_hash_md5" in result[0]


def test_sumologic_cse_pipeline_registry_event_mapping():
    """Test registry event field mappings"""
    backend = SumoLogicCSERuleBackend(
        processing_pipeline=sumologic_cse_pipeline(), min_confidence=0.0
    )

    result = backend.convert(
        SigmaCollection.from_yaml(
            """
            title: Registry Event Field Mapping Test
            id: 00000000-0000-0000-0001-000000000005
            status: test
            logsource:
                category: registry_event
                product: windows
            detection:
                sel:
                    TargetObject: "HKLM\\\\Software\\\\Test"
                    Details: "malicious"
                condition: sel
        """
        )
    )

    # Verify field mapping occurred
    assert "changeTarget" in result[0]
    # Details is not mapped in the registry_event category — it becomes a vendor pass-through field
    assert "fields['EventData.Details']" in result[0]


def test_sumologic_cse_pipeline_proxy_mapping():
    """Test proxy/web log field mappings including bytesIn/bytesOut"""
    backend = SumoLogicCSERuleBackend(
        processing_pipeline=sumologic_cse_pipeline(), min_confidence=0.0
    )

    result = backend.convert(
        SigmaCollection.from_yaml(
            """
            title: Proxy Field Mapping Test
            id: 00000000-0000-0000-0001-000000000006
            status: test
            logsource:
                category: proxy
            detection:
                sel:
                    c-uri: "http://malicious.com"
                    cs-method: "GET"
                    sc-status: 200
                    cs-bytes: 1024
                    sc-bytes: 2048
                condition: sel
        """
        )
    )

    # Verify field mapping occurred including CSE schema fields
    assert "http_url" in result[0]
    assert "http_method" in result[0]
    assert "http_response_statusCode" in result[0]
    assert "bytesOut" in result[0]  # CSE schema field
    assert "bytesIn" in result[0]  # CSE schema field


def test_sumologic_cse_pipeline_hash_field_variations():
    """Test that various hash field names map correctly"""
    backend = SumoLogicCSERuleBackend(
        processing_pipeline=sumologic_cse_pipeline(), min_confidence=0.0
    )

    result = backend.convert(
        SigmaCollection.from_yaml(
            """
            title: Hash Field Variations Test
            id: 00000000-0000-0000-0001-000000000007
            status: test
            logsource:
                category: process_creation
                product: windows
            detection:
                sel:
                    Image: "test.exe"
                    md5: "abc123"
                    SHA256: "def456"
                condition: sel
        """
        )
    )

    # Verify both lowercase and uppercase hash fields map correctly
    assert "file_hash_md5" in result[0]
    assert "file_hash_sha256" in result[0]


def test_sumologic_cse_pipeline_user_field_variations():
    """Test that various user field names map correctly"""
    backend = SumoLogicCSERuleBackend(
        processing_pipeline=sumologic_cse_pipeline(), min_confidence=0.0
    )

    result = backend.convert(
        SigmaCollection.from_yaml(
            """
            title: User Field Variations Test
            id: 00000000-0000-0000-0001-000000000008
            status: test
            logsource:
                category: process_creation
                product: windows
            detection:
                sel:
                    Image: "test.exe"
                    User: "admin"
                condition: sel
        """
        )
    )

    # Verify user field maps correctly
    assert "user_username" in result[0]


def test_sumologic_cse_pipeline_aws_cloudtrail_mapping():
    """Test AWS CloudTrail field mappings"""
    backend = SumoLogicCSERuleBackend(
        processing_pipeline=sumologic_cse_pipeline(), min_confidence=0.0
    )

    result = backend.convert(
        SigmaCollection.from_yaml(
            """
            title: AWS CloudTrail Field Mapping Test
            id: 00000000-0000-0000-0001-000000000009
            status: test
            logsource:
                product: aws
                service: cloudtrail
            detection:
                sel:
                    eventName: "ConsoleLogin"
                    sourceIPAddress: "1.2.3.4"
                condition: sel
        """
        )
    )

    # Verify field mapping occurred
    assert "action" in result[0]
    assert "srcDevice_ip" in result[0]


def test_sumologic_cse_pipeline_multiple_logsources():
    """Test that pipeline handles multiple logsource categories correctly"""
    pipeline = sumologic_cse_pipeline()

    # Verify pipeline has processing items for all major categories
    identifiers = [item.identifier for item in pipeline.items]

    assert "sumologic_cse_process_creation" in identifiers
    assert "sumologic_cse_network_connection" in identifiers
    assert "sumologic_cse_dns_query" in identifiers
    assert "sumologic_cse_file_event" in identifiers
    assert "sumologic_cse_registry_event" in identifiers
    assert "sumologic_cse_proxy" in identifiers
    assert "sumologic_cse_firewall" in identifiers
    assert "sumologic_cse_aws_cloudtrail" in identifiers


def test_data_field_blocked():
    """Test that Data field with arbitrary strings triggers helpful error message."""
    from sigma.exceptions import SigmaTransformationError

    backend = SumoLogicCSERuleBackend(processing_pipeline=sumologic_cse_pipeline())

    # Rule using Data field with arbitrary string should fail
    with pytest.raises(SigmaTransformationError) as exc_info:
        backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test Data Field Block
            id: 00000000-0000-0000-0000-000000000001
            status: test
            logsource:
                product: windows
                service: powershell-classic
            detection:
                selection:
                    Data|contains: 'Net.WebClient'
                condition: selection
        """
            )
        )

    # Verify error message is helpful and shows context
    error_msg = str(exc_info.value)
    assert "arbitrary string patterns" in error_msg.lower()
    assert "Net.WebClient" in error_msg
    assert "✗" in error_msg  # Should show unsupported marker
    assert "Original Sigma detection:" in error_msg  # Should show original criteria
    assert "EventData" in error_msg
    assert "Solution" in error_msg


def test_data_field_structured_key_value():
    """Test that Data field with key=value patterns gets transformed to EventData fields."""
    backend = SumoLogicCSERuleBackend(
        processing_pipeline=sumologic_cse_pipeline(), min_confidence=0.0
    )

    result = backend.convert(
        SigmaCollection.from_yaml(
            """
        title: Test Data Field Key=Value Transform
        id: 00000000-0000-0000-0000-000000000002
        status: test
        logsource:
            product: windows
            service: powershell-classic
        detection:
            selection:
                Data|contains: 'EngineVersion=2.'
            condition: selection
    """
        )
    )

    # Should convert successfully and map to EventData.EngineVersion
    assert (
        "EventData.EngineVersion" in result[0]
        or "fields['EventData.EngineVersion']" in result[0]
    )


def test_data_field_structured_key_colon_value():
    """Test that Data field with key:value patterns gets transformed to EventData fields."""
    backend = SumoLogicCSERuleBackend(
        processing_pipeline=sumologic_cse_pipeline(), min_confidence=0.0
    )

    result = backend.convert(
        SigmaCollection.from_yaml(
            """
        title: Test Data Field Key:Value Transform
        id: 00000000-0000-0000-0000-000000000003
        status: test
        logsource:
            product: windows
            service: application
        detection:
            selection:
                Data|contains: 'statement:DROP TABLE'
            condition: selection
    """
        )
    )

    # Should convert successfully and map to EventData.statement
    assert (
        "EventData.statement" in result[0]
        or "fields['EventData.statement']" in result[0]
    )


def test_data_field_mixed_patterns():
    """Test that Data field with mixed structured and arbitrary patterns shows helpful context."""
    from sigma.exceptions import SigmaTransformationError

    backend = SumoLogicCSERuleBackend(processing_pipeline=sumologic_cse_pipeline())

    # Rule with mix of structured and arbitrary patterns
    with pytest.raises(SigmaTransformationError) as exc_info:
        backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test Mixed Patterns
            id: 00000000-0000-0000-0000-000000000004
            status: test
            logsource:
                product: windows
                service: powershell-classic
            detection:
                selection:
                    Data|contains:
                        - 'EngineVersion=2.'
                        - 'Net.WebClient'
                condition: selection
        """
            )
        )

    error_msg = str(exc_info.value)
    # Should show both patterns with appropriate markers
    assert "✓" in error_msg  # Supported pattern marker
    assert "✗" in error_msg  # Unsupported pattern marker
    assert "EngineVersion=2." in error_msg  # Structured pattern
    assert "Net.WebClient" in error_msg  # Arbitrary string
    assert "Successfully converted:" in error_msg  # Should show what worked
    assert "EventData.EngineVersion" in error_msg  # Should show the converted field


def test_eventdata_fields_work():
    """Test that specific EventData fields are properly mapped."""
    import json

    backend = SumoLogicCSERuleBackend(
        processing_pipeline=sumologic_cse_pipeline(), min_confidence=0.0
    )

    result = backend.convert(
        SigmaCollection.from_yaml(
            """
        title: Test EventData Fields
        id: 00000000-0000-0000-0000-000000000001
        status: test
        logsource:
            product: windows
            service: security
        detection:
            selection:
                EventID: 4624
                LogonType: '3'
                TargetUserName: 'Administrator'
            condition: selection
    """
        )
    )

    parsed = json.loads(result[0])
    expr = parsed["rules"][0]["expression"]

    # Verify EventData fields are mapped correctly
    assert 'logonType="3"' in expr  # LogonType → logonType (via common Windows mapping)
    assert 'user_username="Administrator"' in expr  # TargetUserName → user_username
