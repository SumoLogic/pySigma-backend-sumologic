"""
Tests for vendor/product metadata injection based on CSE parser mappings.
"""

import pytest
import json
from sigma.collection import SigmaCollection
from sigma.backends.sumologic import SumoLogicCSERuleBackend
from sigma.pipelines.sumologic import sumologic_cse_pipeline


@pytest.fixture
def backend():
    """Create backend with pipeline"""
    return SumoLogicCSERuleBackend(
        processing_pipeline=sumologic_cse_pipeline(), min_confidence=0.0
    )


def test_windows_sysmon_metadata(backend):
    """Test Windows Sysmon gets correct vendor/product and full EventID."""
    result = backend.convert(
        SigmaCollection.from_yaml(
            """
            title: Sysmon Process Creation
            id: 00000000-0000-0000-0000-000000000001
            status: test
            logsource:
                product: windows
                service: sysmon
                category: process_creation
            detection:
                sel:
                    EventID: 1
                    Image|endswith: '\\powershell.exe'
                condition: sel
        """
        )
    )

    parsed = json.loads(result[0])
    expr = parsed["rules"][0]["expression"]

    # Check vendor/product metadata
    assert 'metadata_vendor="Microsoft"' in expr
    assert 'metadata_product="Windows"' in expr
    # Check full Sysmon channel name with EventID
    assert 'metadata_deviceEventId="Microsoft-Windows-Sysmon/Operational-1"' in expr


def test_windows_security_metadata(backend):
    """Test Windows Security log gets correct channel prefix."""
    result = backend.convert(
        SigmaCollection.from_yaml(
            """
            title: Failed Logon
            id: 00000000-0000-0000-0000-000000000002
            status: test
            logsource:
                product: windows
                service: security
            detection:
                sel:
                    EventID: 4625
                condition: sel
        """
        )
    )

    parsed = json.loads(result[0])
    expr = parsed["rules"][0]["expression"]

    assert 'metadata_vendor="Microsoft"' in expr
    assert 'metadata_product="Windows"' in expr
    assert 'metadata_deviceEventId="Security-4625"' in expr


def test_aws_cloudtrail_metadata(backend):
    """Test AWS CloudTrail gets correct vendor/product."""
    result = backend.convert(
        SigmaCollection.from_yaml(
            """
            title: AWS S3 Bucket Deletion
            id: 00000000-0000-0000-0000-000000000003
            status: test
            logsource:
                product: aws
                service: cloudtrail
            detection:
                sel:
                    eventName: DeleteBucket
                condition: sel
        """
        )
    )

    parsed = json.loads(result[0])
    expr = parsed["rules"][0]["expression"]

    assert 'metadata_vendor="Amazon AWS"' in expr
    assert 'metadata_product="CloudTrail"' in expr


def test_azure_signinlogs_metadata(backend):
    """Test Azure Sign-in logs get correct vendor/product."""
    result = backend.convert(
        SigmaCollection.from_yaml(
            """
            title: Azure Failed Authentication
            id: 00000000-0000-0000-0000-000000000004
            status: test
            logsource:
                product: azure
                service: signinlogs
            detection:
                sel:
                    ResultType: '50126'
                condition: sel
        """
        )
    )

    parsed = json.loads(result[0])
    expr = parsed["rules"][0]["expression"]

    assert 'metadata_vendor="Microsoft"' in expr
    assert 'metadata_product="Azure"' in expr


def test_linux_auditd_metadata(backend):
    """Test Linux auditd with no vendor mapping produces query without metadata filters."""
    result = backend.convert(
        SigmaCollection.from_yaml(
            """
            title: Linux Privileged Command
            id: 00000000-0000-0000-0000-000000000005
            status: test
            logsource:
                product: linux
                service: auditd
            detection:
                sel:
                    type: EXECVE
                    a0: sudo
                condition: sel
        """
        )
    )

    parsed = json.loads(result[0])
    expr = parsed["rules"][0]["expression"]

    # No vendor/product mapping exists for linux/auditd — query has no metadata filters
    assert "metadata_vendor" not in expr
    assert "fields[" in expr


def test_windows_powershell_metadata(backend):
    """Test Windows PowerShell gets correct channel prefix."""
    result = backend.convert(
        SigmaCollection.from_yaml(
            """
            title: PowerShell Script Block Logging
            id: 00000000-0000-0000-0000-000000000006
            status: test
            logsource:
                product: windows
                service: powershell
            detection:
                sel:
                    EventID: 4104
                condition: sel
        """
        )
    )

    parsed = json.loads(result[0])
    expr = parsed["rules"][0]["expression"]

    assert 'metadata_vendor="Microsoft"' in expr
    assert 'metadata_product="Windows"' in expr
    assert 'metadata_deviceEventId="PowerShell-4104"' in expr


def test_windows_taskscheduler_metadata(backend):
    """Test Windows Task Scheduler gets correct operational channel."""
    result = backend.convert(
        SigmaCollection.from_yaml(
            """
            title: Task Scheduler Event
            id: 00000000-0000-0000-0000-000000000007
            status: test
            logsource:
                product: windows
                service: taskscheduler
            detection:
                sel:
                    EventID: 106
                condition: sel
        """
        )
    )

    parsed = json.loads(result[0])
    expr = parsed["rules"][0]["expression"]

    assert 'metadata_vendor="Microsoft"' in expr
    assert 'metadata_product="Windows"' in expr
    assert (
        'metadata_deviceEventId="Microsoft-Windows-TaskScheduler/Operational-106"'
        in expr
    )


def test_generic_category_fallback(backend):
    """Test generic category fallback is intentionally skipped (not injected into query)."""
    result = backend.convert(
        SigmaCollection.from_yaml(
            """
            title: Generic Proxy Rule
            id: 00000000-0000-0000-0000-000000000008
            status: test
            logsource:
                category: proxy
            detection:
                sel:
                    c-uri|contains: malicious
                condition: sel
        """
        )
    )

    parsed = json.loads(result[0])
    expr = parsed["rules"][0]["expression"]

    # Backend deliberately skips "Generic" vendor/product metadata —
    # these are fallback categories, not actual vendor filters in Cloud SIEM
    assert "metadata_vendor" not in expr
    assert "malicious" in expr


def test_eventid_list_transformation(backend):
    """Test EventID in list gets proper channel prefixes."""
    result = backend.convert(
        SigmaCollection.from_yaml(
            """
            title: Multiple EventIDs
            id: 00000000-0000-0000-0000-000000000009
            status: test
            logsource:
                product: windows
                service: security
            detection:
                sel:
                    EventID:
                        - 4624
                        - 4625
                        - 4648
                condition: sel
        """
        )
    )

    parsed = json.loads(result[0])
    expr = parsed["rules"][0]["expression"]

    # All EventIDs should have Security channel prefix
    assert (
        'metadata_deviceEventId in ("Security-4624", "Security-4625", "Security-4648")'
        in expr
    )


def test_known_good_mappings_confidence():
    """Test that known-good mappings (Action→action, eventName→action) pass confidence checks."""
    # Use default confidence threshold (0.25)
    backend = SumoLogicCSERuleBackend(processing_pipeline=sumologic_cse_pipeline())

    # Test AWS CloudTrail with eventName → action
    result1 = backend.convert(
        SigmaCollection.from_yaml(
            """
            title: AWS CloudTrail Event
            id: 00000000-0000-0000-0000-000000000010
            status: test
            logsource:
                product: aws
                service: cloudtrail
            detection:
                sel:
                    eventName: DeleteBucket
                    errorCode: Success
                condition: sel
        """
        )
    )

    parsed1 = json.loads(result1[0])
    expr1 = parsed1["rules"][0]["expression"]

    # Should successfully convert with known-good mappings
    assert 'action="DeleteBucket"' in expr1
    assert 'errorCode="Success"' in expr1

    # Test exact name match (Action → action)
    result2 = backend.convert(
        SigmaCollection.from_yaml(
            """
            title: Firewall Action
            id: 00000000-0000-0000-0000-000000000011
            status: test
            logsource:
                category: firewall
            detection:
                sel:
                    Action: Block
                condition: sel
        """
        )
    )

    parsed2 = json.loads(result2[0])
    expr2 = parsed2["rules"][0]["expression"]

    # Should successfully convert with exact match
    assert 'action="Block"' in expr2
