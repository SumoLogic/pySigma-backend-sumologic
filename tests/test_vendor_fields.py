"""
Tests for vendor-specific field wrapping in fields[] syntax.
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


def test_vendor_specific_fields_with_dots(backend):
    """Test that vendor-specific fields with dots get wrapped in fields[] syntax."""
    result = backend.convert(
        SigmaCollection.from_yaml(
            """
            title: Azure Audit Log
            id: 00000000-0000-0000-0000-000000000001
            status: test
            logsource:
                product: azure
                service: auditlogs
            detection:
                selection:
                    auditType.category: 'Auditing'
                    auditType.action: 'Audit log configuration updated'
                condition: selection
        """
        )
    )

    parsed = json.loads(result[0])
    expr = parsed["rules"][0]["expression"]

    # Vendor-specific fields should be wrapped
    assert "fields['auditType.category']" in expr
    assert "fields['auditType.action']" in expr
    # Values should be quoted
    assert '"Auditing"' in expr
    assert '"Audit log configuration updated"' in expr


def test_cse_schema_fields_not_wrapped(backend):
    """Test that CSE schema fields are NOT wrapped in fields[] syntax."""
    result = backend.convert(
        SigmaCollection.from_yaml(
            """
            title: Process Creation
            id: 00000000-0000-0000-0000-000000000002
            status: test
            logsource:
                product: windows
                category: process_creation
            detection:
                selection:
                    Image|endswith: '\\powershell.exe'
                    CommandLine|contains: 'Invoke-Mimikatz'
                condition: selection
        """
        )
    )

    parsed = json.loads(result[0])
    expr = parsed["rules"][0]["expression"]

    # CSE schema fields should NOT be wrapped
    assert "fields['baseImage']" not in expr
    assert "fields['commandLine']" not in expr
    # They should appear as direct references
    assert "baseImage" in expr
    assert "commandLine" in expr


def test_eventdata_fields_wrapped(backend):
    """Test that EventData.* fields get wrapped in fields[] syntax."""
    result = backend.convert(
        SigmaCollection.from_yaml(
            """
            title: EventData Field
            id: 00000000-0000-0000-0000-000000000003
            status: test
            logsource:
                product: windows
                service: security
            detection:
                selection:
                    EventData.SubjectUserName: 'Administrator'
                    EventData.TargetUserName: 'Guest'
                condition: selection
        """
        )
    )

    parsed = json.loads(result[0])
    expr = parsed["rules"][0]["expression"]

    # EventData fields should be wrapped
    assert "fields['EventData.SubjectUserName']" in expr
    assert "fields['EventData.TargetUserName']" in expr


def test_mixed_cse_and_vendor_fields(backend):
    """Test rules with both CSE schema fields and vendor-specific fields."""
    result = backend.convert(
        SigmaCollection.from_yaml(
            """
            title: Mixed Fields
            id: 00000000-0000-0000-0000-000000000004
            status: test
            logsource:
                product: azure
                service: signinlogs
            detection:
                selection:
                    ResultType: '50126'
                    properties.customField: 'suspicious'
                condition: selection
        """
        )
    )

    parsed = json.loads(result[0])
    expr = parsed["rules"][0]["expression"]

    # ResultType might be CSE field or vendor field depending on mapping
    # properties.customField should definitely be wrapped
    assert "fields['properties.customField']" in expr


def test_aws_nested_fields(backend):
    """Test AWS CloudTrail nested fields get wrapped."""
    result = backend.convert(
        SigmaCollection.from_yaml(
            """
            title: AWS Nested Fields
            id: 00000000-0000-0000-0000-000000000005
            status: test
            logsource:
                product: aws
                service: cloudtrail
            detection:
                selection:
                    requestParameters.bucketName: 'sensitive-data'
                    responseElements.bucketArn: 'arn:aws:s3:::sensitive-data'
                condition: selection
        """
        )
    )

    parsed = json.loads(result[0])
    expr = parsed["rules"][0]["expression"]

    # Nested AWS fields should be wrapped
    assert "fields['requestParameters.bucketName']" in expr
    assert "fields['responseElements.bucketArn']" in expr


def test_fields_prefix_already_present(backend):
    """Test that fields.* prefix is handled correctly (shouldn't double-wrap)."""
    result = backend.convert(
        SigmaCollection.from_yaml(
            """
            title: Fields Prefix
            id: 00000000-0000-0000-0000-000000000006
            status: test
            logsource:
                product: windows
                service: security
            detection:
                selection:
                    fields.CustomField: 'value'
                condition: selection
        """
        )
    )

    parsed = json.loads(result[0])
    expr = parsed["rules"][0]["expression"]

    # Should be wrapped as fields['CustomField'], not fields['fields.CustomField']
    assert "fields['CustomField']" in expr
    assert "fields['fields.CustomField']" not in expr


def test_vendor_fields_in_list(backend):
    """Test vendor-specific fields in OR lists."""
    result = backend.convert(
        SigmaCollection.from_yaml(
            """
            title: Vendor Field List
            id: 00000000-0000-0000-0000-000000000007
            status: test
            logsource:
                product: azure
                service: auditlogs
            detection:
                selection:
                    auditType.category:
                        - 'Auditing'
                        - 'Security'
                        - 'Compliance'
                condition: selection
        """
        )
    )

    parsed = json.loads(result[0])
    expr = parsed["rules"][0]["expression"]

    # Vendor field should be wrapped
    assert "fields['auditType.category']" in expr
    # Should be in a list expression
    assert "in (" in expr or "OR" in expr


def test_vendor_fields_with_modifiers(backend):
    """Test vendor-specific fields with Sigma modifiers (contains, endswith)."""
    result = backend.convert(
        SigmaCollection.from_yaml(
            """
            title: Vendor Field Modifiers
            id: 00000000-0000-0000-0000-000000000008
            status: test
            logsource:
                product: azure
                service: auditlogs
            detection:
                selection:
                    auditType.category|contains: 'Audit'
                    properties.userAgent|endswith: 'python-requests'
                condition: selection
        """
        )
    )

    parsed = json.loads(result[0])
    expr = parsed["rules"][0]["expression"]

    # Vendor fields should still be wrapped even with modifiers
    assert "fields['auditType.category']" in expr
    assert "fields['properties.userAgent']" in expr
    # Should use matches for contains/endswith
    assert "matches" in expr
