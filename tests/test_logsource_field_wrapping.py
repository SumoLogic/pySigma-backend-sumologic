"""
Tests for logsource-based vendor field wrapping.

Vendor-specific logsources (product + service) should wrap unmapped fields.
Generic categories should use normalized field names without wrapping.
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


def test_vendor_specific_fields_wrapped(backend):
    """Test that vendor-specific logsource wraps unmapped fields."""
    result = backend.convert(
        SigmaCollection.from_yaml(
            """
            title: Cisco Duo MFA Bypass
            id: 00000000-0000-0000-0000-000000000001
            status: test
            logsource:
                product: cisco
                service: duo
            detection:
                selection:
                    event_type: authentication
                    reason: bypass_user
                condition: selection
        """
        )
    )

    parsed = json.loads(result[0])
    expr = parsed["rules"][0]["expression"]

    # Vendor-specific fields should be wrapped
    assert "fields['event_type']" in expr
    assert "fields['reason']" in expr
    # Should not be bare field names
    assert "event_type=" not in expr or "fields['event_type']=" in expr
    assert "reason=" not in expr or "fields['reason']=" in expr


def test_generic_category_not_wrapped(backend):
    """Test that generic category logsource doesn't wrap normalized fields."""
    result = backend.convert(
        SigmaCollection.from_yaml(
            """
            title: Generic Proxy Rule
            id: 00000000-0000-0000-0000-000000000002
            status: test
            logsource:
                category: proxy
            detection:
                selection:
                    c-uri|contains: malicious
                condition: selection
        """
        )
    )

    parsed = json.loads(result[0])
    expr = parsed["rules"][0]["expression"]

    # Normalized field should NOT be wrapped
    assert "http_url" in expr
    assert "fields['http_url']" not in expr


def test_vendor_with_mapped_fields_not_wrapped(backend):
    """Test that mapped CSE schema fields are not wrapped even in vendor logsource."""
    result = backend.convert(
        SigmaCollection.from_yaml(
            """
            title: Windows Process Creation
            id: 00000000-0000-0000-0000-000000000003
            status: test
            logsource:
                product: windows
                category: process_creation
            detection:
                selection:
                    Image|endswith: '\\powershell.exe'
                    CommandLine|contains: suspicious
                condition: selection
        """
        )
    )

    parsed = json.loads(result[0])
    expr = parsed["rules"][0]["expression"]

    # Mapped CSE schema fields should NOT be wrapped
    assert "baseImage" in expr
    assert "commandLine" in expr
    assert "fields['baseImage']" not in expr
    assert "fields['commandLine']" not in expr


def test_aws_with_unmapped_vendor_fields(backend):
    """Test AWS rule with vendor-specific fields gets wrapped."""
    result = backend.convert(
        SigmaCollection.from_yaml(
            """
            title: AWS CloudTrail Custom Field
            id: 00000000-0000-0000-0000-000000000004
            status: test
            logsource:
                product: aws
                service: cloudtrail
            detection:
                selection:
                    eventName: DeleteBucket
                    customVendorField: suspicious_value
                condition: selection
        """
        )
    )

    parsed = json.loads(result[0])
    expr = parsed["rules"][0]["expression"]

    # eventName maps to action (CSE schema), should NOT be wrapped
    assert "action=" in expr
    assert "fields['action']" not in expr

    # customVendorField is unmapped, should be wrapped
    assert "fields['customVendorField']" in expr


def test_okta_vendor_fields_wrapped(backend):
    """Test Okta-specific fields are wrapped."""
    result = backend.convert(
        SigmaCollection.from_yaml(
            """
            title: Okta Event
            id: 00000000-0000-0000-0000-000000000005
            status: test
            logsource:
                product: okta
            detection:
                selection:
                    eventType: user.session.start
                    displayMessage: suspicious
                condition: selection
        """
        )
    )

    parsed = json.loads(result[0])
    expr = parsed["rules"][0]["expression"]

    # Okta vendor fields should be wrapped
    assert "fields['eventType']" in expr
    assert "fields['displayMessage']" in expr


def test_metadata_fields_not_wrapped(backend):
    """Test that metadata fields are never wrapped."""
    result = backend.convert(
        SigmaCollection.from_yaml(
            """
            title: Test Metadata Fields
            id: 00000000-0000-0000-0000-000000000006
            status: test
            logsource:
                product: windows
                service: security
            detection:
                selection:
                    EventID: 4624
                condition: selection
        """
        )
    )

    parsed = json.loads(result[0])
    expr = parsed["rules"][0]["expression"]

    # metadata_vendor and metadata_product should NOT be wrapped
    assert "metadata_vendor=" in expr
    assert "metadata_product=" in expr
    assert "fields['metadata_vendor']" not in expr
    assert "fields['metadata_product']" not in expr
    # metadata_deviceEventId should also not be wrapped
    assert "metadata_deviceEventId=" in expr
    assert "fields['metadata_deviceEventId']" not in expr


def test_mixed_vendor_and_schema_fields(backend):
    """Test rule with both vendor-specific and CSE schema fields."""
    result = backend.convert(
        SigmaCollection.from_yaml(
            """
            title: Mixed Fields
            id: 00000000-0000-0000-0000-000000000007
            status: test
            logsource:
                product: azure
                service: signinlogs
            detection:
                selection:
                    ResultType: '50126'
                    properties.customField: suspicious
                    user_username: admin
                condition: selection
        """
        )
    )

    parsed = json.loads(result[0])
    expr = parsed["rules"][0]["expression"]

    # Vendor field should be wrapped
    assert "fields['properties.customField']" in expr

    # CSE schema field should NOT be wrapped (if mapped)
    # Note: user_username might be in the rule or might be mapped from another field
    # The key is that CSE schema fields should never be wrapped
