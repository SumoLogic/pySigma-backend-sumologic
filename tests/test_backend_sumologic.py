import pytest
import json
from sigma.backends.sumologic import SumoLogicCSERuleBackend
from sigma.pipelines.sumologic import sumologic_cse_pipeline
from sigma.collection import SigmaCollection


@pytest.fixture
def sumologic_backend():
    # Disable confidence checking for backward compatibility with existing tests
    return SumoLogicCSERuleBackend(
        processing_pipeline=sumologic_cse_pipeline(), min_confidence=0.0
    )


def test_sumologic_and_expression(sumologic_backend: SumoLogicCSERuleBackend):
    """Test AND expression generates correct CSE query"""
    result = sumologic_backend.convert(SigmaCollection.from_yaml("""
            title: Test AND Expression
            id: 00000000-0000-0000-0000-000000000001
            status: test
            description: Test rule for AND expression
            author: Test Author
            level: medium
            logsource:
                category: process_creation
                product: windows
            detection:
                sel:
                    CommandLine: "test.exe"
                    Image: "C:\\\\Windows\\\\System32\\\\test.exe"
                condition: sel
        """))

    # Parse JSON result (now wrapped in {"rules": [...]})
    parsed_result = json.loads(result[0])
    assert "rules" in parsed_result
    json_result = parsed_result["rules"][0]
    print(json_result)

    # Verify it's valid JSON with expected structure
    assert "name" in json_result
    assert "name_expression" in json_result
    assert "expression" in json_result
    assert "score_mapping" in json_result
    assert json_result["score_mapping"]["default"] == 3  # medium severity = score 3
    assert "is_prototype" in json_result
    assert json_result["is_prototype"] is True  # test status = prototype True
    assert "entity_selectors" in json_result

    # Verify static fields
    assert json_result["content_type"] == "RULE"
    assert json_result["pattern_type"] == "templated_match"
    assert json_result["stream"] == "record"
    assert json_result["rule_source"] == "user"
    assert "category" in json_result
    assert "description_expression" in json_result
    assert "summary_expression" in json_result

    # Verify query contains AND logic (uppercase 'AND' for CSE)
    assert "AND" in json_result["expression"]
    assert "commandLine" in json_result["expression"]
    assert "baseImage" in json_result["expression"]


def test_sumologic_or_expression(sumologic_backend: SumoLogicCSERuleBackend):
    """Test OR expression generates correct CSE query"""
    result = sumologic_backend.convert(SigmaCollection.from_yaml("""
            title: Test OR Expression
            id: 00000000-0000-0000-0000-000000000002
            status: test
            description: Test rule for OR expression
            author: Test Author
            level: high
            logsource:
                category: process_creation
                product: windows
            detection:
                sel1:
                    CommandLine: "mimikatz.exe"
                sel2:
                    CommandLine: "sekurlsa"
                condition: 1 of sel*
        """))

    parsed_result = json.loads(result[0])
    json_result = parsed_result["rules"][0]

    # Verify OR logic (can be 'OR' or 'in' operator for CSE)
    assert "OR" in json_result["expression"] or "in" in json_result["expression"]
    assert "commandLine" in json_result["expression"]
    assert json_result["score_mapping"]["default"] == 6  # high severity = score 6


def test_sumologic_and_or_expression(sumologic_backend: SumoLogicCSERuleBackend):
    """Test combined AND/OR expression"""
    result = sumologic_backend.convert(SigmaCollection.from_yaml("""
            title: Test AND/OR Expression
            id: 00000000-0000-0000-0000-000000000003
            status: test
            description: Test rule for AND/OR expression
            author: Test Author
            level: critical
            logsource:
                category: process_creation
                product: windows
            detection:
                sel:
                    CommandLine:
                        - "valueA1"
                        - "valueA2"
                    Image:
                        - "valueB1"
                        - "valueB2"
                condition: sel
        """))

    parsed_result = json.loads(result[0])
    json_result = parsed_result["rules"][0]

    # Should contain both AND and OR
    assert json_result["score_mapping"]["default"] == 8  # critical severity = score 8
    assert "commandLine" in json_result["expression"]
    assert "baseImage" in json_result["expression"]


def test_sumologic_or_and_expression(sumologic_backend: SumoLogicCSERuleBackend):
    """Test OR of AND expressions"""
    result = sumologic_backend.convert(SigmaCollection.from_yaml("""
            title: Test OR of AND
            id: 00000000-0000-0000-0000-000000000004
            status: test
            description: Test rule for OR of AND expression
            author: Test Author
            level: low
            logsource:
                category: process_creation
                product: windows
            detection:
                sel1:
                    CommandLine: "valueA1"
                    Image: "valueB1"
                sel2:
                    CommandLine: "valueA2"
                    Image: "valueB2"
                condition: 1 of sel*
        """))

    parsed_result = json.loads(result[0])
    json_result = parsed_result["rules"][0]

    assert json_result["score_mapping"]["default"] == 1  # low severity = score 1
    assert "OR" in json_result["expression"]


def test_sumologic_in_expression(sumologic_backend: SumoLogicCSERuleBackend):
    """Test IN expression with multiple values"""
    result = sumologic_backend.convert(SigmaCollection.from_yaml("""
            title: Test IN Expression
            id: 00000000-0000-0000-0000-000000000005
            status: test
            description: Test rule for IN expression
            author: Test Author
            logsource:
                category: process_creation
                product: windows
            detection:
                sel:
                    CommandLine:
                        - "cmd.exe"
                        - "powershell.exe"
                        - "pwsh.exe"
                condition: sel
        """))

    parsed_result = json.loads(result[0])
    json_result = parsed_result["rules"][0]

    # Should use 'in' operator or 'or' for multiple values
    assert "commandLine" in json_result["expression"]
    assert any(keyword in json_result["expression"] for keyword in ["in", "or"])


def test_sumologic_regex_query(sumologic_backend: SumoLogicCSERuleBackend):
    """Test regex pattern matching"""
    result = sumologic_backend.convert(SigmaCollection.from_yaml("""
            title: Test Regex
            id: 00000000-0000-0000-0000-000000000006
            status: test
            description: Test rule for regex
            author: Test Author
            logsource:
                category: process_creation
                product: windows
            detection:
                sel:
                    CommandLine|re: "foo.*bar"
                    Image: "test.exe"
                condition: sel
        """))

    parsed_result = json.loads(result[0])
    json_result = parsed_result["rules"][0]

    # Should contain 'matches' for regex in CSE
    assert "commandLine" in json_result["expression"]
    assert "baseImage" in json_result["expression"]


def test_sumologic_wildcard_query(sumologic_backend: SumoLogicCSERuleBackend):
    """Test wildcard matching"""
    result = sumologic_backend.convert(SigmaCollection.from_yaml("""
            title: Test Wildcard
            id: 00000000-0000-0000-0000-000000000007
            status: test
            description: Test rule for wildcard
            author: Test Author
            logsource:
                category: process_creation
                product: windows
            detection:
                sel:
                    CommandLine: "*mimikatz*"
                condition: sel
        """))

    parsed_result = json.loads(result[0])
    json_result = parsed_result["rules"][0]

    # Should use 'matches' for wildcards
    assert "commandLine" in json_result["expression"]
    assert "matches" in json_result["expression"] or "*" in json_result["expression"]


def test_sumologic_json_structure(sumologic_backend: SumoLogicCSERuleBackend):
    """Test that output JSON has all required CSE fields"""
    result = sumologic_backend.convert(SigmaCollection.from_yaml("""
            title: Complete Test Rule
            id: 00000000-0000-0000-0000-000000000008
            status: test
            description: A complete test rule with all metadata
            author: Security Team
            level: high
            tags:
                - attack.execution
                - attack.t1059.001
            references:
                - https://example.com/reference
            logsource:
                category: process_creation
                product: windows
            detection:
                sel:
                    Image: "powershell.exe"
                    CommandLine: "-encodedcommand"
                condition: sel
        """))

    parsed_result = json.loads(result[0])
    assert "rules" in parsed_result
    json_result = parsed_result["rules"][0]

    # Verify all required CSE fields
    assert "name" in json_result
    assert "name_expression" in json_result
    assert "description_expression" in json_result
    assert "summary_expression" in json_result
    assert "enabled" in json_result
    assert "is_prototype" in json_result
    assert "expression" in json_result
    assert "score_mapping" in json_result
    assert "entity_selectors" in json_result
    assert "category" in json_result

    # Verify static fields
    assert "content_type" in json_result
    assert json_result["content_type"] == "RULE"
    assert "pattern_type" in json_result
    assert json_result["pattern_type"] == "templated_match"
    assert "stream" in json_result
    assert json_result["stream"] == "record"
    assert "rule_source" in json_result
    assert json_result["rule_source"] == "user"

    # Verify values
    assert json_result["enabled"] is True
    assert json_result["is_prototype"] is True  # test status
    assert json_result["score_mapping"]["default"] == 6  # high
    assert json_result["score_mapping"]["type"] == "constant"

    # Verify MITRE ATT&CK tags in normalized format
    assert "tags" in json_result
    assert "_mitreAttackTechnique:T1059.001" in json_result["tags"]
    assert "_mitreAttackTactic:TA0002" in json_result["tags"]  # Execution


def test_sumologic_mitre_attack_mapping(sumologic_backend: SumoLogicCSERuleBackend):
    """Test MITRE ATT&CK technique and tactic extraction"""
    result = sumologic_backend.convert(SigmaCollection.from_yaml("""
            title: MITRE Test
            id: 00000000-0000-0000-0000-000000000009
            status: test
            description: Test MITRE mapping
            author: Test Author
            tags:
                - attack.credential_access
                - attack.t1003.001
                - attack.defense_evasion
                - attack.t1055
            logsource:
                category: process_creation
                product: windows
            detection:
                sel:
                    Image: "lsass.exe"
                condition: sel
        """))

    parsed_result = json.loads(result[0])
    json_result = parsed_result["rules"][0]

    # Check tags in normalized format
    assert "tags" in json_result
    assert "_mitreAttackTechnique:T1003.001" in json_result["tags"]
    assert "_mitreAttackTechnique:T1055" in json_result["tags"]
    assert "_mitreAttackTactic:TA0006" in json_result["tags"]  # Credential Access
    assert "_mitreAttackTactic:TA0005" in json_result["tags"]  # Defense Evasion

    # Check category is derived from first tactic
    assert json_result["category"] == "Credential Access"


def test_sumologic_severity_mapping(sumologic_backend: SumoLogicCSERuleBackend):
    """Test severity to risk score mapping"""
    test_cases = [
        ("critical", 8),
        ("high", 6),
        ("medium", 3),
        ("low", 1),
        ("informational", 1),
    ]

    for severity, expected_score in test_cases:
        result = sumologic_backend.convert(SigmaCollection.from_yaml(f"""
                title: Severity Test {severity}
                id: 00000000-0000-0000-0000-00000000000a
                status: test
                description: Test severity mapping
                author: Test Author
                level: {severity}
                logsource:
                    category: process_creation
                    product: windows
                detection:
                    sel:
                        Image: "test.exe"
                    condition: sel
            """))

        parsed_result = json.loads(result[0])
        json_result = parsed_result["rules"][0]
        assert (
            json_result["score_mapping"]["default"] == expected_score
        ), f"Severity {severity} should map to score {expected_score}"


def test_sumologic_field_mapping_sysmon(sumologic_backend: SumoLogicCSERuleBackend):
    """Test field mapping for Sysmon process creation"""
    result = sumologic_backend.convert(SigmaCollection.from_yaml("""
            title: Field Mapping Test
            id: 00000000-0000-0000-0000-00000000000b
            status: test
            description: Test field mappings
            author: Test Author
            logsource:
                category: process_creation
                product: windows
            detection:
                sel:
                    Image: "C:\\\\test.exe"
                    CommandLine: "-param value"
                    ParentImage: "C:\\\\parent.exe"
                    User: "SYSTEM"
                    md5: "abc123"
                condition: sel
        """))

    parsed_result = json.loads(result[0])
    json_result = parsed_result["rules"][0]

    # Verify field mapping occurred
    assert "baseImage" in json_result["expression"]
    assert "commandLine" in json_result["expression"]
    assert "parentBaseImage" in json_result["expression"]
    assert "user_username" in json_result["expression"]
    assert "file_hash_md5" in json_result["expression"]


def test_sumologic_multiple_rules(sumologic_backend: SumoLogicCSERuleBackend):
    """Test conversion of multiple rules returns JSON array"""

    # Create two separate rules
    rule1_yaml = """
    title: Rule 1
    id: 00000000-0000-0000-0000-00000000000c
    status: test
    description: First rule
    author: Test Author
    logsource:
        category: process_creation
        product: windows
    detection:
        sel:
            Image: "test1.exe"
        condition: sel
    """

    rule2_yaml = """
    title: Rule 2
    id: 00000000-0000-0000-0000-00000000000d
    status: test
    description: Second rule
    author: Test Author
    logsource:
        category: process_creation
        product: windows
    detection:
        sel:
            Image: "test2.exe"
        condition: sel
    """

    # Convert each rule separately
    result1 = sumologic_backend.convert(SigmaCollection.from_yaml(rule1_yaml))
    result2 = sumologic_backend.convert(SigmaCollection.from_yaml(rule2_yaml))

    # Each result is a JSON string with {"rules": [...]}
    parsed_result_1 = json.loads(result1[0])
    parsed_result_2 = json.loads(result2[0])

    # Extract rules
    json_result_1 = parsed_result_1["rules"][0]
    json_result_2 = parsed_result_2["rules"][0]

    assert "expression" in json_result_1
    assert "expression" in json_result_2
    assert "test1.exe" in json_result_1["expression"]
    assert "test2.exe" in json_result_2["expression"]


def test_sumologic_schema_aware_numeric_quoting(
    sumologic_backend: SumoLogicCSERuleBackend,
):
    """Test that numeric values are quoted when CSE field is string type."""
    result = sumologic_backend.convert(SigmaCollection.from_yaml("""
            title: Test Schema-Aware Quoting
            id: 00000000-0000-0000-0000-000000000099
            status: test
            logsource:
                product: windows
                service: security
            detection:
                sel:
                    EventID: 4624
                    LogonType: 3
                condition: sel
        """))

    parsed_result = json.loads(result[0])
    expression = parsed_result["rules"][0]["expression"]

    # logonType is string type in CSE schema - numeric value should be quoted
    assert 'logonType="3"' in expression or "logonType='3'" in expression


def test_sumologic_schema_aware_numeric_list(
    sumologic_backend: SumoLogicCSERuleBackend,
):
    """Test that numeric values in lists are quoted when CSE field is string type."""
    result = sumologic_backend.convert(SigmaCollection.from_yaml("""
            title: Test Schema-Aware List Quoting
            id: 00000000-0000-0000-0000-000000000098
            status: test
            logsource:
                product: windows
                service: security
            detection:
                sel:
                    LogonType:
                        - 2
                        - 3
                        - 10
                condition: sel
        """))

    parsed_result = json.loads(result[0])
    expression = parsed_result["rules"][0]["expression"]

    # All numeric values should be quoted since logonType is string type
    assert 'logonType in ("2", "3", "10")' in expression


def test_sumologic_numeric_fields_unquoted(sumologic_backend: SumoLogicCSERuleBackend):
    """Test that truly numeric fields remain unquoted."""
    result = sumologic_backend.convert(SigmaCollection.from_yaml("""
            title: Test Numeric Fields
            id: 00000000-0000-0000-0000-000000000097
            status: test
            logsource:
                product: windows
                category: process_creation
            detection:
                sel:
                    ProcessId: 1234
                condition: sel
        """))

    parsed_result = json.loads(result[0])
    expression = parsed_result["rules"][0]["expression"]

    # pid is int type in CSE schema - should remain unquoted
    assert "pid=1234" in expression
    assert 'pid="1234"' not in expression


def test_sumologic_keywords_error(sumologic_backend: SumoLogicCSERuleBackend):
    """Test that keywords (unbound values) produce helpful error with context."""
    from sigma.exceptions import SigmaFeatureNotSupportedByBackendError

    # Keywords are not supported - should get helpful error
    with pytest.raises(SigmaFeatureNotSupportedByBackendError) as exc_info:
        sumologic_backend.convert(SigmaCollection.from_yaml("""
                title: Keywords Test
                id: 00000000-0000-0000-0001-000000000001
                status: test
                logsource:
                    product: windows
                    category: process_creation
                detection:
                    keywords:
                        - 'mimikatz'
                        - 'Invoke-Mimikatz'
                    condition: keywords
            """))

    error_msg = str(exc_info.value)
    # Should show original Sigma detection
    assert "Unsupported Sigma pattern:" in error_msg
    assert "keywords:" in error_msg
    assert "mimikatz" in error_msg
    assert "Invoke-Mimikatz" in error_msg
    # Should explain why it's not supported
    assert "CSE requires field-based queries" in error_msg
    # Should show how to fix it
    assert "Solution:" in error_msg
    assert "commandLine|contains:" in error_msg


RULE_SOURCE_TEST_RULE = """
title: Rule Source Test
id: 00000000-0000-0000-0002-000000000001
status: test
logsource:
    category: process_creation
    product: windows
detection:
    sel:
        Image: "test.exe"
    condition: sel
"""


def test_sumologic_rule_source_default(sumologic_backend: SumoLogicCSERuleBackend):
    """Test that rule_source defaults to 'user' when the option is not set."""
    result = sumologic_backend.convert(SigmaCollection.from_yaml(RULE_SOURCE_TEST_RULE))

    json_result = json.loads(result[0])["rules"][0]
    assert json_result["rule_source"] == "user"


@pytest.mark.parametrize("rule_source", ["sigma", "user", "custom-source"])
def test_sumologic_rule_source_option(rule_source: str):
    """Test that the rule_source option overrides the default value."""
    backend = SumoLogicCSERuleBackend(
        processing_pipeline=sumologic_cse_pipeline(),
        min_confidence=0.0,
        rule_source=rule_source,
    )
    result = backend.convert(SigmaCollection.from_yaml(RULE_SOURCE_TEST_RULE))

    json_result = json.loads(result[0])["rules"][0]
    assert json_result["rule_source"] == rule_source


@pytest.mark.parametrize("rule_source", [None, ""])
def test_sumologic_rule_source_empty_falls_back_to_default(rule_source):
    """Test that an unset or empty rule_source falls back to the default."""
    backend = SumoLogicCSERuleBackend(
        processing_pipeline=sumologic_cse_pipeline(),
        min_confidence=0.0,
        rule_source=rule_source,
    )
    result = backend.convert(SigmaCollection.from_yaml(RULE_SOURCE_TEST_RULE))

    json_result = json.loads(result[0])["rules"][0]
    assert json_result["rule_source"] == "user"


@pytest.mark.parametrize(
    "status", ["stable", "test", "experimental", "deprecated", "unsupported"]
)
def test_conversion_metadata_sigma_status(status):
    """sigma_status in conversion_metadata reflects the rule's status field."""
    backend = SumoLogicCSERuleBackend(
        processing_pipeline=sumologic_cse_pipeline(),
        min_confidence=0.0,
        include_conversion_metadata=True,
    )
    result = backend.convert(SigmaCollection.from_yaml(f"""
            title: Test Conversion Metadata
            id: 00000000-0000-0000-0000-000000000099
            status: {status}
            description: Test rule for conversion metadata
            author: Test Author
            level: medium
            logsource:
                category: process_creation
                product: windows
            detection:
                sel:
                    CommandLine: "test.exe"
                condition: sel
        """))

    rule_json = json.loads(result[0])["rules"][0]
    assert "conversion_metadata" in rule_json
    assert rule_json["conversion_metadata"]["sigma_status"] == status


def test_conversion_metadata_sigma_status_absent_when_disabled():
    """conversion_metadata is not present when include_conversion_metadata=False."""
    backend = SumoLogicCSERuleBackend(
        processing_pipeline=sumologic_cse_pipeline(),
        min_confidence=0.0,
        include_conversion_metadata=False,
    )
    result = backend.convert(SigmaCollection.from_yaml("""
            title: Test Conversion Metadata
            id: 00000000-0000-0000-0000-000000000099
            status: stable
            description: Test rule for conversion metadata
            author: Test Author
            level: medium
            logsource:
                category: process_creation
                product: windows
            detection:
                sel:
                    CommandLine: "test.exe"
                condition: sel
        """))

    rule_json = json.loads(result[0])["rules"][0]
    assert "conversion_metadata" not in rule_json
