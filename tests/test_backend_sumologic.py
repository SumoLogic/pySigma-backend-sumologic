import pytest
import json
from sigma.backends.sumologic import SumoLogicCSERuleBackend
from sigma.pipelines.sumologic import sumologic_cse_pipeline
from sigma.collection import SigmaCollection


@pytest.fixture
def sumologic_backend():
    return SumoLogicCSERuleBackend(processing_pipeline=sumologic_cse_pipeline())


def test_sumologic_and_expression(sumologic_backend: SumoLogicCSERuleBackend):
    """Test AND expression generates correct CSE query"""
    result = sumologic_backend.convert(
        SigmaCollection.from_yaml("""
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
        """)
    )

    # Parse JSON result
    json_result = json.loads(result[0])
    print(json_result)

    # Verify it's valid JSON with expected structure
    assert "name" in json_result
    assert "expression" in json_result
    assert "score" in json_result
    assert json_result["score"] == 3  # medium severity = score 3
    assert "prototype" in json_result
    assert json_result["prototype"] is True  # test status = prototype True
    assert "entity_selectors" in json_result

    # Verify query contains AND logic (uppercase 'AND' for CSE)
    assert "AND" in json_result["expression"]
    assert "commandLine" in json_result["expression"]
    assert "baseImage" in json_result["expression"]


def test_sumologic_or_expression(sumologic_backend: SumoLogicCSERuleBackend):
    """Test OR expression generates correct CSE query"""
    result = sumologic_backend.convert(
        SigmaCollection.from_yaml("""
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
        """)
    )

    json_result = json.loads(result[0])

    # Verify OR logic (can be 'OR' or 'in' operator for CSE)
    assert "OR" in json_result["expression"] or "in" in json_result["expression"]
    assert "commandLine" in json_result["expression"]
    assert json_result["score"] == 6  # high severity = score 6


def test_sumologic_and_or_expression(sumologic_backend: SumoLogicCSERuleBackend):
    """Test combined AND/OR expression"""
    result = sumologic_backend.convert(
        SigmaCollection.from_yaml("""
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
        """)
    )

    json_result = json.loads(result[0])

    # Should contain both AND and OR
    assert json_result["score"] == 8  # critical severity = score 8
    assert "commandLine" in json_result["expression"]
    assert "baseImage" in json_result["expression"]


def test_sumologic_or_and_expression(sumologic_backend: SumoLogicCSERuleBackend):
    """Test OR of AND expressions"""
    result = sumologic_backend.convert(
        SigmaCollection.from_yaml("""
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
        """)
    )

    json_result = json.loads(result[0])

    assert json_result["score"] == 1  # low severity = score 1
    assert "OR" in json_result["expression"]


def test_sumologic_in_expression(sumologic_backend: SumoLogicCSERuleBackend):
    """Test IN expression with multiple values"""
    result = sumologic_backend.convert(
        SigmaCollection.from_yaml("""
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
        """)
    )

    json_result = json.loads(result[0])

    # Should use 'in' operator or 'or' for multiple values
    assert "commandLine" in json_result["expression"]
    assert any(keyword in json_result["expression"] for keyword in ["in", "or"])


def test_sumologic_regex_query(sumologic_backend: SumoLogicCSERuleBackend):
    """Test regex pattern matching"""
    result = sumologic_backend.convert(
        SigmaCollection.from_yaml("""
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
        """)
    )

    json_result = json.loads(result[0])

    # Should contain 'matches' for regex in CSE
    assert "commandLine" in json_result["expression"]
    assert "baseImage" in json_result["expression"]


def test_sumologic_wildcard_query(sumologic_backend: SumoLogicCSERuleBackend):
    """Test wildcard matching"""
    result = sumologic_backend.convert(
        SigmaCollection.from_yaml("""
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
        """)
    )

    json_result = json.loads(result[0])

    # Should use 'matches' for wildcards
    assert "commandLine" in json_result["expression"]
    assert "matches" in json_result["expression"] or "*" in json_result["expression"]


def test_sumologic_json_structure(sumologic_backend: SumoLogicCSERuleBackend):
    """Test that output JSON has all required CSE fields"""
    result = sumologic_backend.convert(
        SigmaCollection.from_yaml("""
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
        """)
    )

    json_result = json.loads(result[0])

    # Verify all required CSE fields
    assert "name" in json_result
    assert "description" in json_result
    assert "enabled" in json_result
    assert "prototype" in json_result
    assert "expression" in json_result
    assert "score" in json_result
    assert "entity_selectors" in json_result

    # Verify values
    assert json_result["enabled"] is True
    assert json_result["prototype"] is True  # test status
    assert json_result["score"] == 6  # high

    # Verify MITRE ATT&CK tags in normalized format
    assert "tags" in json_result
    assert "_mitreAttackTechnique:T1059.001" in json_result["tags"]
    assert "_mitreAttackTactic:TA0002" in json_result["tags"]  # Execution


def test_sumologic_mitre_attack_mapping(sumologic_backend: SumoLogicCSERuleBackend):
    """Test MITRE ATT&CK technique and tactic extraction"""
    result = sumologic_backend.convert(
        SigmaCollection.from_yaml("""
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
        """)
    )

    json_result = json.loads(result[0])

    # Check tags in normalized format
    assert "tags" in json_result
    assert "_mitreAttackTechnique:T1003.001" in json_result["tags"]
    assert "_mitreAttackTechnique:T1055" in json_result["tags"]
    assert "_mitreAttackTactic:TA0006" in json_result["tags"]  # Credential Access
    assert "_mitreAttackTactic:TA0005" in json_result["tags"]  # Defense Evasion


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
        result = sumologic_backend.convert(
            SigmaCollection.from_yaml(f"""
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
            """)
        )

        json_result = json.loads(result[0])
        assert json_result["score"] == expected_score, (
            f"Severity {severity} should map to score {expected_score}"
        )


def test_sumologic_field_mapping_sysmon(sumologic_backend: SumoLogicCSERuleBackend):
    """Test field mapping for Sysmon process creation"""
    result = sumologic_backend.convert(
        SigmaCollection.from_yaml("""
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
        """)
    )

    json_result = json.loads(result[0])

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

    # Combine results
    result = result1 + result2

    # Should have 2 rules
    assert isinstance(result, list)
    assert len(result) == 2

    # Both should be valid JSON
    json_result_1 = json.loads(result[0])
    json_result_2 = json.loads(result[1])

    assert "expression" in json_result_1
    assert "expression" in json_result_2
    assert "test1.exe" in json_result_1["expression"]
    assert "test2.exe" in json_result_2["expression"]
