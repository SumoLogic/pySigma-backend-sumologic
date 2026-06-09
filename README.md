# pySigma Sumo Logic Backend

![Status](https://img.shields.io/badge/Status-released-green)
[![PyPI](https://img.shields.io/pypi/v/pysigma-backend-sumologic)](https://pypi.org/project/pysigma-backend-sumologic/)
![Python](https://img.shields.io/pypi/pyversions/pysigma-backend-sumologic)
![License](https://img.shields.io/github/license/SumoLogic/pySigma-backend-sumologic)
![Coverage](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/jc-sumo/6d3725acf17134aee954b139dd60d316/raw/pysigma-backend-sumologic-coverage.json)

## Overview

A [pySigma](https://github.com/SigmaHQ/pySigma) backend that converts [Sigma](https://github.com/SigmaHQ/sigma) detection rules into Sumo Logic Cloud SIEM rule JSON, ready for import via the CSE API. Includes field mappings for 70+ log sources, automatic entity selector assignment, MITRE ATT&CK tag mapping, and confidence scoring.

## Quick Start

```bash
pip install sigma-cli pysigma-backend-sumologic
sigma convert -t sumologic_cse_rule -p sumologic_cse rule.yml
```

## Supported Log Sources

### Full Field Mapping

These log sources have Sigma fields automatically renamed to CSE normalized schema fields:

| Log Source | Key Field Mappings |
|------------|-------------------|
| Process creation | CommandLine→commandLine, Image→baseImage, ParentImage→parentBaseImage, User→user_username |
| Network connection | SourceIp→srcDevice_ip, DestinationIp→dstDevice_ip, SourcePort→srcPort, DestinationPort→dstPort |
| DNS query | QueryName→dns_query, QueryResults→dns_reply |
| File events | TargetFilename→file_path, md5→file_hash_md5, SHA256→file_hash_sha256 |
| Registry events | TargetObject→changeTarget |
| Image load | ImageLoaded→baseImage |
| Proxy / web | c-uri→http_url, cs-method→http_method, sc-status→http_response_statusCode, cs-bytes→bytesOut, sc-bytes→bytesIn |
| Firewall | src_ip→srcDevice_ip, dst_ip→dstDevice_ip, action→action |
| Windows authentication | LogonType→logonType, TargetUserName→user_username, IpAddress→srcDevice_ip |
| Windows Sysmon | Inherits process/network/file/registry mappings + EventID→metadata_deviceEventId |
| Windows PowerShell | ScriptBlockText→commandLine |
| AWS CloudTrail | eventName→action, sourceIPAddress→srcDevice_ip, userIdentity.arn→user_username |
| Azure Activity Logs | operationName→action, callerIpAddress→srcDevice_ip |
| Office 365 | Operation→action, ClientIP→srcDevice_ip |

### Metadata-Only (Vendor/Product Tagging)

These log sources get `metadata_vendor` and `metadata_product` injected into the query. Fields pass through as `fields['FieldName']` in CSE syntax:

- **Windows** (30+ services): powershell-classic, taskscheduler, WMI, DNS-server, windefend, driver-framework, etc.
- **AWS**: S3, GuardDuty, VPC, WAF, Route53, Config, EKS, ELB, CloudWatch, SecurityHub, etc.
- **Azure**: Sign-in Logs, Audit Logs, Firewall, Risk Detection, PIM, etc.
- **GCP**: Audit, GCE, GCS, BigQuery, Security Center
- **Google Workspace**: Admin, Login
- **Cisco**: ASA, Firepower, ISE, Umbrella, Meraki, Duo, AnyConnect, etc.
- **Palo Alto Networks**: Threat, Traffic, Cortex, GlobalProtect, Prisma Cloud, etc.
- **Fortinet**: FortiGate, FortiClient
- **Other**: Okta, OneLogin, GitHub, Kubernetes, Check Point, Zeek, Exchange

## Output Format

Produces complete CSE rule JSON ready for the Rules API:

```json
{
  "rules": [
    {
      "name": "Suspicious PowerShell Execution",
      "expression": "commandLine matches /.*powershell -enc.*/",
      "entity_selectors": [
        {"entity_type": "_hostname", "expression": "device_hostname"},
        {"entity_type": "_username", "expression": "user_username"},
        {"entity_type": "_process", "expression": "baseImage"}
      ],
      "score_mapping": {"default": 6, "type": "constant"},
      "tags": ["_mitreAttackTactic:TA0002", "_mitreAttackTechnique:T1059"],
      "category": "Execution",
      "enabled": true,
      "is_prototype": true,
      "mapping_confidence": {"overall_score": 0.691, "...": "..."}
    }
  ]
}
```

## How It Works

**Field Mapping** — The `sumologic_cse` pipeline renames Sigma standard fields to CSE normalized schema fields based on the rule's log source category.

**Confidence Scoring** — Each field mapping receives a confidence score (0–1). If the lowest score falls below the threshold (default: 0.25), conversion is blocked with a message showing exactly which fields failed and what threshold to use.

**Entity Selectors** — Automatically assigned based on log source category:
- Process rules → hostname + username + process
- Network/firewall rules → hostname + IP
- DNS rules → hostname + domain
- Authentication rules → hostname + IP + username
- File rules → hostname + file path

**MITRE ATT&CK** — Tags from Sigma rules are mapped to CSE format (`attack.execution` → `_mitreAttackTactic:TA0002`).

**Severity** — Sigma levels map to CSE scores: critical=8, high=6, medium=3, low=1, informational=1.

## Unmapped Field Handling

| Scenario | Behavior | Confidence |
|----------|----------|------------|
| Field mapped by pipeline | Renamed to CSE schema field | 0.85–1.0 |
| Vendor-specific rule, unmapped field | Passes through as `fields['FieldName']` | 0.8 |
| Generic rule (no product), unmapped field | Blocked with warning | 0.0 |
| `Data` field with `Key=Value` pattern | Auto-converted to `EventData.Key` | Normal |
| `Data` field with arbitrary string | Blocked with helpful error | N/A |

## Installation

### From PyPI

```bash
pip install pysigma-backend-sumologic
```

### From Source

```bash
git clone https://github.com/SumoLogic/pySigma-backend-sumologic
cd pySigma-backend-sumologic
pip install .
```

## Usage

### With sigma-cli

```bash
# Convert to CSE rule JSON
sigma convert -t sumologic_cse_rule -p sumologic_cse rule.yml

# Convert a directory of rules
sigma convert -t sumologic_cse_rule -p sumologic_cse ./rules/windows/

# Lower confidence threshold for more permissive conversion
sigma convert -t sumologic_cse_rule -p sumologic_cse -O min_confidence=0.0 rule.yml
```

### As Python Library

```python
from sigma.collection import SigmaCollection
from sigma.backends.sumologic import SumoLogicCSERuleBackend
from sigma.pipelines.sumologic import sumologic_cse_pipeline

pipeline = sumologic_cse_pipeline()
backend = SumoLogicCSERuleBackend(processing_pipeline=pipeline)

rule = SigmaCollection.from_yaml(open('rule.yml').read())
result = backend.convert(rule)
print(result[0])  # CSE rule JSON string
```

## Configuration Options

Pass via `-O key=value` with sigma-cli or as constructor kwargs in Python:

| Option | Default | Description |
|--------|---------|-------------|
| `min_confidence` | `0.25` | Minimum confidence score to allow conversion (0.0 disables threshold) |
| `include_confidence_metadata` | `true` | Include `mapping_confidence` object in output |
| `fail_on_unmapped_logsource` | `false` | Error if rule's log source has no vendor/product mapping |

## Limitations

- **Correlation rules** — Not supported (Sigma correlation features)
- **Data field arbitrary strings** — `Data|contains: 'Net.WebClient'` cannot be converted (~12 Sigma rules affected). Structured patterns like `Data|contains: 'EngineVersion=2.'` are handled automatically.
- **Keywords field** — Not supported (CSE requires structured field-based queries)
- **Complex regex** — Limited support for advanced regex modifiers

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run with coverage
pytest --cov=sigma --cov-report=term
```

CI also runs `mypy sigma/`, so local changes should pass type checks before opening a PR.

## Resources

- [Sumo Logic Cloud SIEM Documentation](https://www.sumologic.com/help/docs/cse/)
- [Sigma Rule Specification](https://github.com/SigmaHQ/sigma-specification)
- [pySigma Documentation](https://github.com/SigmaHQ/pySigma)
- [sigma-cli](https://github.com/SigmaHQ/sigma-cli)

## License

LGPL-3.0 — see [LICENSE](LICENSE).
