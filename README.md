# pySigma Sumo Logic Backend

![Status](https://img.shields.io/badge/Status-testing-yellow)

## Overview

This is the Sumo Logic backend for pySigma. It provides the package `sigma.backends.sumologic` with backend classes for converting Sigma rules into Sumo Logic Cloud SIEM (CSIEM) detection rules.

The backend includes:
- **`SumoLogicCSEBackend`**: Converts Sigma rules to Sumo Logic Cloud SIEM queries
- **`SumoLogicCSERuleBackend`**: Converts Sigma rules to complete CSIEM rule JSON format
- **`sumologic_cse_pipeline`**: Processing pipeline with field mappings for common log sources

## Supported Log Sources

The backend includes field mappings for the following log sources:

- **Windows**: Process creation (Sysmon), registry events, file events
- **Network**: Connection events, DNS queries, proxy logs
- **Cloud**: AWS CloudTrail events

Field mappings align with Sumo Logic Cloud SIEM's normalized schema.

## Output Formats

The backend supports two output formats:

- **`default`**: Plain CSIEM query syntax (for manual rule creation)
- **`cse_rule`**: Complete JSON rule format for Cloud SIEM API import (includes metadata, severity, MITRE ATT&CK mapping)

### Example Output

**Input (Sigma rule):**
```yaml
title: Suspicious PowerShell Execution
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: 'powershell'
    condition: selection
```

**Output (CSIEM rule format):**
```json
{
  "rules": [
    {
      "content_type": "RULE",
      "sigma_uid": "1cf98dc2-fcb0-47c9-8aea-654c9284d1ae",
      "enabled": true,
      "is_prototype": true,
      "name": "Disk Image Creation Via Hdiutil - MacOS",
      "name_expression": "Disk Image Creation Via Hdiutil - MacOS",
      "rule_source": "user",
      "summary_expression": "",
      "pattern_type": "templated_match",
      "stream": "record",
      "description_expression": "Detects the execution of hdiutil to create a disk image...",
      "expression": "baseImage matches /.*\\/hdiutil/ AND commandLine matches /.*create.*/",
      "entity_selectors": [
        {"entity_type": "_hostname", "expression": "device_hostname"},
        {"entity_type": "_username", "expression": "user_username"},
        {"entity_type": "_process", "expression": "baseImage"}
      ],
      "score_mapping": {"default": 3, "type": "constant", "field": null, "mapping": []},
      "tags": ["_mitreAttackTactic:TA0010"],
      "category": "Exfiltration",
      "mapping_confidence": {"overall_score": 0.7, "...": "..."}
    }
  ]
}
```

## Installation

### Quick Start (Docker - Recommended for Testing)

For the easiest setup with the included Sigma Rule Browser:

```bash
./quick-start.sh
```

This will set up a complete environment with Docker. See **[SETUP.md](SETUP.md)** for detailed instructions.

### From PyPI

```bash
pip install pysigma-backend-sumologic
```

### From Source (Development)

```bash
git clone https://github.com/SumoLogic/pySigma-backend-sumologic
cd pySigma-backend-sumologic
pip install .
```

For complete setup instructions including Docker, Poetry, and the Sigma Rule Browser, see **[SETUP.md](SETUP.md)**.

## Usage

### Sigma Rule Browser (Web Interface)

A Streamlit-based browser for exploring and converting Sigma rules:

```bash
# With Docker (easiest)
docker-compose up

# Or locally
streamlit run sigma_rule_browser.py
```

Visit `http://localhost:8501` to browse, preview, and convert rules. See **[RULE_BROWSER.md](RULE_BROWSER.md)** for details.

### With sigma-cli

```bash
# Convert to CSE query
sigma convert -t sumo_logic_cse -p sumologic_cse rule.yml

# Convert to full CSE rule JSON
sigma convert -t sumo_logic_cse_rule -p sumologic_cse rule.yml
```

### As Python Library

```python
from sigma.collection import SigmaCollection
from sigma.backends.sumologic import SumoLogicCSERuleBackend
from sigma.pipelines.sumologic import sumologic_cse_pipeline

# Load Sigma rule
with open('rule.yml') as f:
    rule = SigmaCollection.from_yaml(f.read())

# Convert to CSE rule
backend = SumoLogicCSERuleBackend(processing_pipeline=sumologic_cse_pipeline())
result = backend.convert(rule)

print(result[0])  # CSE rule JSON
```

## Field Mappings

The `sumologic_cse_pipeline` provides automatic field mapping from Sigma standard fields to Sumo Logic CSE fields:

| Sigma Field | CSE Field |
|-------------|-----------|
| `CommandLine` | `commandLine` |
| `Image` | `baseImage` |
| `ParentImage` | `parentBaseImage` |
| `User` | `user_username` |
| `SourceIp` | `srcDevice_ip` |
| `DestinationIp` | `dstDevice_ip` |
| `SourcePort` | `srcPort` |
| `DestinationPort` | `dstPort` |
| `QueryName` | `dns_query` |

For a complete list of field mappings, see `sigma/pipelines/sumologic/sumologic.py`.

## Limitations

### General Limitations

- **Correlation rules**: Not yet supported (Sigma correlation features)
- **Regex modifiers**: Limited support for complex regex patterns
- **Custom fields**: Fields not in the standard mapping must be manually mapped

### Unsupported Fields

#### Data Field (Windows Event Logs)

The `Data` field in Windows Event Logs has **smart conversion** that automatically handles structured patterns but blocks arbitrary string matching.

**How It Works:**

✅ **Supported (automatically converted):**
- **Key=Value patterns** (PowerShell logs): `Data|contains: 'EngineVersion=2.'` → `EventData.EngineVersion|contains: '2.'`
- **Key:Value patterns** (MSSQL/App logs): `Data|contains: 'statement:DROP TABLE'` → `EventData.statement|contains: 'DROP TABLE'`

❌ **Not supported (conversion fails):**
- **Arbitrary strings**: `Data|contains: 'Net.WebClient'` - no field name to extract

**Reason:** CSE parses Windows Event Log Data XML into structured `EventData.*` fields. Arbitrary string matching requires knowing which field contains the string, which isn't possible from the Data field alone.

**Impact:** ~12 Sigma rules use arbitrary Data field patterns (primarily PowerShell Classic command detection rules).

**Examples:**

**Automatic Conversion (no changes needed):**
```yaml
# PowerShell downgrade attack detection
detection:
  selection:
    Data|contains: 'EngineVersion=2.'  # Automatically converted to EventData.EngineVersion
  condition: selection
```
↓ Converts to:
```
EventData.EngineVersion matches /.*2\..*/
```

**Manual Rewrite Required:**
```yaml
# Before (fails - arbitrary string)
detection:
  selection:
    Data|contains: 'Net.WebClient'
  condition: selection
```
↓ Rewrite to:
```yaml
# After (works - specific field)
detection:
  selection:
    EventData.ContextInfo|contains: 'Net.WebClient'
  condition: selection
```

**Common EventData field mappings:**
- `EventData.TargetUserName` → `user_username`
- `EventData.LogonType` → `logonType`
- `EventData.IpAddress` → `srcDevice_ip`
- `EventData.CommandLine` → `commandLine`
- `EventData.ContextInfo` → Raw PowerShell context (for command/script content)
- See CSE schema documentation for complete list

#### Keywords Field

Similarly, the `keywords` field (generic full-text search) is not supported as CSE requires structured field-based queries.

## Development

### Running Tests

```bash
# Install development dependencies
pip install -e .[dev]

# Run unit tests
pytest

# Run with coverage
pytest --cov=sigma --cov-report=term
```

### Integration Test

```bash
# Test package installation and conversion
./tests/test_integration.sh
```

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

See [PUBLISHING.md](PUBLISHING.md) for information on publishing releases.

## Maintainer

This backend is maintained by:

- **Sumo Logic** | [GitHub](https://github.com/SumoLogic) | [Website](https://www.sumologic.com)

## Resources

- [Sumo Logic Cloud SIEM Documentation](https://www.sumologic.com/help/docs/cse/)
- [Sigma Rule Specification](https://github.com/SigmaHQ/sigma-specification)
- [pySigma Documentation](https://github.com/SigmaHQ/pySigma)

## License

This project is licensed under the GNU Lesser General Public License v3.0 - see the [LICENSE](LICENSE) file for details.
