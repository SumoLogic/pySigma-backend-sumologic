# pySigma Sumo Logic Backend

![Status](https://img.shields.io/badge/Status-testing-yellow)

## Overview

This is the Sumo Logic backend for pySigma. It provides the package `sigma.backends.sumologic` with backend classes for converting Sigma rules into Sumo Logic Cloud SIEM (CSE) detection rules.

The backend includes:
- **`SumoLogicCSEBackend`**: Converts Sigma rules to Sumo Logic CSE queries
- **`SumoLogicCSERuleBackend`**: Converts Sigma rules to complete CSE rule JSON format
- **`sumologic_cse_pipeline`**: Processing pipeline with field mappings for common log sources

## Supported Log Sources

The backend includes field mappings for the following log sources:

- **Windows**: Process creation (Sysmon), registry events, file events
- **Network**: Connection events, DNS queries, proxy logs
- **Cloud**: AWS CloudTrail events

Field mappings align with Sumo Logic CSE's schema and [Anchor schema](https://github.com/SumoLogic/anchor-schema) where applicable.

## Output Formats

The backend supports two output formats:

- **`default`**: Plain CSE query syntax (for manual rule creation)
- **`cse_rule`**: Complete JSON rule format for CSE API import (includes metadata, severity, MITRE ATT&CK mapping)

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

**Output (CSE rule format):**
```json
{
  "name": "Suspicious PowerShell Execution",
  "expression": "commandLine matches \"*powershell*\"",
  "enabled": true,
  "severity": "medium",
  "tags": ["windows", "process_creation"]
}
```

## Installation

### From PyPI (Recommended)

```bash
pip install pysigma-backend-sumologic
```

### From Source (Development)

```bash
git clone https://github.com/SumoLogic/pySigma-backend-sumologic
cd pySigma-backend-sumologic
pip install .
```

## Usage

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

- **Correlation rules**: Not yet supported (Sigma correlation features)
- **Regex modifiers**: Limited support for complex regex patterns
- **Custom fields**: Fields not in the standard mapping must be manually mapped

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

- [Sumo Logic Cloud SIEM Documentation](https://help.sumologic.com/Cloud_SIEM)
- [Sigma Rule Specification](https://github.com/SigmaHQ/sigma-specification)
- [pySigma Documentation](https://github.com/SigmaHQ/pySigma)

## License

This project is licensed under the GNU Lesser General Public License v3.0 - see the [LICENSE](LICENSE) file for details.
