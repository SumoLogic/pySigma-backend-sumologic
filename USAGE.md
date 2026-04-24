# Usage Guide

## Installation

### From PyPI (when published)
```bash
pip install pysigma-backend-sumologic
```

### From Source
```bash
git clone https://github.com/SumoLogic/pySigma-backend-sumologic
cd pySigma-backend-sumologic
pip install .
```

### Development Installation
```bash
git clone https://github.com/SumoLogic/pySigma-backend-sumologic
cd pySigma-backend-sumologic
poetry install
```

## Using with sigma-cli

### Basic Conversion

Convert a single Sigma rule to CSE query format:
```bash
sigma convert -t sumo_logic_cse -p sumologic_cse rule.yml
```

Convert to CSE Rule JSON format (with metadata):
```bash
sigma convert -t sumo_logic_cse_rule -p sumologic_cse rule.yml
```

### Batch Conversion

Convert all rules in a directory:
```bash
sigma convert -t sumo_logic_cse_rule -p sumologic_cse rules/*.yml -o output.json
```

### Backend Options

Set minimum confidence threshold:
```bash
sigma convert -t sumo_logic_cse -p sumologic_cse -O min_confidence=0.6 rule.yml
```

Use custom CSE schema file:
```bash
sigma convert -t sumo_logic_cse -p sumologic_cse -O schema_path=/path/to/schema.json rule.yml
```

## Using Programmatically

### Basic Usage

```python
from sigma.collection import SigmaCollection
from sigma.backends.sumologic import SumoLogicCSERuleBackend
from sigma.pipelines.sumologic import sumologic_cse_pipeline

# Load Sigma rules
rules = SigmaCollection.from_yaml("""
title: Suspicious PowerShell Download
id: 12345678-1234-1234-1234-123456789012
status: test
logsource:
    product: windows
    service: powershell
detection:
    selection:
        CommandLine|contains:
            - 'Net.WebClient'
            - 'DownloadFile'
    condition: selection
""")

# Create backend with pipeline
backend = SumoLogicCSERuleBackend(
    processing_pipeline=sumologic_cse_pipeline()
)

# Convert rules
result = backend.convert(rules)

# Result is a list with one JSON string
print(result[0])
```

### With Custom Confidence Threshold

```python
backend = SumoLogicCSERuleBackend(
    processing_pipeline=sumologic_cse_pipeline(),
    min_confidence=0.6  # Lower threshold
)
```

### Using Plugin Discovery

```python
from sigma.plugins import InstalledSigmaPlugins
from sigma.collection import SigmaCollection

# Discover installed backends and pipelines
plugins = InstalledSigmaPlugins.autodiscover()

# Get backend and pipeline
backend_class = plugins.backends['sumo_logic_cse_rule']
pipeline_fn = plugins.pipelines['sumologic_cse']

# Create backend
backend = backend_class(processing_pipeline=pipeline_fn())

# Convert
rules = SigmaCollection.load_ruleset(['rules/'])
result = backend.convert(rules)
```

### Handling Conversion Errors

```python
from sigma.exceptions import SigmaTransformationError

backend = SumoLogicCSERuleBackend(
    processing_pipeline=sumologic_cse_pipeline(),
    collect_errors=True  # Collect errors instead of raising
)

result = backend.convert(rules)

# Check for errors
if backend.errors:
    print(f"Conversion errors: {len(backend.errors)}")
    for rule, error in backend.errors:
        print(f"Rule {rule.id}: {error}")
```

## Output Formats

### Default Format

Query-only output (CSE query expression):
```
metadata_vendor="Microsoft" AND metadata_product="Windows" AND 
metadata_deviceEventId="PowerShell-4104" AND 
commandLine matches /.*Net\.WebClient.*/ AND 
commandLine matches /.*DownloadFile.*/
```

### CSE Rule JSON Format

Complete CSE rule with metadata:
```json
{
  "rules": [
    {
      "content_type": "RULE",
      "enabled": true,
      "is_prototype": false,
      "name": "Suspicious PowerShell Download",
      "name_expression": "Suspicious PowerShell Download",
      "rule_source": "user",
      "summary_expression": "",
      "tags": ["_mitreAttackTactic:TA0002"],
      "category": "Execution",
      "pattern_type": "templated_match",
      "stream": "record",
      "score_mapping": {
        "default": 6,
        "type": "constant",
        "field": null,
        "mapping": []
      },
      "description_expression": "Detects suspicious PowerShell download activity",
      "expression": "metadata_vendor=\"Microsoft\" AND metadata_product=\"Windows\" AND metadata_deviceEventId=\"PowerShell-4104\" AND commandLine matches /.*Net\\.WebClient.*/ AND commandLine matches /.*DownloadFile.*/",
      "entity_selectors": [
        {
          "expression": "device_hostname",
          "entity_type": "_hostname"
        },
        {
          "expression": "user_username",
          "entity_type": "_username"
        }
      ]
    }
  ]
}
```

## Features

### Automatic Vendor/Product Metadata

The backend automatically adds vendor/product filters based on the Sigma rule's logsource:

**Input:**
```yaml
logsource:
    product: aws
    service: cloudtrail
```

**Output:**
```
metadata_vendor="Amazon AWS" AND metadata_product="CloudTrail" AND ...
```

### Windows EventID Transformation

EventIDs are automatically prefixed with the Windows channel:

**Input:**
```yaml
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
```

**Output:**
```
metadata_deviceEventId="Security-4624"
```

### Vendor-Specific Field Wrapping

Fields not in the CSE schema are automatically wrapped in `fields[]` syntax:

**Input:**
```yaml
detection:
    selection:
        auditType.category: 'Auditing'
```

**Output:**
```
fields['auditType.category']="Auditing"
```

### Schema-Aware Numeric Quoting

Numeric values are quoted when the field is a string type in the CSE schema:

**Input:**
```yaml
detection:
    selection:
        EventID: 4624
```

**Output:**
```
metadata_deviceEventId="Security-4624"  # Quoted because metadata_deviceEventId is a string
```

### Confidence Scoring

Field mappings are validated with confidence scores. Low-confidence mappings are rejected by default:

```bash
# Rule with eventName → action mapping (high confidence: 0.95)
sigma convert -t sumo_logic_cse -p sumologic_cse aws_rule.yml  # ✅ Succeeds

# Rule with unknown field mapping (low confidence: 0.3)
sigma convert -t sumo_logic_cse -p sumologic_cse unknown_rule.yml  # ❌ Fails

# Override threshold for testing
sigma convert -t sumo_logic_cse -p sumologic_cse -O min_confidence=0.2 unknown_rule.yml  # ✅ Succeeds
```

## Troubleshooting

### Conversion Blocked: Low Confidence Score

**Error:**
```
Conversion blocked: Confidence score 0.592 below threshold 0.700

Low-confidence field mappings:
  - customField → unknownField: 0.592
    Factors: semantic=0.30, data_pres=0.80, type=0.70, specificity=0.60
```

**Solution:**
- Review the field mapping in the Sigma rule
- Check if the field exists in the CSE schema
- Consider rewriting the rule to use CSE schema fields
- For testing: lower the threshold with `-O min_confidence=0.5`

### Field Not Supported

**Error:**
```
Conversion failed: Field 'Data' is not supported.

Reason: CSE parses Windows Event Log Data into structured EventData.* fields
```

**Solution:**
- Rewrite the rule to use specific EventData field names
- Example: `Data|contains: 'TargetUserName'` → `EventData.TargetUserName`

### Missing Vendor/Product Metadata

If a rule doesn't have vendor/product filters, check the logsource:

```yaml
logsource:
    product: windows  # Should map to Microsoft/Windows
    service: security
```

Supported products: Windows, AWS, Azure, GCP, Linux, Cisco, Palo Alto Networks, etc.

## Examples

See `examples/` directory (if available) for sample Sigma rules and their CSE conversions.

## Support

- **Issues:** https://github.com/SumoLogic/pySigma-backend-sumologic/issues
- **Documentation:** See README.md and inline documentation
- **Sigma Rules:** https://github.com/SigmaHQ/sigma
