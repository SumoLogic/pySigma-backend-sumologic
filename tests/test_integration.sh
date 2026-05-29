#!/bin/sh
# Simple integration test - validates package installation and conversion
set -e

echo "Integration Test: Package Installation & Conversion"
echo "===================================================="

# Get absolute path to project root (parent of tests/)
PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_ROOT"

# Clean and build package
echo "Building package..."
rm -rf dist/
poetry build

# Create temp venv
TEMP_DIR=$(mktemp -d)
cd "$TEMP_DIR"
python3 -m venv venv
. venv/bin/activate

# Install package
echo "Installing package..."
pip install "$PROJECT_ROOT/dist"/*.whl > /dev/null

# Copy test rule
cp "$PROJECT_ROOT/tests/test_sigma_rule.yml" .

# Test import and conversion
echo "Testing conversion..."
python -c "
import json
from sigma.collection import SigmaCollection
from sigma.backends.sumologic import SumoLogicCSERuleBackend
from sigma.pipelines.sumologic import sumologic_cse_pipeline

# Load and convert rule
with open('test_sigma_rule.yml') as f:
    rule = SigmaCollection.from_yaml(f.read())

backend = SumoLogicCSERuleBackend(processing_pipeline=sumologic_cse_pipeline(), min_confidence=0.0)
result = backend.convert(rule)
json_result = json.loads(result[0])
print(json_result)

if result and len(result) > 0:
    print('✅ Integration test passed - rule converted successfully')
else:
    print('❌ Conversion failed')
    exit(1)
"

# Cleanup
deactivate
cd "$PROJECT_ROOT"
rm -rf "$TEMP_DIR"
rm -rf dist/
echo "Cleanup complete"
