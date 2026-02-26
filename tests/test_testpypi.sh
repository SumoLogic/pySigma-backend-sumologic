#!/bin/bash
# Test script for TestPyPI published version
# This tests the package published to TestPyPI, not local code
set -e

echo "=========================================="
echo "Testing pySigma-backend-sumologic from TestPyPI"
echo "=========================================="
echo ""

# Check if version argument provided
if [ -z "$1" ]; then
    echo "Usage: $0 <version>"
    echo "Example: $0 0.1.0"
    echo ""
    echo "This will test version 0.1.0 from TestPyPI"
    exit 1
fi

VERSION="$1"

echo "Version to test: $VERSION"
echo ""

# Create temp directory and venv
TEMP_DIR=$(mktemp -d)
cd "$TEMP_DIR"

echo "📁 Created test environment: $TEMP_DIR"
echo ""

# Cleanup function
cleanup() {
    echo ""
    echo "🧹 Cleaning up..."
    
    # Deactivate venv if active
    if [ -n "$VIRTUAL_ENV" ]; then
        deactivate 2>/dev/null || true
    fi
    
    # Remove temp directory
    if [ -n "$TEMP_DIR" ] && [ -d "$TEMP_DIR" ]; then
        cd /
        rm -rf "$TEMP_DIR"
        echo "   Removed temp directory: $TEMP_DIR"
    fi
    
    # Remove any test files in current directory (if script was run from project root)
    if [ -f "test_rule.yml" ]; then
        rm -f test_rule.yml
        echo "   Removed test_rule.yml"
    fi
    
    if [ -f "output.json" ]; then
        rm -f output.json
        echo "   Removed output.json"
    fi
    
    # Remove test-env if it exists
    if [ -d "test-env" ]; then
        rm -rf test-env
        echo "   Removed test-env"
    fi
    
    echo "✅ Cleanup complete"
}
trap cleanup EXIT

# Create virtual environment
echo "🐍 Creating virtual environment..."
python3 -m venv venv
source venv/bin/activate
echo "✅ Virtual environment created"
echo ""

# Install from TestPyPI
echo "📦 Installing pysigma-backend-sumologic==$VERSION from TestPyPI..."
echo "   (Dependencies will be installed from production PyPI)"
pip install --index-url https://test.pypi.org/simple/ \
            --extra-index-url https://pypi.org/simple/ \
            pysigma-backend-sumologic==$VERSION

if [ $? -ne 0 ]; then
    echo "❌ FAIL: Installation failed"
    exit 1
fi
echo "✅ Package installed successfully"
echo ""

# Test 1: Import backend classes
echo "🧪 Test 1: Import backend classes..."
python -c "
from sigma.backends.sumologic import SumoLogicCSEBackend, SumoLogicCSERuleBackend
from sigma.pipelines.sumologic import sumologic_cse_pipeline
print('✅ All classes imported successfully')
print('   - SumoLogicCSEBackend')
print('   - SumoLogicCSERuleBackend')
print('   - sumologic_cse_pipeline')
"

if [ $? -ne 0 ]; then
    echo "❌ FAIL: Import test failed"
    exit 1
fi
echo ""

# Test 2: Check sigma-cli integration
echo "🧪 Test 2: Check sigma-cli availability..."
pip install sigma-cli > /dev/null 2>&1
echo "✅ sigma-cli installed"
echo ""

# Test 3: Create and convert a test rule
echo "🧪 Test 3: Convert a test Sigma rule..."
cat > test_rule.yml << 'EOF'
title: Test Rule for Package Validation
id: 12345678-1234-1234-1234-123456789abc
status: test
description: Simple test rule to validate backend functionality
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains: 'test.exe'
  condition: selection
level: medium
EOF

echo "   Created test rule: test_rule.yml"
echo ""

echo "   Converting with backend..."
sigma convert -t sumologic-cse-rule -p sumologic_cse test_rule.yml > output.json

if [ $? -ne 0 ]; then
    echo "❌ FAIL: Conversion failed"
    exit 1
fi

echo "✅ Conversion successful"
echo ""

# Test 4: Validate conversion output
echo "🧪 Test 4: Validate conversion output..."
python -c "
import json
import sys

with open('output.json') as f:
    data = json.load(f)
    
# Check required fields in CSE rule
required_fields = ['name', 'expression', 'enabled']
missing_fields = [field for field in required_fields if field not in data]

if missing_fields:
    print(f'❌ FAIL: Missing required fields: {missing_fields}')
    sys.exit(1)

print('✅ Output validation passed')
print(f'   Rule name: {data[\"name\"]}')
print(f'   Expression: {data[\"expression\"][:60]}...')
print(f'   Enabled: {data[\"enabled\"]}')
"

if [ $? -ne 0 ]; then
    exit 1
fi
echo ""

# Success summary
echo "=========================================="
echo "✅ ALL TESTS PASSED!"
echo "=========================================="
echo ""
echo "Summary:"
echo "  ✅ Package installed from TestPyPI"
echo "  ✅ Backend classes imported successfully"
echo "  ✅ sigma-cli integration works"
echo "  ✅ Rule conversion successful"
echo "  ✅ Output validation passed"
echo ""
echo "Version $VERSION on TestPyPI is ready for production!"
echo ""

# Note: cleanup happens automatically via trap on exit
