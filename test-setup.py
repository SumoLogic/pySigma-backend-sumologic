#!/usr/bin/env python3
"""
Quick test script to verify the pySigma Sumo Logic backend installation.
Run this after installation to ensure everything is working correctly.
"""

import sys

def test_imports():
    """Test that all required modules can be imported."""
    print("🧪 Testing imports...")

    try:
        import sigma
        print("  ✅ pysigma")
    except ImportError as e:
        print(f"  ❌ pysigma: {e}")
        return False

    try:
        from sigma.backends.sumologic import SumoLogicCSERuleBackend, SumoLogicCSEBackend
        print("  ✅ sigma.backends.sumologic")
    except ImportError as e:
        print(f"  ❌ sigma.backends.sumologic: {e}")
        return False

    try:
        from sigma.pipelines.sumologic import sumologic_cse_pipeline
        print("  ✅ sigma.pipelines.sumologic")
    except ImportError as e:
        print(f"  ❌ sigma.pipelines.sumologic: {e}")
        return False

    try:
        import yaml
        print("  ✅ pyyaml")
    except ImportError as e:
        print(f"  ❌ pyyaml: {e}")
        return False

    try:
        import streamlit
        print("  ✅ streamlit (browser)")
    except ImportError as e:
        print(f"  ⚠️  streamlit: {e} (browser won't work, but converter will)")

    return True

def test_conversion():
    """Test a simple Sigma rule conversion."""
    print("\n🔄 Testing conversion...")

    try:
        from sigma.collection import SigmaCollection
        from sigma.backends.sumologic import SumoLogicCSERuleBackend
        from sigma.pipelines.sumologic import sumologic_cse_pipeline

        # Simple test rule
        test_rule = """
title: Test Rule
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: 'test'
    condition: selection
"""

        # Convert the rule with lower confidence threshold for testing
        rule = SigmaCollection.from_yaml(test_rule)
        pipeline = sumologic_cse_pipeline()
        backend = SumoLogicCSERuleBackend(
            processing_pipeline=pipeline,
            min_confidence=0.0  # Disable confidence checks for testing
        )
        result = backend.convert(rule)

        if result and len(result) > 0:
            print("  ✅ Conversion successful")
            # The result is a list of JSON strings for the CSE rule backend
            import json
            result_json = json.loads(result[0])

            # The rule is nested in a 'rules' array
            if 'rules' in result_json and len(result_json['rules']) > 0:
                rule = result_json['rules'][0]
                name = rule.get('name', 'N/A')
                expression = rule.get('expression', 'N/A')
                print(f"  📋 Rule name: {name}")
                if expression and len(expression) > 0:
                    print(f"  📋 Expression: {expression[:60]}...")
            return True
        else:
            print("  ❌ Conversion failed: empty result")
            return False

    except Exception as e:
        print(f"  ❌ Conversion failed: {e}")
        return False

def main():
    """Run all tests."""
    print("=" * 60)
    print("pySigma Sumo Logic Backend - Setup Test")
    print("=" * 60)
    print()

    imports_ok = test_imports()
    if not imports_ok:
        print("\n❌ Import tests failed. Please check your installation.")
        print("   Try: pip install -r requirements.txt")
        sys.exit(1)

    conversion_ok = test_conversion()
    if not conversion_ok:
        print("\n❌ Conversion tests failed. Check error messages above.")
        sys.exit(1)

    print("\n" + "=" * 60)
    print("✅ All tests passed! Setup is working correctly.")
    print("=" * 60)
    print()
    print("Next steps:")
    print("  1. Run the browser: streamlit run sigma_rule_browser.py")
    print("  2. Or use Docker: docker-compose up")
    print("  3. See SETUP.md for more information")
    print()

if __name__ == "__main__":
    main()
