# Sigma Rule Browser & Converter

A Streamlit-based web interface for browsing Sigma rules and converting them to Sumo Logic CSE format.

## Features

- 📁 Browse Sigma rules from multiple directories (rules, rules-dfir, rules-compliance, etc.)
- 🔍 Search and filter rules by name or path
- 📋 Preview rule content (title, description, detection logic, tags, etc.)
- ✅ Select multiple rules for batch conversion
- 🔄 Convert rules to Sumo Logic CSE format
- 📊 View conversion results with detailed output
- 📥 Download individual or bulk CSE rules as JSON

## Installation

1. Install Streamlit (if not already installed):

```bash
# Using pip
pip install streamlit pyyaml

# Or using poetry (recommended for this project)
poetry add streamlit pyyaml --group dev
```

2. Ensure you have the pySigma Sumo Logic backend installed:

```bash
poetry install
```

## Usage

1. Make sure the Sigma repository path is correct in `sigma_rule_browser.py`:

```python
SIGMA_REPO_PATH = Path("./sigma-rules")  # Or set SIGMA_REPO_PATH environment variable
```

2. Run the Streamlit app:

```bash
# Using poetry
poetry run streamlit run sigma_rule_browser.py

# Or if streamlit is in your PATH
streamlit run sigma_rule_browser.py
```

3. The app will open in your browser at `http://localhost:8501`

## How to Use

### Browsing Rules

1. **Select Directory**: Use the sidebar dropdown to choose which rule directory to browse (rules, rules-dfir, etc.)
2. **Search**: Use the search box to filter rules by name or path
3. **View Count**: See how many rules match your search

### Selecting Rules

1. Use checkboxes in the sidebar to select individual rules
2. Click "Select All" to select all visible rules
3. Click "Clear All" to deselect everything
4. Go to the "Rule Preview" tab to see detailed information about selected rules

### Converting Rules

1. Select one or more rules from the sidebar
2. Go to the "Convert" tab
3. Click "🚀 Convert to Sumo Logic CSE" button
4. Wait for the conversion to complete

### Viewing Results

1. Go to the "Results" tab after conversion
2. See summary metrics (total, successful, errors)
3. Download all rules as JSON or individual rules
4. Expand each rule to see:
   - Converted CSE expression
   - Full rule metadata (name, score, enabled, prototype, etc.)
   - Full JSON output

## Tips for Iterating on Conversion

- **Test with a single rule first**: Select one rule, convert it, and verify the output
- **Use search to find specific types**: Search for "process_creation" or "windows" to test specific categories
- **Compare before/after**: Use the Preview tab to see the original Sigma rule and the Results tab to see the CSE output
- **Download and import**: Download the JSON and import it into CSE to test in a real environment
- **Batch testing**: Select multiple similar rules to test consistency across related detections

## Troubleshooting

### No rules found
- Verify `SIGMA_REPO_PATH` points to the correct Sigma repository
- Check that the repository has directories named `rules`, `rules-dfir`, etc.

### Conversion errors
- Check the "Results" tab for specific error messages
- Some Sigma rules may use features not yet supported by the backend
- Review the backend code in `sigma/backends/sumologic/sumologic.py` to understand conversion logic

### Performance issues
- The app limits display to 50 rules at a time for performance
- Use the search feature to narrow down results
- For large batch conversions, consider running the backend programmatically instead

## Development

To modify the conversion logic:

1. Edit `sigma/backends/sumologic/sumologic.py`
2. Restart the Streamlit app to see changes
3. Use the browser to quickly test different rules

The browser will automatically reload when you save changes to the Python file (Streamlit's hot reload feature).
