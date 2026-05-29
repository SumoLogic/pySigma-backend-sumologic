# Setup Guide for pySigma Sumo Logic Backend

This guide provides multiple options for setting up and running the Sigma Rule Converter and Browser tools.

## Table of Contents

- [Quick Start with Docker (Recommended)](#quick-start-with-docker-recommended)
- [Local Installation](#local-installation)
- [Running the Tools](#running-the-tools)
- [Troubleshooting](#troubleshooting)

## Quick Start with Docker (Recommended)

The easiest way to run the tools is using Docker. This method requires no Python setup and works consistently across all platforms.

### Prerequisites

- [Docker](https://docs.docker.com/get-docker/) installed
- [Docker Compose](https://docs.docker.com/compose/install/) installed (included with Docker Desktop)
- Local copy of the [Sigma rules repository](https://github.com/SigmaHQ/sigma)

### Steps

1. **Clone this repository**:
   ```bash
   git clone https://github.com/SumoLogic/pySigma-backend-sumologic.git
   cd pySigma-backend-sumologic
   ```

2. **Clone the Sigma rules repository** (if you don't have it):
   ```bash
   cd ..
   git clone https://github.com/SigmaHQ/sigma.git
   cd pySigma-backend-sumologic
   ```

3. **Update docker-compose.yml**:
   Edit `docker-compose.yml` and update the volume path to point to your Sigma rules directory:
   ```yaml
   volumes:
     - /absolute/path/to/sigma:/sigma-rules:ro
   ```

4. **Build and run**:
   ```bash
   docker-compose up --build
   ```

5. **Access the browser**:
   Open your browser to [http://localhost:8501](http://localhost:8501)

### Docker Commands

- **Start the container**: `docker-compose up`
- **Start in background**: `docker-compose up -d`
- **Stop the container**: `docker-compose down`
- **Rebuild after changes**: `docker-compose up --build`
- **View logs**: `docker-compose logs -f`

## Local Installation

If you prefer to run the tools locally without Docker, follow these steps.

### Prerequisites

- Python 3.10 or higher
- pip or Poetry package manager
- Local copy of the [Sigma rules repository](https://github.com/SigmaHQ/sigma)

### Option 1: Using pip (Simple)

1. **Clone and enter the repository**:
   ```bash
   git clone https://github.com/SumoLogic/pySigma-backend-sumologic.git
   cd pySigma-backend-sumologic
   ```

2. **Create a virtual environment** (recommended):
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   pip install -e .
   ```

### Option 2: Using Poetry (Advanced)

1. **Install Poetry** (if not already installed):
   ```bash
   curl -sSL https://install.python-poetry.org | python3 -
   ```

2. **Clone and enter the repository**:
   ```bash
   git clone https://github.com/SumoLogic/pySigma-backend-sumologic.git
   cd pySigma-backend-sumologic
   ```

3. **Install dependencies**:
   ```bash
   poetry install
   ```

## Running the Tools

### 1. Sigma Rule Browser (Web Interface)

The browser provides a visual interface for selecting and converting rules.

#### With Docker:
```bash
docker-compose up
# Access at http://localhost:8501
```

#### With Local Installation:

First, update the Sigma repository path in `sigma_rule_browser.py`:
```python
SIGMA_REPO_PATH = Path("/path/to/your/sigma")
```

Then run:
```bash
# Using pip
streamlit run sigma_rule_browser.py

# Using Poetry
poetry run streamlit run sigma_rule_browser.py
```

Access the browser at [http://localhost:8501](http://localhost:8501)

### 2. Command Line Converter

For programmatic conversion or batch processing.

#### Basic Usage:

```python
from sigma.collection import SigmaCollection
from sigma.backends.sumologic import SumoLogicCSERuleBackend
from sigma.pipelines.sumologic import sumologic_cse_pipeline

# Load a Sigma rule
sigma_rule = SigmaCollection.from_yaml("""
title: Suspicious Process Creation
detection:
  selection:
    EventID: 1
    CommandLine|contains: 'powershell'
  condition: selection
""")

# Convert to Sumo Logic CSE format
backend = SumoLogicCSERuleBackend(processing_pipeline=sumologic_cse_pipeline())
result = backend.convert(sigma_rule)
print(result)
```

#### Batch Conversion Script:

```python
from pathlib import Path
from sigma.collection import SigmaCollection
from sigma.backends.sumologic import SumoLogicCSERuleBackend
from sigma.pipelines.sumologic import sumologic_cse_pipeline

sigma_dir = Path("/path/to/sigma/rules")
backend = SumoLogicCSERuleBackend(processing_pipeline=sumologic_cse_pipeline())

for rule_file in sigma_dir.rglob("*.yml"):
    try:
        rules = SigmaCollection.load_ruleset([rule_file])
        result = backend.convert(rules)
        print(f"✓ {rule_file.name}: {result}")
    except Exception as e:
        print(f"✗ {rule_file.name}: {e}")
```

## Running Tests

Verify that the installation is working correctly:

```bash
# Using pip
pytest

# Using Poetry
poetry run pytest

# With coverage
poetry run pytest --cov=sigma --cov-report=html
```

## Troubleshooting

### Docker Issues

**Problem**: "Cannot connect to the Docker daemon"
- **Solution**: Ensure Docker Desktop is running

**Problem**: "Port 8501 is already in use"
- **Solution**: Stop any other Streamlit apps or change the port in `docker-compose.yml`:
  ```yaml
  ports:
    - "8502:8501"  # Use port 8502 instead
  ```

**Problem**: "No rules found in the browser"
- **Solution**: Verify the volume path in `docker-compose.yml` points to the correct Sigma repository

### Local Installation Issues

**Problem**: "Module not found: sigma"
- **Solution**: Install the package in development mode: `pip install -e .`

**Problem**: "No rules found in the browser"
- **Solution**: Update `SIGMA_REPO_PATH` in `sigma_rule_browser.py` to point to your local Sigma repository

**Problem**: Poetry installation fails
- **Solution**: Try updating Poetry: `poetry self update`

### Conversion Errors

**Problem**: "Unsupported field mapping"
- **Solution**: Some Sigma rules use fields not yet mapped to Sumo Logic CSE. Check the field mappings in `sigma/pipelines/sumologic/sumologic.py`

**Problem**: "Invalid detection logic"
- **Solution**: Some complex Sigma detection patterns may not translate directly. Review the specific rule and consider simplifying the detection logic.

## Dependencies

The tools require the following main dependencies:

- **pysigma** (≥1.0.0): Core Sigma parsing and conversion library
- **pyyaml** (≥6.0): YAML parsing for Sigma rules
- **defusedxml** (≥0.7.1): Secure XML parsing
- **streamlit** (≥1.32.0): Web interface for the browser

These are automatically installed via `requirements.txt` or `pyproject.toml`.

## Additional Resources

- [Sigma Rule Specification](https://github.com/SigmaHQ/sigma-specification)
- [pySigma Documentation](https://github.com/SigmaHQ/pySigma)
- [Sumo Logic CSE Documentation](https://help.sumologic.com/docs/cse/)
- [Streamlit Documentation](https://docs.streamlit.io/)

## Getting Help

If you encounter issues:

1. Check this troubleshooting section
2. Review the [RULE_BROWSER.md](RULE_BROWSER.md) for browser-specific help
3. Open an issue on the [GitHub repository](https://github.com/SumoLogic/pySigma-backend-sumologic/issues)

## Development

To modify the conversion logic or add new features:

1. Make changes to the code
2. Run tests: `pytest`
3. Test with the browser: `streamlit run sigma_rule_browser.py`
4. Submit a pull request

For Docker development with live code updates, uncomment the volume mounts in `docker-compose.yml`:
```yaml
volumes:
  - /path/to/sigma:/sigma-rules:ro
  - ./sigma:/app/sigma
  - ./sigma_rule_browser.py:/app/sigma_rule_browser.py
```

This will mount your local code into the container for faster iteration.
