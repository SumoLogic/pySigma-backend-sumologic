FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the package code
COPY sigma/ ./sigma/
COPY pyproject.toml .
COPY README.md .

# Install the package in development mode
RUN pip install -e .

# Copy the browser application
COPY sigma_rule_browser.py .
COPY .streamlit/ ./.streamlit/

# Create a directory for sigma rules (will be mounted as volume)
RUN mkdir -p /sigma-rules

# Expose Streamlit default port
EXPOSE 8501

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8501/_stcore/health || exit 1

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV SIGMA_REPO_PATH=/sigma-rules

# Run the browser
CMD ["streamlit", "run", "sigma_rule_browser.py", "--server.address", "0.0.0.0"]
