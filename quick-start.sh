#!/bin/bash

# Quick Start Script for pySigma Sumo Logic Backend
# This script helps you get started quickly with the Sigma Rule Browser

set -e

echo "🚀 pySigma Sumo Logic Backend - Quick Start"
echo "==========================================="
echo ""

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first:"
    echo "   https://docs.docker.com/get-docker/"
    exit 1
fi

# Check if Docker is running
if ! docker info &> /dev/null; then
    echo "❌ Docker is not running. Please start Docker Desktop."
    exit 1
fi

echo "✅ Docker is installed and running"
echo ""

# Check if Sigma repo path is configured
if [ ! -f docker-compose.yml ]; then
    echo "❌ docker-compose.yml not found in current directory"
    exit 1
fi

# Prompt for Sigma repository path
echo "📁 Please enter the path to your Sigma rules repository:"
echo "   (e.g., /Users/username/sigma or ~/Documents/sigma)"
read -p "Path: " SIGMA_PATH

# Expand tilde if present
SIGMA_PATH="${SIGMA_PATH/#\~/$HOME}"

# Check if the path exists
if [ ! -d "$SIGMA_PATH" ]; then
    echo "❌ Directory not found: $SIGMA_PATH"
    echo ""
    echo "Would you like to clone the Sigma repository? (y/n)"
    read -p "Clone: " CLONE_SIGMA

    if [ "$CLONE_SIGMA" = "y" ] || [ "$CLONE_SIGMA" = "Y" ]; then
        # Get parent directory
        PARENT_DIR=$(dirname "$SIGMA_PATH")
        mkdir -p "$PARENT_DIR"
        echo "📥 Cloning Sigma repository..."
        git clone https://github.com/SigmaHQ/sigma.git "$SIGMA_PATH"
        echo "✅ Sigma repository cloned successfully"
    else
        exit 1
    fi
fi

echo "✅ Sigma repository found at: $SIGMA_PATH"
echo ""

# Update docker-compose.yml with the path
echo "📝 Updating docker-compose.yml with Sigma repository path..."

# Create a temporary file with the updated path
if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS
    sed -i '' "s|/path/to/sigma|$SIGMA_PATH|g" docker-compose.yml
else
    # Linux
    sed -i "s|/path/to/sigma|$SIGMA_PATH|g" docker-compose.yml
fi

echo "✅ docker-compose.yml updated"
echo ""

# Build and start the container
echo "🔨 Building Docker container..."
docker-compose build

echo ""
echo "🚀 Starting Sigma Rule Browser..."
docker-compose up -d

echo ""
echo "✅ Setup complete!"
echo ""
echo "🌐 Open your browser to: http://localhost:8501"
echo ""
echo "Useful commands:"
echo "  - View logs:    docker-compose logs -f"
echo "  - Stop:         docker-compose down"
echo "  - Restart:      docker-compose restart"
echo ""
