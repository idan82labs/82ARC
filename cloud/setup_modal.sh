#!/bin/bash
# Quick setup script for Modal deployment of 82ARC

set -e

echo "=========================================="
echo "82ARC Modal Cloud Setup"
echo "=========================================="
echo ""

# Check if Modal is installed
if ! command -v modal &> /dev/null; then
    echo "Installing Modal CLI..."
    pip install modal
fi

# Check Modal authentication
if ! modal token check &> /dev/null 2>&1; then
    echo "Please authenticate with Modal:"
    modal setup
fi

echo ""
echo "Modal is ready!"
echo ""

# Check for API keys
if [ -z "$GROQ_API_KEY" ] && [ -z "$TOGETHER_API_KEY" ]; then
    echo "⚠️  No API keys found in environment."
    echo ""
    echo "You need at least one LLM provider API key:"
    echo "  - Groq (recommended): https://console.groq.com/keys"
    echo "  - Together AI: https://api.together.ai/settings/api-keys"
    echo ""
    echo "Enter your API keys (press Enter to skip):"
    echo ""

    read -p "GROQ_API_KEY: " GROQ_KEY
    read -p "TOGETHER_API_KEY: " TOGETHER_KEY

    if [ -n "$GROQ_KEY" ] || [ -n "$TOGETHER_KEY" ]; then
        echo ""
        echo "Creating Modal secret 'arc-api-keys'..."

        SECRET_CMD="modal secret create arc-api-keys"
        [ -n "$GROQ_KEY" ] && SECRET_CMD="$SECRET_CMD GROQ_API_KEY=$GROQ_KEY"
        [ -n "$TOGETHER_KEY" ] && SECRET_CMD="$SECRET_CMD TOGETHER_API_KEY=$TOGETHER_KEY"

        eval $SECRET_CMD
        echo "✓ Secret created!"
    else
        echo ""
        echo "No keys provided. You can set them later with:"
        echo "  modal secret create arc-api-keys GROQ_API_KEY=your_key"
    fi
else
    echo "Found API keys in environment."
    echo "Creating Modal secret from environment..."

    SECRET_CMD="modal secret create arc-api-keys"
    [ -n "$GROQ_API_KEY" ] && SECRET_CMD="$SECRET_CMD GROQ_API_KEY=$GROQ_API_KEY"
    [ -n "$TOGETHER_API_KEY" ] && SECRET_CMD="$SECRET_CMD TOGETHER_API_KEY=$TOGETHER_API_KEY"

    eval $SECRET_CMD 2>/dev/null || echo "Secret may already exist, continuing..."
fi

echo ""
echo "=========================================="
echo "Setup Complete!"
echo "=========================================="
echo ""
echo "Run these commands to start:"
echo ""
echo "  # Test with 10 tasks:"
echo "  modal run cloud/modal_app.py --num-tasks 10 --strategy fast"
echo ""
echo "  # Full ARC-AGI 2 benchmark (400 tasks):"
echo "  modal run cloud/modal_app.py --dataset evaluation --num-tasks 400 --parallel 20"
echo ""
echo "  # View results:"
echo "  modal volume ls arc-results"
echo ""
