#!/bin/bash
# Run the Web UI tests to validate all routes and functionality

# Change to the script directory
cd "$(dirname "$0")"

# Set up Python path
export PYTHONPATH="../:$PYTHONPATH"

echo "Running Web UI route tests..."
python3 test_webui_routes.py

# Check the result
if [ $? -eq 0 ]; then
    echo "✅ All Web UI tests passed!"
    exit 0
else
    echo "❌ Web UI tests failed!"
    exit 1
fi
