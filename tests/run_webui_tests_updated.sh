#!/bin/bash
# Run the Web UI tests to validate all routes and functionality
# Updated for the refactored webui module

# Change to the script directory
cd "$(dirname "$0")"

# Set up Python path
export PYTHONPATH="../:$PYTHONPATH"

ERRORS=0

# Print banner
echo "=========================================================="
echo "Running Web UI Tests with Refactored WebUI Module"
echo "=========================================================="

echo "Running Web UI route tests..."
python3 test_webui_routes_updated.py
if [ $? -ne 0 ]; then
    echo "❌ Web UI route tests failed!"
    ERRORS=$((ERRORS+1))
else
    echo "✅ Web UI route tests passed!"
fi

echo -e "\nRunning port scan display tests..."
python3 test_port_scan_display_updated.py
if [ $? -ne 0 ]; then
    echo "❌ Port scan display tests failed!"
    ERRORS=$((ERRORS+1))
else
    echo "✅ Port scan display tests passed!"
fi

# Check the overall result
if [ $ERRORS -eq 0 ]; then
    echo -e "\n✅ All Web UI tests passed!"
    exit 0
else
    echo -e "\n❌ Some Web UI tests failed! ($ERRORS test suites had errors)"
    exit 1
fi
