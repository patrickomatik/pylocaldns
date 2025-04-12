#!/bin/bash
#
# Run WebUI scan route tests
#

echo "Running WebUI scan route tests..."
cd "$(dirname "$0")/.."
python3 -m tests.test_webui_scan_routes

if [ $? -eq 0 ]; then
    echo -e "\033[0;32mAll tests passed!\033[0m"
else
    echo -e "\033[0;31mSome tests failed.\033[0m"
    exit 1
fi
