#!/bin/bash
# Run all tests
echo "Running all tests..."

# Get the directory of this script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

cd "$SCRIPT_DIR" || exit 1

# Run preallocation tests
echo -e "\n==== Running IP Preallocation Tests ===="
python3 test_ip_preallocation.py -v

# Run simple preallocation test
echo -e "\n==== Running Simple Preallocation Test ===="
python3 test_preallocation_simple.py -v

# Run API tests
echo -e "\n==== Running API Tests ===="
python3 test_api.py -v

echo -e "\n==== All tests completed ===="
