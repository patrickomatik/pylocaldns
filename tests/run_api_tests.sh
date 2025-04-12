#!/bin/bash
# Run only the API tests
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

cd "$SCRIPT_DIR" || exit 1

echo "Running API tests..."
python3 test_api.py -v
echo "API tests completed with exit code: $?"
