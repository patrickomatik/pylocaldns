#!/bin/bash
# Run the simple preallocation test
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

cd "$SCRIPT_DIR" || exit 1

echo "Running simplified preallocation test..."
python3 test_preallocation_simple.py -v
echo "Test completed with exit code: $?"
