#!/bin/bash
# Run the simple preallocation test
echo "Running simplified preallocation test..."
cd /Users/patrick/active_home_dev/pylocaldns
python3 test_preallocation_simple.py -v
echo "Test completed with exit code: $?"
