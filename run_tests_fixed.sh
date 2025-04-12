#!/bin/bash
# Run the IP preallocation tests
echo "Running IP Preallocation Tests with fixed implementation..."
cd /Users/patrick/active_home_dev/pylocaldns
python3 test_ip_preallocation.py -v 
echo "Run complete with exit code: $?"
