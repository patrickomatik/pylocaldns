#!/bin/bash
# Run the IP preallocation tests
echo "Running IP Preallocation Tests..."
python3 test_ip_preallocation.py -v
exit $?
