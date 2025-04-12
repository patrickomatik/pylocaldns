#!/bin/bash
# chmod +x util_scripts/run_vendor_tests.sh to make executable
# Run the MAC vendor database tests

cd "$(dirname "$0")/.."
python -m unittest tests/test_vendor_db.py
