#!/bin/bash

# Script to run DNS toggle feature tests
# This script runs the test_dns_toggle.py tests within the virtual environment

# Change to the project root directory
cd "$(dirname "$0")/.."

# Set up colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Running DNS Toggle Feature Tests...${NC}"
echo "----------------------------------------"

# Activate the virtual environment
if [ -d ".venv" ]; then
    echo "Activating virtual environment..."
    source .venv/bin/activate
else
    echo -e "${RED}Virtual environment not found at .venv${NC}"
    echo "Please ensure your virtual environment is set up and dependencies are installed."
    exit 1
fi

# Set PYTHONPATH to include the project root
export PYTHONPATH="$PYTHONPATH:$(pwd)"

# Run the tests
python -m unittest tests/test_dns_toggle.py

# Check the test result
TEST_RESULT=$?

# Deactivate the virtual environment
deactivate

# Return the test result
if [ $TEST_RESULT -eq 0 ]; then
    echo -e "${GREEN}All DNS Toggle Feature tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed. Please check the output above.${NC}"
    exit 1
fi
