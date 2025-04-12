#!/bin/bash
# Run all tests for PyLocalDNS Flask routes
# 
# This script runs all tests for the Flask web interface

# Set colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

# Ensure we're in the virtual environment
if [ -z "$VIRTUAL_ENV" ]; then
  if [ -d ".venv" ]; then
    echo -e "${YELLOW}Activating virtual environment...${NC}"
    source .venv/bin/activate
  else
    echo -e "${RED}No virtual environment found. You may need to run install_flask.sh first.${NC}"
    echo -e "${YELLOW}Attempting to continue without virtual environment...${NC}"
  fi
fi

# Check if Flask is installed
if ! python -c "import flask" &> /dev/null; then
  echo -e "${RED}Flask is not installed. Please run install_flask.sh first.${NC}"
  exit 1
fi

# Create the tests directory if it doesn't exist
if [ ! -d "tests" ]; then
  mkdir -p tests
  echo -e "${YELLOW}Created tests directory${NC}"
fi

# Run each test file
echo -e "${GREEN}Running Flask routes tests...${NC}"
python -m unittest tests/test_flask_routes.py

echo -e "${GREEN}Running HTMX integration tests...${NC}"
python -m unittest tests/test_htmx_integration.py

echo -e "${GREEN}Running port scanning tests...${NC}"
python -m unittest tests/test_port_scanning.py

# Run all tests with coverage if available
if python -c "import coverage" &> /dev/null; then
  echo -e "${GREEN}Running all tests with coverage report...${NC}"
  coverage run -m unittest discover -s tests
  coverage report -m
else
  echo -e "${YELLOW}Coverage not installed. Install with 'pip install coverage' for coverage reports.${NC}"
  echo -e "${GREEN}Running all tests without coverage...${NC}"
  python -m unittest discover -s tests
fi

echo -e "${GREEN}All tests completed!${NC}"
