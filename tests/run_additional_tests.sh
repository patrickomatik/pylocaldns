#!/bin/bash
# Run additional tests for PyLocalDNS Flask routes
# 
# This script runs the additional tests for the Flask web interface

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

# Run the additional test file
echo -e "${GREEN}Running additional Flask routes tests...${NC}"
python -m unittest tests/test_flask_routes_additional.py

# Run with coverage if available
if python -c "import coverage" &> /dev/null; then
  echo -e "${GREEN}Running with coverage report...${NC}"
  coverage run -m unittest tests/test_flask_routes_additional.py
  coverage report -m
fi

echo -e "${GREEN}Additional tests completed!${NC}"
