#!/bin/bash
# Run the enhanced port display and HTMX integration tests

# Set up colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Running tests for enhanced port display and HTMX integration...${NC}"

# Run test_port_display_enhanced.py
echo -e "${YELLOW}Running enhanced port display tests...${NC}"
python3 test_port_display_enhanced.py
PORT_DISPLAY_RESULT=$?

# Run test_htmx_integration.py
echo -e "${YELLOW}Running HTMX integration tests...${NC}"
python3 test_htmx_integration.py
HTMX_RESULT=$?

# Check results
if [ $PORT_DISPLAY_RESULT -eq 0 ] && [ $HTMX_RESULT -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed. See output above for details.${NC}"
    exit 1
fi
