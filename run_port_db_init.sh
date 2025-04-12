#!/bin/bash
# Initialize the port database and scan for open ports

# Set up colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Initializing port database...${NC}"

# Check if Python is available
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Python 3 is required but could not be found. Please install Python 3.${NC}"
    exit 1
fi

# Run the initialization script
python3 init_port_db.py $@

# Check result
if [ $? -eq 0 ]; then
    echo -e "${GREEN}Port database initialization complete!${NC}"
    echo -e "${YELLOW}You can now restart the server to see open ports on the dashboard.${NC}"
    exit 0
else
    echo -e "${RED}Failed to initialize port database. See error messages above.${NC}"
    exit 1
fi
