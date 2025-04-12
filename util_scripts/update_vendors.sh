#!/bin/bash
# Update the MAC vendor database
# Make executable with: chmod +x update_vendors.sh

# Change to the script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Starting MAC vendor database update...${NC}"

# Try Wireshark source first (it's more reliable)
echo -e "${YELLOW}Trying Wireshark source...${NC}"
python ./update_mac_vendors.py --source wireshark --force

# If that fails, try IEEE source
if [ $? -ne 0 ]; then
    echo -e "${YELLOW}Wireshark source failed, trying IEEE...${NC}"
    python ./update_mac_vendors.py --source ieee --force
fi

# Check if the update was successful
if [ -f ../mac_vendors.db ]; then
    SIZE=$(stat -f %z ../mac_vendors.db 2>/dev/null || stat -c %s ../mac_vendors.db 2>/dev/null)
    if [ $SIZE -gt 100000 ]; then
        echo -e "${GREEN}MAC vendor database updated successfully!${NC}"
        echo -e "Database size: $(du -h ../mac_vendors.db | cut -f1)"
        echo -e "Last update: $(date)"
        exit 0
    else
        echo -e "${RED}WARNING: Database file exists but appears to be too small (${SIZE} bytes).${NC}"
        echo -e "${RED}Update may have failed.${NC}"
        exit 1
    fi
else
    echo -e "${RED}ERROR: Database file not found after update.${NC}"
    exit 1
fi
