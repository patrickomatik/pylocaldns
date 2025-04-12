#!/bin/bash
# Update DNS entry using curl
# This script is a simpler alternative to the Python client, using only curl
# It's useful for systems where Python might not be available

# Configuration
SERVER_URL="http://localhost:8081"
TOKEN=""

# Function to print usage
function print_usage() {
    echo "Usage: $0 [options]"
    echo "Options:"
    echo "  --server URL       API server URL (default: http://localhost:8081)"
    echo "  --hostname NAME    Hostname to set (default: current hostname)"
    echo "  --ip ADDRESS       IP address (default: current IP)"
    echo "  --mac ADDRESS      MAC address (default: not included)"
    echo "  --token TOKEN      Authentication token (if required)"
    echo "  --help             Show this help message"
    echo ""
    echo "Example:"
    echo "  $0 --server http://dns-server:8081 --hostname mydevice.local"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --server)
            SERVER_URL="$2"
            shift 2
            ;;
        --hostname)
            HOSTNAME="$2"
            shift 2
            ;;
        --ip)
            IP_ADDRESS="$2"
            shift 2
            ;;
        --mac)
            MAC_ADDRESS="$2"
            shift 2
            ;;
        --token)
            TOKEN="$2"
            shift 2
            ;;
        --help)
            print_usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            print_usage
            exit 1
            ;;
    esac
done

# Get current hostname if not specified
if [ -z "$HOSTNAME" ]; then
    HOSTNAME="$(hostname).local"
    echo "Using current hostname: $HOSTNAME"
fi

# Get current IP address if not specified
if [ -z "$IP_ADDRESS" ]; then
    # Try different methods to get the IP address
    IP_ADDRESS=$(hostname -I 2>/dev/null | awk '{print $1}')
    
    # If hostname -I failed, try ifconfig
    if [ -z "$IP_ADDRESS" ]; then
        IP_ADDRESS=$(ifconfig 2>/dev/null | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0.1' | head -n 1)
    fi
    
    # If ifconfig failed, try ip addr
    if [ -z "$IP_ADDRESS" ]; then
        IP_ADDRESS=$(ip addr 2>/dev/null | grep -Eo 'inet ([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0.1' | head -n 1)
    fi
    
    if [ -z "$IP_ADDRESS" ]; then
        echo "Error: Could not determine local IP address"
        echo "Please specify an IP address with --ip"
        exit 1
    fi
    
    echo "Using current IP address: $IP_ADDRESS"
fi

# Build the request data
JSON_DATA="{\n  \"ip\": \"$IP_ADDRESS\",\n  \"hostname\": \"$HOSTNAME\""

# Add MAC address if specified
if [ -n "$MAC_ADDRESS" ]; then
    JSON_DATA="$JSON_DATA,\n  \"mac\": \"$MAC_ADDRESS\""
    echo "Using MAC address: $MAC_ADDRESS"
fi

# Close the JSON object
JSON_DATA="$JSON_DATA\n}"

# Add auth header if token is provided
AUTH_HEADER=""
if [ -n "$TOKEN" ]; then
    AUTH_HEADER="-H \"Authorization: Bearer $TOKEN\""
fi

# Construct the full URL
API_ENDPOINT="$SERVER_URL/api/dns/set_hostname"

# Print the command for debugging
echo "Sending request to: $API_ENDPOINT"
echo -e "Data: $JSON_DATA"

# Execute the curl command
RESPONSE=$(curl -s -X POST "$API_ENDPOINT" \
  -H "Content-Type: application/json" \
  $AUTH_HEADER \
  -d "$(echo -e $JSON_DATA)")

# Check if the request was successful
if [ $? -ne 0 ]; then
    echo "Error: Failed to connect to the server"
    exit 1
fi

# Print the response
echo "Response from server:"
echo $RESPONSE

# Check if the response contains success
if [[ $RESPONSE == *"success"* ]]; then
    echo "Hostname set successfully!"
    exit 0
elif [[ $RESPONSE == *"no_change"* ]]; then
    echo "No changes needed. Hostname already set correctly."
    exit 0
else
    echo "Error: Failed to set hostname"
    exit 1
fi
