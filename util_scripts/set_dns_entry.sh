#!/bin/bash
# Set DNS entry using the DNS API client
# This script uses the DNS API client to set a hostname for the current host
# or a specified IP address
#
# Usage:
#   ./set_dns_entry.sh [--server SERVER_URL] [--hostname HOSTNAME] [--ip IP_ADDRESS] [--mac MAC_ADDRESS] [--token TOKEN]
#
# All arguments are optional. If not provided, the script will use:
# - SERVER_URL: http://localhost:8081 by default
# - HOSTNAME: Current hostname if not provided
# - IP_ADDRESS: Current IP address if not provided
# - MAC_ADDRESS: Current MAC address if not provided

# Set default values
SERVER_URL="http://localhost:8081"
HOSTNAME=""
IP_ADDRESS=""
MAC_ADDRESS=""
TOKEN=""

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
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Build the command
CMD="python3 $(dirname "$0")/dns_api_client.py --server $SERVER_URL set"

# Add optional arguments if provided
if [ -n "$HOSTNAME" ]; then
    CMD="$CMD --hostname $HOSTNAME"
fi

if [ -n "$IP_ADDRESS" ]; then
    CMD="$CMD --ip $IP_ADDRESS"
fi

if [ -n "$MAC_ADDRESS" ]; then
    CMD="$CMD --mac $MAC_ADDRESS"
fi

if [ -n "$TOKEN" ]; then
    CMD="$CMD --token $TOKEN"
fi

# Run the command
echo "Running: $CMD"
$CMD

# Exit with the same status as the command
exit $?
