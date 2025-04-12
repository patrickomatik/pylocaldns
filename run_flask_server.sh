#!/bin/bash
# Run the Flask-based Network Server
# Usage: ./run_flask_server.sh [--debug]

# Check if virtual environment exists
if [ ! -d ".venv" ]; then
  echo "Virtual environment not found. Setting up virtual environment..."
  ./setup_venv.sh
  if [ $? -ne 0 ]; then
    echo "Failed to set up virtual environment. Please check the errors above."
    exit 1
  fi
fi

# Activate the virtual environment
source .venv/bin/activate
if [ $? -ne 0 ]; then
  echo "Failed to activate virtual environment. Please check the errors above."
  exit 1
fi

# Check if Flask is installed
python3 -c "import flask" >/dev/null 2>&1
if [ $? -ne 0 ]; then
  echo "Error: Flask is not installed in the virtual environment!"
  echo "Please run ./setup_venv.sh to reinstall dependencies."
  deactivate
  exit 1
fi

DEBUG=""
if [ "$1" == "--debug" ]; then
  DEBUG="--debug"
fi

# Get the directory where this script is located
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Set the hosts file path
HOSTS_FILE="${DIR}/hosts.txt"

# Create the hosts file if it doesn't exist
if [ ! -f "$HOSTS_FILE" ]; then
  echo "# PyLocalDNS hosts file" > "$HOSTS_FILE"
  echo "# Format: <IP> <hostname1> [hostname2] ..." >> "$HOSTS_FILE"
  echo "# For DHCP: <IP> <hostname> [MAC=xx:xx:xx:xx:xx:xx]" >> "$HOSTS_FILE"
  echo "" >> "$HOSTS_FILE"
  echo "127.0.0.1 localhost" >> "$HOSTS_FILE"
  echo "::1 localhost" >> "$HOSTS_FILE"
  echo "" >> "$HOSTS_FILE"
  echo "# Add your custom entries below" >> "$HOSTS_FILE"
  echo "# Example: 192.168.1.10 router.local" >> "$HOSTS_FILE"
  echo "# Example with MAC: 192.168.1.20 desktop.local [MAC=00:11:22:33:44:55]" >> "$HOSTS_FILE"
fi

# Run the server
echo "Starting PyLocalDNS with Flask web UI..."
python3 "${DIR}/network_server_flask.py" \
  --hosts-file "$HOSTS_FILE" \
  --webui-enable \
  --webui-port 8082 \
  --dhcp-enable \
  --dhcp-range "192.168.1.100-192.168.1.200" \
  --dhcp-subnet "255.255.255.0" \
  --dhcp-router "192.168.1.1" \
  --dhcp-dns "8.8.8.8,8.8.4.4" \
  $DEBUG

# Deactivate virtual environment when done
deactivate
