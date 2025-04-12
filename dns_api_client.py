#!/usr/bin/env python3
"""
DNS API Client

A simple client for the DNS API server. This script can be used to set DNS entries
from the command line or from scripts.
"""

import sys
import json
import socket
import argparse
import urllib.request
import urllib.parse
import urllib.error
import logging
import os

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('dns_api_client')


def get_current_ip() -> str:
    """Get the current IP address of this machine."""
    try:
        # Create a socket to connect to an external server
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        # This doesn't actually establish a connection
        s.connect(("8.8.8.8", 80))
        
        # Get the local IP address used for this connection
        ip_address = s.getsockname()[0]
        s.close()
        
        return ip_address
    except Exception as e:
        logger.error(f"Error getting local IP: {e}")
        # Fallback to localhost
        return "127.0.0.1"


def get_mac_address() -> str:
    """Get the MAC address of the primary network interface."""
    try:
        if sys.platform == 'win32':
            # On Windows, use the 'getmac' command
            import re
            from subprocess import Popen, PIPE
            
            # Get the IP address first
            ip = get_current_ip()
            
            # Run the command to get the MAC address for the interface with that IP
            proc = Popen(["getmac", "/v", "/fo", "csv"], stdout=PIPE, stderr=PIPE)
            out, _ = proc.communicate()
            out = out.decode('utf-8')
            
            # Look for the line with our IP
            for line in out.splitlines():
                if ip in line:
                    # Extract the MAC address
                    match = re.search(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', line)
                    if match:
                        return match.group(0).replace('-', ':').lower()
            
            # If we can't find the MAC for our IP, try to get any physical adapter
            for line in out.splitlines():
                if "Physical" in line:
                    match = re.search(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', line)
                    if match:
                        return match.group(0).replace('-', ':').lower()
            
            raise Exception("No suitable network adapter found")
            
        elif sys.platform == 'darwin':  # macOS
            # On macOS, use 'ifconfig' and find the active interface
            from subprocess import Popen, PIPE
            import re
            
            # Get the IP address first
            ip = get_current_ip()
            
            # Run ifconfig to get all interface info
            proc = Popen(["ifconfig"], stdout=PIPE, stderr=PIPE)
            out, _ = proc.communicate()
            out = out.decode('utf-8')
            
            # Parse the output to find the active interface
            current_interface = None
            for line in out.splitlines():
                if line.startswith('\t'):
                    # This is a continuation of the current interface
                    if current_interface and 'inet ' + ip in line:
                        # This is our active interface
                        # Now look for the ether (MAC) line
                        ether_pattern = re.compile(r'\tether\s+([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2})')
                        for ether_line in out.splitlines():
                            if ether_line.startswith('\t') and current_interface in out.splitlines()[out.splitlines().index(ether_line) - 1]:
                                match = ether_pattern.match(ether_line)
                                if match:
                                    return match.group(1).lower()
                else:
                    # This is a new interface
                    if ':' in line:
                        current_interface = line.split(':')[0]
            
            # If we couldn't find the MAC by IP, try to get any physical adapter
            ether_pattern = re.compile(r'\tether\s+([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2})')
            for line in out.splitlines():
                match = ether_pattern.match(line)
                if match:
                    return match.group(1).lower()
                    
            raise Exception("No suitable network adapter found")
            
        else:  # Linux
            # On Linux, read from /sys/class/net/*/address
            # First, try to find the interface with our IP
            ip = get_current_ip()
            from subprocess import Popen, PIPE
            import re
            
            # Find the interface with our IP
            proc = Popen(["ip", "addr", "show"], stdout=PIPE, stderr=PIPE)
            out, _ = proc.communicate()
            out = out.decode('utf-8')
            
            # Parse to find interface with our IP
            pattern = re.compile(r'^\d+:\s+(\w+):.*\n(?:\s+.*\n)*\s+inet\s+' + re.escape(ip) + r'\/', re.MULTILINE)
            match = pattern.search(out)
            if match:
                interface = match.group(1)
                # Now get the MAC for this interface
                mac_path = f"/sys/class/net/{interface}/address"
                if os.path.exists(mac_path):
                    with open(mac_path, 'r') as f:
                        return f.read().strip().lower()
            
            # If we couldn't find by IP, try any physical interface
            for interface in os.listdir('/sys/class/net'):
                # Skip loopback
                if interface == 'lo':
                    continue
                    
                mac_path = f"/sys/class/net/{interface}/address"
                if os.path.exists(mac_path):
                    with open(mac_path, 'r') as f:
                        mac = f.read().strip()
                        if mac != '00:00:00:00:00:00':
                            return mac.lower()
                            
            raise Exception("No suitable network adapter found")
            
    except Exception as e:
        logger.error(f"Error getting MAC address: {e}")
        return None


def set_hostname(server_url: str, ip: str = None, hostname: str = None, mac: str = None, token: str = None) -> bool:
    """
    Set a hostname for an IP address using the DNS API.
    
    Args:
        server_url: The base URL of the DNS API server (http://hostname:port)
        ip: The IP address to set (default: current IP)
        hostname: The hostname to set (default: current hostname)
        mac: The MAC address to set (default: current MAC)
        token: Optional authentication token
    
    Returns:
        True if successful, False otherwise
    """
    # Build the endpoint URL
    endpoint = f"{server_url}/api/dns/set_hostname"
    
    # Set default values if not provided
    if ip is None:
        ip = get_current_ip()
        logger.info(f"Using detected IP: {ip}")
    
    if hostname is None:
        hostname = socket.gethostname()
        logger.info(f"Using local hostname: {hostname}")
    
    if mac is None:
        mac = get_mac_address()
        if mac:
            logger.info(f"Using detected MAC: {mac}")
    
    # Build the request data
    data = {
        'ip': ip,
        'hostname': hostname,
    }
    
    if mac:
        data['mac'] = mac
    
    # Convert data to JSON
    json_data = json.dumps(data).encode('utf-8')
    
    # Create the request
    req = urllib.request.Request(
        endpoint,
        data=json_data,
        headers={
            'Content-Type': 'application/json'
        }
    )
    
    # Add authentication token if provided
    if token:
        req.add_header('Authorization', f"Bearer {token}")
    
    try:
        # Send the request
        with urllib.request.urlopen(req) as response:
            result = json.loads(response.read().decode('utf-8'))
            
        # Check the result
        if 'status' in result and result['status'] in ['success', 'partial_success', 'no_change']:
            logger.info(f"Hostname updated successfully: {result['message']}")
            return True
        else:
            logger.error(f"Error updating hostname: {result.get('error', 'Unknown error')}")
            return False
    
    except urllib.error.URLError as e:
        logger.error(f"Connection error: {e.reason}")
        return False
    except urllib.error.HTTPError as e:
        logger.error(f"HTTP error: {e.code} - {e.reason}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return False


def lookup_hostname(server_url: str, hostname: str, token: str = None) -> dict:
    """
    Lookup a hostname using the DNS API.
    
    Args:
        server_url: The base URL of the DNS API server (http://hostname:port)
        hostname: The hostname to look up
        token: Optional authentication token
    
    Returns:
        Dictionary with lookup results or None if error
    """
    # Build the endpoint URL
    endpoint = f"{server_url}/api/dns/lookup?hostname={urllib.parse.quote(hostname)}"
    
    # Add authentication token if provided
    headers = {}
    if token:
        headers['Authorization'] = f"Bearer {token}"
    
    try:
        # Send the request
        req = urllib.request.Request(endpoint, headers=headers)
        with urllib.request.urlopen(req) as response:
            result = json.loads(response.read().decode('utf-8'))
        
        return result
    
    except Exception as e:
        logger.error(f"Error looking up hostname: {e}")
        return None


def reverse_lookup(server_url: str, ip: str, token: str = None) -> dict:
    """
    Perform a reverse lookup for an IP address using the DNS API.
    
    Args:
        server_url: The base URL of the DNS API server (http://hostname:port)
        ip: The IP address to look up
        token: Optional authentication token
    
    Returns:
        Dictionary with lookup results or None if error
    """
    # Build the endpoint URL
    endpoint = f"{server_url}/api/dns/reverse?ip={urllib.parse.quote(ip)}"
    
    # Add authentication token if provided
    headers = {}
    if token:
        headers['Authorization'] = f"Bearer {token}"
    
    try:
        # Send the request
        req = urllib.request.Request(endpoint, headers=headers)
        with urllib.request.urlopen(req) as response:
            result = json.loads(response.read().decode('utf-8'))
        
        return result
    
    except Exception as e:
        logger.error(f"Error performing reverse lookup: {e}")
        return None


def print_results(result: dict) -> None:
    """Print the results in a readable format."""
    if not result:
        print("No results returned")
        return
    
    # Pretty print the JSON
    print(json.dumps(result, indent=2))


def main() -> None:
    """Main function for command-line usage."""
    parser = argparse.ArgumentParser(description='DNS API Client')
    
    # Server URL argument
    parser.add_argument('--server', required=True, help='DNS API server URL (http://hostname:port)')
    
    # Authentication token
    parser.add_argument('--token', help='Authentication token')
    
    # Subcommands
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # Set hostname command
    set_parser = subparsers.add_parser('set', help='Set hostname for an IP address')
    set_parser.add_argument('--ip', help='IP address (default: current IP)')
    set_parser.add_argument('--hostname', help='Hostname (default: current hostname)')
    set_parser.add_argument('--mac', help='MAC address (default: current MAC)')
    
    # Lookup hostname command
    lookup_parser = subparsers.add_parser('lookup', help='Lookup IP addresses for a hostname')
    lookup_parser.add_argument('hostname', help='Hostname to look up')
    
    # Reverse lookup command
    reverse_parser = subparsers.add_parser('reverse', help='Reverse lookup hostname for an IP address')
    reverse_parser.add_argument('ip', help='IP address to look up')
    
    args = parser.parse_args()
    
    # Process commands
    if args.command == 'set':
        success = set_hostname(args.server, args.ip, args.hostname, args.mac, args.token)
        sys.exit(0 if success else 1)
    
    elif args.command == 'lookup':
        result = lookup_hostname(args.server, args.hostname, args.token)
        if result:
            print_results(result)
            sys.exit(0)
        else:
            sys.exit(1)
    
    elif args.command == 'reverse':
        result = reverse_lookup(args.server, args.ip, args.token)
        if result:
            print_results(result)
            sys.exit(0)
        else:
            sys.exit(1)
    
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
