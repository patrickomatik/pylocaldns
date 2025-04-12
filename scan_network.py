#!/usr/bin/env python3
"""
Network Scanning Utility

This script scans a network range for active devices and adds them to the hosts file
to prevent IP conflicts. It's useful for setting up a network server on an existing
network where devices are already using IP addresses that might conflict with DHCP.
"""

import os
import sys
import argparse
import logging
import time
from typing import Dict, Optional, List, Tuple

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('scan_network')

# Import local modules
from hosts_file import HostsFile
import ip_utils


def format_mac(mac: Optional[str]) -> str:
    """Format MAC address for display or 'Unknown' if None."""
    return mac if mac else "Unknown"


def display_scan_results(discovered: Dict[str, Optional[str]], hosts_file: HostsFile) -> None:
    """
    Display scan results in a human-readable format.
    
    Args:
        discovered: Dictionary mapping IP addresses to MAC addresses
        hosts_file: The HostsFile instance to check against
    """
    print("\nNetwork Scan Results")
    print("===================\n")
    
    print(f"Found {len(discovered)} active devices on the network.\n")
    
    # Categorize devices
    known_devices = []
    preallocated_devices = []
    new_devices = []
    
    for ip, mac in discovered.items():
        # Check if this IP is already in the hosts file
        if ip in hosts_file.reserved_ips:
            known_devices.append((ip, mac))
        elif "preallocated" in hosts_file.get_hostnames_for_ip(ip):
            preallocated_devices.append((ip, mac))
        else:
            new_devices.append((ip, mac))
    
    # Display known devices
    if known_devices:
        print(f"\nKnown Devices ({len(known_devices)}):")
        print("-" * 80)
        print(f"{'IP Address':<15} {'MAC Address':<20} {'Hostnames':<40}")
        print("-" * 80)
        for ip, mac in known_devices:
            hostnames = ", ".join(hosts_file.get_hostnames_for_ip(ip))
            print(f"{ip:<15} {format_mac(mac):<20} {hostnames:<40}")
    
    # Display pre-allocated devices
    if preallocated_devices:
        print(f"\nPre-allocated Devices ({len(preallocated_devices)}):")
        print("-" * 80)
        print(f"{'IP Address':<15} {'MAC Address':<20} {'Hostnames':<40}")
        print("-" * 80)
        for ip, mac in preallocated_devices:
            hostnames = ", ".join(hosts_file.get_hostnames_for_ip(ip))
            print(f"{ip:<15} {format_mac(mac):<20} {hostnames:<40}")
    
    # Display newly discovered devices
    if new_devices:
        print(f"\nNewly Discovered Devices ({len(new_devices)}):")
        print("-" * 80)
        print(f"{'IP Address':<15} {'MAC Address':<20} {'Status':<40}")
        print("-" * 80)
        for ip, mac in new_devices:
            print(f"{ip:<15} {format_mac(mac):<20} {'Added as pre-allocated':<40}")
    
    print("\nScan complete.")


def scan_network(hosts_file_path: str, ip_range: Optional[Tuple[str, str]] = None) -> None:
    """
    Scan the network and update the hosts file with discovered devices.
    
    Args:
        hosts_file_path: Path to the hosts file
        ip_range: Optional tuple of (start_ip, end_ip) to scan
    """
    try:
        # Initialize the hosts file
        if not os.path.exists(hosts_file_path):
            logger.error(f"Hosts file not found: {hosts_file_path}")
            sys.exit(1)
        
        # Create HostsFile instance
        hosts_file = HostsFile(hosts_file_path, ip_range)
        
        if not ip_range and not hosts_file.dhcp_range:
            logger.error("No IP range specified. Please specify a range using --range.")
            sys.exit(1)
        
        # Use the DHCP range from the hosts file if no range was specified
        effective_range = ip_range or hosts_file.dhcp_range
        
        logger.info(f"Scanning network range {effective_range[0]} to {effective_range[1]}")
        print(f"Scanning network range {effective_range[0]} to {effective_range[1]}...")
        print("This may take several minutes depending on the size of your network.")
        
        # Define a simple progress callback
        def progress_callback(scanned, total):
            if scanned % 10 == 0 or scanned == total:
                percent = scanned / total * 100
                time_elapsed = time.time() - start_time
                ips_per_second = scanned / time_elapsed if time_elapsed > 0 else 0
                time_remaining = (total - scanned) / ips_per_second if ips_per_second > 0 else 0
                print(f"\rProgress: {scanned}/{total} IPs ({percent:.1f}%) - {ips_per_second:.1f} IPs/sec - {time_remaining:.0f}s remaining   ", end="", flush=True)
        
        # Perform the scan
        start_time = time.time()
        discovered = ip_utils.scan_network_async(effective_range, callback=progress_callback)
        end_time = time.time()
        
        print(f"\nScan completed in {end_time - start_time:.2f} seconds.")
        
        # Update our configuration with discovered devices
        for ip, mac in discovered.items():
            if ip not in hosts_file.reserved_ips and ip not in [lease.ip_address for lease in hosts_file.leases.values()]:
                logger.info(f"Discovered new device at {ip}" + (f" with MAC {mac}" if mac else ""))
                hosts_file._add_preallocated_ip(ip)
        
        # Display the results
        display_scan_results(discovered, hosts_file)
        
    except Exception as e:
        logger.error(f"Error during network scan: {e}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description='Network Scanner for IP Address Pre-allocation')
    
    parser.add_argument('--hosts-file', '-f', required=True,
                       help='Path to the hosts file')
    
    parser.add_argument('--range', '-r',
                       help='IP range to scan (format: 192.168.1.1-192.168.1.254)')
    
    args = parser.parse_args()
    
    # Parse IP range if specified
    ip_range = None
    if args.range:
        try:
            start_ip, end_ip = args.range.split('-')
            start_ip = start_ip.strip()
            end_ip = end_ip.strip()
            ip_range = (start_ip, end_ip)
        except Exception as e:
            logger.error(f"Invalid IP range format: {args.range}. Expected format: '192.168.1.1-192.168.1.254'")
            sys.exit(1)
    
    # Run the scan
    scan_network(args.hosts_file, ip_range)


if __name__ == '__main__':
    main()
