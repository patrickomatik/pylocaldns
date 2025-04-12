#!/usr/bin/env python3
"""
Initialize Port Database

This script initializes the port database and populates it with existing hosts data.
It's useful for initial setup and for migrating from the hosts file-based storage.
"""

import os
import sys
import time
import logging
import argparse
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('init_port_db')

# Make sure we can import our modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import required modules
from port_database import get_port_db
from hosts_file import HostsFile
from ip_utils import scan_client_ports, PORT_SERVICES

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Initialize port database and scan existing hosts.')
    
    parser.add_argument('--hosts-file', '-f', type=str, required=False,
                        default=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'hosts.txt'),
                        help='Path to the hosts file (default: hosts.txt in the same directory)')
    
    parser.add_argument('--skip-scan', '-s', action='store_true',
                        help='Skip port scanning (just initialize database schema)')
    
    parser.add_argument('--force-scan', '-F', action='store_true',
                        help='Rescan all hosts even if they already have port data')
    
    return parser.parse_args()

def main():
    """Main function to initialize the database and scan hosts."""
    args = parse_args()
    
    # Check if hosts file exists
    if not os.path.exists(args.hosts_file):
        logger.error(f"Hosts file not found: {args.hosts_file}")
        return 1
    
    # Initialize database
    logger.info("Initializing port database...")
    db = get_port_db()
    
    if args.skip_scan:
        logger.info("Database schema initialized successfully. Skipping host scan as requested.")
        return 0
    
    # Load hosts file
    logger.info(f"Loading hosts from: {args.hosts_file}")
    hosts = HostsFile(args.hosts_file)
    
    # Get all IP addresses from the hosts file
    ip_list = set()
    
    # Add static entries
    for mac, ip in hosts.mac_to_ip.items():
        logger.info(f"Found static entry: {ip} ({mac})")
        
        # Add to database
        db.add_or_update_device(ip, mac)
        
        # Extract hostname for the device
        hostnames = hosts.get_hostnames_for_ip(ip)
        display_names = [h for h in hostnames if not h.startswith('ports-') and h != 'preallocated']
        
        if display_names:
            # Update hostname in database
            db.add_or_update_device(ip, mac, display_names[0])
        
        # Get port info from hostnames
        ports = []
        for hostname in hostnames:
            if hostname.startswith('ports-'):
                try:
                    # Try to extract port numbers
                    port_list = hostname[6:].split(',')
                    ports = [int(p) for p in port_list if p.isdigit()]
                except Exception as e:
                    logger.error(f"Error extracting ports from hostname {hostname}: {e}")
        
        # Add to the list for scanning
        ip_list.add(ip)
        
        # If we already have ports from the hostname, add them to the database
        if ports and not args.force_scan:
            logger.info(f"Adding {len(ports)} ports from hostname for {ip}")
            
            # Prepare port services mapping
            services = {}
            for port in ports:
                if port in PORT_SERVICES:
                    services[port] = PORT_SERVICES[port]
            
            # Add ports to database
            db.bulk_update_ports(ip, ports, services)
    
    # Add dynamic leases
    for mac, lease in hosts.leases.items():
        if not lease.is_expired():
            logger.info(f"Found dynamic lease: {lease.ip_address} ({mac})")
            
            # Add to database
            db.add_or_update_device(lease.ip_address, mac, lease.hostname)
            
            # Add to the list for scanning
            ip_list.add(lease.ip_address)
    
    # Now scan all IPs for open ports
    total_devices = len(ip_list)
    logger.info(f"Found {total_devices} devices to scan")
    
    # Skip if already populated and not forcing rescan
    if not args.force_scan:
        # Check which devices already have port data
        devices_to_scan = []
        for ip in ip_list:
            ports = db.get_ports_for_device(ip)
            if not ports:
                devices_to_scan.append(ip)
        
        if len(devices_to_scan) < total_devices:
            logger.info(f"Skipping {total_devices - len(devices_to_scan)} devices that already have port data")
            ip_list = devices_to_scan
    
    # Scan for open ports
    if not ip_list:
        logger.info("No devices to scan")
        return 0
    
    logger.info(f"Scanning {len(ip_list)} devices for open ports...")
    
    ports_found = 0
    for i, ip in enumerate(ip_list):
        logger.info(f"[{i+1}/{len(ip_list)}] Scanning {ip}...")
        
        try:
            ports = scan_client_ports(ip)
            
            if ports:
                logger.info(f"Found {len(ports)} open ports for {ip}: {', '.join(map(str, ports))}")
                ports_found += len(ports)
            else:
                logger.info(f"No open ports found for {ip}")
        except Exception as e:
            logger.error(f"Error scanning {ip}: {e}")
    
    # Log scan statistics
    logger.info(f"Scan complete. Found {ports_found} open ports across {len(ip_list)} devices.")
    db.record_scan(len(ip_list), ports_found)
    
    logger.info("Port database initialized and populated successfully")
    return 0

if __name__ == "__main__":
    sys.exit(main())
