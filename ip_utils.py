#!/usr/bin/env python3
"""
IP Address Utilities

This module provides utilities for working with IP addresses,
including functions to check if an IP is already in use on the network.

Note: This is a compatibility layer for the refactored modules:
- ip_detection.py
- port_scanner.py
- network_scanner.py
"""

import logging
from typing import List, Dict, Optional, Set, Tuple, Any, Callable

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('ip_utils')

# Import functions from refactored modules
try:
    # Import from ip_detection.py
    from ip_detection import (
        is_ip_in_use,
        ping_ip,
        scan_ports,
        is_in_arp_cache,
        get_mac_from_arp,
        get_arp_output,
        is_same_client_requesting,
    )
    
    # Import from port_scanner.py
    from port_scanner import (
        scan_client_ports,
        get_device_ports_from_db,
        get_active_devices_with_ports,
        refresh_port_data,
        COMMON_PORTS,
        PORT_SERVICES,
    )
    
    # Import from network_scanner.py
    from network_scanner import (
        scan_network_async,
        scan_ip_range,
        format_scan_results,
    )
except ImportError as e:
    logger.warning(f"Error importing module: {e}")
    logger.warning("Functions may not be available or may behave differently")

# Re-export everything for backward compatibility
__all__ = [
    # From ip_detection.py
    'is_ip_in_use',
    'ping_ip',
    'scan_ports',
    'is_in_arp_cache',
    'get_mac_from_arp',
    'get_arp_output',
    'is_same_client_requesting',
    
    # From port_scanner.py
    'scan_client_ports',
    'get_device_ports_from_db',
    'get_active_devices_with_ports',
    'refresh_port_data',
    'COMMON_PORTS',
    'PORT_SERVICES',
    
    # From network_scanner.py
    'scan_network_async',
    'scan_ip_range',
    'format_scan_results',
]

# Import port database if not already imported
try:
    from port_database import get_port_db
except ImportError:
    logger.warning("Port database module not available")
    get_port_db = lambda: None

if __name__ == "__main__":
    # Example usage
    import sys
    
    if len(sys.argv) > 1:
        test_ip = sys.argv[1]
        print(f"Testing IP: {test_ip}")
        
        print(f"IP in use: {is_ip_in_use(test_ip)}")
        print(f"Responds to ping: {ping_ip(test_ip)}")
        
        open_ports = scan_client_ports(test_ip)
        if open_ports:
            print(f"Open ports: {', '.join(map(str, open_ports))}")
            
            # Check if we have service names for these ports
            for port in open_ports:
                service = PORT_SERVICES.get(port)
                if service:
                    print(f"  Port {port}: {service}")
                else:
                    print(f"  Port {port}: Unknown service")
        else:
            print("No open ports found")
        
        mac = get_mac_from_arp(test_ip)
        if mac:
            print(f"MAC address: {mac}")
        else:
            print("MAC address not found")
            
        # If we have a database, show device info
        db = get_port_db()
        if db:
            try:
                device = db.get_device_with_ports(test_ip)
                if device:
                    print(f"Device in database: {device['ip_address']} ({device['mac_address']})")
                    print(f"Last seen: {device['last_seen']}")
                    print(f"Open ports in database: {', '.join(str(p['port_number']) for p in device['ports'])}")
            except Exception as e:
                print(f"Error getting device info from database: {e}")
    else:
        print("Please provide an IP address to test")
