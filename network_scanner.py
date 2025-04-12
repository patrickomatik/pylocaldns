#!/usr/bin/env python3
"""
Network Scanning Utilities

This module provides functions for scanning IP ranges to discover devices
and gather information about them.
"""

import threading
import logging
import time
from typing import Dict, Optional, Tuple, List, Any, Callable
from ipaddress import IPv4Address

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('network_scanner')

# Import other modules
try:
    from ip_detection import is_ip_in_use, get_mac_from_arp
    from port_scanner import scan_client_ports, COMMON_PORTS
    from port_database import get_port_db
except ImportError as e:
    logger.warning(f"Error importing module: {e}")
    # Define dummy functions for missing imports
    if 'is_ip_in_use' not in locals():
        is_ip_in_use = lambda ip, timeout=1.0: False
    if 'get_mac_from_arp' not in locals():
        get_mac_from_arp = lambda ip: None
    if 'scan_client_ports' not in locals():
        scan_client_ports = lambda ip, ports=None, timeout=0.5, max_ports=30: []
    if 'COMMON_PORTS' not in locals():
        COMMON_PORTS = [80, 443, 22, 8080]
    if 'get_port_db' not in locals():
        get_port_db = lambda: None


def scan_network_async(
    ip_range: Tuple[str, str], 
    callback: Optional[Callable[[int, int], None]] = None,
    use_db: bool = True,
    scan_name: Optional[str] = None
) -> Dict[str, Dict[str, Any]]:
    """
    Scan a range of IP addresses asynchronously to find devices.
    
    This function performs a quick network scan to find active devices,
    retrieve their MAC addresses, and check for open ports.
    It uses multiple threads for speed.
    
    Args:
        ip_range: Tuple with start and end IP addresses
        callback: Optional progress callback function
        use_db: Whether to store results in the port database
        scan_name: Optional name to identify this scan in the database
        
    Returns:
        Dictionary mapping IP addresses to dictionaries containing:
        - 'mac': MAC address (or None if not found)
        - 'ports': List of open ports
    """
    # Get the port database if we're using it
    port_db = get_port_db() if use_db else None
    
    # Convert IP strings to integers
    start_int = int(IPv4Address(ip_range[0]))
    end_int = int(IPv4Address(ip_range[1]))
    
    # Calculate total number of IPs to scan
    total_ips = end_int - start_int + 1
    
    # Results dictionary
    results: Dict[str, Dict[str, Any]] = {}
    results_lock = threading.Lock()
    
    # Keep track of progress
    scanned_count = 0
    progress_lock = threading.Lock()
    
    # Keep track of total ports found (for database record)
    total_devices = 0
    total_ports = 0
    stats_lock = threading.Lock()
    
    def scan_worker(ip: str) -> None:
        nonlocal scanned_count, total_devices, total_ports
        
        # Check if IP is in use
        if is_ip_in_use(ip, timeout=0.5):
            # Try to get MAC address
            mac = get_mac_from_arp(ip)
            
            # Scan for open ports
            open_ports = scan_client_ports(ip, COMMON_PORTS)
            
            with results_lock:
                results[ip] = {
                    'mac': mac,
                    'ports': open_ports,
                    'hostname': None  # We don't have hostname information yet
                }
            
            # Update database if enabled
            if port_db:
                try:
                    # Add or update device
                    port_db.add_or_update_device(ip, mac)
                    
                    # Add service names for well-known ports
                    port_services = {}
                    for port in open_ports:
                        if hasattr(COMMON_PORTS, 'get') and callable(getattr(COMMON_PORTS, 'get')):
                            service_name = COMMON_PORTS.get(port)
                            if service_name:
                                port_services[port] = service_name
                    
                    # Bulk update ports for this device
                    port_db.bulk_update_ports(ip, open_ports, port_services)
                    
                except Exception as e:
                    logger.error(f"Error updating port database for {ip}: {e}")
            
            # Update stats for the database record
            with stats_lock:
                total_devices += 1
                total_ports += len(open_ports)
        
        # Update progress
        with progress_lock:
            scanned_count += 1
            if callback and scanned_count % max(1, total_ips // 100) == 0:
                callback(scanned_count, total_ips)
    
    # Create and start threads
    threads = []
    for i in range(start_int, end_int + 1):
        ip = str(IPv4Address(i))
        thread = threading.Thread(target=scan_worker, args=(ip,))
        thread.daemon = True
        threads.append(thread)
        thread.start()
        
        # Limit concurrent threads to avoid overwhelming the network
        if len(threads) >= 20:
            for t in threads:
                t.join(timeout=0.1)
            threads = [t for t in threads if t.is_alive()]
    
    # Wait for all threads to complete
    for t in threads:
        t.join()
    
    # Final callback
    if callback:
        callback(total_ips, total_ips)
    
    # Record the scan in the database
    if port_db:
        try:
            port_db.record_scan(total_devices, total_ports)
        except Exception as e:
            logger.error(f"Error recording scan in database: {e}")
    
    return results


def scan_ip_range(start_ip: str, end_ip: str) -> Dict[str, Dict[str, Any]]:
    """
    Scan a range of IP addresses to find devices (simpler interface).
    
    Args:
        start_ip: Starting IP address of the range
        end_ip: Ending IP address of the range
        
    Returns:
        Dictionary mapping IP addresses to device info
    """
    return scan_network_async((start_ip, end_ip))


def format_scan_results(results: Dict[str, Dict[str, Any]]) -> str:
    """
    Format scan results as a human-readable string.
    
    Args:
        results: Dictionary of scan results from scan_network_async
        
    Returns:
        Formatted string with scan results
    """
    if not results:
        return "No devices found."
    
    output = []
    output.append(f"Found {len(results)} device(s):")
    
    for ip, info in sorted(results.items()):
        mac = info.get('mac') or "Unknown"
        ports = info.get('ports') or []
        port_str = ", ".join(map(str, ports)) if ports else "None"
        
        output.append(f"- {ip} (MAC: {mac})")
        if ports:
            output.append(f"  Open ports: {port_str}")
    
    return "\n".join(output)


if __name__ == "__main__":
    # Example usage
    import sys
    
    if len(sys.argv) > 2:
        start_ip = sys.argv[1]
        end_ip = sys.argv[2]
        print(f"Scanning IP range: {start_ip} - {end_ip}")
        
        # Define a simple progress callback
        def progress(current, total):
            percent = int(current / total * 100)
            print(f"\rProgress: {percent}% ({current}/{total})", end="")
        
        # Run the scan
        results = scan_network_async((start_ip, end_ip), callback=progress)
        print("\n")  # Newline after progress
        
        # Print results
        print(format_scan_results(results))
    else:
        print("Please provide start and end IP addresses")
        print("Example: python network_scanner.py 192.168.1.1 192.168.1.254")
