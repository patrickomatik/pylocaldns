#!/usr/bin/env python3
"""
IP Address Utilities

This module provides utilities for working with IP addresses,
including functions to check if an IP is already in use on the network.
"""

import os
import re
import socket
import logging
import subprocess
import sys
import threading
from typing import List, Dict, Optional, Set, Tuple, Any

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('ip_utils')

# Common ports to check for active devices
COMMON_PORTS = [80, 443, 22, 445, 139, 135, 21, 23, 25, 587, 3389, 5900, 8080, 8443]


def is_ip_in_use(ip_address: str, timeout: float = 1.0) -> bool:
    """
    Check if an IP address is already in use on the network.
    
    Uses multiple methods to check if an IP is in use:
    1. Ping test (ICMP)
    2. Common ports scan (TCP)
    3. ARP table lookup
    
    Args:
        ip_address: The IP address to check
        timeout: Timeout in seconds for the checks
        
    Returns:
        True if the IP is in use, False otherwise
    """
    # Only check actual network IPs (skip localhost)
    if ip_address.startswith('127.'):
        return False
    
    # Check the ARP cache first (fastest method)
    if is_in_arp_cache(ip_address):
        logger.debug(f"IP {ip_address} found in ARP cache")
        return True
    
    # Try ping (works for most devices that respond to ICMP)
    if ping_ip(ip_address, timeout):
        logger.debug(f"IP {ip_address} responded to ping")
        return True
    
    # Try connecting to common ports
    if scan_ports(ip_address, COMMON_PORTS, timeout/2):
        return True
    
    # Final check: if we can get a MAC address for this IP from any source,
    # then it's likely in use even if it doesn't respond to our other checks
    if get_mac_from_arp(ip_address) is not None:
        logger.debug(f"IP {ip_address} has a MAC address in the system")
        return True
    
    return False


def ping_ip(ip_address: str, timeout: float = 1.0) -> bool:
    """
    Check if an IP address responds to ping.
    
    Args:
        ip_address: The IP address to ping
        timeout: Timeout in seconds
        
    Returns:
        True if ping successful, False otherwise
    """
    try:
        # Adjust ping command based on OS
        if sys.platform == "win32":
            # Windows ping command
            ping_cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip_address]
        else:
            # Linux/macOS ping command
            ping_cmd = ["ping", "-c", "1", "-W", str(int(timeout)), ip_address]
        
        result = subprocess.run(
            ping_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout + 0.5  # Add a small buffer to the timeout
        )
        return result.returncode == 0
    except (subprocess.SubprocessError, subprocess.TimeoutExpired):
        return False


def scan_ports(ip_address: str, ports: List[int], timeout: float = 0.5) -> bool:
    """
    Check if any of the specified ports are open on the IP address.
    
    Args:
        ip_address: The IP address to scan
        ports: List of port numbers to check
        timeout: Timeout for each connection attempt in seconds
        
    Returns:
        True if any port is open, False otherwise
    """
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                result = s.connect_ex((ip_address, port))
                if result == 0:  # Port is open
                    logger.debug(f"IP {ip_address} has open port {port}")
                    return True
        except:
            pass  # Ignore any errors and continue
    
    return False


def is_in_arp_cache(ip_address: str) -> bool:
    """
    Check if an IP address is in the ARP cache.
    
    Args:
        ip_address: The IP address to check
        
    Returns:
        True if in ARP cache, False otherwise
    """
    try:
        arp_output = get_arp_output(ip_address)
        if not arp_output:
            return False
        
        # Check if we have a valid MAC address (not incomplete)
        if sys.platform in ['linux', 'darwin']:  # Linux or macOS
            if (ip_address in arp_output and 
                "incomplete" not in arp_output.lower() and 
                "no match" not in arp_output.lower()):
                return "(" not in arp_output  # Valid MAC found
        elif sys.platform == 'win32':  # Windows
            return (ip_address in arp_output and 
                    "no arp entry" not in arp_output.lower())
    except:
        pass  # If ARP check fails, assume not in cache
    
    return False


def get_mac_from_arp(ip_address: str) -> Optional[str]:
    """
    Get the MAC address from the ARP table for a given IP.
    
    Args:
        ip_address: The IP address to look up
        
    Returns:
        MAC address string if found, None otherwise
    """
    try:
        arp_output = get_arp_output(ip_address)
        if not arp_output:
            return None
        
        # Extract MAC from output (format varies by OS)
        if sys.platform in ['linux', 'darwin']:  # Linux or macOS
            # Linux/macOS format varies but generally has the MAC after the IP
            lines = arp_output.strip().split('\n')
            for line in lines:
                if ip_address in line:
                    # Look for a MAC address pattern in the line
                    parts = line.split()
                    for part in parts:
                        # Look for word that's a MAC address format
                        if re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', part):
                            return part.lower()
        elif sys.platform == 'win32':  # Windows
            # Windows format: IP  MAC  Type
            pattern = re.compile(rf'\s*{re.escape(ip_address)}\s+([0-9a-f-]+)\s+')
            match = pattern.search(arp_output)
            if match:
                # Convert Windows format (00-11-22-33-44-55) to standard (00:11:22:33:44:55)
                return match.group(1).replace('-', ':').lower()
    except Exception as e:
        logger.debug(f"Error getting MAC from ARP for {ip_address}: {e}")
        return None  # If ARP check fails, return None
    
    return None


def get_arp_output(ip_address: str) -> Optional[str]:
    """
    Get the raw ARP output for an IP address.
    
    Args:
        ip_address: The IP address to query
        
    Returns:
        ARP command output string or None if failed
    """
    try:
        if sys.platform in ['linux', 'darwin']:  # Linux or macOS
            cmd = ["arp", "-n", ip_address]
        else:  # Windows
            cmd = ["arp", "-a", ip_address]
        
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=1
        )
        return result.stdout.decode('utf-8', errors='ignore')
    except:
        return None


def scan_network_async(ip_range: Tuple[str, str], callback=None) -> Dict[str, Dict[str, Any]]:
    """
    Scan a range of IP addresses asynchronously to find devices.
    
    This function performs a quick network scan to find active devices,
    retrieve their MAC addresses, and check for open ports.
    It uses multiple threads for speed.
    
    Args:
        ip_range: Tuple with start and end IP addresses
        callback: Optional progress callback function
        
    Returns:
        Dictionary mapping IP addresses to dictionaries containing:
        - 'mac': MAC address (or None if not found)
        - 'ports': List of open ports
    """
    from ipaddress import IPv4Address
    
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
    
    def scan_worker(ip: str) -> None:
        nonlocal scanned_count
        
        # Check if IP is in use
        if is_ip_in_use(ip, timeout=0.5):
            # Try to get MAC address
            mac = get_mac_from_arp(ip)
            
            # Scan for open ports
            open_ports = scan_client_ports(ip, COMMON_PORTS)
            
            with results_lock:
                results[ip] = {
                    'mac': mac,
                    'ports': open_ports
                }
        
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
    
    return results


def scan_client_ports(ip_address: str, ports: List[int] = None) -> List[int]:
    """
    Scan specific ports on an IP address to see if they're open.
    
    This is useful for determining what kind of device is at an IP address.
    
    Args:
        ip_address: The IP address to scan
        ports: List of ports to check, or None to check common ports
        
    Returns:
        List of open port numbers
    """
    if ports is None:
        ports = COMMON_PORTS
    
    open_ports = []
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.2)  # Short timeout
                result = s.connect_ex((ip_address, port))
                if result == 0:  # Port is open
                    open_ports.append(port)
        except:
            pass  # Ignore errors and continue
    
    return open_ports


def is_same_client_requesting(mac_address: str, ip_address: str) -> bool:
    """
    Check if the device requesting an IP is the same device that currently has the IP.
    
    This is important for handling devices that are requesting their existing IP.
    
    Args:
        mac_address: The MAC address of the requesting client
        ip_address: The IP address being requested
        
    Returns:
        True if the MAC matches the device at the IP, False otherwise
    """
    current_mac = get_mac_from_arp(ip_address)
    if not current_mac:
        return False
    
    # Compare MAC addresses (case-insensitive)
    return current_mac.lower() == mac_address.lower()


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
        else:
            print("No open ports found")
        
        mac = get_mac_from_arp(test_ip)
        if mac:
            print(f"MAC address: {mac}")
        else:
            print("MAC address not found")
    else:
        print("Please provide an IP address to test")
