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
import time
from datetime import datetime
from typing import List, Dict, Optional, Set, Tuple, Any
from ipaddress import IPv4Address

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('ip_utils')

# Import our port database module
try:
    from port_database import get_port_db
except ImportError:
    logger.warning("Port database module not available; port data will not be stored persistently")
    get_port_db = lambda: None

# Common ports to check for active devices
COMMON_PORTS = [
    # Web servers
    80, 443, 8080, 8443, 8000, 8081, 8181, 3000, 4000, 8082, 9000, 9001, 9090, 9091, 8888, 8889,
    # Remote access
    22, 23, 3389, 5900, 5901, 5800, 5000, 5001, 2222, 2200, 222,
    # Windows services
    445, 139, 135, 389, 636, 3268, 3269, 88, 464, 49152, 49153, 49154,
    # Email and messaging
    25, 587, 465, 110, 143, 993, 995, 389, 1025, 1026, 1027, 1028, 1029,
    # File transfer
    21, 115, 990, 989, 2049, 20, 989, 990,
    # Databases
    1433, 3306, 5432, 6379, 27017, 9200, 1521, 1830, 50000, 1010, 1011, 1012, 1158, 5984, 5985, 7474, 7687,
    # IoT and smart home
    1883, 8883, 5683, 5684, 8086, 8087, 8088, 8089, 8090, 8091, 8092, 8093, 8094, 8095, 8123, 8124, 8125,
    # Media streaming
    8096, 32400, 8123, 554, 1900, 8200, 8201, 8202, 8203, 8204, 8205, 8206, 8207, 8208, 8209, 9777, 9876, 9080, 9081,
    # Print services
    631, 515, 9100, 9101, 9102, 9103, 9104, 9105, 9106, 9107, 9108, 9109,
    # Network services
    53, 67, 68, 123, 161, 162, 1900, 5353, 49152, 49153, 49154, 49155, 49156, 49157, 49158, 49159, 49160, 5060, 5061,
    # VPN and routing
    500, 4500, 1194, 51820, 1701, 1723, 1724, 4500, 500, 4400, 4401, 4402, 4403,
    # Game servers
    25565, 27015, 7777, 7778, 7779, 7780, 7781, 7782, 7783, 7784, 7785, 7786, 7787, 7788, 7789, 7790, 7791, 3478, 3479, 3480, 3724,
    # Monitoring
    9090, 9091, 9092, 9093, 9094, 9095, 9096, 9097, 9098, 9099, 3000, 3001, 3002, 3003, 3004, 3005, 3006, 3007, 3008, 3009,
    # Container platforms
    2375, 2376, 2377, 4243, 4244, 4245, 4246, 4247, 4248, 4249, 4250, 8086, 10250, 10251, 10252, 10253, 10254, 10255, 10256, 10257, 10258, 10259,
    # Additional common services
    111, 179, 427, 548, 902, 5009, 5222, 5269, 6000, 6001, 6002, 6003, 6004, 6005, 6006, 6007, 6008, 6009
]

# Map of port numbers to service names
PORT_SERVICES = {
    20: "FTP (Data)",
    21: "FTP (Control)",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP (Server)",
    68: "DHCP (Client)",
    80: "HTTP",
    88: "Kerberos",
    110: "POP3",
    111: "NFS/RPC",
    115: "SFTP",
    119: "NNTP",
    123: "NTP",
    135: "RPC",
    137: "NetBIOS Name",
    138: "NetBIOS Datagram",
    139: "NetBIOS Session",
    143: "IMAP",
    161: "SNMP",
    162: "SNMP Trap",
    179: "BGP",
    389: "LDAP",
    427: "SLP",
    443: "HTTPS",
    445: "SMB/CIFS",
    464: "Kerberos",
    465: "SMTPS",
    500: "IKE/IPsec",
    515: "LPD/LPR",
    548: "AFP",
    554: "RTSP",
    587: "SMTP (Submission)",
    631: "IPP",
    636: "LDAPS",
    989: "FTPS (Data)",
    990: "FTPS (Control)",
    993: "IMAPS",
    995: "POP3S",
    1194: "OpenVPN",
    1433: "MS SQL",
    1521: "Oracle DB",
    1701: "L2TP",
    1723: "PPTP",
    1883: "MQTT",
    1900: "UPNP",
    2049: "NFS",
    2082: "cPanel",
    2083: "cPanel SSL",
    2222: "SSH (Alt)",
    2375: "Docker API",
    2376: "Docker API (SSL)",
    3000: "Grafana",
    3306: "MySQL",
    3389: "RDP",
    3724: "Blizzard Games",
    3478: "STUN/TURN",
    5000: "UPnP",
    5001: "Synology DSM",
    5060: "SIP",
    5222: "XMPP",
    5353: "mDNS",
    5432: "PostgreSQL",
    5683: "CoAP",
    5900: "VNC",
    5984: "CouchDB",
    6379: "Redis",
    6881: "BitTorrent",
    8000: "Web Alt",
    8080: "HTTP Proxy",
    8083: "Proxy",
    8086: "InfluxDB",
    8096: "Jellyfin",
    8123: "Home Assistant",
    8443: "HTTPS Alt",
    8883: "MQTT (SSL)",
    9000: "Portainer",
    9090: "Prometheus",
    9091: "Transmission",
    9100: "Printer Job",
    9200: "Elasticsearch",
    27017: "MongoDB",
    32400: "Plex",
    51820: "WireGuard"
}


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


def scan_network_async(ip_range: Tuple[str, str], callback=None, use_db=True, scan_name=None) -> Dict[str, Dict[str, Any]]:
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
                        if port in PORT_SERVICES:
                            port_services[port] = PORT_SERVICES[port]
                    
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


def scan_client_ports(ip_address: str, ports: List[int] = None, timeout: float = 0.2, max_ports: int = 30) -> List[int]:
    """
    Scan specific ports on an IP address to see if they're open.
    
    This is useful for determining what kind of device is at an IP address.
    
    Args:
        ip_address: The IP address to scan
        ports: List of ports to check, or None to check common ports
        timeout: Timeout for each connection attempt in seconds
        max_ports: Maximum number of ports to return (to avoid overloading the UI)
        
    Returns:
        List of open port numbers
    """
    db = get_port_db()
    
    # If we have a database, check if we already have recent port data
    # Skip this for now as we're having issues with timestamps
    use_cached_data = False
    
    if use_cached_data and db:
        try:
            device = db.get_device(ip_address)
            if device:
                # Get ports for this device
                port_data = db.get_ports_for_device(ip_address)
                if port_data:
                    # Just use the port data we have
                    logger.debug(f"Using cached port data for {ip_address} from database")
                    return [port['port_number'] for port in port_data]
        except Exception as e:
            logger.warning(f"Error retrieving port data from database for {ip_address}: {e}")
    
    # Otherwise, perform the scan
    if ports is None:
        ports = COMMON_PORTS
    
    # Use threading to speed up the scan
    open_ports = []
    open_ports_lock = threading.Lock()
    
    def check_port(port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)  # Short timeout
                result = s.connect_ex((ip_address, port))
                if result == 0:  # Port is open
                    with open_ports_lock:
                        open_ports.append(port)
                        
                        # Update the database if available
                        if db:
                            try:
                                service_name = PORT_SERVICES.get(port)
                                db.add_or_update_port(ip_address, port, service_name)
                            except Exception as e:
                                logger.error(f"Error updating port database for {ip_address}:{port}: {e}")
        except:
            pass  # Ignore errors and continue
    
    # Create and start threads (max 20 threads at a time to avoid overwhelming the network)
    threads = []
    max_threads = 20
    
    for port in ports:
        thread = threading.Thread(target=check_port, args=(port,))
        thread.daemon = True
        threads.append(thread)
        thread.start()
        
        # Limit concurrent threads
        if len(threads) >= max_threads:
            for t in threads:
                t.join(timeout=0.1)
            threads = [t for t in threads if t.is_alive()]
    
    # Wait for all threads to complete
    for t in threads:
        t.join()
    
    # Sort the ports and limit to max_ports
    sorted_ports = sorted(open_ports)
    if max_ports > 0 and len(sorted_ports) > max_ports:
        logger.info(f"Found {len(sorted_ports)} open ports on {ip_address}, limiting to {max_ports} most common ones")
        # Prioritize common service ports over high-numbered ports
        # Create a scoring function based on port commonality
        def port_score(port):
            # Known common service ports get higher priority (lower score = higher priority)
            if port in [80, 443, 22, 21, 25, 53, 110, 143, 3389, 445, 139, 8080]:
                return 0
            elif port < 1024:  # Well-known ports
                return 1
            elif port < 10000:  # Registered ports
                return 2
            else:  # Dynamic/private ports
                return 3
        
        # Sort by score and then by port number
        return sorted(sorted_ports, key=lambda p: (port_score(p), p))[:max_ports]
    
    return sorted_ports


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


def get_device_ports_from_db(ip_address: str) -> List[int]:
    """
    Get open ports for a device from the database.
    
    Args:
        ip_address: The IP address to look up
        
    Returns:
        List of port numbers or empty list if not found
    """
    db = get_port_db()
    if not db:
        return []
    
    try:
        ports = db.get_ports_for_device(ip_address)
        return [port['port_number'] for port in ports] if ports else []
    except Exception as e:
        logger.error(f"Error getting ports from database for {ip_address}: {e}")
        return []


def get_active_devices_with_ports() -> Dict[str, Dict[str, Any]]:
    """
    Get all active devices with their open ports from the database.
    
    Returns:
        Dictionary mapping IP addresses to device info and ports
    """
    db = get_port_db()
    if not db:
        return {}
    
    try:
        devices = db.get_all_devices_with_ports()
        result = {}
        
        for device in devices:
            ip = device['ip_address']
            result[ip] = {
                'mac': device['mac_address'],
                'hostname': device['hostname'],
                'first_seen': device['first_seen'],
                'last_seen': device['last_seen'],
                'ports': [port['port_number'] for port in device['ports']]
            }
        
        return result
    except Exception as e:
        logger.error(f"Error getting devices with ports from database: {e}")
        return {}


def refresh_port_data(ip_address: str, force=False) -> List[int]:
    """
    Refresh port data for a device in the database.
    
    Args:
        ip_address: The IP address of the device
        force: If True, do a fresh scan even if we have recent data
        
    Returns:
        List of open port numbers
    """
    if not force:
        # Check if we have recent data
        ports = get_device_ports_from_db(ip_address)
        if ports:
            return ports
    
    # Do a fresh scan
    return scan_client_ports(ip_address)


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
            device = db.get_device_with_ports(test_ip)
            if device:
                print(f"Device in database: {device['ip_address']} ({device['mac_address']})")
                print(f"Last seen: {device['last_seen']}")
                print(f"Open ports in database: {', '.join(str(p['port_number']) for p in device['ports'])}")
    else:
        print("Please provide an IP address to test")
