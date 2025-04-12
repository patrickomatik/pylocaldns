#!/usr/bin/env python3
"""
Port Scanning Utilities

This module provides functions for scanning ports on network devices
and identifying open services.
"""

import socket
import logging
import threading
from typing import List, Dict, Any, Optional

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('port_scanner')

# Import port database if available
try:
    from port_database import get_port_db
except ImportError:
    logger.warning("Port database module not available; port data will not be stored persistently")
    get_port_db = lambda: None

# Common ports to check for active services
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
    
    # If we have a database, check if we have recent data
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


def get_service_name(port: int) -> Optional[str]:
    """
    Get the service name for a port number.
    
    Args:
        port: The port number
        
    Returns:
        Service name or None if not known
    """
    return PORT_SERVICES.get(port)


if __name__ == "__main__":
    # Example usage
    import sys
    
    if len(sys.argv) > 1:
        test_ip = sys.argv[1]
        print(f"Testing IP: {test_ip}")
        
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
