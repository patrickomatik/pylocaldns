#!/usr/bin/env python3
"""
Utility functions for the Network Services Server

This module contains utility functions used by both DNS and DHCP servers.
"""

import ipaddress
import logging
import socket
import fcntl
import struct
import sys
from typing import Tuple, List

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('utils')


def parse_ip_range(ip_range: str) -> Tuple[str, str]:
    """Parse an IP range string like '192.168.1.100-192.168.1.200'."""
    try:
        start, end = ip_range.split('-')
        start = start.strip()
        end = end.strip()

        # Validate IPs
        ipaddress.IPv4Address(start)
        ipaddress.IPv4Address(end)

        return start, end
    except Exception as e:
        raise ValueError(f"Invalid IP range format: {ip_range}. Expected format: '192.168.1.100-192.168.1.200'")


def get_local_ips() -> List[str]:
    """Get a list of local IP addresses for this machine."""
    ips = []
    try:
        # This is a platform-independent way to get all local IPs
        if 'fcntl' in sys.modules:  # Only available on Unix-like systems
            for interface_name in socket.if_nameindex():
                try:
                    # Skip loopback interfaces
                    if 'lo' in interface_name[1]:
                        continue

                    # Get the IP address for this interface
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    ip = socket.inet_ntoa(fcntl.ioctl(
                        s.fileno(),
                        0x8915,  # SIOCGIFADDR
                        struct.pack('256s', interface_name[1][:15].encode())
                    )[20:24])
                    s.close()

                    if ip and ip != '127.0.0.1':
                        ips.append(ip)
                except:
                    pass
        else:
            # Fallback method for Windows and other systems
            hostname = socket.gethostname()
            for ip in socket.gethostbyname_ex(hostname)[2]:
                if not ip.startswith('127.'):
                    ips.append(ip)
    except Exception as e:
        logger.debug(f"Error getting local IPs: {e}")

    # If we couldn't get any IPs, add a placeholder
    if not ips:
        ips.append('<server-ip>')

    return ips
