#!/usr/bin/env python3
"""
Models for the Network Services Server

This module contains the data models used by both DNS and DHCP services.
"""

import time
import logging

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('models')

# DNS related constants
TTL = 300  # Time to live (5 minutes)
DNS_QUERY_CLASS_IN = 1
DNS_QUERY_TYPE_A = 1  # IPv4 address record
DNS_QUERY_TYPE_AAAA = 28  # IPv6 address record
DNS_RESPONSE_FLAG = 0x8000  # Response bit in the flags
DNS_AUTHORITATIVE_FLAG = 0x0400  # Authoritative answer bit

# DHCP related constants
DHCP_SERVER_PORT = 67
DHCP_CLIENT_PORT = 68
DHCP_MAGIC_COOKIE = bytes([99, 130, 83, 99])  # Magic cookie for DHCP

# DHCP message types
DHCP_DISCOVER = 1
DHCP_OFFER = 2
DHCP_REQUEST = 3
DHCP_DECLINE = 4
DHCP_ACK = 5
DHCP_NAK = 6
DHCP_RELEASE = 7
DHCP_INFORM = 8

# DHCP options
DHCP_OPT_SUBNET_MASK = 1
DHCP_OPT_ROUTER = 3
DHCP_OPT_DNS_SERVER = 6
DHCP_OPT_HOSTNAME = 12
DHCP_OPT_REQUESTED_IP = 50
DHCP_OPT_LEASE_TIME = 51
DHCP_OPT_MSG_TYPE = 53
DHCP_OPT_SERVER_ID = 54
DHCP_OPT_PARAM_REQ_LIST = 55
DHCP_OPT_END = 255

# Default DHCP lease time (24 hours in seconds)
DEFAULT_LEASE_TIME = 86400


class DNSRecord:
    """Represents a DNS record with address, type, and TTL."""
    
    def __init__(self, address: str, record_type: int):
        self.address = address
        self.record_type = record_type
        self.ttl = TTL

    def __str__(self):
        return f"{self.address} (Type: {self.record_type}, TTL: {self.ttl})"


class DHCPLease:
    """Represents a DHCP lease with MAC address, IP address, hostname, and lease time."""
    
    def __init__(self, mac_address: str, ip_address: str, hostname: str = None, lease_time: int = DEFAULT_LEASE_TIME):
        self.mac_address = mac_address.lower()
        self.ip_address = ip_address
        self.hostname = hostname
        self.lease_time = lease_time
        self.expiry_time = time.time() + lease_time

    def is_expired(self) -> bool:
        """Check if the lease has expired."""
        return time.time() > self.expiry_time

    def renew(self, lease_time: int = None) -> None:
        """Renew the lease for the specified time or the default lease time."""
        if lease_time is None:
            lease_time = self.lease_time
        self.lease_time = lease_time
        self.expiry_time = time.time() + lease_time

    def __str__(self) -> str:
        return f"MAC: {self.mac_address}, IP: {self.ip_address}, Hostname: {self.hostname}, Expires: {time.ctime(self.expiry_time)}"
