#!/usr/bin/env python3
"""
Network Services Server - Serves DNS and DHCP requests based on a local hosts file

This application acts as both a DNS server that resolves domain names to IP addresses
and a DHCP server that assigns IP addresses to devices based on MAC addresses.
Both services use a common hosts file for configuration.

Usage:
  python network_server.py --hosts-file /path/to/hosts.txt [--dns-port 53]
                           [--dhcp-enable] [--dhcp-range 192.168.1.100-192.168.1.200]
                           [--dhcp-subnet 255.255.255.0] [--dhcp-router 192.168.1.1]
                           [--interface 0.0.0.0]
"""

import argparse
import socket
import sys
import os
import threading
import time
import re
import logging
import struct
import random
import ipaddress
from collections import defaultdict, OrderedDict
from typing import Dict, Tuple, List, Union, Optional, Set, Any

# DNS related constants
DNS_PORT = 53
DNS_QUERY_CLASS_IN = 1
DNS_QUERY_TYPE_A = 1  # IPv4 address record
DNS_QUERY_TYPE_AAAA = 28  # IPv6 address record
DNS_RESPONSE_FLAG = 0x8000  # Response bit in the flags
DNS_AUTHORITATIVE_FLAG = 0x0400  # Authoritative answer bit
TTL = 300  # Time to live (5 minutes)

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

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('network_server')


class DNSRecord:
    def __init__(self, address: str, record_type: int):
        self.address = address
        self.record_type = record_type
        self.ttl = TTL

    def __str__(self):
        return f"{self.address} (Type: {self.record_type}, TTL: {self.ttl})"


class DHCPLease:
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


class HostsFile:
    def __init__(self, file_path: str, dhcp_range: Tuple[str, str] = None):
        self.file_path = file_path
        self.last_modified = 0
        self.dns_records = defaultdict(list)  # Hostname to DNS records
        self.mac_to_ip = {}  # MAC address to IP address
        self.ip_to_hostnames = defaultdict(list)  # IP to list of hostnames

        # DHCP leases (MAC to DHCPLease objects)
        self.leases = {}

        # IP addresses reserved in the hosts file
        self.reserved_ips = set()

        # DHCP dynamic range
        self.dhcp_range = dhcp_range
        self.available_ips = set()  # IPs available for dynamic allocation
        if dhcp_range:
            self._setup_dhcp_range(dhcp_range)

        self.load_file()

    def _setup_dhcp_range(self, dhcp_range: Tuple[str, str]) -> None:
        """Setup the DHCP dynamic range of IP addresses."""
        start_ip, end_ip = dhcp_range

        # Convert to integer representations for easier range calculations
        start = int(ipaddress.IPv4Address(start_ip))
        end = int(ipaddress.IPv4Address(end_ip))

        # Create the set of available IPs
        self.available_ips = {str(ipaddress.IPv4Address(ip)) for ip in range(start, end + 1)}
        logger.info(f"DHCP range initialized with {len(self.available_ips)} addresses from {start_ip} to {end_ip}")

    def load_file(self) -> None:
        """Load the hosts file and parse its contents."""
        if not os.path.exists(self.file_path):
            logger.error(f"Hosts file not found: {self.file_path}")
            return

        try:
            # Check if the file has been modified
            current_mtime = os.path.getmtime(self.file_path)
            if current_mtime <= self.last_modified:
                return  # File hasn't changed

            logger.info(f"Loading hosts file: {self.file_path}")
            self.dns_records.clear()
            self.mac_to_ip.clear()
            self.ip_to_hostnames.clear()
            self.reserved_ips.clear()
            self.last_modified = current_mtime

            mac_pattern = re.compile(
                r'\[MAC=([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2})\]', re.IGNORECASE)

            with open(self.file_path, 'r') as f:
                for line in f:
                    # Remove comments
                    line = line.split('#', 1)[0].strip()
                    if not line:
                        continue

                    parts = line.split()
                    if len(parts) < 2:
                        continue

                    ip_address = parts[0]
                    hostnames = []
                    mac_address = None

                    # Extract MAC address if present
                    for part in parts[1:]:
                        mac_match = mac_pattern.match(part)
                        if mac_match:
                            mac_address = mac_match.group(1).lower()
                        elif part != '-':  # Skip placeholder hostnames
                            hostnames.append(part.lower())

                    # Add to reserved IPs (for DHCP)
                    if ':' not in ip_address:  # Only track IPv4 for DHCP
                        self.reserved_ips.add(ip_address)

                    # If we have a MAC address, record the MAC to IP mapping
                    if mac_address:
                        self.mac_to_ip[mac_address] = ip_address
                        logger.debug(f"Reserved IP {ip_address} for MAC {mac_address}")

                    # Record IP to hostname mapping
                    if hostnames:
                        self.ip_to_hostnames[ip_address].extend(hostnames)

                    # Determine record type (A for IPv4, AAAA for IPv6)
                    record_type = DNS_QUERY_TYPE_AAAA if ':' in ip_address else DNS_QUERY_TYPE_A

                    # Add each hostname to our DNS records
                    for hostname in hostnames:
                        hostname = hostname.lower()  # DNS lookups are case-insensitive
                        self.dns_records[hostname].append(DNSRecord(ip_address, record_type))

            # Update available IPs by removing reserved ones
            if self.dhcp_range:
                self.available_ips -= self.reserved_ips
                logger.info(f"After reservations, {len(self.available_ips)} addresses available for dynamic DHCP")

            logger.info(
                f"Loaded {len(self.dns_records)} unique hostnames and {len(self.mac_to_ip)} MAC address reservations")
        except Exception as e:
            logger.error(f"Error loading hosts file: {e}")

    def check_for_updates(self) -> None:
        """Check if the hosts file has been modified and reload if necessary."""
        if os.path.exists(self.file_path):
            current_mtime = os.path.getmtime(self.file_path)
            if current_mtime > self.last_modified:
                logger.info("Hosts file has changed, reloading...")
                self.load_file()

    def get_dns_records(self, hostname: str, record_type: int) -> List[DNSRecord]:
        """Get all matching DNS records for a hostname and record type."""
        self.check_for_updates()  # Check for file updates before each query
        result = []
        hostname = hostname.lower()  # DNS lookups are case-insensitive

        for record in self.dns_records.get(hostname, []):
            if record.record_type == record_type:
                result.append(record)

        return result

    def get_ip_for_mac(self, mac_address: str) -> Optional[str]:
        """Get the reserved IP address for a MAC address."""
        self.check_for_updates()
        return self.mac_to_ip.get(mac_address.lower())

    def get_hostnames_for_ip(self, ip_address: str) -> List[str]:
        """Get all hostnames associated with an IP address."""
        self.check_for_updates()
        return self.ip_to_hostnames.get(ip_address, [])

    def allocate_ip(self, mac_address: str) -> Optional[str]:
        """
        Allocate an IP address for a MAC address.
        First checks for a static reservation, then for an existing lease,
        and finally allocates a new IP from the pool.
        """
        mac_address = mac_address.lower()

        # Check for static reservation
        static_ip = self.get_ip_for_mac(mac_address)
        if static_ip:
            logger.info(f"Using static reservation {static_ip} for MAC {mac_address}")
            return static_ip

        # Check for existing lease
        if mac_address in self.leases and not self.leases[mac_address].is_expired():
            lease = self.leases[mac_address]
            logger.info(f"Using existing lease {lease.ip_address} for MAC {mac_address}")
            return lease.ip_address

        # Allocate from pool if available
        if not self.available_ips:
            logger.warning(f"No available IP addresses for MAC {mac_address}")
            return None

        # Remove any IPs that are currently leased
        leased_ips = {lease.ip_address for lease in self.leases.values() if not lease.is_expired()}
        available = self.available_ips - leased_ips

        if not available:
            logger.warning(f"All IP addresses in pool are leased, no address available for MAC {mac_address}")
            return None

        # Choose a random IP from the available pool
        ip_address = random.choice(list(available))
        logger.info(f"Allocated new IP {ip_address} for MAC {mac_address}")
        return ip_address

    def add_or_update_lease(self, mac_address: str, ip_address: str, hostname: str = None,
                            lease_time: int = DEFAULT_LEASE_TIME) -> DHCPLease:
        """Add or update a DHCP lease."""
        mac_address = mac_address.lower()
        lease = DHCPLease(mac_address, ip_address, hostname, lease_time)
        self.leases[mac_address] = lease
        logger.info(f"Added/updated lease: {lease}")
        return lease

    def get_lease(self, mac_address: str) -> Optional[DHCPLease]:
        """Get the current lease for a MAC address."""
        mac_address = mac_address.lower()
        lease = self.leases.get(mac_address)

        if lease and lease.is_expired():
            logger.info(f"Lease for MAC {mac_address} has expired")
            return None

        return lease

    def release_lease(self, mac_address: str) -> None:
        """Release a DHCP lease."""
        mac_address = mac_address.lower()
        if mac_address in self.leases:
            logger.info(f"Released lease for MAC {mac_address}")
            del self.leases[mac_address]

    def cleanup_expired_leases(self) -> None:
        """Remove expired leases."""
        expired = [mac for mac, lease in self.leases.items() if lease.is_expired()]
        for mac in expired:
            logger.info(f"Removing expired lease for MAC {mac}")
            del self.leases[mac]

        if expired:
            logger.info(f"Cleaned up {len(expired)} expired leases")


class DNSServer:
    def __init__(self, hosts_file: HostsFile, port: int = DNS_PORT, interface: str = '0.0.0.0'):
        self.hosts = hosts_file
        self.port = port
        self.interface = interface
        self.sock = None
        self.running = False

    def start(self) -> None:
        """Start the DNS server."""
        # Create UDP socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        try:
            self.sock.bind((self.interface, self.port))
            logger.info(f"DNS Server started on {self.interface}:{self.port}")
            self.running = True

            while self.running:
                try:
                    data, addr = self.sock.recvfrom(512)  # Standard DNS message size
                    threading.Thread(target=self.handle_query, args=(data, addr)).start()
                except Exception as e:
                    logger.error(f"Error receiving data: {e}")

        except PermissionError:
            logger.error(f"Permission denied. To bind to port {self.port}, you need root privileges.")
            sys.exit(1)
        except OSError as e:
            logger.error(f"Error binding to {self.interface}:{self.port} - {e}")
            sys.exit(1)
        finally:
            if self.sock:
                self.sock.close()

    def stop(self) -> None:
        """Stop the DNS server."""
        self.running = False
        if self.sock:
            self.sock.close()
            self.sock = None
        logger.info("DNS Server stopped")

    def parse_query(self, data: bytes) -> Tuple[int, str, int, int]:
        """
        Parse a DNS query packet.
        Returns: (transaction_id, question_domain, question_type, question_class)
        """
        # Extract transaction ID (first 2 bytes)
        transaction_id = (data[0] << 8) + data[1]

        # Skip the header (12 bytes) to get to the question section
        question_start = 12

        # Parse domain name (sequence of labels)
        domain_parts = []
        position = question_start

        while True:
            length = data[position]
            if length == 0:
                position += 1
                break

            position += 1
            domain_parts.append(data[position:position + length].decode('utf-8'))
            position += length

        domain_name = '.'.join(domain_parts)

        # Get question type and class (2 bytes each)
        question_type = (data[position] << 8) + data[position + 1]
        position += 2

        question_class = (data[position] << 8) + data[position + 1]

        return transaction_id, domain_name, question_type, question_class

    def create_response(self, query_data: bytes, transaction_id: int,
                        domain: str, query_type: int, records: List[DNSRecord]) -> bytes:
        """Create a DNS response packet."""
        # Start with the original query
        response = bytearray(query_data)

        # Set QR bit to indicate this is a response
        response[2] |= (DNS_RESPONSE_FLAG >> 8)  # Set QR bit in flags

        # Set AA bit to indicate this is an authoritative answer
        response[2] |= (DNS_AUTHORITATIVE_FLAG >> 8)

        # Set ANCOUNT (answer count) - 2 bytes starting at offset 6
        num_answers = len(records)
        response[6] = (num_answers >> 8) & 0xFF
        response[7] = num_answers & 0xFF

        # Find where the question ends to start adding answers
        # Skip to the first byte after the header (12 bytes)
        position = 12

        # Skip the QNAME
        while True:
            length = response[position]
            if length == 0:
                position += 1
                break
            position += (length + 1)

        # Skip QTYPE and QCLASS (4 bytes)
        position += 4

        # Add each answer
        for record in records:
            # Add a pointer to the domain name in the question section
            response.extend(b'\xC0\x0C')  # Pointer to the domain name at offset 12

            # Add the TYPE (A=1, AAAA=28)
            response.extend(query_type.to_bytes(2, byteorder='big'))

            # Add the CLASS (IN=1)
            response.extend(DNS_QUERY_CLASS_IN.to_bytes(2, byteorder='big'))

            # Add the TTL (4 bytes)
            response.extend(record.ttl.to_bytes(4, byteorder='big'))

            # Add the RDLENGTH and RDATA
            if query_type == DNS_QUERY_TYPE_A:  # IPv4
                # RDLENGTH - 4 bytes for IPv4
                response.extend(b'\x00\x04')
                # RDATA - IPv4 address in bytes
                octets = [int(octet) for octet in record.address.split('.')]
                response.extend(bytes(octets))
            elif query_type == DNS_QUERY_TYPE_AAAA:  # IPv6
                # RDLENGTH - 16 bytes for IPv6
                response.extend(b'\x00\x10')
                # RDATA - IPv6 address in bytes
                response.extend(socket.inet_pton(socket.AF_INET6, record.address))

        return bytes(response)

    def handle_query(self, data: bytes, client_addr: Tuple[str, int]) -> None:
        """Handle an incoming DNS query."""
        try:
            transaction_id, domain, query_type, query_class = self.parse_query(data)

            logger.info(f"DNS query from {client_addr[0]}:{client_addr[1]} - Domain: {domain}, "
                        f"Type: {query_type}, Class: {query_class}")

            # Only handle IN class queries for A and AAAA records
            if query_class != DNS_QUERY_CLASS_IN or query_type not in (DNS_QUERY_TYPE_A, DNS_QUERY_TYPE_AAAA):
                logger.warning(f"Unsupported query type {query_type} or class {query_class}")
                return

            # Get matching records for the domain and query type
            records = self.hosts.get_dns_records(domain, query_type)

            if not records:
                logger.info(f"No records found for {domain}")
                # Send a response with ANCOUNT=0 (we use the original query with QR bit set)
                response = bytearray(data)
                response[2] |= (DNS_RESPONSE_FLAG >> 8)  # Set QR bit in flags
                self.sock.sendto(bytes(response), client_addr)
                return

            # Create and send the response
            response = self.create_response(data, transaction_id, domain, query_type, records)
            self.sock.sendto(response, client_addr)

            logger.info(f"Responded to {client_addr[0]}:{client_addr[1]} with {len(records)} records for {domain}")

        except Exception as e:
            logger.error(f"Error handling DNS query: {e}")


class DHCPServer:
    def __init__(self, hosts_file: HostsFile, interface: str = '0.0.0.0',
                 subnet_mask: str = '255.255.255.0', router: str = None,
                 dns_servers: List[str] = None, lease_time: int = DEFAULT_LEASE_TIME):
        self.hosts = hosts_file
        self.interface = interface
        self.subnet_mask = subnet_mask
        self.router = router
        self.dns_servers = dns_servers or ['8.8.8.8', '8.8.4.4']  # Default to Google DNS
        self.lease_time = lease_time
        self.sock = None
        self.running = False
        self.server_id = None  # Will be set to the server's IP address

    def start(self) -> None:
        """Start the DHCP server."""
        # Create UDP socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            self.sock.bind((self.interface, DHCP_SERVER_PORT))

            # Get the server's IP address for server identifier option
            if self.interface == '0.0.0.0':
                # Attempt to get the primary interface IP
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                try:
                    # This doesn't actually establish a connection
                    s.connect(('8.8.8.8', 53))
                    self.server_id = s.getsockname()[0]
                except Exception:
                    self.server_id = '127.0.0.1'  # Fallback to localhost
                finally:
                    s.close()
            else:
                self.server_id = self.interface

            if not self.router:
                # Use the server's IP as the default gateway if not specified
                self.router = self.server_id

            logger.info(f"DHCP Server started on {self.interface}:{DHCP_SERVER_PORT} with server ID {self.server_id}")
            self.running = True

            # Start a thread to clean up expired leases periodically
            cleanup_thread = threading.Thread(target=self._cleanup_leases_thread, daemon=True)
            cleanup_thread.start()

            while self.running:
                try:
                    data, addr = self.sock.recvfrom(1024)
                    threading.Thread(target=self.handle_dhcp_packet, args=(data, addr)).start()
                except Exception as e:
                    logger.error(f"Error receiving DHCP data: {e}")

        except PermissionError:
            logger.error(f"Permission denied. To bind to port {DHCP_SERVER_PORT}, you need root privileges.")
            sys.exit(1)
        except OSError as e:
            logger.error(f"Error binding to {self.interface}:{DHCP_SERVER_PORT} - {e}")
            sys.exit(1)
        finally:
            if self.sock:
                self.sock.close()

    def stop(self) -> None:
        """Stop the DHCP server."""
        self.running = False
        if self.sock:
            self.sock.close()
            self.sock = None
        logger.info("DHCP Server stopped")

    def _cleanup_leases_thread(self) -> None:
        """Thread that periodically cleans up expired leases."""
        while self.running:
            try:
                self.hosts.cleanup_expired_leases()
                time.sleep(60)  # Check every minute
            except Exception as e:
                logger.error(f"Error in lease cleanup thread: {e}")

    def parse_dhcp_packet(self, data: bytes) -> Dict[str, Any]:
        """Parse a DHCP packet and return a dictionary of fields."""
        if len(data) < 240:  # Minimum DHCP packet size
            raise ValueError("Packet too small to be a valid DHCP packet")

        result = {}

        # Standard DHCP fields
        result['op'] = data[0]  # Message op code (1=request, 2=reply)
        result['htype'] = data[1]  # Hardware address type (1=Ethernet)
        result['hlen'] = data[2]  # Hardware address length (6 for Ethernet)
        result['hops'] = data[3]  # Hops
        result['xid'] = struct.unpack('!I', data[4:8])[0]  # Transaction ID
        result['secs'] = struct.unpack('!H', data[8:10])[0]  # Seconds elapsed
        result['flags'] = struct.unpack('!H', data[10:12])[0]  # Flags
        result['ciaddr'] = socket.inet_ntoa(data[12:16])  # Client IP address
        result['yiaddr'] = socket.inet_ntoa(data[16:20])  # Your (client) IP address
        result['siaddr'] = socket.inet_ntoa(data[20:24])  # Server IP address
        result['giaddr'] = socket.inet_ntoa(data[24:28])  # Relay agent IP address

        # Client hardware address (MAC)
        mac_bytes = data[28:28 + result['hlen']]
        result['chaddr'] = ':'.join(f'{b:02x}' for b in mac_bytes)

        # Check for DHCP magic cookie
        if data[236:240] != DHCP_MAGIC_COOKIE:
            raise ValueError("Invalid DHCP packet: missing magic cookie")

        # Parse options
        result['options'] = {}
        i = 240

        while i < len(data):
            if data[i] == DHCP_OPT_END:
                break

            if data[i] == 0:  # Padding
                i += 1
                continue

            if i + 1 >= len(data):
                break  # Avoid out of bounds

            opt_code = data[i]
            opt_len = data[i + 1]
            opt_data = data[i + 2:i + 2 + opt_len]

            # Process some common options
            if opt_code == DHCP_OPT_MSG_TYPE and opt_len == 1:
                result['options']['message_type'] = opt_data[0]
            elif opt_code == DHCP_OPT_REQUESTED_IP and opt_len == 4:
                result['options']['requested_ip'] = socket.inet_ntoa(opt_data)
            elif opt_code == DHCP_OPT_SERVER_ID and opt_len == 4:
                result['options']['server_id'] = socket.inet_ntoa(opt_data)
            elif opt_code == DHCP_OPT_HOSTNAME:
                result['options']['hostname'] = opt_data.decode('utf-8', errors='ignore')
            elif opt_code == DHCP_OPT_PARAM_REQ_LIST:
                result['options']['param_req_list'] = list(opt_data)

            i += 2 + opt_len

        return result

    def create_dhcp_packet(self, message_type: int, xid: int, chaddr: bytes,
                           yiaddr: str = '0.0.0.0', options: List[Tuple[int, bytes]] = None) -> bytes:
        """Create a DHCP packet."""
        # Convert MAC address string to bytes if needed
        if isinstance(chaddr, str):
            chaddr = bytes.fromhex(chaddr.replace(':', ''))

        # Basic packet structure
        packet = bytearray(240)  # Basic header size before options

        # Header
        packet[0] = 2  # BOOTREPLY
        packet[1] = 1  # Ethernet
        packet[2] = 6  # Ethernet MAC length
        packet[3] = 0  # Hops
        packet[4:8] = struct.pack('!I', xid)  # Transaction ID
        packet[8:10] = struct.pack('!H', 0)  # Secs
        packet[10:12] = struct.pack('!H', 0)  # Flags
        packet[12:16] = socket.inet_aton('0.0.0.0')  # ciaddr
        packet[16:20] = socket.inet_aton(yiaddr)  # yiaddr
        packet[20:24] = socket.inet_aton(self.server_id)  # siaddr
        packet[24:28] = socket.inet_aton('0.0.0.0')  # giaddr

        # Copy MAC address to chaddr field
        for i in range(min(16, len(chaddr))):
            packet[28 + i] = chaddr[i]

        # Server hostname and boot filename (left empty)

        # DHCP magic cookie
        packet[236:240] = DHCP_MAGIC_COOKIE

        # Add message type option
        packet.extend([DHCP_OPT_MSG_TYPE, 1, message_type])

        # Add server identifier
        packet.extend([DHCP_OPT_SERVER_ID, 4])
        packet.extend(socket.inet_aton(self.server_id))

        # Add other options
        if options:
            for code, data in options:
                packet.extend([code, len(data)])
                packet.extend(data)

        # End option
        packet.append(DHCP_OPT_END)

        return bytes(packet)

    def create_dhcp_offer(self, request: Dict[str, Any], offer_ip: str) -> bytes:
        """Create a DHCP offer packet."""
        options = []

        # Lease time
        options.append((DHCP_OPT_LEASE_TIME, struct.pack('!I', self.lease_time)))

        # Subnet mask
        options.append((DHCP_OPT_SUBNET_MASK, socket.inet_aton(self.subnet_mask)))

        # Router (gateway)
        if self.router:
            options.append((DHCP_OPT_ROUTER, socket.inet_aton(self.router)))

        # DNS servers
        if self.dns_servers:
            dns_bytes = b''.join(socket.inet_aton(ip) for ip in self.dns_servers)
            options.append((DHCP_OPT_DNS_SERVER, dns_bytes))

        return self.create_dhcp_packet(
            message_type=DHCP_OFFER,
            xid=request['xid'],
            chaddr=bytes.fromhex(request['chaddr'].replace(':', '')),
            yiaddr=offer_ip,
            options=options
        )

    def create_dhcp_ack(self, request: Dict[str, Any], assigned_ip: str) -> bytes:
        """Create a DHCP ACK packet."""
        options = []

        # Lease time
        options.append((DHCP_OPT_LEASE_TIME, struct.pack('!I', self.lease_time)))

        # Subnet mask
        options.append((DHCP_OPT_SUBNET_MASK, socket.inet_aton(self.subnet_mask)))

        # Router (gateway)
        if self.router:
            options.append((DHCP_OPT_ROUTER, socket.inet_aton(self.router)))

        # DNS servers
        if self.dns_servers:
            dns_bytes = b''.join(socket.inet_aton(ip) for ip in self.dns_servers)
            options.append((DHCP_OPT_DNS_SERVER, dns_bytes))

        return self.create_dhcp_packet(
            message_type=DHCP_ACK,
            xid=request['xid'],
            chaddr=bytes.fromhex(request['chaddr'].replace(':', '')),
            yiaddr=assigned_ip,
            options=options
        )

    def create_dhcp_nak(self, request: Dict[str, Any]) -> bytes:
        """Create a DHCP NAK packet."""
        return self.create_dhcp_packet(
            message_type=DHCP_NAK,
            xid=request['xid'],
            chaddr=bytes.fromhex(request['chaddr'].replace(':', '')),
            options=[]
        )

    def handle_dhcp_discover(self, request: Dict[str, Any], client_addr: Tuple[str, int]) -> None:
        """Handle a DHCP DISCOVER message."""
        mac_address = request['chaddr']
        logger.info(f"DHCP DISCOVER from MAC {mac_address}")

        # Allocate an IP address for this client
        offer_ip = self.hosts.allocate_ip(mac_address)

        if not offer_ip:
            logger.warning(f"No IP available to offer to {mac_address}")
            return

        logger.info(f"Offering IP {offer_ip} to MAC {mac_address}")

        # Create and send DHCP OFFER
        offer_packet = self.create_dhcp_offer(request, offer_ip)

        # Send to broadcast or directly to client
        if client_addr[0] == '0.0.0.0' or request['flags'] & 0x8000:  # Broadcast bit set
            self.sock.sendto(offer_packet, ('255.255.255.255', DHCP_CLIENT_PORT))
        else:
            self.sock.sendto(offer_packet, (client_addr[0], DHCP_CLIENT_PORT))

    def handle_dhcp_request(self, request: Dict[str, Any], client_addr: Tuple[str, int]) -> None:
        """Handle a DHCP REQUEST message."""
        mac_address = request['chaddr']

        # Check if this request is for us
        if 'server_id' in request['options']:
            server_id = request['options']['server_id']
            if server_id != self.server_id:
                logger.debug(f"DHCP REQUEST for another server {server_id}, ignoring")
                return

        # Get the requested IP
        requested_ip = request['options'].get('requested_ip') or request['ciaddr']
        if requested_ip == '0.0.0.0':
            logger.warning(f"DHCP REQUEST without IP from {mac_address}")
            # Send NAK
            nak_packet = self.create_dhcp_nak(request)
            self.sock.sendto(nak_packet, ('255.255.255.255', DHCP_CLIENT_PORT))
            return

        logger.info(f"DHCP REQUEST from MAC {mac_address} for IP {requested_ip}")

        # Check if this IP is valid for this client
        static_ip = self.hosts.get_ip_for_mac(mac_address)

        if static_ip and static_ip != requested_ip:
            # Client is requesting an IP that doesn't match its static assignment
            logger.warning(f"Client {mac_address} requested {requested_ip} but has static IP {static_ip}")
            nak_packet = self.create_dhcp_nak(request)
            self.sock.sendto(nak_packet, ('255.255.255.255', DHCP_CLIENT_PORT))
            return

        # For dynamic IPs, check if it's a valid allocation
        if not static_ip:
            # Check if client has an existing lease
            existing_lease = self.hosts.get_lease(mac_address)

            if existing_lease and existing_lease.ip_address != requested_ip:
                # Client is requesting a different IP than its current lease
                logger.warning(
                    f"Client {mac_address} requested {requested_ip} but has lease for {existing_lease.ip_address}")
                nak_packet = self.create_dhcp_nak(request)
                self.sock.sendto(nak_packet, ('255.255.255.255', DHCP_CLIENT_PORT))
                return

            # If no existing lease, check if the IP is in the available pool
            if not existing_lease and requested_ip not in self.hosts.available_ips:
                logger.warning(f"Client {mac_address} requested unavailable IP {requested_ip}")
                nak_packet = self.create_dhcp_nak(request)
                self.sock.sendto(nak_packet, ('255.255.255.255', DHCP_CLIENT_PORT))
                return

        # Get hostname if provided
        hostname = request['options'].get('hostname')

        # Update or create the lease
        self.hosts.add_or_update_lease(mac_address, requested_ip, hostname, self.lease_time)

        # Send ACK
        logger.info(f"Acknowledging IP {requested_ip} to MAC {mac_address}")
        ack_packet = self.create_dhcp_ack(request, requested_ip)

        # Send to broadcast or directly to client
        if client_addr[0] == '0.0.0.0' or request['flags'] & 0x8000:  # Broadcast bit set
            self.sock.sendto(ack_packet, ('255.255.255.255', DHCP_CLIENT_PORT))
        else:
            self.sock.sendto(ack_packet, (client_addr[0], DHCP_CLIENT_PORT))

    def handle_dhcp_release(self, request: Dict[str, Any]) -> None:
        """Handle a DHCP RELEASE message."""
        mac_address = request['chaddr']
        ip_address = request['ciaddr']

        logger.info(f"DHCP RELEASE from MAC {mac_address} for IP {ip_address}")

        # Check if this is a static IP
        static_ip = self.hosts.get_ip_for_mac(mac_address)
        if static_ip:
            logger.info(f"Ignoring release for static IP {ip_address} from MAC {mac_address}")
            return

        # Release the lease
        self.hosts.release_lease(mac_address)

    def handle_dhcp_inform(self, request: Dict[str, Any], client_addr: Tuple[str, int]) -> None:
        """Handle a DHCP INFORM message."""
        mac_address = request['chaddr']
        ip_address = request['ciaddr']

        logger.info(f"DHCP INFORM from MAC {mac_address} at IP {ip_address}")

        # Create ACK with network configuration, but no IP assignment
        options = []

        # Subnet mask
        options.append((DHCP_OPT_SUBNET_MASK, socket.inet_aton(self.subnet_mask)))

        # Router (gateway)
        if self.router:
            options.append((DHCP_OPT_ROUTER, socket.inet_aton(self.router)))

        # DNS servers
        if self.dns_servers:
            dns_bytes = b''.join(socket.inet_aton(ip) for ip in self.dns_servers)
            options.append((DHCP_OPT_DNS_SERVER, dns_bytes))

        ack_packet = self.create_dhcp_packet(
            message_type=DHCP_ACK,
            xid=request['xid'],
            chaddr=bytes.fromhex(request['chaddr'].replace(':', '')),
            options=options
        )

        # Send directly to client
        self.sock.sendto(ack_packet, (client_addr[0], DHCP_CLIENT_PORT))

    def handle_dhcp_packet(self, data: bytes, client_addr: Tuple[str, int]) -> None:
        """Handle a DHCP packet."""
        try:
            request = self.parse_dhcp_packet(data)

            # Only respond to BOOTREQUEST (op=1)
            if request['op'] != 1:
                return

            # Get message type
            message_type = request['options'].get('message_type')
            if not message_type:
                logger.warning("DHCP packet without message type, ignoring")
                return

            # Process based on message type
            if message_type == DHCP_DISCOVER:
                self.handle_dhcp_discover(request, client_addr)
            elif message_type == DHCP_REQUEST:
                self.handle_dhcp_request(request, client_addr)
            elif message_type == DHCP_RELEASE:
                self.handle_dhcp_release(request)
            elif message_type == DHCP_INFORM:
                self.handle_dhcp_inform(request, client_addr)
            else:
                logger.debug(f"Ignoring DHCP message type {message_type}")

        except Exception as e:
            logger.error(f"Error handling DHCP packet: {e}")


class NetworkServer:
    """Combined DNS and DHCP server."""

    def __init__(self, hosts_file: HostsFile, dns_port: int = DNS_PORT,
                 interface: str = '0.0.0.0', dhcp_enable: bool = False,
                 subnet_mask: str = '255.255.255.0', router: str = None,
                 dns_servers: List[str] = None):
        self.hosts = hosts_file
        self.interface = interface
        self.dns_server = DNSServer(hosts_file, dns_port, interface)

        self.dhcp_enable = dhcp_enable
        self.dhcp_server = None

        if dhcp_enable:
            self.dhcp_server = DHCPServer(
                hosts_file,
                interface,
                subnet_mask,
                router,
                dns_servers
            )

    def start(self) -> None:
        """Start the network services."""
        # Start the DNS server in a new thread
        dns_thread = threading.Thread(target=self.dns_server.start, daemon=True)
        dns_thread.start()

        # Start the DHCP server if enabled
        if self.dhcp_enable and self.dhcp_server:
            dhcp_thread = threading.Thread(target=self.dhcp_server.start, daemon=True)
            dhcp_thread.start()

        # Start a thread to monitor the hosts file for changes
        monitor_thread = threading.Thread(
            target=self._file_monitoring_thread,
            daemon=True
        )
        monitor_thread.start()

        try:
            # Keep the main thread alive
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()

    def stop(self) -> None:
        """Stop all network services."""
        logger.info("Stopping network services...")
        self.dns_server.stop()

        if self.dhcp_enable and self.dhcp_server:
            self.dhcp_server.stop()

    def _file_monitoring_thread(self) -> None:
        """Thread function to periodically check for hosts file updates."""
        while True:
            try:
                self.hosts.check_for_updates()
                time.sleep(5)  # Check every 5 seconds
            except Exception as e:
                logger.error(f"Error in file monitoring thread: {e}")


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


def main() -> None:
    parser = argparse.ArgumentParser(description='Network Server - DNS and DHCP services using a local hosts file')

    # Common arguments
    parser.add_argument('--hosts-file', required=True, help='Path to the hosts file')
    parser.add_argument('--interface', default='0.0.0.0', help='Interface to bind to (default: 0.0.0.0)')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')

    # DNS specific arguments
    parser.add_argument('--dns-port', type=int, default=DNS_PORT, help='DNS port to listen on (default: 53)')

    # DHCP specific arguments
    parser.add_argument('--dhcp-enable', action='store_true', help='Enable DHCP server')
    parser.add_argument('--dhcp-range', help='DHCP IP range (format: 192.168.1.100-192.168.1.200)')
    parser.add_argument('--dhcp-subnet', default='255.255.255.0', help='DHCP subnet mask (default: 255.255.255.0)')
    parser.add_argument('--dhcp-router', help='DHCP default gateway/router IP (default: server IP)')
    parser.add_argument('--dhcp-dns', help='DHCP DNS servers (comma-separated, default: 8.8.8.8,8.8.4.4)')
    parser.add_argument('--dhcp-lease-time', type=int, default=DEFAULT_LEASE_TIME,
                        help=f'DHCP lease time in seconds (default: {DEFAULT_LEASE_TIME})')

    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.setLevel(logging.DEBUG)

    try:
        # Process DHCP range if DHCP is enabled
        dhcp_range = None
        if args.dhcp_enable:
            if not args.dhcp_range:
                logger.error("DHCP is enabled but no IP range specified. Use --dhcp-range")
                sys.exit(1)
            dhcp_range = parse_ip_range(args.dhcp_range)

        # Process DNS servers for DHCP
        dns_servers = None
        if args.dhcp_dns:
            dns_servers = [s.strip() for s in args.dhcp_dns.split(',')]

        # Create the hosts file manager
        hosts_file = HostsFile(args.hosts_file, dhcp_range)

        # Create and start the network server
        server = NetworkServer(
            hosts_file=hosts_file,
            dns_port=args.dns_port,
            interface=args.interface,
            dhcp_enable=args.dhcp_enable,
            subnet_mask=args.dhcp_subnet,
            router=args.dhcp_router,
            dns_servers=dns_servers
        )

        logger.info("Starting network services...")
        server.start()

    except KeyboardInterrupt:
        logger.info("Keyboard interrupt received, shutting down...")
        if 'server' in locals():
            server.stop()
    except Exception as e:
        logger.error(f"Unhandled exception: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()