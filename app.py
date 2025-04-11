#!/usr/bin/env python3
"""
Simple DNS Server - Serves DNS requests based on a local hosts file

This application acts as a DNS server that resolves domain names to IP addresses
using a locally managed hosts file. It supports both IPv4 and IPv6 addresses.

Usage:
  python dns_server.py --hosts-file /path/to/hosts.txt [--port 53] [--interface 0.0.0.0]
"""

import argparse
import socket
import sys
import os
import threading
import time
import re
import logging
from collections import defaultdict
from typing import Dict, Tuple, List, Union, Optional

# DNS related constants
DNS_PORT = 53
DNS_QUERY_CLASS_IN = 1
DNS_QUERY_TYPE_A = 1  # IPv4 address record
DNS_QUERY_TYPE_AAAA = 28  # IPv6 address record
DNS_RESPONSE_FLAG = 0x8000  # Response bit in the flags
DNS_AUTHORITATIVE_FLAG = 0x0400  # Authoritative answer bit
TTL = 300  # Time to live (5 minutes)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('dns_server')


class DNSRecord:
    def __init__(self, address: str, record_type: int):
        self.address = address
        self.record_type = record_type
        self.ttl = TTL

    def __str__(self):
        return f"{self.address} (Type: {self.record_type}, TTL: {self.ttl})"


class HostsFile:
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.last_modified = 0
        self.records = defaultdict(list)
        self.load_file()

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
            self.records.clear()
            self.last_modified = current_mtime

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
                    hostnames = parts[1:]

                    # Determine record type (A for IPv4, AAAA for IPv6)
                    record_type = DNS_QUERY_TYPE_AAAA if ':' in ip_address else DNS_QUERY_TYPE_A

                    # Add each hostname to our records
                    for hostname in hostnames:
                        hostname = hostname.lower()  # DNS lookups are case-insensitive
                        self.records[hostname].append(DNSRecord(ip_address, record_type))

            logger.info(f"Loaded {len(self.records)} unique hostnames from hosts file")
        except Exception as e:
            logger.error(f"Error loading hosts file: {e}")

    def check_for_updates(self) -> None:
        """Check if the hosts file has been modified and reload if necessary."""
        if os.path.exists(self.file_path):
            current_mtime = os.path.getmtime(self.file_path)
            if current_mtime > self.last_modified:
                logger.info("Hosts file has changed, reloading...")
                self.load_file()

    def get_records(self, hostname: str, record_type: int) -> List[DNSRecord]:
        """Get all matching records for a hostname and record type."""
        self.check_for_updates()  # Check for file updates before each query
        result = []
        hostname = hostname.lower()  # DNS lookups are case-insensitive

        for record in self.records.get(hostname, []):
            if record.record_type == record_type:
                result.append(record)

        return result


class DNSServer:
    def __init__(self, hosts_file: str, port: int = DNS_PORT, interface: str = '0.0.0.0'):
        self.hosts = HostsFile(hosts_file)
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

            logger.info(f"Query from {client_addr[0]}:{client_addr[1]} - Domain: {domain}, "
                        f"Type: {query_type}, Class: {query_class}")

            # Only handle IN class queries for A and AAAA records
            if query_class != DNS_QUERY_CLASS_IN or query_type not in (DNS_QUERY_TYPE_A, DNS_QUERY_TYPE_AAAA):
                logger.warning(f"Unsupported query type {query_type} or class {query_class}")
                return

            # Get matching records for the domain and query type
            records = self.hosts.get_records(domain, query_type)

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
            logger.error(f"Error handling query: {e}")


def file_monitoring_thread(hosts_file: HostsFile) -> None:
    """Thread function to periodically check for hosts file updates."""
    while True:
        try:
            hosts_file.check_for_updates()
            time.sleep(5)  # Check every 5 seconds
        except Exception as e:
            logger.error(f"Error in file monitoring thread: {e}")


def main() -> None:
    parser = argparse.ArgumentParser(description='Simple DNS Server using a local hosts file')
    parser.add_argument('--hosts-file', required=True, help='Path to the hosts file')
    parser.add_argument('--port', type=int, default=DNS_PORT, help='Port to listen on (default: 53)')
    parser.add_argument('--interface', default='0.0.0.0', help='Interface to bind to (default: 0.0.0.0)')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')

    args = parser.parse_args()

    if args.debug:
        logger.setLevel(logging.DEBUG)

    try:
        server = DNSServer(args.hosts_file, args.port, args.interface)

        # Start a thread to monitor the hosts file for changes
        monitor_thread = threading.Thread(
            target=file_monitoring_thread,
            args=(server.hosts,),
            daemon=True
        )
        monitor_thread.start()

        # Start the server
        server.start()
    except KeyboardInterrupt:
        logger.info("Keyboard interrupt received, shutting down...")
        server.stop()
    except Exception as e:
        logger.error(f"Unhandled exception: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()