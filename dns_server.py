#!/usr/bin/env python3
"""
DNS Server component

This module implements a lightweight DNS server that resolves hostnames
using a hosts file as its source of records.
"""

import socket
import logging
import threading
import sys
from typing import Tuple, List

from models import DNSRecord, DNS_QUERY_CLASS_IN, DNS_QUERY_TYPE_A, DNS_QUERY_TYPE_AAAA
from models import DNS_RESPONSE_FLAG, DNS_AUTHORITATIVE_FLAG
from hosts_file import HostsFile

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('dns_server')


class DNSServer:
    """A simple DNS server that resolves hostnames from a hosts file."""
    
    def __init__(self, hosts_file: HostsFile, port: int = 53, interface: str = '0.0.0.0'):
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
