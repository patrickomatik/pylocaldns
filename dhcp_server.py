#!/usr/bin/env python3
"""
DHCP Server component

This module implements a lightweight DHCP server that allocates IP addresses
using a hosts file as its source of MAC-to-IP mappings.
"""

import socket
import logging
import threading
import sys
import struct
from typing import Dict, Tuple, List, Any, Optional

from models import (DHCPLease, DHCP_SERVER_PORT, DHCP_CLIENT_PORT, DHCP_MAGIC_COOKIE,
                   DHCP_DISCOVER, DHCP_OFFER, DHCP_REQUEST, DHCP_ACK, DHCP_NAK,
                   DHCP_RELEASE, DHCP_INFORM, DEFAULT_LEASE_TIME,
                   DHCP_OPT_SUBNET_MASK, DHCP_OPT_ROUTER, DHCP_OPT_DNS_SERVER,
                   DHCP_OPT_HOSTNAME, DHCP_OPT_REQUESTED_IP, DHCP_OPT_LEASE_TIME,
                   DHCP_OPT_MSG_TYPE, DHCP_OPT_SERVER_ID, DHCP_OPT_PARAM_REQ_LIST,
                   DHCP_OPT_END)
from hosts_file import HostsFile

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('dhcp_server')


class DHCPServer:
    """
    A DHCP server that assigns IP addresses to devices based on MAC addresses.
    It uses a hosts file for static reservations and manages dynamic allocations.
    """
    
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


# Add missing import
import time
