#!/usr/bin/env python3
"""
Hosts File Manager

This module handles loading and parsing the hosts file for DNS and DHCP services.
"""

import os
import re
import time
import socket
import logging
import ipaddress
import subprocess
import sys
from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Tuple, Optional, Set, Any

from models import DNSRecord, DHCPLease, DNS_QUERY_TYPE_A, DNS_QUERY_TYPE_AAAA, DEFAULT_LEASE_TIME

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('hosts_file')


class HostsFile:
    """Manages the hosts file for DNS and DHCP services."""
    
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

        # Sort available IPs for deterministic allocation and easier testing
        sorted_ips = sorted(list(available), key=lambda ip: [int(octet) for octet in ip.split('.')])

        # Check each IP to see if it's in use on the network
        for ip_address in sorted_ips:
            if not self._is_ip_in_use(ip_address):
                logger.info(f"Allocated new IP {ip_address} for MAC {mac_address}")
                return ip_address
            else:
                # IP is in use but not in our system - mark it as pre-allocated
                logger.warning(f"IP {ip_address} is already in use on network but not in our system")
                self._add_preallocated_ip(ip_address)
                # Remove it from available pool
                self.available_ips.discard(ip_address)

        logger.warning(f"All available IPs are currently in use on the network")
        return None

    def _is_ip_in_use(self, ip_address: str) -> bool:
        """
        Check if an IP address is already in use on the network.
        Returns True if the IP is in use, False otherwise.
        """
        # Common ports to check - add more as needed
        common_ports = [80, 443, 22, 445, 139, 135, 21, 23, 25, 587, 3389, 5900]

        # Only check local network IPs (skip the local machine)
        if ip_address.startswith('127.'):
            return False

        # Use ping to see if device responds
        try:
            # Use ping with a short timeout
            result = subprocess.run(
                ["ping", "-c", "1", "-W", "1", ip_address],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=2
            )
            if result.returncode == 0:
                logger.debug(f"IP {ip_address} responded to ping")
                return True
        except (subprocess.SubprocessError, subprocess.TimeoutExpired):
            pass  # Ping failed, continue with port checks

        # Try connecting to common ports with a very short timeout
        for port in common_ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.2)  # Very short timeout
                result = s.connect_ex((ip_address, port))
                s.close()

                if result == 0:  # Port is open
                    logger.debug(f"IP {ip_address} has open port {port}")
                    return True
            except:
                pass

        # Additional check using ARP tables (works on Linux and macOS)
        try:
            # Try to get the MAC address from the ARP table
            if sys.platform in ['linux', 'darwin']:  # Linux or macOS
                result = subprocess.run(
                    ["arp", "-n", ip_address],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=1
                )
                # Check if we got a MAC address (not an incomplete entry)
                arp_output = result.stdout.decode('utf-8')
                if ip_address in arp_output and "incomplete" not in arp_output.lower() and "no match" not in arp_output.lower():
                    if "(" not in arp_output:  # Valid MAC found
                        logger.debug(f"IP {ip_address} found in ARP cache with valid MAC")
                        return True
            elif sys.platform == 'win32':  # Windows
                result = subprocess.run(
                    ["arp", "-a", ip_address],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=1
                )
                arp_output = result.stdout.decode('utf-8')
                if ip_address in arp_output and "no arp entry" not in arp_output.lower():
                    logger.debug(f"IP {ip_address} found in Windows ARP cache")
                    return True
        except:
            pass  # If ARP check fails, continue

        return False

    def _get_mac_from_arp(self, ip_address: str) -> Optional[str]:
        """
        Try to get the MAC address from the ARP table for a given IP.
        Returns the MAC address if found, None otherwise.
        """
        try:
            if sys.platform in ['linux', 'darwin']:  # Linux or macOS
                result = subprocess.run(
                    ["arp", "-n", ip_address],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=1
                )
                output = result.stdout.decode('utf-8')

                # Parse the output for MAC address
                if ip_address in output and result.returncode == 0:
                    # Extract MAC from output (format varies by OS)
                    lines = output.strip().split('\n')
                    for line in lines:
                        if ip_address in line:
                            # Try different approaches to extract MAC
                            # Linux format: IP_ADDRESS ether MAC_ADDRESS ...
                            parts = line.split()
                            for i, part in enumerate(parts):
                                # Look for word that's a MAC address format
                                if re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', part):
                                    return part.lower()
            elif sys.platform == 'win32':  # Windows
                result = subprocess.run(
                    ["arp", "-a", ip_address],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=1
                )
                output = result.stdout.decode('utf-8')

                # Parse the output for MAC address
                if ip_address in output and result.returncode == 0:
                    # Windows format: Internet Address Physical Address Type
                    pattern = re.compile(rf'\s*{re.escape(ip_address)}\s+([0-9a-f-]+)\s+')
                    match = pattern.search(output)
                    if match:
                        # Convert from Windows format (00-11-22-33-44-55) to
                        # standard format (00:11:22:33:44:55)
                        return match.group(1).replace('-', ':').lower()

        except (subprocess.SubprocessError, UnicodeDecodeError):
            pass  # If ARP check fails, continue

        return None

    def _add_preallocated_ip(self, ip_address: str) -> None:
        """
        Add an IP address as pre-allocated in the configuration.
        This is used when we detect an IP is in use but not in our system.
        """
        # Add to reserved IPs
        self.reserved_ips.add(ip_address)

        # Try to get MAC address from ARP table
        mac_address = self._get_mac_from_arp(ip_address)
        hostname = f"device-{ip_address.replace('.', '-')}"

        if mac_address:
            # Add to static mappings with discovered MAC
            logger.info(f"Adding pre-allocated IP {ip_address} with MAC {mac_address} to configuration")
            self.mac_to_ip[mac_address] = ip_address
            self.ip_to_hostnames[ip_address] = [hostname]

            # Create DNS records
            record_type = 1  # IPv4
            dns_record = DNSRecord(ip_address, record_type)
            self.dns_records[hostname.lower()].append(dns_record)
        else:
            # Just add the IP as a hostname mapping if we can't find MAC
            logger.info(f"Adding pre-allocated IP {ip_address} to configuration (MAC unknown)")
            self.ip_to_hostnames[ip_address] = [hostname, "preallocated"]

            # Create DNS records
            record_type = 1  # IPv4
            dns_record = DNSRecord(ip_address, record_type)
            self.dns_records[hostname.lower()].append(dns_record)
            self.dns_records["preallocated"].append(dns_record)

        # Update the hosts file
        self._update_hosts_file()

    def _update_hosts_file(self) -> None:
        """Update the hosts file with current entries."""
        if not self.file_path:
            return

        try:
            # Read the original file to preserve comments and formatting
            original_lines = []
            with open(self.file_path, 'r') as f:
                original_lines = f.readlines()

            # Extract comments and non-entry lines
            comments_and_blanks = []
            for line in original_lines:
                stripped = line.strip()
                if not stripped or stripped.startswith('#'):
                    comments_and_blanks.append(line)

            # Create new entries
            entries = []

            # First add MAC-based entries
            for mac, ip in self.mac_to_ip.items():
                hostnames = self.ip_to_hostnames.get(ip, [])
                if hostnames:
                    entries.append(f"{ip} {' '.join(hostnames)} [MAC={mac}]\n")
                else:
                    entries.append(f"{ip} - [MAC={mac}]\n")

            # Then add IP-only entries (like pre-allocated)
            for ip, hostnames in self.ip_to_hostnames.items():
                # Skip if this IP is already covered by a MAC entry
                if any(ip == mac_ip for mac_ip in self.mac_to_ip.values()):
                    continue

                entries.append(f"{ip} {' '.join(hostnames)}\n")

            # Start with a header comment
            output = ["# Hosts file updated by Network Server\n",
                      f"# Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n",
                      "#\n",
                      "# Format for DNS entries:\n",
                      "# <IP address> <hostname1> [hostname2] [hostname3] ...\n",
                      "#\n",
                      "# Format for DHCP entries with MAC address:\n",
                      "# <IP address> <hostname1> [hostname2] ... [MAC=aa:bb:cc:dd:ee:ff]\n",
                      "#\n",
                      "# Pre-allocated entries have 'preallocated' in their hostnames\n",
                      "#\n"]

            # Add some original comments if available
            for i, line in enumerate(comments_and_blanks):
                if i < 5:  # Limit to avoid duplicating too many comments
                    output.append(line)

            # Add a separator
            output.append("\n# Static and dynamic entries\n")

            # Add all the entries
            output.extend(sorted(entries))  # Sort for readability

            # Write the updated file
            with open(self.file_path, 'w') as f:
                f.writelines(output)

            # Update the last_modified time to avoid immediate reload
            self.last_modified = os.path.getmtime(self.file_path)

        except Exception as e:
            logger.error(f"Error updating hosts file: {e}")

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
