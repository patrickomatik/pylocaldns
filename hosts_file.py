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
import ip_utils  # Import the new IP utilities module

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

    def add_a_record(self, hostname, ip):
        """Add an A record (IPv4) for a hostname."""
        # Create the DNS record
        dns_record = DNSRecord(ip, 1)  # 1 is the record type for A records (IPv4)
        
        # Add or update the DNS record for this hostname
        if hostname.lower() not in self.dns_records:
            self.dns_records[hostname.lower()] = []
        
        # Remove any existing A records for this hostname
        self.dns_records[hostname.lower()] = [r for r in self.dns_records[hostname.lower()] 
                                             if r.record_type != 1 or r.address != ip]
        
        # Add the new record
        self.dns_records[hostname.lower()].append(dns_record)
        
        # Make sure the hostname is in the IP-to-hostnames map
        if ip not in self.ip_to_hostnames:
            self.ip_to_hostnames[ip] = []
        if hostname not in self.ip_to_hostnames[ip]:
            self.ip_to_hostnames[ip].append(hostname)
            
    def add_aaaa_record(self, hostname, ip):
        """Add an AAAA record (IPv6) for a hostname."""
        # Create the DNS record
        dns_record = DNSRecord(ip, 28)  # 28 is the record type for AAAA records (IPv6)
        
        # Add or update the DNS record for this hostname
        if hostname.lower() not in self.dns_records:
            self.dns_records[hostname.lower()] = []
        
        # Remove any existing AAAA records for this hostname
        self.dns_records[hostname.lower()] = [r for r in self.dns_records[hostname.lower()] 
                                             if r.record_type != 28 or r.address != ip]
        
        # Add the new record
        self.dns_records[hostname.lower()].append(dns_record)
        
        # Make sure the hostname is in the IP-to-hostnames map
        if ip not in self.ip_to_hostnames:
            self.ip_to_hostnames[ip] = []
        if hostname not in self.ip_to_hostnames[ip]:
            self.ip_to_hostnames[ip].append(hostname)

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

        # Pre-check: scan all IPs for usage and pre-allocate any that are already in use
        # This is crucial for handling network devices not in our system
        for ip_address in sorted_ips.copy():  # Use a copy to avoid modifying during iteration
            if ip_utils.is_ip_in_use(ip_address):
                current_mac = ip_utils.get_mac_from_arp(ip_address)
                
                # If the device requesting the IP is the same one that has it, allow the allocation
                if current_mac and current_mac.lower() == mac_address:
                    logger.info(f"Device with MAC {mac_address} is requesting its existing IP {ip_address}")
                    # Add it as a static reservation to prevent reassignment
                    self.mac_to_ip[mac_address] = ip_address
                    return ip_address
                    
                logger.warning(f"IP {ip_address} is already in use by another device (MAC: {current_mac or 'unknown'})")
                self._add_preallocated_ip(ip_address)
        
        # Recalculate available IPs - pre-allocated IPs should now be in reserved_ips
        available = self.available_ips - self.reserved_ips - leased_ips
        sorted_ips = sorted(list(available), key=lambda ip: [int(octet) for octet in ip.split('.')])
        
        # Now we can safely allocate from the remaining IPs
        if sorted_ips:
            # Allocate the first available IP that's not in use
            ip_address = sorted_ips[0]
            logger.info(f"Allocated new IP {ip_address} for MAC {mac_address}")
            return ip_address
            
        logger.warning(f"All available IPs are currently in use on the network")
        return None

    def _add_preallocated_ip(self, ip_address: str, device_info: Dict[str, Any] = None) -> None:
        """
        Add an IP address as pre-allocated in the configuration.
        This is used when we detect an IP is in use but not in our system.
        
        Args:
            ip_address: The IP address to pre-allocate
            device_info: Optional dictionary containing device information like MAC and open ports
        """
        # Add to reserved IPs
        self.reserved_ips.add(ip_address)
        
        # Remove from available IPs if it's in our DHCP range
        if hasattr(self, 'available_ips'):
            self.available_ips.discard(ip_address)
            logger.debug(f"Removed {ip_address} from available DHCP pool (pre-allocated)")

        # Gather device information
        device_info = device_info or {}
        mac_address = device_info.get('mac') or ip_utils.get_mac_from_arp(ip_address)
        
        # Scan for open ports if not provided
        open_ports = device_info.get('ports', [])
        if not open_ports:
            # Try to get port information
            try:
                open_ports = ip_utils.scan_client_ports(ip_address)
                logger.info(f"Discovered open ports for {ip_address}: {', '.join(map(str, open_ports))}")
            except Exception as e:
                logger.warning(f"Error scanning ports for {ip_address}: {e}")
        
        # Generate base hostname
        hostname = f"device-{ip_address.replace('.', '-')}"
        
        # Add port information to the hostname tags if available
        host_tags = ["preallocated"]
        if open_ports:
            # Store port information in a compact format
            port_tag = f"ports-{','.join(map(str, sorted(open_ports)))}"
            host_tags.append(port_tag)

        if mac_address:
            # Add to static mappings with discovered MAC
            logger.info(f"Adding pre-allocated IP {ip_address} with MAC {mac_address} to configuration")
            self.mac_to_ip[mac_address] = ip_address
            self.ip_to_hostnames[ip_address] = [hostname] + host_tags

            # Create DNS records
            record_type = DNS_QUERY_TYPE_A  # IPv4
            dns_record = DNSRecord(ip_address, record_type)
            self.dns_records[hostname.lower()].append(dns_record)
            self.dns_records["preallocated"].append(dns_record)
        else:
            # Just add the IP as a hostname mapping if we can't find MAC
            logger.info(f"Adding pre-allocated IP {ip_address} to configuration (MAC unknown)")
            self.ip_to_hostnames[ip_address] = [hostname] + host_tags

            # Create DNS records
            record_type = DNS_QUERY_TYPE_A  # IPv4
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

            # Then add IP-only entries (DNS-only entries without MAC addresses)
            for ip, hostnames in self.ip_to_hostnames.items():
                # Skip if this IP is already covered by a MAC entry
                # This check is important to avoid duplicate entries
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
        
        # Check if the IP address is already in use by another device
        if ip_utils.is_ip_in_use(ip_address):
            current_mac = ip_utils.get_mac_from_arp(ip_address)
            if current_mac and current_mac.lower() != mac_address:
                logger.warning(f"IP {ip_address} is already in use by device with MAC {current_mac}, "
                              f"but being requested by {mac_address}")
        
        lease = DHCPLease(mac_address, ip_address, hostname, lease_time)
        self.leases[mac_address] = lease
        logger.info(f"Added/updated lease: {lease}")
        return lease

    def add_dns_only_entry(self, ip_address: str, hostnames: List[str]) -> None:
        """Add DNS records for an IP address without associating it with a MAC address.
        
        Args:
            ip_address: The IP address for the DNS records
            hostnames: List of hostnames to associate with the IP address
        """
        # Validate input
        if not ip_address or not hostnames:
            return
            
        # Add to the IP to hostnames mapping
        self.ip_to_hostnames[ip_address] = hostnames
        
        # Create DNS records for each hostname
        for hostname in hostnames:
            # Determine if IPv4 or IPv6
            if ':' in ip_address:  # IPv6
                self.add_aaaa_record(hostname, ip_address)
            else:  # IPv4
                self.add_a_record(hostname, ip_address)
                
        # Update the hosts file
        self._update_hosts_file()
        logger.info(f"Added DNS-only entry for IP {ip_address} with hostnames: {', '.join(hostnames)}")
        
    def delete_dns_only_entry(self, ip_address: str) -> bool:
        """Delete a DNS-only entry (IP without MAC address).
        
        Args:
            ip_address: The IP address to delete
            
        Returns:
            bool: True if successful, False otherwise
        """
        # Validate this is a DNS-only entry (not associated with a MAC)
        if not ip_address or ip_address not in self.ip_to_hostnames:
            return False
            
        # Check it's not associated with a MAC address
        if any(ip_address == mac_ip for mac_ip in self.mac_to_ip.values()):
            return False
            
        # Get hostnames to clean up DNS records
        hostnames = self.ip_to_hostnames[ip_address]
        
        # Remove DNS records
        for hostname in hostnames:
            if hostname.lower() in self.dns_records:
                # Filter out records for this IP
                self.dns_records[hostname.lower()] = [
                    record for record in self.dns_records[hostname.lower()]
                    if record.address != ip_address
                ]
                
                # Remove hostname entry if empty
                if not self.dns_records[hostname.lower()]:
                    del self.dns_records[hostname.lower()]
        
        # Remove from IP to hostnames mapping
        del self.ip_to_hostnames[ip_address]
        
        # Update hosts file
        self._update_hosts_file()
        logger.info(f"Deleted DNS-only entry for IP {ip_address}")
        return True
    
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
            
    def scan_network(self) -> Dict[str, Dict[str, Any]]:
        """
        Scan the network for active devices and update the configuration.
        
        This is useful for discovering devices on the network that aren't
        already in our configuration. It helps build a more complete picture
        of the network.
        
        Returns:
            Dictionary mapping IP addresses to device information including:
            - 'mac': MAC address (or None if not found)
            - 'ports': List of open ports
        """
        if not self.dhcp_range:
            logger.warning("Cannot scan network without DHCP range configured")
            return {}
            
        logger.info(f"Scanning network range {self.dhcp_range[0]} to {self.dhcp_range[1]}")
        
        # Define a simple progress callback
        def progress_callback(scanned, total):
            if scanned % 20 == 0 or scanned == total:
                logger.info(f"Network scan progress: {scanned}/{total} IPs ({scanned/total*100:.1f}%)")
        
        # Perform the scan
        discovered = ip_utils.scan_network_async(self.dhcp_range, callback=progress_callback)
        
        # Check if we need to perform deeper port scanning
        do_port_scan = True  # Always perform port scanning for better device identification
        
        # Perform more detailed port scanning if requested
        if do_port_scan:
            logger.info("Performing detailed port scanning for discovered devices...")
            for ip, device_info in discovered.items():
                # Check for open ports (more extensive list for better identification)
                logger.debug(f"Scanning common ports on {ip}...")
                # Get existing ports if any
                existing_ports = device_info.get('ports', [])
                # Scan for open ports
                open_ports = ip_utils.scan_client_ports(ip)
                # Combine results
                all_ports = sorted(set(existing_ports + open_ports))
                
                if all_ports:
                    device_info['ports'] = all_ports  # Store open ports in device info
                    logger.info(f"Device at {ip} has open ports: {', '.join(map(str, all_ports))}")
        
        # Update our configuration with discovered devices
        for ip, device_info in discovered.items():
            if ip not in self.reserved_ips and ip not in [lease.ip_address for lease in self.leases.values()]:
                mac = device_info.get('mac')
                ports = device_info.get('ports', [])
                port_info = f" with open ports: {', '.join(map(str, ports))}" if ports else ""
                logger.info(f"Discovered new device at {ip}" + (f" with MAC {mac}" if mac else "") + port_info)
                self._add_preallocated_ip(ip, device_info)
        
        logger.info(f"Network scan complete. Discovered {len(discovered)} active devices.")
        return discovered
