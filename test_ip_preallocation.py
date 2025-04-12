#!/usr/bin/env python3
"""
Test Script for IP Address Pre-allocation Feature

This script tests the functionality of the IP address usage checking
and pre-allocation features in the Network Server.
"""

import os
import sys
import time
import socket
import logging
import unittest
import subprocess
import tempfile
from typing import Dict, List, Optional, Tuple

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('test_ip_preallocation')

# Import local modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from models import DNSRecord, DHCPLease, DNS_QUERY_TYPE_A
from hosts_file import HostsFile
import ip_utils


class MockSocket:
    """Mock socket class for testing network connectivity."""
    
    def __init__(self, mock_open_ports: Dict[str, List[int]]) -> None:
        """
        Initialize a MockSocket.
        
        Args:
            mock_open_ports: Dictionary mapping IP addresses to lists of open ports
        """
        self.mock_open_ports = mock_open_ports
        self.settimeout_called = False
        self.connect_ex_called = False
        self.connect_ex_args = None
        self.closed = False
    
    def settimeout(self, timeout: float) -> None:
        """Mock settimeout method."""
        self.settimeout_called = True
        self.timeout = timeout
    
    def connect_ex(self, address: Tuple[str, int]) -> int:
        """
        Mock connect_ex method.
        
        Returns 0 if the port is mocked as open, otherwise 1.
        """
        self.connect_ex_called = True
        self.connect_ex_args = address
        
        ip, port = address
        if ip in self.mock_open_ports and port in self.mock_open_ports[ip]:
            return 0  # Port is open
        return 1  # Port is closed
    
    def close(self) -> None:
        """Mock close method."""
        self.closed = True


class MockSubprocess:
    """Mock subprocess class for testing command execution."""
    
    def __init__(self, mock_arp_data: Dict[str, str]) -> None:
        """
        Initialize a MockSubprocess.
        
        Args:
            mock_arp_data: Dictionary mapping IP addresses to mock ARP output
        """
        self.mock_arp_data = mock_arp_data
    
    def run(self, cmd, **kwargs):
        """
        Mock subprocess.run method.
        
        Returns a mock CompletedProcess with stdout set to the mock ARP data
        for the given IP address.
        """
        # Check if this is an ARP command
        if cmd[0] == 'arp':
            # Get the IP from the command
            ip = cmd[-1]
            if ip in self.mock_arp_data:
                # Return a mock CompletedProcess with the mock ARP data
                return type('CompletedProcess', (), {
                    'returncode': 0,
                    'stdout': self.mock_arp_data[ip].encode('utf-8'),
                    'stderr': b''
                })
            else:
                # Return a mock CompletedProcess with no ARP entry
                return type('CompletedProcess', (), {
                    'returncode': 1,
                    'stdout': b'',
                    'stderr': b'No ARP entry found'
                })
        
        # For ping commands
        if cmd[0] == 'ping':
            ip = cmd[-1]
            # Simulate successful ping for specific IPs
            if ip in self.mock_arp_data and 'responds_to_ping' in self.mock_arp_data[ip]:
                return type('CompletedProcess', (), {
                    'returncode': 0,
                    'stdout': b'64 bytes from 192.168.1.1: icmp_seq=1 ttl=64 time=0.123 ms',
                    'stderr': b''
                })
            else:
                return type('CompletedProcess', (), {
                    'returncode': 1,
                    'stdout': b'',
                    'stderr': b'Request timeout'
                })
        
        # Default response for other commands
        return type('CompletedProcess', (), {
            'returncode': 0,
            'stdout': b'',
            'stderr': b''
        })


class TestIPPreallocation(unittest.TestCase):
    """Test cases for IP address pre-allocation feature."""
    
    def setUp(self) -> None:
        """Set up test environment."""
        # Create a temporary file for the hosts file
        self.hosts_fd, self.hosts_path = tempfile.mkstemp()
        os.close(self.hosts_fd)
        
        # Write initial hosts file content
        with open(self.hosts_path, 'w') as f:
            f.write("""# Test hosts file
192.168.1.10 server1.local server1 [MAC=00:11:22:33:44:55]
192.168.1.20 server2.local server2 [MAC=aa:bb:cc:dd:ee:ff]
192.168.1.30 db.local database
""")
        
        # Initialize hosts file with DHCP range
        self.dhcp_range = ('192.168.1.100', '192.168.1.200')
        self.hosts_file = HostsFile(self.hosts_path, self.dhcp_range)
        
        # Mock network state
        self.mock_in_use_ips = {
            '192.168.1.10': True,   # Static entry
            '192.168.1.105': True,  # In DHCP range, but not allocated
            '192.168.1.120': True   # In DHCP range, not allocated
        }
        
        # Mock ARP table
        self.mock_arp_data = {
            '192.168.1.10': """Address         HWtype  HWaddress           Flags Mask            Iface
192.168.1.10     ether   00:11:22:33:44:55   C                     eth0""",
            '192.168.1.105': """Address         HWtype  HWaddress           Flags Mask            Iface
192.168.1.105    ether   01:23:45:67:89:ab   C                     eth0""",
            '192.168.1.120': """Address         HWtype  HWaddress           Flags Mask            Iface
192.168.1.120    ether   ab:cd:ef:12:34:56   C                     eth0"""
        }
        
        # Mock open ports
        self.mock_open_ports = {
            '192.168.1.10': [22, 80],   # SSH and HTTP
            '192.168.1.105': [443],     # HTTPS
            '192.168.1.120': [8080]     # Custom web server
        }
        
        # Save original functions to restore later
        self.original_socket = socket.socket
        self.original_subprocess_run = subprocess.run
        
        # Apply mocks
        self._apply_mocks()
    
    def tearDown(self) -> None:
        """Clean up after tests."""
        # Restore original functions
        socket.socket = self.original_socket
        subprocess.run = self.original_subprocess_run
        
        # Remove temporary hosts file
        os.remove(self.hosts_path)
    
    def _apply_mocks(self) -> None:
        """Apply mocks for network testing."""
        # Mock socket creation
        def mock_socket_factory(*args, **kwargs):
            return MockSocket(self.mock_open_ports)
        
        socket.socket = mock_socket_factory
        
        # Mock subprocess.run
        mock_subprocess = MockSubprocess(self.mock_arp_data)
        subprocess.run = mock_subprocess.run
    
    def test_is_ip_in_use(self) -> None:
        """Test the is_ip_in_use function."""
        # Test IP that should be in use
        self.assertTrue(ip_utils.is_ip_in_use('192.168.1.105'))
        
        # Test IP that should not be in use
        self.assertFalse(ip_utils.is_ip_in_use('192.168.1.150'))
    
    def test_get_mac_from_arp(self) -> None:
        """Test the get_mac_from_arp function."""
        # Test IP with MAC in ARP table
        mac = ip_utils.get_mac_from_arp('192.168.1.105')
        self.assertEqual(mac, '01:23:45:67:89:ab')
        
        # Test IP without MAC in ARP table
        mac = ip_utils.get_mac_from_arp('192.168.1.150')
        self.assertIsNone(mac)
    
    def test_allocate_ip_avoids_in_use_ips(self) -> None:
        """Test that allocate_ip avoids IPs that are already in use."""
        # Allocate an IP for a new MAC
        ip = self.hosts_file.allocate_ip('22:22:22:22:22:22')
        
        # It should not allocate 192.168.1.105 or 192.168.1.120 since they're in use
        self.assertNotEqual(ip, '192.168.1.105')
        self.assertNotEqual(ip, '192.168.1.120')
        
        # It should allocate the first available IP that's not in use
        self.assertEqual(ip, '192.168.1.100')
    
    def test_preallocate_ip_with_mac(self) -> None:
        """Test that _add_preallocated_ip properly handles IPs with MAC addresses."""
        # Add a pre-allocated IP that has a MAC address
        self.hosts_file._add_preallocated_ip('192.168.1.105')
        
        # Check that the IP was added to reserved IPs
        self.assertIn('192.168.1.105', self.hosts_file.reserved_ips)
        
        # Check that the MAC to IP mapping was created
        self.assertEqual(self.hosts_file.mac_to_ip.get('01:23:45:67:89:ab'), '192.168.1.105')
        
        # Check that hostnames were created
        hostnames = self.hosts_file.get_hostnames_for_ip('192.168.1.105')
        self.assertIn('device-192-168-1-105', hostnames)
        self.assertIn('preallocated', hostnames)
        
        # Check that DNS records were created
        records = self.hosts_file.get_dns_records('device-192-168-1-105', DNS_QUERY_TYPE_A)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].address, '192.168.1.105')
    
    def test_preallocate_ip_without_mac(self) -> None:
        """Test that _add_preallocated_ip properly handles IPs without MAC addresses."""
        # Mock an IP without a MAC
        self.mock_arp_data.pop('192.168.1.120', None)
        
        # Add a pre-allocated IP that doesn't have a MAC address
        self.hosts_file._add_preallocated_ip('192.168.1.120')
        
        # Check that the IP was added to reserved IPs
        self.assertIn('192.168.1.120', self.hosts_file.reserved_ips)
        
        # Check that no MAC to IP mapping was created
        for mac, ip in self.hosts_file.mac_to_ip.items():
            self.assertNotEqual(ip, '192.168.1.120')
        
        # Check that hostnames were created
        hostnames = self.hosts_file.get_hostnames_for_ip('192.168.1.120')
        self.assertIn('device-192-168-1-120', hostnames)
        self.assertIn('preallocated', hostnames)
        
        # Check that DNS records were created
        records = self.hosts_file.get_dns_records('device-192-168-1-120', DNS_QUERY_TYPE_A)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].address, '192.168.1.120')
    
    def test_scan_network(self) -> None:
        """Test the scan_network function."""
        # Add a device after initial setup
        self.mock_in_use_ips['192.168.1.150'] = True
        self.mock_arp_data['192.168.1.150'] = """Address         HWtype  HWaddress           Flags Mask            Iface
192.168.1.150    ether   aa:aa:aa:aa:aa:aa   C                     eth0"""
        self.mock_open_ports['192.168.1.150'] = [22]
        
        # Run the network scan
        discovered = self.hosts_file.scan_network()
        
        # Check that we discovered the expected IPs
        self.assertIn('192.168.1.105', discovered)
        self.assertEqual(discovered['192.168.1.105'], '01:23:45:67:89:ab')
        
        self.assertIn('192.168.1.150', discovered)
        self.assertEqual(discovered['192.168.1.150'], 'aa:aa:aa:aa:aa:aa')
        
        # Check that the discovered IPs were added to our configuration
        self.assertIn('192.168.1.150', self.hosts_file.reserved_ips)
        
        # Check that hostnames were created for the discovered IP
        hostnames = self.hosts_file.get_hostnames_for_ip('192.168.1.150')
        self.assertIn('device-192-168-1-150', hostnames)
        self.assertIn('preallocated', hostnames)
    
    def test_allocate_ip_for_device_requesting_own_ip(self) -> None:
        """Test allocating an IP for a device requesting its own current IP."""
        # Mock a device that's already using 192.168.1.105 and has MAC 01:23:45:67:89:ab
        # This device is not in our configuration yet
        
        # Try to allocate an IP for this device
        ip = self.hosts_file.allocate_ip('01:23:45:67:89:ab')
        
        # It should allocate the IP the device is already using
        self.assertEqual(ip, '192.168.1.105')
        
        # Check that the IP was added to reserved IPs
        self.assertIn('192.168.1.105', self.hosts_file.reserved_ips)
    
    def test_hosts_file_updated_after_preallocation(self) -> None:
        """Test that the hosts file is updated after pre-allocating an IP."""
        # Add a pre-allocated IP
        self.hosts_file._add_preallocated_ip('192.168.1.105')
        
        # Read the hosts file
        with open(self.hosts_path, 'r') as f:
            content = f.read()
        
        # Check that the pre-allocated IP was added to the hosts file
        self.assertIn('192.168.1.105', content)
        self.assertIn('device-192-168-1-105', content)
        self.assertIn('preallocated', content)
        self.assertIn('01:23:45:67:89:ab', content)
    
    def test_dhcp_range_excludes_preallocated_ips(self) -> None:
        """Test that the DHCP range excludes pre-allocated IPs."""
        # Initially, 192.168.1.105 should be in the available IPs
        self.assertIn('192.168.1.105', self.hosts_file.available_ips)
        
        # Add a pre-allocated IP
        self.hosts_file._add_preallocated_ip('192.168.1.105')
        
        # After pre-allocation, 192.168.1.105 should no longer be in the available IPs
        self.assertNotIn('192.168.1.105', self.hosts_file.available_ips)
        
        # Allocate an IP for a new MAC
        ip = self.hosts_file.allocate_ip('22:22:22:22:22:22')
        
        # It should not allocate the pre-allocated IP
        self.assertNotEqual(ip, '192.168.1.105')
    
    def test_same_client_requesting_same_ip(self) -> None:
        """Test handling when the same client requests the same IP again."""
        # Add a lease for a client
        self.hosts_file.add_or_update_lease('01:23:45:67:89:ab', '192.168.1.110', 'client1')
        
        # Now simulate that client requesting the same IP again
        ip = self.hosts_file.allocate_ip('01:23:45:67:89:ab')
        
        # It should allocate the same IP
        self.assertEqual(ip, '192.168.1.110')
    
    def test_different_client_requesting_in_use_ip(self) -> None:
        """Test handling when a different client requests an IP that's already in use."""
        # Mock a device that's already using 192.168.1.105 and has MAC 01:23:45:67:89:ab
        
        # Try to allocate the same IP for a different device
        # The allocate_ip method should recognize that 192.168.1.105 is in use by a different device
        # and should not allocate it
        ip = self.hosts_file.allocate_ip('ff:ff:ff:ff:ff:ff')
        
        # It should not allocate 192.168.1.105
        self.assertNotEqual(ip, '192.168.1.105')
        
        # It should have pre-allocated 192.168.1.105 to the device using it
        self.assertIn('192.168.1.105', self.hosts_file.reserved_ips)
        self.assertEqual(self.hosts_file.mac_to_ip.get('01:23:45:67:89:ab'), '192.168.1.105')


if __name__ == '__main__':
    unittest.main()
