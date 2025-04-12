#!/usr/bin/env python3
"""
Simple focused test for the preallocation issue
"""

import unittest
import tempfile
import os
import sys
# Add parent directory to the path so we can import the necessary modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ip_utils
from hosts_file import HostsFile

class SimplePreallocationTest(unittest.TestCase):
    """Test the preallocation functionality directly."""
    
    def setUp(self):
        """Set up a simple test environment."""
        # Create a simple hosts file
        self.hosts_fd, self.hosts_path = tempfile.mkstemp()
        os.close(self.hosts_fd)
        
        with open(self.hosts_path, 'w') as f:
            f.write("""# Test hosts file
192.168.1.10 server1.local server1 [MAC=00:11:22:33:44:55]
""")
        
        # Initialize the hosts file with DHCP range
        self.dhcp_range = ('192.168.1.100', '192.168.1.200')
        self.hosts_file = HostsFile(self.hosts_path, self.dhcp_range)
        
        # Save the original functions
        self.original_is_ip_in_use = ip_utils.is_ip_in_use
        self.original_get_mac_from_arp = ip_utils.get_mac_from_arp
        
        # Create mock functions
        def mock_is_ip_in_use(ip_address, timeout=1.0):
            if ip_address == '192.168.1.105':
                return True
            return False
        
        def mock_get_mac_from_arp(ip_address):
            if ip_address == '192.168.1.105':
                return '01:23:45:67:89:ab'
            return None
        
        # Apply mocks
        ip_utils.is_ip_in_use = mock_is_ip_in_use
        ip_utils.get_mac_from_arp = mock_get_mac_from_arp
        
        # Ensure 192.168.1.105 is in available IPs initially
        self.hosts_file.available_ips.add('192.168.1.105')
    
    def tearDown(self):
        """Clean up after the test."""
        # Restore original functions
        ip_utils.is_ip_in_use = self.original_is_ip_in_use
        ip_utils.get_mac_from_arp = self.original_get_mac_from_arp
        
        # Remove the temporary hosts file
        os.remove(self.hosts_path)
    
    def test_add_preallocated_ip_direct(self):
        """Test the _add_preallocated_ip method directly."""
        # Call the method directly
        self.hosts_file._add_preallocated_ip('192.168.1.105')
        
        # Verify it was added to reserved_ips
        self.assertIn('192.168.1.105', self.hosts_file.reserved_ips)
        
        # Verify MAC to IP mapping was added
        self.assertEqual(self.hosts_file.mac_to_ip.get('01:23:45:67:89:ab'), '192.168.1.105')
        
        # Verify it was removed from available_ips
        self.assertNotIn('192.168.1.105', self.hosts_file.available_ips)
    
    def test_allocate_ip_with_in_use_ip(self):
        """Test allocate_ip when an IP is already in use."""
        # Try to allocate an IP for a different MAC
        allocated_ip = self.hosts_file.allocate_ip('ff:ff:ff:ff:ff:ff')
        
        # Verify it didn't allocate the in-use IP
        self.assertNotEqual(allocated_ip, '192.168.1.105')
        
        # Verify the in-use IP was pre-allocated
        self.assertIn('192.168.1.105', self.hosts_file.reserved_ips)
        
        # Verify MAC to IP mapping was added
        self.assertEqual(self.hosts_file.mac_to_ip.get('01:23:45:67:89:ab'), '192.168.1.105')

if __name__ == '__main__':
    unittest.main()
