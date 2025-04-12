#!/usr/bin/env python3
"""
Additional test suite for PyLocalDNS Flask routes.

This module contains additional tests for the Flask web interface routes
in the PyLocalDNS application that weren't covered in the original test file.
It verifies that all routes handle requests correctly and return the expected responses.
"""

import os
import sys
import unittest
import tempfile
import json
from unittest.mock import patch, MagicMock

# Add the parent directory to the path so we can import app
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import required modules
from app import app, init_flask_server
from hosts_file import HostsFile
from models import Lease


class TestFlaskRoutesAdditional(unittest.TestCase):
    """Additional test cases for Flask routes."""

    def setUp(self):
        """Set up test environment before each test."""
        # Create a temporary hosts file
        self.hosts_fd, self.hosts_path = tempfile.mkstemp()
        with open(self.hosts_path, 'w') as f:
            f.write("# Test hosts file\n")
            f.write("127.0.0.1 localhost\n")
            f.write("192.168.1.10 test.local [MAC=00:11:22:33:44:55]\n")

        # Initialize the hosts file
        self.hosts_file = HostsFile(self.hosts_path)
        
        # Add a test lease
        import time
        expiry_time = int(time.time()) + 3600  # 1 hour from now
        self.hosts_file.leases["aa:bb:cc:dd:ee:ff"] = Lease(
            ip_address="192.168.1.100",
            mac_address="aa:bb:cc:dd:ee:ff",
            hostname="dhcp-client",
            expiry_time=expiry_time,
            lease_time=3600
        )
        
        # Mock network server
        self.network_server = MagicMock()
        self.network_server.dhcp_server = MagicMock()
        self.network_server.dhcp_enable = True
        
        # Initialize the Flask app
        self.flask_app = init_flask_server(
            hosts_file_obj=self.hosts_file,
            network_server_obj=self.network_server,
            port=8080,
            host='127.0.0.1'
        )
        
        # Configure the Flask test client
        self.flask_app.config['TESTING'] = True
        self.client = self.flask_app.test_client()
        self.client.testing = True

    def tearDown(self):
        """Clean up after each test."""
        os.close(self.hosts_fd)
        os.unlink(self.hosts_path)

    def test_edit_lease_get(self):
        """Test the edit lease form page."""
        response = self.client.get('/edit-lease?mac=aa:bb:cc:dd:ee:ff')
        # Check response is OK
        self.assertEqual(response.status_code, 200)
        # Check the form is pre-populated with existing data
        self.assertIn(b'Edit DHCP Lease', response.data)
        self.assertIn(b'<form method="post" action="/update-lease">', response.data)
        self.assertIn(b'value="aa:bb:cc:dd:ee:ff"', response.data)
        self.assertIn(b'value="192.168.1.100"', response.data)
        self.assertIn(b'value="dhcp-client"', response.data)
        self.assertIn(b'value="3600"', response.data)

    @patch('app._update_hosts_file')
    def test_update_lease_post(self, mock_update_hosts_file):
        """Test updating a lease via POST."""
        # Prepare form data
        form_data = {
            'mac': 'aa:bb:cc:dd:ee:ff',
            'ip': '192.168.1.101',
            'hostname': 'updated-client',
            'hostnames': 'client.local, client',
            'lease_time': '7200',
            'make_static': 'no'
        }
        
        # Post the form
        response = self.client.post('/update-lease', data=form_data, follow_redirects=True)
        
        # Check response is OK
        self.assertEqual(response.status_code, 200)
        
        # Verify the lease was updated in hosts_file
        lease = self.hosts_file.get_lease('aa:bb:cc:dd:ee:ff')
        self.assertEqual(lease.ip_address, '192.168.1.101')
        self.assertEqual(lease.hostname, 'updated-client')
        # Hostnames should be added to ip_to_hostnames
        self.assertIn('client.local', self.hosts_file.ip_to_hostnames['192.168.1.101'])
        self.assertIn('client', self.hosts_file.ip_to_hostnames['192.168.1.101'])
        
        # Check that _update_hosts_file was called
        mock_update_hosts_file.assert_called_once()
        
        # Check that success message is displayed
        self.assertIn(b'Lease updated successfully', response.data)

    @patch('app._update_hosts_file')
    def test_convert_lease_to_static(self, mock_update_hosts_file):
        """Test converting a DHCP lease to a static entry."""
        # Prepare form data
        form_data = {
            'mac': 'aa:bb:cc:dd:ee:ff',
            'ip': '192.168.1.100',
            'hostname': 'dhcp-client',
            'hostnames': 'client.local',
            'lease_time': '3600',
            'make_static': 'yes'  # Convert to static
        }
        
        # Post the form
        response = self.client.post('/update-lease', data=form_data, follow_redirects=True)
        
        # Check response is OK
        self.assertEqual(response.status_code, 200)
        
        # Verify the lease was converted to a static entry
        self.assertIn('aa:bb:cc:dd:ee:ff', self.hosts_file.mac_to_ip)
        self.assertEqual(self.hosts_file.mac_to_ip['aa:bb:cc:dd:ee:ff'], '192.168.1.100')
        self.assertIn('client.local', self.hosts_file.ip_to_hostnames['192.168.1.100'])
        
        # Lease should be released
        self.assertNotIn('aa:bb:cc:dd:ee:ff', self.hosts_file.leases)
        
        # Check that _update_hosts_file was called
        mock_update_hosts_file.assert_called_once()
        
        # Check that success message is displayed
        self.assertIn(b'Lease updated successfully', response.data)

    @patch('app._update_hosts_file')
    def test_delete_lease(self, mock_update_hosts_file):
        """Test deleting a DHCP lease."""
        # Delete the lease
        response = self.client.get('/delete-lease?mac=aa:bb:cc:dd:ee:ff', follow_redirects=True)
        
        # Check response is OK
        self.assertEqual(response.status_code, 200)
        
        # Verify the lease was deleted from hosts_file
        self.assertNotIn('aa:bb:cc:dd:ee:ff', self.hosts_file.leases)
        
        # Check that success message is displayed
        self.assertIn(b'Lease released successfully', response.data)

    def test_invalid_mac_edit_lease(self):
        """Test edit lease with an invalid MAC address."""
        response = self.client.get('/edit-lease?mac=invalid', follow_redirects=True)
        
        # Check that an error message is displayed
        self.assertIn(b'No lease found for MAC: invalid', response.data)

    def test_invalid_mac_edit_entry(self):
        """Test edit entry with an invalid MAC address."""
        response = self.client.get('/edit?mac=invalid', follow_redirects=True)
        
        # Check that an error message is displayed
        self.assertIn(b'No entry found for MAC: invalid', response.data)

    def test_invalid_ip_update(self):
        """Test updating with an invalid IP address."""
        # Prepare form data with invalid IP
        form_data = {
            'mac': '00:11:22:33:44:55',
            'ip': 'invalid-ip',
            'original_ip': '192.168.1.10',
            'hostnames': 'test.local'
        }
        
        # Post the form
        response = self.client.post('/update', data=form_data)
        
        # Check that an error message is displayed
        self.assertIn(b'Invalid IP address format', response.data)

    def test_invalid_ip_add(self):
        """Test adding with an invalid IP address."""
        # Prepare form data with invalid IP
        form_data = {
            'mac': '00:22:33:44:55:66',
            'ip': 'invalid-ip',
            'hostnames': 'test2.local'
        }
        
        # Post the form
        response = self.client.post('/add', data=form_data)
        
        # Check that an error message is displayed
        self.assertIn(b'Invalid IP address format', response.data)

    def test_invalid_mac_format_add(self):
        """Test adding with an invalid MAC format."""
        # Prepare form data with invalid MAC
        form_data = {
            'mac': 'invalid-mac',
            'ip': '192.168.1.20',
            'hostnames': 'test2.local'
        }
        
        # Post the form
        response = self.client.post('/add', data=form_data)
        
        # Check that an error message is displayed
        self.assertIn(b'Invalid MAC address format', response.data)

    def test_duplicate_mac_add(self):
        """Test adding a duplicate MAC address."""
        # Prepare form data with existing MAC
        form_data = {
            'mac': '00:11:22:33:44:55',  # This MAC already exists in setup
            'ip': '192.168.1.20',
            'hostnames': 'test2.local'
        }
        
        # Post the form
        response = self.client.post('/add', data=form_data)
        
        # Check that an error message is displayed
        self.assertIn(b'An entry with MAC 00:11:22:33:44:55 already exists', response.data)

    @patch('app.handle_scan_request')
    def test_scan_network_dhcp_disabled(self, mock_handle_scan_request):
        """Test the scan network POST request when DHCP is disabled."""
        # Disable DHCP
        self.network_server.dhcp_enable = False
        
        # Remove DHCP range
        self.hosts_file.dhcp_range = None
        
        # Post to the scan endpoint
        response = self.client.post('/scan', follow_redirects=True)
        
        # Check that error message is displayed
        self.assertIn(b'DHCP range not configured', response.data)
        
        # Check that handle_scan_request was not called
        mock_handle_scan_request.assert_not_called()

    @patch('app.scan_client_ports')
    def test_scan_ports_database_disabled(self, mock_scan_client_ports):
        """Test the scan ports functionality when database is disabled."""
        with patch('app.USE_PORT_DB', False):
            # Post to the scan ports endpoint
            response = self.client.post('/scan-ports', follow_redirects=True)
            
            # Check response is OK
            self.assertEqual(response.status_code, 200)
            
            # Check that error message is displayed
            self.assertIn(b'Port scanning requires database support', response.data)
            
            # Check that scan_client_ports was not called
            mock_scan_client_ports.assert_not_called()

    def test_settings_invalid_dhcp_range(self):
        """Test settings with invalid DHCP range."""
        # Prepare form data with invalid DHCP range
        form_data = {
            'dhcp_enabled': 'yes',
            'dhcp_range_start': '192.168.1.200',  # End is lower than start
            'dhcp_range_end': '192.168.1.100',
            'subnet_mask': '255.255.255.0',
            'router_ip': '192.168.1.1',
            'dns_servers': '8.8.8.8, 8.8.4.4',
            'lease_time': '86400'
        }
        
        # Post the form
        response = self.client.post('/settings', data=form_data)
        
        # Check that an error message is displayed
        self.assertIn(b'DHCP range start IP must be less than or equal to end IP', response.data)

    def test_settings_invalid_dns_servers(self):
        """Test settings with invalid DNS servers."""
        # Prepare form data with invalid DNS servers
        form_data = {
            'dhcp_enabled': 'yes',
            'dhcp_range_start': '192.168.1.100',
            'dhcp_range_end': '192.168.1.200',
            'subnet_mask': '255.255.255.0',
            'router_ip': '192.168.1.1',
            'dns_servers': '8.8.8.8, invalid-ip',  # Invalid DNS server
            'lease_time': '86400'
        }
        
        # Post the form
        response = self.client.post('/settings', data=form_data)
        
        # Check that an error message is displayed
        self.assertIn(b'Invalid DNS server IP', response.data)

    def test_settings_invalid_lease_time(self):
        """Test settings with invalid lease time."""
        # Prepare form data with invalid lease time
        form_data = {
            'dhcp_enabled': 'yes',
            'dhcp_range_start': '192.168.1.100',
            'dhcp_range_end': '192.168.1.200',
            'subnet_mask': '255.255.255.0',
            'router_ip': '192.168.1.1',
            'dns_servers': '8.8.8.8, 8.8.4.4',
            'lease_time': '-100'  # Negative lease time
        }
        
        # Post the form
        response = self.client.post('/settings', data=form_data)
        
        # Check that an error message is displayed
        self.assertIn(b'Lease time must be a positive number of seconds', response.data)

    @patch('app._update_hosts_file')
    def test_settings_dhcp_disabled(self, mock_update_hosts_file):
        """Test settings with DHCP disabled."""
        # Prepare form data with DHCP disabled
        form_data = {
            'dhcp_enabled': 'no',  # DHCP disabled
            'subnet_mask': '255.255.255.0',
            'lease_time': '86400'
        }
        
        # Post the form
        response = self.client.post('/settings', data=form_data, follow_redirects=True)
        
        # Check response is OK
        self.assertEqual(response.status_code, 200)
        
        # Check that network server was updated
        self.network_server.dhcp_enable = False


if __name__ == '__main__':
    unittest.main()
