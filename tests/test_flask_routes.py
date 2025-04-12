#!/usr/bin/env python3
"""
Test suite for PyLocalDNS Flask routes.

This module contains tests for the Flask web interface routes in the PyLocalDNS application.
It verifies that routes handle requests correctly and return the expected responses.
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


class TestFlaskRoutes(unittest.TestCase):
    """Test cases for Flask routes."""

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

    def test_home_route(self):
        """Test the home route (/)."""
        response = self.client.get('/')
        # Check response is OK
        self.assertEqual(response.status_code, 200)
        # Check the title is in the response
        self.assertIn(b'Network Server Admin', response.data)
        # Check the static entry is displayed
        self.assertIn(b'192.168.1.10', response.data)
        self.assertIn(b'00:11:22:33:44:55', response.data)
        self.assertIn(b'test.local', response.data)

    def test_dashboard_content_route(self):
        """Test the dashboard content route for HTMX updates."""
        response = self.client.get('/dashboard-content', headers={'HX-Request': 'true'})
        # Check response is OK
        self.assertEqual(response.status_code, 200)
        # Check the content is returned (should be the same as home page content)
        self.assertIn(b'192.168.1.10', response.data)
        self.assertIn(b'00:11:22:33:44:55', response.data)

    def test_add_entry_get(self):
        """Test the add entry form page."""
        response = self.client.get('/add')
        # Check response is OK
        self.assertEqual(response.status_code, 200)
        # Check the form is in the response
        self.assertIn(b'Add New Entry', response.data)
        self.assertIn(b'<form method="post" action="/add">', response.data)
        self.assertIn(b'<input type="text" id="mac" name="mac"', response.data)
        self.assertIn(b'<input type="text" id="ip" name="ip"', response.data)
        self.assertIn(b'<input type="text" id="hostnames" name="hostnames"', response.data)

    @patch('app._update_hosts_file')
    def test_add_entry_post(self, mock_update_hosts_file):
        """Test adding a new entry via POST."""
        # Prepare form data
        form_data = {
            'mac': '00:22:33:44:55:66',
            'ip': '192.168.1.20',
            'hostnames': 'test2.local, test2'
        }
        
        # Post the form
        response = self.client.post('/add', data=form_data, follow_redirects=True)
        
        # Check response is OK
        self.assertEqual(response.status_code, 200)
        
        # Verify the entry was added to hosts_file
        self.assertIn('00:22:33:44:55:66', self.hosts_file.mac_to_ip)
        self.assertEqual(self.hosts_file.mac_to_ip['00:22:33:44:55:66'], '192.168.1.20')
        
        # Check that _update_hosts_file was called
        mock_update_hosts_file.assert_called_once()
        
        # Check that success message is displayed
        self.assertIn(b'Entry added successfully', response.data)

    def test_edit_entry_get(self):
        """Test the edit entry form page."""
        response = self.client.get('/edit?mac=00:11:22:33:44:55')
        # Check response is OK
        self.assertEqual(response.status_code, 200)
        # Check the form is pre-populated with existing data
        self.assertIn(b'Edit Entry', response.data)
        self.assertIn(b'<form method="post" action="/update">', response.data)
        self.assertIn(b'value="00:11:22:33:44:55"', response.data)
        self.assertIn(b'value="192.168.1.10"', response.data)
        self.assertIn(b'value="test.local"', response.data)

    @patch('app._update_hosts_file')
    def test_update_entry_post(self, mock_update_hosts_file):
        """Test updating an entry via POST."""
        # Prepare form data
        form_data = {
            'mac': '00:11:22:33:44:55',
            'ip': '192.168.1.10',
            'original_ip': '192.168.1.10',
            'hostnames': 'updated.local, test'
        }
        
        # Post the form
        response = self.client.post('/update', data=form_data, follow_redirects=True)
        
        # Check response is OK
        self.assertEqual(response.status_code, 200)
        
        # Verify the entry was updated in hosts_file
        self.assertEqual(self.hosts_file.mac_to_ip['00:11:22:33:44:55'], '192.168.1.10')
        self.assertIn('updated.local', self.hosts_file.ip_to_hostnames['192.168.1.10'])
        
        # Check that _update_hosts_file was called
        mock_update_hosts_file.assert_called_once()
        
        # Check that success message is displayed
        self.assertIn(b'Entry updated successfully', response.data)

    @patch('app._update_hosts_file')
    def test_delete_entry(self, mock_update_hosts_file):
        """Test deleting an entry."""
        # Delete the entry
        response = self.client.get('/delete?mac=00:11:22:33:44:55', follow_redirects=True)
        
        # Check response is OK
        self.assertEqual(response.status_code, 200)
        
        # Verify the entry was deleted from hosts_file
        self.assertNotIn('00:11:22:33:44:55', self.hosts_file.mac_to_ip)
        
        # Check that _update_hosts_file was called
        mock_update_hosts_file.assert_called_once()
        
        # Check that success message is displayed
        self.assertIn(b'Entry deleted successfully', response.data)

    def test_scan_network_page(self):
        """Test the scan network page."""
        response = self.client.get('/scan')
        # Check response is OK
        self.assertEqual(response.status_code, 200)
        # Check the page displays the scan form
        self.assertIn(b'Network Scanner', response.data)
        self.assertIn(b'<form method="post" action="/scan">', response.data)
        self.assertIn(b'Start Network Scan', response.data)

    @patch('app.handle_scan_request')
    def test_scan_network_post(self, mock_handle_scan_request):
        """Test the scan network POST request."""
        # Set up mock to simulate a successful scan
        def side_effect():
            # Store results in app object
            self.flask_app.scan_results = {
                '192.168.1.50': {
                    'mac': '11:22:33:44:55:66',
                    'status': 'Added',
                    'ports': [22, 80, 443]
                }
            }
            return self.client.get('/scan?message=Network+scan+started.&type=success')
            
        mock_handle_scan_request.side_effect = side_effect
        
        # Post to the scan endpoint
        response = self.client.post('/scan', follow_redirects=True)
        
        # Check response is OK
        self.assertEqual(response.status_code, 200)
        
        # Check that handle_scan_request was called
        mock_handle_scan_request.assert_called_once()
        
        # Check that success message is displayed
        self.assertIn(b'Network scan started', response.data)

    def test_settings_page(self):
        """Test the settings page."""
        response = self.client.get('/settings')
        # Check response is OK
        self.assertEqual(response.status_code, 200)
        # Check the page displays the settings form
        self.assertIn(b'Network Settings', response.data)
        self.assertIn(b'<form method="post" action="/save-settings">', response.data)
        self.assertIn(b'DHCP Settings', response.data)
        self.assertIn(b'Subnet Mask', response.data)
        self.assertIn(b'Save Settings', response.data)

    @patch('app._update_hosts_file')
    def test_settings_post(self, mock_update_hosts_file):
        """Test saving settings via POST."""
        # Prepare form data
        form_data = {
            'dhcp_enabled': 'yes',
            'dhcp_range_start': '192.168.1.100',
            'dhcp_range_end': '192.168.1.200',
            'subnet_mask': '255.255.255.0',
            'router_ip': '192.168.1.1',
            'dns_servers': '8.8.8.8, 8.8.4.4',
            'lease_time': '86400'
        }
        
        # Post the form
        response = self.client.post('/save-settings', data=form_data, follow_redirects=True)
        
        # Check response is OK
        self.assertEqual(response.status_code, 200)
        
        # Check the network server was updated
        self.network_server.dhcp_server.subnet_mask = '255.255.255.0'
        self.network_server.dhcp_server.router = '192.168.1.1'
        
        # Check that success message is displayed
        self.assertIn(b'Settings saved successfully', response.data)

    def test_api_health_check(self):
        """Test the API health check endpoint."""
        response = self.client.get('/api/health-check')
        # Check response is OK
        self.assertEqual(response.status_code, 200)
        # Check the response is JSON
        self.assertEqual(response.content_type, 'application/json')
        # Parse the JSON
        data = json.loads(response.data)
        # Check the status is 'ok'
        self.assertEqual(data['status'], 'ok')
        # Check other fields
        self.assertIn('dns_server', data)
        self.assertIn('dhcp_server', data)
        self.assertIn('web_ui', data)
        self.assertIn('hosts_file', data)
        self.assertTrue(data['web_ui'])  # Web UI should be enabled
        self.assertTrue(data['hosts_file'])  # Hosts file should be available


if __name__ == '__main__':
    unittest.main()
