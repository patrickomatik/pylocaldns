#!/usr/bin/env python3
"""
Test suite for PyLocalDNS HTMX integration.

This module contains tests for the HTMX integration in the PyLocalDNS Flask web interface.
It verifies that HTMX requests are handled correctly and appropriate partial content is returned.
"""

import os
import sys
import unittest
import tempfile
from unittest.mock import patch, MagicMock

# Add the parent directory to the path so we can import app
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import required modules
from app import init_flask_server
from hosts_file import HostsFile


class TestHTMXIntegration(unittest.TestCase):
    """Test cases for HTMX integration."""

    def setUp(self):
        """Set up test environment before each test."""
        # Create a temporary hosts file
        self.hosts_fd, self.hosts_path = tempfile.mkstemp()
        with open(self.hosts_path, 'w') as f:
            f.write("# Test hosts file\n")
            f.write("127.0.0.1 localhost\n")
            f.write("192.168.1.10 test.local [MAC=00:11:22:33:44:55]\n")
            f.write("192.168.1.20 test2.local [MAC=00:22:33:44:55:66]\n")

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

    def test_htmx_library_inclusion(self):
        """Test that the HTMX library is included in the HTML."""
        response = self.client.get('/')
        # Check response is OK
        self.assertEqual(response.status_code, 200)
        # Check that HTMX library is included
        self.assertIn(b'https://unpkg.com/htmx.org@1.9.9', response.data)

    def test_dashboard_content_htmx_request(self):
        """Test that dashboard-content endpoint handles HTMX requests correctly."""
        # Make an HTMX request to the dashboard-content endpoint
        response = self.client.get('/dashboard-content', headers={
            'HX-Request': 'true'
        })
        
        # Check response is OK
        self.assertEqual(response.status_code, 200)
        
        # Check that response contains expected content
        self.assertIn(b'192.168.1.10', response.data)
        self.assertIn(b'test.local', response.data)
        self.assertIn(b'00:11:22:33:44:55', response.data)
        self.assertIn(b'192.168.1.20', response.data)
        self.assertIn(b'test2.local', response.data)
        self.assertIn(b'00:22:33:44:55:66', response.data)
        
        # Check that it doesn't include the full HTML page (no header/footer)
        self.assertNotIn(b'<!DOCTYPE html>', response.data)
        self.assertNotIn(b'</html>', response.data)

    def test_port_scan_htmx_request(self):
        """Test that port scanning works with HTMX."""
        # Setup a mock for scan_client_ports
        with patch('app.scan_client_ports') as mock_scan_ports, \
             patch('app.refresh_port_data') as mock_refresh_port_data, \
             patch('app.get_port_db') as mock_get_port_db, \
             patch('app.USE_PORT_DB', True):
            
            # Configure mocks
            mock_get_port_db.return_value = MagicMock()
            mock_refresh_port_data.return_value = [80, 443]
            
            # Make an HTMX request to scan ports
            response = self.client.post('/scan-ports', headers={
                'HX-Request': 'true'
            }, follow_redirects=True)
            
            # Check response is OK
            self.assertEqual(response.status_code, 200)
            
            # Check that the scan function was called for all devices
            # There should be 2 static entries in our test hosts file
            self.assertEqual(mock_refresh_port_data.call_count, 2)
            
            # Check that response contains expected content without full HTML
            self.assertIn(b'192.168.1.10', response.data)
            self.assertIn(b'192.168.1.20', response.data)
            self.assertNotIn(b'<!DOCTYPE html>', response.data)

    def test_api_refresh_dashboard(self):
        """Test the API endpoint for refreshing the dashboard."""
        response = self.client.get('/api/refresh-dashboard')
        
        # Check response is OK
        self.assertEqual(response.status_code, 200)
        
        # Check that response contains expected content
        self.assertIn(b'192.168.1.10', response.data)
        self.assertIn(b'test.local', response.data)
        self.assertIn(b'192.168.1.20', response.data)
        self.assertIn(b'test2.local', response.data)

    def test_htmx_attributes_in_html(self):
        """Test that HTMX attributes are present in the HTML."""
        response = self.client.get('/')
        
        # Check response is OK
        self.assertEqual(response.status_code, 200)
        
        # Check for HTMX attributes in the HTML
        # Auto-refresh attribute
        self.assertIn(b'hx-trigger="every 10s"', response.data)
        # Target attribute
        self.assertIn(b'hx-target="#dashboard-content"', response.data)
        # HTMX GET attribute
        self.assertIn(b'hx-get="/dashboard-content"', response.data)
        # Loading indicator
        self.assertIn(b'class="htmx-indicator"', response.data)

    def test_scan_ports_button(self):
        """Test the scan ports button has proper HTMX attributes."""
        response = self.client.get('/')
        
        # Check response is OK
        self.assertEqual(response.status_code, 200)
        
        # Check for HTMX attributes on the scan ports button
        self.assertIn(b'hx-post="/scan-ports"', response.data)
        self.assertIn(b'hx-target="#dashboard-content"', response.data)
        self.assertIn(b'Scan Ports', response.data)

    def test_add_entry_trigger(self):
        """Test adding an entry and returning to the dashboard."""
        # Setup a mock for _update_hosts_file to avoid writing to the real file
        with patch('app._update_hosts_file'):
            # Make a request to add a new entry
            response = self.client.post('/add', data={
                'mac': '00:33:44:55:66:77',
                'ip': '192.168.1.30',
                'hostnames': 'test3.local'
            }, follow_redirects=True)
            
            # Check response is OK
            self.assertEqual(response.status_code, 200)
            
            # Check that the new entry appears in the dashboard
            self.assertIn(b'192.168.1.30', response.data)
            self.assertIn(b'test3.local', response.data)
            self.assertIn(b'00:33:44:55:66:77', response.data)
            
            # Check that the entry was added to hosts_file
            self.assertIn('00:33:44:55:66:77', self.hosts_file.mac_to_ip)
            self.assertEqual(self.hosts_file.mac_to_ip['00:33:44:55:66:77'], '192.168.1.30')


if __name__ == '__main__':
    unittest.main()
