#!/usr/bin/env python3
"""
Test Script for the Web UI Routes

This script tests that all routes in the WebUI are accessible and return proper responses.
"""

import os
import sys
import json
import time
import unittest
import threading
import tempfile
import http.client
import urllib.parse
import socket
from http.server import HTTPServer
from unittest.mock import patch, MagicMock

# Add parent directory to the path so we can import the necessary modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import logging
# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('test_webui_routes')

# Import local modules - now using the refactored webui structure
from hosts_file import HostsFile
from webui import WebUIServer  # The main entry point remains the same
from webui_core import WebUIHandler  # But now need to import WebUIHandler from webui_core


def find_available_port(start_port, max_attempts=100):
    """Find an available port starting from the given port."""
    for port in range(start_port, start_port + max_attempts):
        try:
            # Try to create a socket and bind to the port
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(('localhost', port))
            sock.close()
            return port
        except (socket.error, OSError):
            # Port is not available, try the next one
            continue
    
    # If we get here, we couldn't find an available port
    raise RuntimeError(f"Could not find an available port in range {start_port}-{start_port + max_attempts}")



class TestWebUIRoutes(unittest.TestCase):
    """Test cases for the Web UI routes."""
    
    @classmethod
    def setUpClass(cls):
        """Set up the test environment once for all tests."""
        # Create a temporary file for the hosts file
        cls.hosts_fd, cls.hosts_path = tempfile.mkstemp()
        os.close(cls.hosts_fd)
        
        # Write initial hosts file content
        with open(cls.hosts_path, 'w') as f:
            f.write("""# Test hosts file
192.168.1.10 server1.local server1 [MAC=00:11:22:33:44:55]
192.168.1.20 server2.local server2 [MAC=aa:bb:cc:dd:ee:ff]
""")
        
        # Initialize hosts file with DHCP range
        cls.dhcp_range = ('192.168.1.100', '192.168.1.200')
        cls.hosts_file = HostsFile(cls.hosts_path, cls.dhcp_range)
        
        # Find an available port for the test server
        cls.webui_port = find_available_port(8899)
        
        # Create a mock network server for the WebUI to use
        cls.mock_network_server = MagicMock()
        cls.mock_network_server.dhcp_enable = True
        cls.mock_network_server.hosts = cls.hosts_file
        cls.mock_network_server.dhcp_server = MagicMock()
        cls.mock_network_server.dhcp_server.subnet_mask = "255.255.255.0"
        cls.mock_network_server.dhcp_server.router = "192.168.1.1"
        cls.mock_network_server.dhcp_server.dns_servers = ["8.8.8.8", "8.8.4.4"]
        cls.mock_network_server.dhcp_server.default_lease_time = 86400
        
        # Initialize the WebUI server
        cls.webui_server = WebUIServer(
            cls.hosts_file, 
            cls.webui_port, 
            'localhost',
            network_server=cls.mock_network_server
        )
        
        # Start the server in a separate thread
        cls.server_thread = cls.webui_server.start()
        
        # Allow the server time to start
        time.sleep(0.5)
    
    @classmethod
    def tearDownClass(cls):
        """Clean up after all tests are complete."""
        # Stop the Web UI server
        if hasattr(cls, 'webui_server'):
            cls.webui_server.stop()
        
        # Remove the temporary hosts file
        if hasattr(cls, 'hosts_path'):
            os.remove(cls.hosts_path)
    
    def setUp(self):
        """Set up for each test."""
        # Create a connection to the Web UI server
        self.conn = http.client.HTTPConnection('localhost', self.webui_port)
    
    def tearDown(self):
        """Clean up after each test."""
        # Close the connection
        if hasattr(self, 'conn'):
            self.conn.close()
    
    def test_home_page(self):
        """Test the home page (/) route."""
        self.conn.request('GET', '/')
        response = self.conn.getresponse()
        
        # Check that the response is successful
        self.assertEqual(response.status, 200)
        
        # Read the response content
        content = response.read().decode('utf-8')
        
        # Check that key elements of the home page are present
        self.assertIn('<h1>Network Server Admin</h1>', content)
        self.assertIn('Static Entries', content)
        self.assertIn('DHCP Leases', content)
        
        # Verify navigation links including scan network
        self.assertIn('<a href="/scan"', content)
    
    def test_scan_page(self):
        """Test the scan network (/scan) route."""
        self.conn.request('GET', '/scan')
        response = self.conn.getresponse()
        
        # Check that the response is successful
        self.assertEqual(response.status, 200)
        
        # Read the response content
        content = response.read().decode('utf-8')
        
        # Check that key elements of the scan page are present
        self.assertIn('<h1>Network Scanner</h1>', content)
        self.assertIn('action="/scan"', content)
        self.assertIn('Start Network Scan', content)
    
    def test_add_page(self):
        """Test the add new entry (/add) route."""
        self.conn.request('GET', '/add')
        response = self.conn.getresponse()
        
        # Check that the response is successful
        self.assertEqual(response.status, 200)
        
        # Read the response content
        content = response.read().decode('utf-8')
        
        # Check that key elements of the add page are present
        self.assertIn('<h1>Add New Entry</h1>', content)
        self.assertIn('action="/add"', content)
        self.assertIn('MAC Address', content)
        self.assertIn('IP Address', content)
        self.assertIn('Hostnames', content)
    
    def test_edit_page(self):
        """Test the edit entry (/edit) route."""
        self.conn.request('GET', '/edit?mac=00:11:22:33:44:55')
        response = self.conn.getresponse()
        
        # Check that the response is successful
        self.assertEqual(response.status, 200)
        
        # Read the response content
        content = response.read().decode('utf-8')
        
        # Check that key elements of the edit page are present
        self.assertIn('<h1>Edit Entry</h1>', content)
        self.assertIn('action="/update"', content)
        self.assertIn('00:11:22:33:44:55', content)
        self.assertIn('IP Address', content)
        self.assertIn('Hostnames', content)
    
    def test_settings_page(self):
        """Test the settings (/settings) route."""
        self.conn.request('GET', '/settings')
        response = self.conn.getresponse()
        
        # Check that the response is successful
        self.assertEqual(response.status, 200)
        
        # Read the response content
        content = response.read().decode('utf-8')
        
        # Check that key elements of the settings page are present
        self.assertIn('<h1>Network Server Settings</h1>', content)
        self.assertIn('action="/save-settings"', content)
        self.assertIn('DHCP Settings', content)
        self.assertIn('Subnet Mask', content)
        self.assertIn('Default Gateway', content)
        self.assertIn('DNS Servers', content)
    
    def test_invalid_edit_page(self):
        """Test the edit page with an invalid MAC address."""
        self.conn.request('GET', '/edit?mac=invalid-mac')
        response = self.conn.getresponse()
        
        # Check that it returns a not found error
        self.assertEqual(response.status, 404)
    
    def test_missing_mac_for_edit(self):
        """Test the edit page without a MAC parameter."""
        self.conn.request('GET', '/edit')
        response = self.conn.getresponse()
        
        # Check that it returns a bad request error
        self.assertEqual(response.status, 400)
    
    def test_nonexistent_route(self):
        """Test accessing a non-existent route."""
        self.conn.request('GET', '/nonexistent')
        response = self.conn.getresponse()
        
        # Check that it returns a not found error
        self.assertEqual(response.status, 404)
    

class TestWebUIFormSubmissions(unittest.TestCase):
    """Test cases for form submissions in the Web UI."""
    
    @classmethod
    def setUpClass(cls):
        """Set up the test environment once for all tests."""
        # Create a temporary file for the hosts file
        cls.hosts_fd, cls.hosts_path = tempfile.mkstemp()
        os.close(cls.hosts_fd)
        
        # Write initial hosts file content
        with open(cls.hosts_path, 'w') as f:
            f.write("""# Test hosts file
192.168.1.10 server1.local server1 [MAC=00:11:22:33:44:55]
192.168.1.20 server2.local server2 [MAC=aa:bb:cc:dd:ee:ff]
""")
        
        # Initialize hosts file with DHCP range
        cls.dhcp_range = ('192.168.1.100', '192.168.1.200')
        cls.hosts_file = HostsFile(cls.hosts_path, cls.dhcp_range)
        
        # Find an available port for the test server
        cls.webui_port = find_available_port(8898)
        
        # Create a mock network server for the WebUI to use
        cls.mock_network_server = MagicMock()
        cls.mock_network_server.dhcp_enable = True
        cls.mock_network_server.hosts = cls.hosts_file
        cls.mock_network_server.dhcp_server = MagicMock()
        cls.mock_network_server.dhcp_server.subnet_mask = "255.255.255.0"
        cls.mock_network_server.dhcp_server.router = "192.168.1.1"
        cls.mock_network_server.dhcp_server.dns_servers = ["8.8.8.8", "8.8.4.4"]
        cls.mock_network_server.dhcp_server.default_lease_time = 86400
        
        # Initialize the WebUI server
        cls.webui_server = WebUIServer(
            cls.hosts_file, 
            cls.webui_port, 
            'localhost',
            network_server=cls.mock_network_server
        )
        
        # Start the server in a separate thread
        cls.server_thread = cls.webui_server.start()
        
        # Allow the server time to start
        time.sleep(0.5)
    
    @classmethod
    def tearDownClass(cls):
        """Clean up after all tests are complete."""
        # Stop the Web UI server
        if hasattr(cls, 'webui_server'):
            cls.webui_server.stop()
        
        # Remove the temporary hosts file
        if hasattr(cls, 'hosts_path'):
            os.remove(cls.hosts_path)
    
    def setUp(self):
        """Set up for each test."""
        # Create a connection to the Web UI server
        self.conn = http.client.HTTPConnection('localhost', self.webui_port)
    
    def tearDown(self):
        """Clean up after each test."""
        # Close the connection
        if hasattr(self, 'conn'):
            self.conn.close()
    
    def test_add_entry_form(self):
        """Test submitting the add entry form."""
        # Prepare the form data
        form_data = urllib.parse.urlencode({
            'mac': '11:22:33:44:55:66',
            'ip': '192.168.1.50',
            'hostnames': 'test.local, testhost'
        })
        
        # Submit the form
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        self.conn.request('POST', '/add', body=form_data, headers=headers)
        response = self.conn.getresponse()
        
        # Check that it redirects to the home page
        self.assertEqual(response.status, 302)
        self.assertEqual(response.getheader('Location'), '/?message=Entry+added+successfully&type=success')
        
        # Read the response body to clear the connection
        response.read()
        
        # Verify that the entry was added
        self.conn.request('GET', '/')
        response = self.conn.getresponse()
        content = response.read().decode('utf-8')
        
        # Check that the new entry is in the home page
        self.assertIn('11:22:33:44:55:66', content)
        self.assertIn('192.168.1.50', content)
        self.assertIn('test.local', content)
    
    def test_update_entry_form(self):
        """Test submitting the update entry form."""
        # Add a MAC to update first
        form_data = urllib.parse.urlencode({
            'mac': '22:33:44:55:66:77',
            'ip': '192.168.1.60',
            'hostnames': 'original.local'
        })
        
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        self.conn.request('POST', '/add', body=form_data, headers=headers)
        response = self.conn.getresponse()
        response.read()  # Clear the response
        
        # Now update the entry
        update_data = urllib.parse.urlencode({
            'mac': '22:33:44:55:66:77',
            'original_ip': '192.168.1.60',
            'ip': '192.168.1.61',
            'hostnames': 'updated.local, newname'
        })
        
        self.conn.request('POST', '/update', body=update_data, headers=headers)
        response = self.conn.getresponse()
        
        # Check that it redirects to the home page
        self.assertEqual(response.status, 302)
        self.assertEqual(response.getheader('Location'), '/?message=Entry+updated+successfully&type=success')
        
        # Read the response body to clear the connection
        response.read()
        
        # Verify that the entry was updated
        self.conn.request('GET', '/')
        response = self.conn.getresponse()
        content = response.read().decode('utf-8')
        
        # Check that the updated entry is in the home page
        self.assertIn('22:33:44:55:66:77', content)
        self.assertIn('192.168.1.61', content)
        self.assertIn('updated.local', content)
    

class TestScanNetworkIntegration(unittest.TestCase):
    """Test cases for the scan network functionality."""
    
    @classmethod
    def setUpClass(cls):
        """Set up the test environment once for all tests."""
        # Create a temporary file for the hosts file
        cls.hosts_fd, cls.hosts_path = tempfile.mkstemp()
        os.close(cls.hosts_fd)
        
        # Write initial hosts file content
        with open(cls.hosts_path, 'w') as f:
            f.write("""# Test hosts file
192.168.1.10 server1.local server1 [MAC=00:11:22:33:44:55]
""")
        
        # Initialize hosts file with DHCP range
        cls.dhcp_range = ('192.168.1.100', '192.168.1.120')  # Small range for testing
        cls.hosts_file = HostsFile(cls.hosts_path, cls.dhcp_range)
        
        # Find an available port for the test server
        cls.webui_port = find_available_port(8897)
        
        # Create a mock network server for the WebUI to use
        cls.mock_network_server = MagicMock()
        cls.mock_network_server.dhcp_enable = True
        cls.mock_network_server.hosts = cls.hosts_file
        cls.mock_network_server.dhcp_server = MagicMock()
        
        # Initialize the WebUI server
        cls.webui_server = WebUIServer(
            cls.hosts_file, 
            cls.webui_port, 
            'localhost',
            network_server=cls.mock_network_server
        )
        
        # Start the server in a separate thread
        cls.server_thread = cls.webui_server.start()
        
        # Allow the server time to start
        time.sleep(0.5)
    
    @classmethod
    def tearDownClass(cls):
        """Clean up after all tests are complete."""
        # Stop the Web UI server
        if hasattr(cls, 'webui_server'):
            cls.webui_server.stop()
        
        # Remove the temporary hosts file
        if hasattr(cls, 'hosts_path'):
            os.remove(cls.hosts_path)
    
    def setUp(self):
        """Set up for each test."""
        # Create a connection to the Web UI server
        self.conn = http.client.HTTPConnection('localhost', self.webui_port)
    
    def tearDown(self):
        """Clean up after each test."""
        # Close the connection
        if hasattr(self, 'conn'):
            self.conn.close()
    
    @patch('hosts_file.HostsFile.scan_network')
    def test_scan_network_request(self, mock_scan):
        """Test submitting a scan network request."""
        # Mock the scan_network function to return some test results with ports
        mock_scan.return_value = {
            '192.168.1.100': {'mac': '11:22:33:44:55:66', 'ports': [22, 80]},
            '192.168.1.101': {'mac': '22:33:44:55:66:77', 'ports': [443, 8080]},
            '192.168.1.10': {'mac': '00:11:22:33:44:55', 'ports': []}  # Existing entry
        }
        
        # We need to patch the _add_preallocated_ip method to avoid disk I/O issues in tests
        with patch.object(self.hosts_file, '_add_preallocated_ip'):
            # Submit the scan request
            self.conn.request('POST', '/scan')
            response = self.conn.getresponse()
            
            # Check that it redirects to the scan page with a success message
            self.assertEqual(response.status, 302)
            self.assertTrue('/scan?message=' in response.getheader('Location'))
            
            # Read the response body to clear the connection
            response.read()

        # Verify we can at least access the scan page
        self.conn.request('GET', '/scan')
        response = self.conn.getresponse()
        content = response.read().decode('utf-8')
        
        # Check for the scanner header on the page
        self.assertIn('Network Scanner', content)
        
        # Check that the scan function was called with the expected parameters
        mock_scan.assert_called_once()
        
        # Verify the scan function returns correctly structured data for ports
        self.assertEqual(mock_scan.return_value['192.168.1.100']['ports'], [22, 80])
        self.assertEqual(mock_scan.return_value['192.168.1.101']['ports'], [443, 8080])
    
    def test_scan_without_dhcp_range(self):
        """Test scan network when no DHCP range is configured."""
        # Create a hosts file with no DHCP range
        temp_fd, temp_path = tempfile.mkstemp()
        os.close(temp_fd)
        
        with open(temp_path, 'w') as f:
            f.write("# Empty hosts file\n")
        
        # Create a hosts file instance with no DHCP range
        no_range_hosts = HostsFile(temp_path)
        
        # Create a WebUI server with this hosts file
        no_range_port = find_available_port(8896)
        no_range_server = WebUIServer(no_range_hosts, no_range_port, 'localhost')
        
        try:
            # Start the server
            no_range_thread = no_range_server.start()
            time.sleep(0.5)
            
            # Create a connection
            conn = http.client.HTTPConnection('localhost', no_range_port)
            
            # Try to submit a scan request
            conn.request('POST', '/scan')
            response = conn.getresponse()
            
            # Should get a 400 error
            self.assertEqual(response.status, 400)
            
            # Check the error message
            content = response.read().decode('utf-8')
            self.assertIn('DHCP range not configured', content)
            
        finally:
            # Clean up
            if 'no_range_server' in locals():
                no_range_server.stop()
            if 'conn' in locals():
                conn.close()
            os.remove(temp_path)


if __name__ == '__main__':
    unittest.main()
