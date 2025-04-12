#!/usr/bin/env python3
"""
Tests for the WebUI scan network functionality.
"""

import os
import sys
import unittest
import socket
import threading
import time
from http.server import HTTPServer
from urllib.request import urlopen, Request
from http.client import HTTPConnection
from urllib.parse import urlencode

# Add parent directory to sys.path to allow imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import the necessary components
from webui_core import WebUIHandler, WebUIServer
from webui_handlers import do_GET, do_POST
from webui_scan import render_scan_page, handle_scan_request
from webui_pages import (
    render_home_page, render_edit_page, render_edit_lease_page,
    render_add_page, render_settings_page, render_edit_page_with_data,
    render_add_page_with_data, render_edit_lease_page_with_data
)
from hosts_file import HostsFile

class MockNetworkServer:
    """Mock network server for testing."""
    def __init__(self):
        self.dhcp_enable = True
        self.hosts = MockHosts()
        self.dhcp_server = MockDHCPServer()

class MockHosts:
    """Mock hosts for testing."""
    def __init__(self):
        self.dhcp_range = ['192.168.1.100', '192.168.1.200']

class MockDHCPServer:
    """Mock DHCP server for testing."""
    def __init__(self):
        self.subnet_mask = '255.255.255.0'
        self.router = '192.168.1.1'
        self.dns_servers = ['8.8.8.8', '8.8.4.4']
        self.default_lease_time = 86400

def find_available_port():
    """Find an available port for the test server."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('localhost', 0))
        return s.getsockname()[1]

class TestWebUIScanRoutes(unittest.TestCase):
    """Test WebUI scan routes."""
    
    @classmethod
    def setUpClass(cls):
        """Set up test environment."""
        # Create a temporary hosts file
        cls.hosts_file_path = os.path.abspath(os.path.join(os.path.dirname(__file__), 'test_hosts.txt'))
        with open(cls.hosts_file_path, 'w') as f:
            f.write("# Test hosts file\n")
            f.write("192.168.1.10 test1.local [MAC=00:11:22:33:44:55]\n")
        
        # Set up hosts file and network server
        cls.hosts = HostsFile(cls.hosts_file_path)
        
        # Add DHCP range
        cls.hosts.dhcp_range = ['192.168.1.100', '192.168.1.200']
        
        # Set up mock network server
        cls.network_server = MockNetworkServer()
        
        # Set up the WebUIHandler class like in webui.py
        WebUIHandler.do_GET = do_GET
        WebUIHandler.do_POST = do_POST
        WebUIHandler._render_home_page = render_home_page
        WebUIHandler._render_edit_page = render_edit_page
        WebUIHandler._render_edit_page_with_data = render_edit_page_with_data
        WebUIHandler._render_add_page = render_add_page
        WebUIHandler._render_add_page_with_data = render_add_page_with_data
        WebUIHandler._render_edit_lease_page = render_edit_lease_page
        WebUIHandler._render_edit_lease_page_with_data = render_edit_lease_page_with_data
        WebUIHandler._render_settings_page = render_settings_page
        WebUIHandler._render_scan_page = render_scan_page
        WebUIHandler._handle_scan_request = handle_scan_request
        
        # Find an available port
        cls.port = find_available_port()
        
        # Set up WebUI server
        cls.webui = WebUIServer(cls.hosts, port=cls.port, interface='localhost', network_server=cls.network_server)
        
        # Start server in a thread
        cls.server_thread = cls.webui.start()
        
        # Give server time to start
        time.sleep(0.5)
    
    @classmethod
    def tearDownClass(cls):
        """Clean up test environment."""
        # Stop server
        cls.webui.stop()
        
        # Wait for server to stop
        time.sleep(0.5)
        
        # Remove test hosts file
        if os.path.exists(cls.hosts_file_path):
            os.remove(cls.hosts_file_path)
    
    def test_scan_page_get(self):
        """Test GET request to /scan."""
        # Make request
        url = f'http://localhost:{self.port}/scan'
        response = urlopen(url)
        
        # Check response
        self.assertEqual(response.getcode(), 200)
        
        # Check content
        content = response.read().decode('utf-8')
        self.assertIn('Network Scanner', content)
        self.assertIn('Start Network Scan', content)
    
    def test_scan_page_get_with_message(self):
        """Test GET request to /scan with message."""
        # Make request
        url = f'http://localhost:{self.port}/scan?message=Test+message&type=success'
        response = urlopen(url)
        
        # Check response
        self.assertEqual(response.getcode(), 200)
        
        # Check content
        content = response.read().decode('utf-8')
        self.assertIn('Test message', content)
        self.assertIn('success', content)
    
    def test_scan_request_post(self):
        """Test POST request to /scan."""
        # Make request
        url = f'http://localhost:{self.port}/scan'
        data = {}
        
        # Try to patch the scan_network_async function to avoid actual scanning
        # This is a bit of a hack, but it avoids making actual network requests
        import ip_utils
        original_scan_network_async = ip_utils.scan_network_async
        
        try:
            # Replace scan_network_async with a mock function
            def mock_scan_network_async(ip_range, callback=None, use_db=True, scan_name=None):
                # Call the callback function to simulate progress
                if callback:
                    callback(10, 10)
                
                # Return mock results
                return {
                    '192.168.1.150': {
                        'mac': '00:11:22:33:44:56',
                        'ports': [80, 443]
                    }
                }
            
            # Replace the function
            ip_utils.scan_network_async = mock_scan_network_async
            
            # Send the POST request
            headers = {'Content-Type': 'application/x-www-form-urlencoded'}
            connection = HTTPConnection('localhost', self.port)
            connection.request('POST', '/scan', urlencode(data), headers)
            response = connection.getresponse()
            
            # Check response - should be a redirect to /scan
            self.assertEqual(response.status, 302)
            self.assertIn('/scan', response.getheader('Location'))
            
            # Check if the scan was started (redirected to scan page with message)
            redirect_url = f'http://localhost:{self.port}{response.getheader("Location")}'
            redirect_response = urlopen(redirect_url)
            redirect_content = redirect_response.read().decode('utf-8')
            
            # Check that the scan page shows the expected message
            self.assertIn('Network scan started', redirect_content)
        
        finally:
            # Restore the original function
            ip_utils.scan_network_async = original_scan_network_async
            
            # Close connection
            connection.close()

if __name__ == '__main__':
    unittest.main()
