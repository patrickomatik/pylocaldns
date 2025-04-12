#!/usr/bin/env python3
"""
Test Script for HTMX Integration

This script tests the HTMX integration for dynamically updating the dashboard.
"""

import os
import sys
import time
import unittest
import tempfile
import http.client
import socket
from unittest.mock import patch, MagicMock

# Add parent directory to the path so we can import the necessary modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import logging
# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('test_htmx_integration')

# Import local modules
from hosts_file import HostsFile
from webui import WebUIServer
from webui_core import WebUIHandler


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


class TestHTMXIntegration(unittest.TestCase):
    """Test cases for HTMX integration in the Web UI."""
    
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
192.168.1.20 server2.local server2 ports-80,443 [MAC=aa:bb:cc:dd:ee:ff]
""")
        
        # Initialize hosts file with DHCP range
        cls.dhcp_range = ('192.168.1.100', '192.168.1.120')
        cls.hosts_file = HostsFile(cls.hosts_path, cls.dhcp_range)
        
        # Find an available port for the test server
        cls.webui_port = find_available_port(8897)
        
        # Create a mock network server
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
    
    def test_htmx_library_included(self):
        """Test that the HTMX library is included on the home page."""
        self.conn.request('GET', '/')
        response = self.conn.getresponse()
        self.assertEqual(response.status, 200)
        
        content = response.read().decode('utf-8')
        
        # Check for HTMX script inclusion
        self.assertIn('htmx.org', content, "HTMX library not included in the page")
        
        # Check for <script> tag with HTMX
        self.assertIn('<script src=', content, "No script tag found for HTMX")
        self.assertIn('unpkg.com/htmx', content, "HTMX script source not found")
    
    def test_dashboard_content_endpoint(self):
        """Test that the dashboard-content endpoint works."""
        # Make a request to the dashboard-content endpoint
        self.conn.request('GET', '/dashboard-content')
        response = self.conn.getresponse()
        
        # Check that the response is successful
        self.assertEqual(response.status, 200)
        
        # Read the response content
        content = response.read().decode('utf-8')
        
        # It should contain table data but not the full HTML structure
        self.assertIn('<table>', content, "No table found in dashboard content")
        self.assertIn('server1.local', content, "Static entry not found in dashboard content")
        
        # It should NOT contain the HTML header or footer elements
        self.assertNotIn('<!DOCTYPE html>', content, "Full HTML structure found in dashboard content")
        self.assertNotIn('</html>', content, "HTML closing tag found in dashboard content")
    
    def test_htmx_attributes_present(self):
        """Test that HTMX attributes are present on the home page."""
        self.conn.request('GET', '/')
        response = self.conn.getresponse()
        self.assertEqual(response.status, 200)
        
        content = response.read().decode('utf-8')
        
        # Check for HTMX attributes
        htmx_attributes = [
            'hx-get',
            'hx-trigger',
            'hx-swap',
            'id="dashboard-content"'
        ]
        
        found_attributes = [attr for attr in htmx_attributes if attr in content]
        
        # All of these attributes should be present
        for attr in htmx_attributes:
            self.assertIn(attr, content, f"HTMX attribute '{attr}' not found")
        
        # Specifically check for the auto-refresh trigger
        self.assertIn('every 10s', content, "Auto-refresh trigger not found")
    
    def test_auto_refresh_not_using_javascript(self):
        """Test that auto-refresh is not using JavaScript setTimeout."""
        self.conn.request('GET', '/')
        response = self.conn.getresponse()
        self.assertEqual(response.status, 200)
        
        content = response.read().decode('utf-8')
        
        # Check that the JavaScript auto-refresh code is not present
        self.assertNotIn('setTimeout(function() {', content, "JavaScript setTimeout found")
        self.assertNotIn('location.reload()', content, "JavaScript page reload found")
    
    def test_htmx_trigger_for_dashboard(self):
        """Test that HTMX trigger for the dashboard is correctly set up."""
        self.conn.request('GET', '/')
        response = self.conn.getresponse()
        self.assertEqual(response.status, 200)
        
        content = response.read().decode('utf-8')
        
        # Check for the specific HTMX trigger configuration
        self.assertIn('hx-get="/dashboard-content"', content, "Dashboard content endpoint not configured")
        self.assertIn('hx-trigger="every 10s"', content, "Auto-refresh trigger not correctly configured")
        self.assertIn('hx-swap="innerHTML"', content, "Inner HTML swap not configured")
    
    def test_hx_request_header_handling(self):
        """Test that HTMX request header is properly handled."""
        # Send a request with HX-Request header to simulate HTMX
        headers = {'HX-Request': 'true'}
        self.conn.request('GET', '/', headers=headers)
        response = self.conn.getresponse()
        self.assertEqual(response.status, 200)
        
        content = response.read().decode('utf-8')
        
        # The response should be different when HX-Request header is present
        # When HX-Request is true, we should get just the dashboard content
        # and not the full page with HTML headers
        
        # This test requires a bit of care because we don't have direct access
        # to the handler's internal state. We'll check for key differences.
        
        # Make another request without the HX-Request header
        self.conn.close()
        self.conn = http.client.HTTPConnection('localhost', self.webui_port)
        self.conn.request('GET', '/')
        normal_response = self.conn.getresponse()
        normal_content = normal_response.read().decode('utf-8')
        
        # If header is handled correctly, the content should be different
        self.assertNotEqual(len(content), len(normal_content), 
                          "HX-Request header doesn't appear to change the response")
    
    def test_dashboard_partial_update(self):
        """Test that dashboard content can be updated without a full page reload."""
        # This is difficult to test directly in an automated way
        # since we'd need to simulate the HTMX JavaScript behavior
        
        # We'll focus on testing that the API endpoints exist and return the expected content
        
        # First, check that the /dashboard-content endpoint returns content
        self.conn.request('GET', '/dashboard-content')
        response = self.conn.getresponse()
        self.assertEqual(response.status, 200, "Dashboard content endpoint failed")
        
        # Save the current content
        content = response.read().decode('utf-8')
        
        # Check that it includes tables but not HTML headers
        self.assertIn('<table>', content, "Table not found in dashboard content")
        self.assertNotIn('<!DOCTYPE html>', content, "Full HTML found in dashboard content")
        
        # Now simulate a change in the hosts file
        # Add a new entry to the hosts file
        with open(self.hosts_path, 'a') as f:
            f.write("\n192.168.1.30 server3.local server3 ports-22,21 [MAC=bb:cc:dd:ee:ff:00]\n")
        
        # Force the hosts file to reload
        self.hosts_file.last_modified = 0
        self.hosts_file.load_file()
        
        # Get the dashboard content again
        self.conn.close()
        self.conn = http.client.HTTPConnection('localhost', self.webui_port)
        self.conn.request('GET', '/dashboard-content')
        response = self.conn.getresponse()
        self.assertEqual(response.status, 200, "Dashboard content endpoint failed after update")
        
        # Get the new content
        new_content = response.read().decode('utf-8')
        
        # Check that the new content is different and includes the new server
        self.assertNotEqual(content, new_content, "Dashboard content didn't change after hosts file update")
        self.assertIn('server3.local', new_content, "New server not found in updated dashboard content")


if __name__ == '__main__':
    unittest.main()
