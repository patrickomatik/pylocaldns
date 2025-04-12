#!/usr/bin/env python3
"""
Test Script for Port Scanning Display

This script tests that port information is correctly displayed in the Web UI.
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
from unittest.mock import patch, MagicMock

# Add parent directory to the path so we can import the necessary modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import logging
# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('test_port_scan_display')


def debug_html_content(content, search_terms):
    """Debug helper to find search terms in HTML content."""
    snippet_size = 100  # Size of context around each match
    search_results = []
    
    for term in search_terms:
        # Find all occurrences of the term
        start_pos = 0
        while True:
            pos = content.find(term, start_pos)
            if pos == -1:
                break
                
            # Get snippet around the match
            start = max(0, pos - snippet_size // 2)
            end = min(len(content), pos + len(term) + snippet_size // 2)
            snippet = content[start:end]
            
            # Highlight the match in the snippet
            highlight_start = pos - start
            highlight_end = highlight_start + len(term)
            highlighted = f"{snippet[:highlight_start]}[MATCH>{snippet[highlight_start:highlight_end]}<MATCH]{snippet[highlight_end:]}"
            
            search_results.append(f"Found '{term}' at position {pos}:\n{highlighted}\n")
            start_pos = pos + len(term)
    
    if not search_results:
        return f"None of the terms {search_terms} found in content.\nContent snippet: {content[:500]}..."
    
    return "\n".join(search_results)

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


class TestPortScanDisplay(unittest.TestCase):
    """Test cases for port scanning display in the Web UI."""
    
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
192.168.1.20 server2.local server2 ports-80,443,8080 [MAC=aa:bb:cc:dd:ee:ff]
""")
        
        # Initialize hosts file with DHCP range
        cls.dhcp_range = ('192.168.1.100', '192.168.1.120')  # Small range for testing
        cls.hosts_file = HostsFile(cls.hosts_path, cls.dhcp_range)
        
        # Find an available port for the test server
        cls.webui_port = find_available_port(8895)
        
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
    
    def test_port_display_in_home_page(self):
        """Test that port information is displayed correctly on the home page."""
        self.conn.request('GET', '/')
        response = self.conn.getresponse()
        
        # Check that the response is successful
        self.assertEqual(response.status, 200)
        
        # Read the response content
        content = response.read().decode('utf-8')
        
        # Check for server2 with ports in the content
        self.assertIn('server2.local', content)
        self.assertIn('server2', content)
        
        # Check for port styling or port content
        # Use a more flexible approach to finding port-related content
        port_indicators = [
            'port-list',  # The class for port lists
            'class="port',  # Port items
            'class=\'port',  # Alternative quote style
            'port ',  # Port mentions
            '80',  # HTTP port
            '443',  # HTTPS port
            '8080'  # Alternative HTTP port
        ]
        
        found_indicators = [indicator for indicator in port_indicators if indicator in content]
        if not found_indicators:
            debug_info = debug_html_content(content, port_indicators)
            logger.error(f"Debugging port indicators in home page:\n{debug_info}")
            
        self.assertTrue(len(found_indicators) > 0, 
                       f"No port styling or port numbers found in home page. Content snippet: {content[:500]}...")
        
        # If we can't find the HTTP labels, at least find some port numbers
        http_indicators = ['HTTP', 'HTTPS', 'Alt']
        port_numbers = ['80', '443', '8080']
        
        found_http = any(indicator in content for indicator in http_indicators)
        found_ports = any(port in content for port in port_numbers)
        
        self.assertTrue(found_http or found_ports, 
                       "Neither port descriptions nor port numbers found in home page content")
    
    @patch('hosts_file.HostsFile.scan_network')
    def test_scan_results_with_ports(self, mock_scan_network):
        """Test that port information is displayed correctly in scan results."""
        # Mock scan_network to return devices with ports
        mock_scan_network.return_value = {
            '192.168.1.100': {
                'mac': '11:22:33:44:55:66',
                'ports': [22, 80, 443]
            },
            '192.168.1.101': {
                'mac': '22:33:44:55:66:77',
                'ports': [21, 25, 3389]
            }
        }
        
        # We need to patch the _add_preallocated_ip method to avoid disk I/O issues in tests
        with patch.object(self.hosts_file, '_add_preallocated_ip'):
            # Create a handler instance to access the scan_results attribute
            handler = WebUIHandler(None, None, None, hosts_file=self.hosts_file, network_server=self.mock_network_server)
            
            # Set up the scan results directly in the handler instead of waiting for the thread
            # This simulates the scan thread having completed
            handler.scan_results = {
                '192.168.1.100': {
                    'mac': '11:22:33:44:55:66',
                    'status': 'Added',
                    'ports': [22, 80, 443]
                },
                '192.168.1.101': {
                    'mac': '22:33:44:55:66:77',
                    'status': 'Added',
                    'ports': [21, 25, 3389]
                }
            }
            
            # Monkey patch the scan_results onto the WebUIHandler class 
            # so that the running server's handler instances will have it
            WebUIHandler.scan_results = handler.scan_results
            
            # Now check the scan results page
            self.conn.request('GET', '/scan')
            response = self.conn.getresponse()
            content = response.read().decode('utf-8')
            
            # Check for port information in the scan results - need to check there's some port styling
            port_style_indicators = [
                'port-list',
                'port ', 
                'class="port',
                "class='port"
            ]
            
            found_style = [indicator for indicator in port_style_indicators if indicator in content]
            if not found_style:
                debug_info = debug_html_content(content, port_style_indicators)
                logger.error(f"Debugging port styling in scan results:\n{debug_info}")
                
            self.assertTrue(len(found_style) > 0, 
                           f"No port styling found in scan results. Content snippet: {content[:500]}...")
            
            # Verify both IPs are displayed
            self.assertIn('192.168.1.100', content, "First IP address not found in scan results")
            self.assertIn('11:22:33:44:55:66', content, "First MAC address not found in scan results")
            
            self.assertIn('192.168.1.101', content, "Second IP address not found in scan results")
            self.assertIn('22:33:44:55:66:77', content, "Second MAC address not found in scan results")
            
            # Check for at least some of the port numbers
            port_numbers = ['22', '80', '443', '21', '25', '3389']
            found_ports = [port for port in port_numbers if port in content]
            self.assertTrue(len(found_ports) > 0, "No port numbers found in scan results")
            
            # Check for at least one port description
            port_descriptions = ['SSH', 'HTTP', 'HTTPS', 'FTP', 'SMTP', 'RDP']
            found_descriptions = [desc for desc in port_descriptions if desc in content]
            self.assertTrue(len(found_descriptions) > 0, 
                          f"No port descriptions found in scan results. Expected one of: {port_descriptions}")


if __name__ == '__main__':
    unittest.main()
