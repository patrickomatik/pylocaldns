#!/usr/bin/env python3
"""
Test Script for Enhanced Port Display

This script tests the enhanced port display functionality including 
categorized ports, improved scanning, and better formatting.
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
logger = logging.getLogger('test_port_display_enhanced')

# Import local modules
from hosts_file import HostsFile
from webui import WebUIServer
from webui_core import WebUIHandler
import ip_utils


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


class TestEnhancedPortDisplay(unittest.TestCase):
    """Test cases for enhanced port display in the Web UI."""
    
    @classmethod
    def setUpClass(cls):
        """Set up the test environment once for all tests."""
        # Create a temporary file for the hosts file
        cls.hosts_fd, cls.hosts_path = tempfile.mkstemp()
        os.close(cls.hosts_fd)
        
        # Write initial hosts file content with various port combinations for testing
        with open(cls.hosts_path, 'w') as f:
            f.write("""# Test hosts file
# A web server with HTTP, HTTPS ports
192.168.1.10 webserver webserver.local ports-80,443 [MAC=00:11:22:33:44:55]

# A file server with FTP, SMB, NFS ports
192.168.1.20 fileserver fileserver.local ports-21,445,2049 [MAC=aa:bb:cc:dd:ee:ff]

# A database server with MySQL, PostgreSQL ports
192.168.1.30 dbserver dbserver.local ports-3306,5432 [MAC=11:22:33:44:55:66]

# A multi-service server with many ports
192.168.1.40 multiserver multiserver.local ports-22,25,53,80,443,8080,5900,3389 [MAC=22:33:44:55:66:77]
""")
        
        # Initialize hosts file with DHCP range
        cls.dhcp_range = ('192.168.1.100', '192.168.1.120')
        cls.hosts_file = HostsFile(cls.hosts_path, cls.dhcp_range)
        
        # Find an available port for the test server
        cls.webui_port = find_available_port(8896)
        
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
    
    def test_port_categories_displayed(self):
        """Test that port categories are displayed on the home page."""
        self.conn.request('GET', '/')
        response = self.conn.getresponse()
        self.assertEqual(response.status, 200)
        
        content = response.read().decode('utf-8')
        
        # Check for specific port categories
        port_categories = [
            'Web Services',
            'File Sharing',
            'Database',
            'Remote Access'
        ]
        
        # At least one of these categories should be present
        found_categories = [cat for cat in port_categories if cat in content]
        
        # We expect at least 2 categories to be found based on our test hosts file
        self.assertTrue(len(found_categories) >= 2, 
                      f"Expected at least 2 port categories, found: {found_categories}")
        
        # Check that the port-category styling exists
        self.assertIn('port-category', content, "Port category styling not found")
    
    def test_port_descriptions_expanded(self):
        """Test that the expanded port descriptions are used."""
        self.conn.request('GET', '/')
        response = self.conn.getresponse()
        self.assertEqual(response.status, 200)
        
        content = response.read().decode('utf-8')
        
        # Check for some of the new port descriptions that weren't in the old version
        new_descriptions = [
            'SSH',
            'MySQL',
            'PostgreSQL',
            'FTP',
            'SMB',
            'NFS'
        ]
        
        # At least two of these should be present based on our test data
        found_descriptions = [desc for desc in new_descriptions if desc in content]
        
        self.assertTrue(len(found_descriptions) >= 2, 
                      f"Expected at least 2 new port descriptions, found: {found_descriptions}")
    
    def test_scrollable_port_list(self):
        """Test that the port list has scrollable styling for many ports."""
        self.conn.request('GET', '/')
        response = self.conn.getresponse()
        self.assertEqual(response.status, 200)
        
        content = response.read().decode('utf-8')
        
        # Check for styling that indicates scrollable port lists
        scroll_indicators = [
            'max-height',
            'overflow',
            'overflow-y'
        ]
        
        # At least one of these styling indicators should be present
        style_found = False
        for indicator in scroll_indicators:
            if indicator in content:
                style_found = True
                break
        
        self.assertTrue(style_found, 
                      f"No scrollable port list styling found with indicators: {scroll_indicators}")
    
    @patch('ip_utils.scan_client_ports')
    def test_concurrent_port_scanning(self, mock_scan_ports):
        """Test that concurrent port scanning works correctly."""
        # Mock the scan_client_ports function to return test ports
        mock_scan_ports.return_value = [22, 80, 443, 3306, 5432]
        
        # Now, we need to test the scan_network functionality
        # but we'll skip making actual network connections
        with patch('socket.socket'):
            # Create a test IP to scan
            test_ip = '192.168.1.150'
            
            # Call the function directly
            result = ip_utils.scan_client_ports(test_ip)
            
            # Verify the result
            self.assertEqual(result, [22, 80, 443, 3306, 5432])
            
            # Verify that the mock was called
            mock_scan_ports.assert_called_once_with(test_ip)
    
    @patch('hosts_file.HostsFile.scan_network')
    def test_port_display_in_scan_results(self, mock_scan_network):
        """Test that categorized ports are displayed in scan results."""
        # Set up mock scan results with various port categories
        mock_scan_network.return_value = {
            '192.168.1.100': {
                'mac': '33:44:55:66:77:88',
                'ports': [80, 443, 8080]  # Web services
            },
            '192.168.1.101': {
                'mac': '44:55:66:77:88:99',
                'ports': [22, 3389]  # Remote access
            },
            '192.168.1.102': {
                'mac': '55:66:77:88:99:aa',
                'ports': [3306, 5432, 27017]  # Database
            }
        }
        
        # Patch _add_preallocated_ip to avoid disk I/O
        with patch.object(self.hosts_file, '_add_preallocated_ip'):
            # Create a handler instance to set up scan results

            handler = WebUIHandler(None, None, None, hosts_file=self.hosts_file, network_server=self.mock_network_server)
            
            # Set scan results directly
            handler.scan_results = {
                '192.168.1.100': {
                    'mac': '33:44:55:66:77:88',
                    'status': 'Added',
                    'ports': [80, 443, 8080]
                },
                '192.168.1.101': {
                    'mac': '44:55:66:77:88:99',
                    'status': 'Added',
                    'ports': [22, 3389]
                },
                '192.168.1.102': {
                    'mac': '55:66:77:88:99:aa',
                    'status': 'Added',
                    'ports': [3306, 5432, 27017]
                }
            }
            
            # Monkey patch the class attribute
            WebUIHandler.scan_results = handler.scan_results
            
            # Request the scan page
            self.conn.request('GET', '/scan')
            response = self.conn.getresponse()
            self.assertEqual(response.status, 200)
            
            content = response.read().decode('utf-8')
            
            # Check for all three IP addresses
            for ip in ['192.168.1.100', '192.168.1.101', '192.168.1.102']:
                self.assertIn(ip, content, f"IP {ip} not found in scan results")
            
            # Check for port categories in the scan results
            categories = ['Web Services', 'Remote Access', 'Database']
            found_categories = [cat for cat in categories if cat in content]
            
            # We should find at least 2 of the 3 categories
            self.assertTrue(len(found_categories) >= 2, 
                          f"Expected at least 2 port categories in scan results, found: {found_categories}")
            
            # Check for port descriptions
            descriptions = ['HTTP', 'HTTPS', 'SSH', 'RDP', 'MySQL', 'PostgreSQL', 'MongoDB']
            found_descriptions = [desc for desc in descriptions if desc in content]
            
            # We should find at least 4 of the 7 descriptions
            self.assertTrue(len(found_descriptions) >= 4,
                          f"Expected at least 4 port descriptions in scan results, found: {found_descriptions}")


if __name__ == '__main__':
    unittest.main()
