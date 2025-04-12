#!/usr/bin/env python3
"""
Test suite for PyLocalDNS port scanning functionality.

This module contains tests for the port scanning functionality in the PyLocalDNS Flask web interface.
It verifies that port scanning works correctly and port information is properly displayed.
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


class TestPortScanning(unittest.TestCase):
    """Test cases for port scanning functionality."""

    def setUp(self):
        """Set up test environment before each test."""
        # Create a temporary hosts file
        self.hosts_fd, self.hosts_path = tempfile.mkstemp()
        with open(self.hosts_path, 'w') as f:
            f.write("# Test hosts file\n")
            f.write("127.0.0.1 localhost\n")
            f.write("192.168.1.10 test.local [MAC=00:11:22:33:44:55]\n")
            f.write("192.168.1.20 test2.local ports-22,80,443 [MAC=00:22:33:44:55:66]\n")

        # Initialize the hosts file
        self.hosts_file = HostsFile(self.hosts_path)
        
        # Mock network server
        self.network_server = MagicMock()
        self.network_server.dhcp_server = MagicMock()
        self.network_server.dhcp_enable = True
        
        # Initialize the Flask app with port database mocked
        with patch('app.USE_PORT_DB', True), \
             patch('app.get_port_db') as mock_get_port_db, \
             patch('app.refresh_port_data') as mock_refresh_port_data:
            
            # Configure mocks
            mock_get_port_db.return_value = MagicMock()
            # Return different ports for different IPs
            def refresh_side_effect(ip, **kwargs):
                if ip == '192.168.1.10':
                    return [22, 80]
                elif ip == '192.168.1.20':
                    return [22, 80, 443, 8080]
                return []
            mock_refresh_port_data.side_effect = refresh_side_effect
            
            # Initialize Flask app
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

    def test_format_ports_utility(self):
        """Test the format_ports utility function."""
        with patch('app.PORT_DESCRIPTIONS', {
            22: "SSH",
            80: "HTTP",
            443: "HTTPS",
            8080: "HTTP Proxy"
        }):
            # Access the utility function from the app context
            with self.flask_app.app_context():
                from app import utility_processor
                util = utility_processor()
                format_ports = util['format_ports']
                
                # Test formatting for various port sets
                # Empty list
                self.assertIn('None detected', format_ports([]))
                
                # Single port
                result = format_ports([80])
                self.assertIn('80', result)
                self.assertIn('HTTP', result)
                
                # Multiple ports
                result = format_ports([22, 80, 443])
                self.assertIn('SSH', result)
                self.assertIn('HTTP', result)
                self.assertIn('HTTPS', result)
                
                # Ports as string
                result = format_ports("22,80,443")
                self.assertIn('SSH', result)
                self.assertIn('HTTP', result)
                self.assertIn('HTTPS', result)
                
                # Port categories
                result = format_ports([22, 80, 443, 8080])
                self.assertIn('Web Services', result)
                self.assertIn('Remote Access', result)

    def test_port_display_in_dashboard(self):
        """Test that ports are displayed correctly in the dashboard."""
        # Set up mocks for port database functions
        with patch('app.USE_PORT_DB', True), \
             patch('app.get_port_db') as mock_get_port_db, \
             patch('app.refresh_port_data') as mock_refresh_port_data:
            
            # Configure mocks
            mock_get_port_db.return_value = MagicMock()
            # Return different ports for different IPs
            def refresh_side_effect(ip, **kwargs):
                if ip == '192.168.1.10':
                    return [22, 80]
                elif ip == '192.168.1.20':
                    return [22, 80, 443, 8080]
                return []
            mock_refresh_port_data.side_effect = refresh_side_effect
            
            # Get the dashboard page
            response = self.client.get('/')
            
            # Check response is OK
            self.assertEqual(response.status_code, 200)
            
            # Check that ports are displayed
            self.assertIn(b'port-list', response.data)  # Port list container
            self.assertIn(b'port-category', response.data)  # Port categories
            
            # Check specific port information
            self.assertIn(b'SSH', response.data)
            self.assertIn(b'HTTP', response.data)
            self.assertIn(b'HTTPS', response.data)
            
            # Check port numbers
            self.assertIn(b'22', response.data)
            self.assertIn(b'80', response.data)
            self.assertIn(b'443', response.data)
            self.assertIn(b'8080', response.data)

    def test_scan_ports_functionality(self):
        """Test the scan ports functionality."""
        # Set up mocks for port scanning
        with patch('app.USE_PORT_DB', True), \
             patch('app.get_port_db') as mock_get_port_db, \
             patch('app.scan_client_ports') as mock_scan_client_ports, \
             patch('app.refresh_port_data') as mock_refresh_port_data:
            
            # Configure mocks
            mock_get_port_db.return_value = MagicMock()
            # Scan function should update ports in the database
            mock_scan_client_ports.return_value = None
            # After scanning, refresh should return updated ports
            mock_refresh_port_data.return_value = [22, 80, 443, 3306, 5432]
            
            # Make a POST request to scan ports
            response = self.client.post('/scan-ports', follow_redirects=True)
            
            # Check response is OK
            self.assertEqual(response.status_code, 200)
            
            # Check that scan function was called for both IPs
            mock_scan_client_ports.assert_called()
            self.assertEqual(mock_scan_client_ports.call_count, 2)
            
            # Check that ports are displayed with new port numbers
            self.assertIn(b'port-list', response.data)
            self.assertIn(b'3306', response.data)  # MySQL
            self.assertIn(b'5432', response.data)  # PostgreSQL

    def test_port_display_in_scan_results(self):
        """Test that ports are displayed in scan results."""
        # Set up mock for handling scan requests
        with patch('app.handle_scan_request') as mock_handle_scan_request, \
             patch('app.scan_network_async') as mock_scan_network:
            
            # Configure the mock to store scan results
            def side_effect():
                # Store results directly in the app
                self.flask_app.scan_results = {
                    '192.168.1.50': {
                        'mac': '11:22:33:44:55:66',
                        'status': 'Added',
                        'ports': [22, 80, 443, 3389]
                    }
                }
                # Return a redirect to the scan page
                return self.client.get('/scan?message=Scan+completed&type=success')
                
            mock_handle_scan_request.side_effect = side_effect
            
            # Make a POST request to scan the network
            response = self.client.post('/scan', follow_redirects=True)
            
            # Check response is OK
            self.assertEqual(response.status_code, 200)
            
            # Check that ports are displayed in the scan results
            self.assertIn(b'192.168.1.50', response.data)
            self.assertIn(b'11:22:33:44:55:66', response.data)
            self.assertIn(b'port-list', response.data)
            
            # Check for specific ports
            self.assertIn(b'22', response.data)  # SSH
            self.assertIn(b'80', response.data)  # HTTP
            self.assertIn(b'443', response.data)  # HTTPS
            self.assertIn(b'3389', response.data)  # RDP

    def test_port_categories(self):
        """Test that ports are properly categorized."""
        # Set up mocks for port database functions
        with patch('app.USE_PORT_DB', True), \
             patch('app.get_port_db') as mock_get_port_db, \
             patch('app.refresh_port_data') as mock_refresh_port_data:
            
            # Configure mocks to return a wide range of ports
            mock_get_port_db.return_value = MagicMock()
            mock_refresh_port_data.return_value = [
                22,    # SSH (Remote Access)
                80,    # HTTP (Web Services)
                443,   # HTTPS (Web Services)
                3306,  # MySQL (Database)
                5432,  # PostgreSQL (Database)
                25,    # SMTP (Email)
                143,   # IMAP (Email)
                445,   # SMB (File Sharing)
                32400  # Plex (Media)
            ]
            
            # Get the dashboard page
            response = self.client.get('/')
            
            # Check response is OK
            self.assertEqual(response.status_code, 200)
            
            # Check that port categories are displayed
            self.assertIn(b'Web Services', response.data)
            self.assertIn(b'Remote Access', response.data)
            self.assertIn(b'Database', response.data)
            self.assertIn(b'Email', response.data)
            self.assertIn(b'File Sharing', response.data)
            self.assertIn(b'Media', response.data)

    def test_port_database_integration(self):
        """Test integration with the port database."""
        # Create a mock implementation for PortDatabase
        port_db_mock = MagicMock()
        
        # Set up mocks for port database functions
        with patch('app.USE_PORT_DB', True), \
             patch('app.get_port_db') as mock_get_port_db, \
             patch('app.refresh_port_data') as mock_refresh_port_data, \
             patch('app.scan_client_ports') as mock_scan_client_ports:
            
            # Configure mocks
            mock_get_port_db.return_value = port_db_mock
            mock_refresh_port_data.return_value = [22, 80, 443]
            
            # Get the dashboard page
            response = self.client.get('/')
            
            # Check response is OK
            self.assertEqual(response.status_code, 200)
            
            # Check port display
            self.assertIn(b'port-list', response.data)
            
            # Now make a scan ports request
            response = self.client.post('/scan-ports', follow_redirects=True)
            
            # Check that scan_client_ports was called
            mock_scan_client_ports.assert_called()
            
            # Check that the database was used
            mock_get_port_db.assert_called()


if __name__ == '__main__':
    unittest.main()
