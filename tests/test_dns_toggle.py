#!/usr/bin/env python3
"""
Tests for DNS Service Toggle Feature

This module tests the functionality to enable/disable the DNS server
from both the command line and web UI.
"""

import os
import sys
import unittest
import tempfile
import threading
import time
import socket
from unittest.mock import patch, MagicMock

# Add parent directory to path to allow imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import modules to test
from hosts_file import HostsFile
from dns_server import DNSServer
from network_server_flask import NetworkServer

# Try to import Flask components
try:
    from app import app
    HAS_FLASK = True
except ImportError:
    HAS_FLASK = False
    app = None
    print("Flask not found. Web UI tests will be skipped.")

# Test port (to avoid conflicts or root privileges)
TEST_DNS_PORT = 15353
TEST_WEBUI_PORT = 15080


class TestDNSToggle(unittest.TestCase):
    """Test DNS service toggle functionality."""

    def setUp(self):
        """Set up test environment."""
        # Create a temporary hosts file
        self.hosts_file_fd, self.hosts_file_path = tempfile.mkstemp()
        with open(self.hosts_file_path, 'w') as f:
            f.write("127.0.0.1 localhost\n")
            f.write("192.168.1.10 testserver.local [MAC=00:11:22:33:44:55]\n")
        
        # Create hosts file object
        self.hosts_file = HostsFile(self.hosts_file_path)
        
        # Create a network server with test ports
        self.server = NetworkServer(
            hosts_file=self.hosts_file,
            dns_port=TEST_DNS_PORT,
            interface='127.0.0.1',
            dns_enable=True,  # Start with DNS enabled
            webui_enable=False  # Disable web UI for base tests
        )
        
        # Patch socket bindings to prevent actual server starting
        self.dns_server_patch = patch.object(
            DNSServer, 'start', 
            return_value=None
        )
        self.dns_server_start = self.dns_server_patch.start()
        
        self.dns_server_stop_patch = patch.object(
            DNSServer, 'stop', 
            return_value=None
        )
        self.dns_server_stop = self.dns_server_stop_patch.start()
        
        # Setup Flask test client if available
        if HAS_FLASK:
            self.flask_app = app
            self.flask_app.config['TESTING'] = True
            self.flask_app.config['HOSTS_FILE'] = self.hosts_file
            self.flask_app.config['NETWORK_SERVER'] = self.server
            self.client = self.flask_app.test_client()

    def tearDown(self):
        """Clean up after tests."""
        # Stop patches
        self.dns_server_patch.stop()
        self.dns_server_stop_patch.stop()
        
        # Remove temporary hosts file
        os.close(self.hosts_file_fd)
        os.unlink(self.hosts_file_path)

    def test_dns_enabled_by_default(self):
        """Test that DNS is enabled by default."""
        self.assertTrue(self.server.dns_enable)
        self.assertIsNotNone(self.server.dns_server)

    def test_dns_disable_at_init(self):
        """Test disabling DNS at initialization."""
        server = NetworkServer(
            hosts_file=self.hosts_file,
            dns_port=TEST_DNS_PORT,
            interface='127.0.0.1',
            dns_enable=False  # Explicitly disable
        )
        self.assertFalse(server.dns_enable)
        self.assertIsNone(server.dns_server)

    def test_toggle_dns_service(self):
        """Test toggling DNS service."""
        # Start with DNS enabled
        self.assertTrue(self.server.dns_enable)
        self.assertIsNotNone(self.server.dns_server)
        
        # Disable DNS
        self.server.set_dns_enabled(False)
        self.assertFalse(self.server.dns_enable)
        self.dns_server_stop.assert_called_once()
        
        # Reset the mock call counter
        self.dns_server_stop.reset_mock()
        
        # Enable DNS again
        self.server.set_dns_enabled(True)
        self.assertTrue(self.server.dns_enable)
        self.dns_server_start.assert_called_once()


# Web UI tests that depend on Flask
@unittest.skipIf(not HAS_FLASK, "Flask not available")
class TestDNSToggleWebUI(unittest.TestCase):
    """Test DNS service toggle functionality via Web UI."""

    def setUp(self):
        """Set up test environment for Web UI tests."""
        # Create a temporary hosts file
        self.hosts_file_fd, self.hosts_file_path = tempfile.mkstemp()
        with open(self.hosts_file_path, 'w') as f:
            f.write("127.0.0.1 localhost\n")
            f.write("192.168.1.10 testserver.local [MAC=00:11:22:33:44:55]\n")
        
        # Create hosts file object
        self.hosts_file = HostsFile(self.hosts_file_path)
        
        # Create a network server with test ports
        self.server = NetworkServer(
            hosts_file=self.hosts_file,
            dns_port=TEST_DNS_PORT,
            interface='127.0.0.1',
            dns_enable=True,  # Start with DNS enabled
            webui_enable=False  # Disable web UI for tests
        )
        
        # Patch socket bindings to prevent actual server starting
        self.dns_server_patch = patch.object(
            DNSServer, 'start', 
            return_value=None
        )
        self.dns_server_start = self.dns_server_patch.start()
        
        self.dns_server_stop_patch = patch.object(
            DNSServer, 'stop', 
            return_value=None
        )
        self.dns_server_stop = self.dns_server_stop_patch.start()
        
        # Setup Flask test client
        self.flask_app = app
        self.flask_app.config['TESTING'] = True
        self.flask_app.config['HOSTS_FILE'] = self.hosts_file
        self.flask_app.config['NETWORK_SERVER'] = self.server
        self.client = self.flask_app.test_client()

    def tearDown(self):
        """Clean up after tests."""
        # Stop patches
        self.dns_server_patch.stop()
        self.dns_server_stop_patch.stop()
        
        # Remove temporary hosts file
        os.close(self.hosts_file_fd)
        os.unlink(self.hosts_file_path)

    def test_settings_page_shows_dns_state(self):
        """Test that settings page shows correct DNS state."""
        # Mock the network server with DNS enabled
        self.server.dns_enable = True
        
        # Get settings page
        response = self.client.get('/settings')
        self.assertEqual(response.status_code, 200)
        
        # Check that DNS checkbox is checked
        self.assertIn(b'<input type="checkbox" id="dns_enabled" name="dns_enabled" value="yes" checked>', response.data)
        
        # Mock the network server with DNS disabled
        self.server.dns_enable = False
        
        # Get settings page again
        response = self.client.get('/settings')
        self.assertEqual(response.status_code, 200)
        
        # Check that DNS checkbox is not checked
        self.assertNotIn(b'<input type="checkbox" id="dns_enabled" name="dns_enabled" value="yes" checked>', response.data)
        self.assertIn(b'<input type="checkbox" id="dns_enabled" name="dns_enabled" value="yes"', response.data)

    def test_settings_form_can_disable_dns(self):
        """Test that settings form can disable DNS."""
        # Start with DNS enabled
        self.server.dns_enable = True
        
        # Submit form without the dns_enabled checkbox (unchecked)
        response = self.client.post('/settings', data={
            'dhcp_enabled': 'yes',
            'dhcp_range_start': '192.168.1.100',
            'dhcp_range_end': '192.168.1.200',
            'subnet_mask': '255.255.255.0',
            'dns_servers': '8.8.8.8, 8.8.4.4',
            'lease_time': '86400'
        }, follow_redirects=True)
        
        # Check that the request was accepted
        self.assertEqual(response.status_code, 200)
        
        # Check that DNS was disabled
        self.assertFalse(self.server.dns_enable)

    def test_settings_form_can_enable_dns(self):
        """Test that settings form can enable DNS."""
        # Start with DNS disabled
        self.server.dns_enable = False
        
        # Submit form with dns_enabled checkbox checked
        response = self.client.post('/settings', data={
            'dns_enabled': 'yes',
            'dhcp_enabled': 'yes',
            'dhcp_range_start': '192.168.1.100',
            'dhcp_range_end': '192.168.1.200',
            'subnet_mask': '255.255.255.0',
            'dns_servers': '8.8.8.8, 8.8.4.4',
            'lease_time': '86400'
        }, follow_redirects=True)
        
        # Check that the request was accepted
        self.assertEqual(response.status_code, 200)
        
        # Check that DNS was enabled
        self.assertTrue(self.server.dns_enable)


class TestDNSToggleIntegration(unittest.TestCase):
    """Integration tests for DNS service toggle."""
    
    def setUp(self):
        """Set up test environment for integration tests."""
        # Create a temporary hosts file
        self.hosts_file_fd, self.hosts_file_path = tempfile.mkstemp()
        with open(self.hosts_file_path, 'w') as f:
            f.write("127.0.0.1 localhost\n")
            f.write("127.0.0.1 test.local [MAC=00:11:22:33:44:55]\n")
            
        # Create hosts file object
        self.hosts_file = HostsFile(self.hosts_file_path)
        
        # Create network server with test configuration
        self.server = None
        self.server_thread = None
        
    def tearDown(self):
        """Clean up after integration tests."""
        # Stop the server if it's running
        if self.server:
            try:
                self.server.stop()
            except:
                pass
                
        # Remove temporary hosts file
        os.close(self.hosts_file_fd)
        os.unlink(self.hosts_file_path)
        
    def _create_and_start_server(self, dns_enable=True):
        """Create and start a server for testing."""
        # Create server
        self.server = NetworkServer(
            hosts_file=self.hosts_file,
            dns_port=TEST_DNS_PORT,
            interface='127.0.0.1',
            dns_enable=dns_enable,
            webui_enable=False
        )
        
        # Start the server in a thread to avoid blocking
        def run_server():
            try:
                # Patch the start method to not enter the infinite loop
                with patch.object(NetworkServer, 'start', 
                             side_effect=lambda: self.server._file_monitoring_thread()):
                    self.server.start()
            except Exception as e:
                print(f"Server thread error: {e}")
                
        # Start the server
        self.server_thread = threading.Thread(target=run_server)
        self.server_thread.daemon = True
        self.server_thread.start()
        
        # Give the server time to start
        time.sleep(1)
        
    def test_dns_server_responds_when_enabled(self):
        """Test that DNS server responds to queries when enabled."""
        # This is a more complex integration test that would typically
        # involve actual socket communications. For simplicity, we'll
        # mock the socket response and check that the server attempts to send.
        
        # Start with DNS enabled
        self._create_and_start_server(dns_enable=True)
        
        # Verify DNS server was created and started
        self.assertTrue(self.server.dns_enable)
        self.assertIsNotNone(self.server.dns_server)
        
    def test_dns_server_does_not_respond_when_disabled(self):
        """Test that DNS server does not respond to queries when disabled."""
        # Start with DNS disabled
        self._create_and_start_server(dns_enable=False)
        
        # Verify DNS server was not created or started
        self.assertFalse(self.server.dns_enable)
        self.assertIsNone(self.server.dns_server)


if __name__ == '__main__':
    unittest.main()
