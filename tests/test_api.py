#!/usr/bin/env python3
"""
Test Script for the DNS API functionality

This script tests the functionality of the HTTP API for DNS management.
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
from http.server import HTTPServer

# Add parent directory to the path so we can import the necessary modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import logging
# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('test_api')

# Import local modules
from hosts_file import HostsFile
from api_server import APIHandler, APIServer


class TestAPIHandler(APIHandler):
    """Custom test API handler that provides access to the hosts file."""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


class TestDNSAPI(unittest.TestCase):
    """Test cases for the DNS API functionality."""
    
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
192.168.1.30 db.local database
""")
        
        # Initialize hosts file
        cls.hosts_file = HostsFile(cls.hosts_path)
        
        # Set up an API server on a test port
        cls.api_port = 8888
        cls.api_server = APIServer(cls.hosts_file, cls.api_port, 'localhost')
        
        # Start the server in a separate thread
        cls.server_thread = cls.api_server.start()
        
        # Allow the server time to start
        time.sleep(0.5)
    
    @classmethod
    def tearDownClass(cls):
        """Clean up after all tests are complete."""
        # Stop the API server
        if hasattr(cls, 'api_server'):
            cls.api_server.stop()
        
        # Remove the temporary hosts file
        if hasattr(cls, 'hosts_path'):
            os.remove(cls.hosts_path)
    
    def setUp(self):
        """Set up for each test."""
        # Create a connection to the API server
        self.conn = http.client.HTTPConnection('localhost', self.api_port)
    
    def tearDown(self):
        """Clean up after each test."""
        # Close the connection
        if hasattr(self, 'conn'):
            self.conn.close()
    
    def test_get_dns_records(self):
        """Test the GET /api/dns/records endpoint."""
        # Send a request
        self.conn.request('GET', '/api/dns/records')
        response = self.conn.getresponse()
        
        # Check the response
        self.assertEqual(response.status, 200)
        
        # Parse the JSON response
        data = json.loads(response.read().decode('utf-8'))
        
        # Check the structure
        self.assertIn('records', data)
        self.assertIsInstance(data['records'], list)
        
        # Check that the initial records are included
        initial_hosts = ['server1.local', 'server2.local', 'server1', 'server2', 'db.local', 'database']
        for record in data['records']:
            self.assertIn('hostname', record)
            self.assertIn('ip', record)
            self.assertIn('type', record)
        
        # Verify at least one expected hostname is found
        found_hostnames = [record['hostname'] for record in data['records']]
        self.assertTrue(any(host in found_hostnames for host in initial_hosts))
    
    def test_lookup_hostname(self):
        """Test the GET /api/dns/lookup endpoint."""
        # Send a request
        self.conn.request('GET', '/api/dns/lookup?hostname=server1.local')
        response = self.conn.getresponse()
        
        # Check the response
        self.assertEqual(response.status, 200)
        
        # Parse the JSON response
        data = json.loads(response.read().decode('utf-8'))
        
        # Check the structure
        self.assertIn('hostname', data)
        self.assertIn('ipv4', data)
        self.assertIn('ipv6', data)
        
        # Check the values
        self.assertEqual(data['hostname'], 'server1.local')
        self.assertEqual(data['ipv4'], ['192.168.1.10'])
    
    def test_reverse_lookup(self):
        """Test the GET /api/dns/reverse endpoint."""
        # Send a request
        self.conn.request('GET', '/api/dns/reverse?ip=192.168.1.10')
        response = self.conn.getresponse()
        
        # Check the response
        self.assertEqual(response.status, 200)
        
        # Parse the JSON response
        data = json.loads(response.read().decode('utf-8'))
        
        # Check the structure
        self.assertIn('ip', data)
        self.assertIn('hostnames', data)
        self.assertIn('mac', data)
        
        # Check the values
        self.assertEqual(data['ip'], '192.168.1.10')
        self.assertIn('server1.local', data['hostnames'])
        self.assertIn('server1', data['hostnames'])
        self.assertEqual(data['mac'], '00:11:22:33:44:55')
    
    def test_set_hostname(self):
        """Test the POST /api/dns/set_hostname endpoint."""
        # Prepare request data
        data = {
            'ip': '192.168.1.50',
            'hostname': 'testhost.local',
            'mac': 'ff:ff:ff:ff:ff:ff'
        }
        json_data = json.dumps(data).encode('utf-8')
        
        # Send a request
        headers = {'Content-Type': 'application/json'}
        self.conn.request('POST', '/api/dns/set_hostname', body=json_data, headers=headers)
        response = self.conn.getresponse()
        
        # Check the response
        self.assertEqual(response.status, 200)
        
        # Parse the JSON response
        data = json.loads(response.read().decode('utf-8'))
        
        # Check the structure
        self.assertIn('status', data)
        
        # Check the values
        self.assertEqual(data['status'], 'success')
        
        # Verify that the hostname was set
        self.conn.request('GET', '/api/dns/lookup?hostname=testhost.local')
        response = self.conn.getresponse()
        lookup_data = json.loads(response.read().decode('utf-8'))
        self.assertEqual(lookup_data['ipv4'], ['192.168.1.50'])
    
    def test_set_hostname_without_mac(self):
        """Test setting a hostname without providing a MAC address."""
        # Prepare request data
        data = {
            'ip': '192.168.1.60',
            'hostname': 'nomac.local'
        }
        json_data = json.dumps(data).encode('utf-8')
        
        # Send a request
        headers = {'Content-Type': 'application/json'}
        self.conn.request('POST', '/api/dns/set_hostname', body=json_data, headers=headers)
        response = self.conn.getresponse()
        
        # Check the response
        self.assertEqual(response.status, 200)
        
        # Parse the JSON response
        data = json.loads(response.read().decode('utf-8'))
        
        # Check the values
        self.assertEqual(data['status'], 'success')
        
        # Verify that the hostname was set
        self.conn.request('GET', '/api/dns/lookup?hostname=nomac.local')
        response = self.conn.getresponse()
        lookup_data = json.loads(response.read().decode('utf-8'))
        self.assertEqual(lookup_data['ipv4'], ['192.168.1.60'])
    
    def test_set_hostname_with_existing_ip(self):
        """Test setting a hostname for an IP that already has a hostname."""
        # First set a hostname
        data1 = {
            'ip': '192.168.1.70',
            'hostname': 'first.local'
        }
        json_data1 = json.dumps(data1).encode('utf-8')
        
        headers = {'Content-Type': 'application/json'}
        self.conn.request('POST', '/api/dns/set_hostname', body=json_data1, headers=headers)
        response = self.conn.getresponse()
        response.read()  # Read and discard the response body
        
        # Now set a different hostname for the same IP
        data2 = {
            'ip': '192.168.1.70',
            'hostname': 'second.local'
        }
        json_data2 = json.dumps(data2).encode('utf-8')
        
        self.conn.request('POST', '/api/dns/set_hostname', body=json_data2, headers=headers)
        response = self.conn.getresponse()
        
        # Check the response
        self.assertEqual(response.status, 200)
        data = json.loads(response.read().decode('utf-8'))
        self.assertEqual(data['status'], 'success')
        
        # Verify that both hostnames are associated with the IP
        self.conn.request('GET', '/api/dns/reverse?ip=192.168.1.70')
        response = self.conn.getresponse()
        reverse_data = json.loads(response.read().decode('utf-8'))
        self.assertIn('first.local', reverse_data['hostnames'])
        self.assertIn('second.local', reverse_data['hostnames'])
    
    def test_set_hostname_validation(self):
        """Test hostname validation in the set_hostname endpoint."""
        # Prepare request with invalid hostname
        data = {
            'ip': '192.168.1.80',
            'hostname': 'invalid hostname with spaces'
        }
        json_data = json.dumps(data).encode('utf-8')
        
        # Send a request
        headers = {'Content-Type': 'application/json'}
        self.conn.request('POST', '/api/dns/set_hostname', body=json_data, headers=headers)
        response = self.conn.getresponse()
        
        # Check the response
        self.assertEqual(response.status, 200)  # Still 200 but with error message
        
        # Parse the JSON response
        data = json.loads(response.read().decode('utf-8'))
        
        # Check the error message
        self.assertIn('error', data)
        self.assertIn('hostname', data['error'])
    
    def test_set_hostname_invalid_ip(self):
        """Test setting a hostname with an invalid IP address."""
        # Prepare request with invalid IP
        data = {
            'ip': 'not-an-ip',
            'hostname': 'invalid.local'
        }
        json_data = json.dumps(data).encode('utf-8')
        
        # Send a request
        headers = {'Content-Type': 'application/json'}
        self.conn.request('POST', '/api/dns/set_hostname', body=json_data, headers=headers)
        response = self.conn.getresponse()
        
        # Check the response
        self.assertEqual(response.status, 200)  # Still 200 but with error message
        
        # Parse the JSON response
        data = json.loads(response.read().decode('utf-8'))
        
        # Check the error message
        self.assertIn('error', data)
        self.assertIn('IP address', data['error'])
    
    def test_set_hostname_invalid_mac(self):
        """Test setting a hostname with an invalid MAC address."""
        # Prepare request with invalid MAC
        data = {
            'ip': '192.168.1.90',
            'hostname': 'validhost.local',
            'mac': 'not-a-mac'
        }
        json_data = json.dumps(data).encode('utf-8')
        
        # Send a request
        headers = {'Content-Type': 'application/json'}
        self.conn.request('POST', '/api/dns/set_hostname', body=json_data, headers=headers)
        response = self.conn.getresponse()
        
        # Check the response
        self.assertEqual(response.status, 200)  # Still 200 but with error message
        
        # Parse the JSON response
        data = json.loads(response.read().decode('utf-8'))
        
        # Check the error message
        self.assertIn('error', data)
        self.assertIn('MAC address', data['error'])
    
    def test_auth_token(self):
        """Test API authentication with a token."""
        # Create a new API server with auth token
        auth_port = 8889
        auth_token = 'test-token'
        auth_server = APIServer(self.hosts_file, auth_port, 'localhost', auth_token)
        
        try:
            # Start the server
            auth_thread = auth_server.start()
            time.sleep(0.5)
            
            # Try without token
            conn = http.client.HTTPConnection('localhost', auth_port)
            conn.request('GET', '/api/dns/records')
            response = conn.getresponse()
            
            # Check that auth is required
            self.assertEqual(response.status, 401)
            
            # Try with token in header
            headers = {'Authorization': f'Bearer {auth_token}'}
            conn = http.client.HTTPConnection('localhost', auth_port)
            conn.request('GET', '/api/dns/records', headers=headers)
            response = conn.getresponse()
            
            # Check that it works with auth
            self.assertEqual(response.status, 200)
            
            # Try with token in query parameter
            conn = http.client.HTTPConnection('localhost', auth_port)
            conn.request('GET', f'/api/dns/records?token={auth_token}')
            response = conn.getresponse()
            
            # Check that it works with auth
            self.assertEqual(response.status, 200)
            
        finally:
            # Stop the auth server
            auth_server.stop()


class TestDNSAPIClient(unittest.TestCase):
    """Test cases for the DNS API client functionality."""
    
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
        
        # Initialize hosts file
        cls.hosts_file = HostsFile(cls.hosts_path)
        
        # Set up an API server on a test port
        cls.api_port = 8890
        cls.api_server = APIServer(cls.hosts_file, cls.api_port, 'localhost')
        
        # Start the server in a separate thread
        cls.server_thread = cls.api_server.start()
        
        # Allow the server time to start
        time.sleep(0.5)
        
        # Set up client script path
        cls.client_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'dns_api_client.py')
        
        # Create client test directory
        cls.client_test_dir = tempfile.mkdtemp()
    
    @classmethod
    def tearDownClass(cls):
        """Clean up after all tests are complete."""
        # Stop the API server
        if hasattr(cls, 'api_server'):
            cls.api_server.stop()
        
        # Remove the temporary hosts file
        if hasattr(cls, 'hosts_path'):
            os.remove(cls.hosts_path)
        
        # Remove the client test directory
        if hasattr(cls, 'client_test_dir'):
            os.rmdir(cls.client_test_dir)


class TestDNSAPIIntegration(unittest.TestCase):
    """Test cases for the integration of DNS API with the network server."""
    
    @classmethod
    def setUpClass(cls):
        """Set up the test environment once for all tests."""
        # Find the network_server.py path
        cls.network_server_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'network_server.py')
        
        # Create a temporary file for the hosts file
        cls.hosts_fd, cls.hosts_path = tempfile.mkstemp()
        os.close(cls.hosts_fd)
        
        # Write initial hosts file content
        with open(cls.hosts_path, 'w') as f:
            f.write("""# Test hosts file
192.168.1.10 server1.local server1 [MAC=00:11:22:33:44:55]
""")


if __name__ == '__main__':
    unittest.main()
