#!/usr/bin/env python3
"""
API Server for DNS/DHCP Network Server

This module provides a simple HTTP API for:
- Setting hostnames for IP addresses
- Viewing current DNS records

This allows remote management of the DNS server through simple HTTP requests.
"""

import logging
import threading
import json
import socket
import re
import ipaddress
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('api_server')


class APIHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the API."""
    
    def __init__(self, *args, hosts_file=None, auth_token=None, **kwargs):
        self.hosts_file = hosts_file
        self.auth_token = auth_token
        # BaseHTTPRequestHandler calls do_GET inside __init__
        super().__init__(*args, **kwargs)
    
    def log_message(self, format, *args):
        """Override logging to use our logger."""
        logger.info("%s - - [%s] %s" % (self.client_address[0],
                                        self.log_date_time_string(),
                                        format % args))
    
    def _send_json_response(self, data, status=200):
        """Send a JSON response."""
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        json_data = json.dumps(data).encode('utf-8')
        self.send_header('Content-Length', len(json_data))
        self.end_headers()
        self.wfile.write(json_data)
    
    def _send_error_json(self, message, status=400):
        """Send an error response in JSON format."""
        self._send_json_response({'error': message}, status)
    
    def _check_auth(self):
        """Check if the request is authenticated with the correct token."""
        if not self.auth_token:
            return True  # No authentication required
        
        # Check Authorization header
        auth_header = self.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header[7:]  # Remove 'Bearer ' prefix
            if token == self.auth_token:
                return True
        
        # Check token in query parameters
        parsed_url = urlparse(self.path)
        query_params = parse_qs(parsed_url.query)
        if 'token' in query_params and query_params['token'][0] == self.auth_token:
            return True
        
        return False
    
    def do_GET(self):
        """Handle GET requests."""
        # Check authentication
        if not self._check_auth():
            self._send_error_json("Authentication required", 401)
            return
        
        parsed_url = urlparse(self.path)
        path = parsed_url.path
        query = parse_qs(parsed_url.query)
        
        try:
            if path == '/api/dns/records':
                # Return all DNS records
                result = self._get_dns_records()
                self._send_json_response(result)
            
            elif path == '/api/dns/lookup':
                # Lookup a hostname
                if 'hostname' not in query:
                    self._send_error_json("Hostname parameter is required")
                    return
                
                hostname = query['hostname'][0]
                result = self._lookup_hostname(hostname)
                self._send_json_response(result)
            
            elif path == '/api/dns/reverse':
                # Reverse lookup an IP
                if 'ip' not in query:
                    self._send_error_json("IP parameter is required")
                    return
                
                ip = query['ip'][0]
                result = self._reverse_lookup(ip)
                self._send_json_response(result)
            
            else:
                self._send_error_json("Endpoint not found", 404)
        
        except Exception as e:
            logger.error(f"Error handling GET request: {e}")
            self._send_error_json(f"Internal server error: {str(e)}", 500)
    
    def do_POST(self):
        """Handle POST requests."""
        # Check authentication
        if not self._check_auth():
            self._send_error_json("Authentication required", 401)
            return
        
        parsed_url = urlparse(self.path)
        path = parsed_url.path
        
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length > 0:
                body = self.rfile.read(content_length).decode('utf-8')
                try:
                    json_data = json.loads(body)
                except json.JSONDecodeError:
                    # Try to parse as form data if not valid JSON
                    form_data = parse_qs(body)
                    json_data = {k: v[0] for k, v in form_data.items()}
            else:
                # For empty body, check query parameters
                query = parse_qs(parsed_url.query)
                json_data = {k: v[0] for k, v in query.items()}
            
            if path == '/api/dns/set_hostname':
                # Set hostname for an IP address
                result = self._set_hostname(json_data)
                self._send_json_response(result)
            
            else:
                self._send_error_json("Endpoint not found", 404)
        
        except Exception as e:
            logger.error(f"Error handling POST request: {e}")
            self._send_error_json(f"Internal server error: {str(e)}", 500)
    
    def _get_dns_records(self):
        """Get all DNS records."""
        if not self.hosts_file:
            return {'error': 'Hosts file not available'}
        
        result = []
        for hostname, records in self.hosts_file.dns_records.items():
            for record in records:
                result.append({
                    'hostname': hostname,
                    'ip': record.address,
                    'type': 'A' if record.record_type == 1 else 'AAAA'
                })
        
        return {'records': result}
    
    def _lookup_hostname(self, hostname):
        """Lookup a hostname to get IP addresses."""
        if not self.hosts_file:
            return {'error': 'Hosts file not available'}
        
        # Check A records (IPv4)
        ipv4_records = self.hosts_file.get_dns_records(hostname, 1)  # 1 = A record type
        
        # Check AAAA records (IPv6)
        ipv6_records = self.hosts_file.get_dns_records(hostname, 28)  # 28 = AAAA record type
        
        result = {
            'hostname': hostname,
            'ipv4': [record.address for record in ipv4_records],
            'ipv6': [record.address for record in ipv6_records]
        }
        
        return result
    
    def _reverse_lookup(self, ip):
        """Reverse lookup an IP to get hostnames."""
        if not self.hosts_file:
            return {'error': 'Hosts file not available'}
        
        hostnames = self.hosts_file.get_hostnames_for_ip(ip)
        
        # Try to get MAC address if available
        mac = None
        for mac_addr, mac_ip in self.hosts_file.mac_to_ip.items():
            if mac_ip == ip:
                mac = mac_addr
                break
        
        result = {
            'ip': ip,
            'hostnames': hostnames,
            'mac': mac
        }
        
        return result
    
    def _set_hostname(self, data):
        """Set hostname for an IP address."""
        if not self.hosts_file:
            return {'error': 'Hosts file not available'}
        
        # Check required fields
        required_fields = ['ip']
        if not all(field in data for field in required_fields):
            return {'error': 'Missing required fields', 'required': required_fields}
        
        ip = data.get('ip')
        hostname = data.get('hostname')
        mac = data.get('mac')
        
        # Validate IP address
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return {'error': 'Invalid IP address format'}
        
        # Validate MAC address if provided
        if mac:
            if not re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', mac):
                return {'error': 'Invalid MAC address format'}
            mac = mac.lower()
        
        # Validate hostname
        if hostname:
            # Simple hostname validation: alphanumeric plus hyphens
            if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$', hostname):
                return {'error': 'Invalid hostname format'}
        
        # If no hostname provided, we need a MAC at least
        if not hostname and not mac:
            return {'error': 'Either hostname or MAC address is required'}
        
        # Process the request
        updated = False
        
        # If MAC address is provided, add or update the static reservation
        if mac:
            # If IP is already assigned to a different MAC, clear that first
            for existing_mac, existing_ip in list(self.hosts_file.mac_to_ip.items()):
                if existing_ip == ip and existing_mac != mac:
                    del self.hosts_file.mac_to_ip[existing_mac]
            
            # Set the MAC to IP mapping
            self.hosts_file.mac_to_ip[mac] = ip
            updated = True
        
        # If hostname is provided, update DNS records
        if hostname:
            # Get existing hostnames for this IP
            existing_hostnames = self.hosts_file.get_hostnames_for_ip(ip)
            
            # Add the new hostname if not already present
            if hostname not in existing_hostnames:
                # Determine if IPv4 or IPv6
                record_type = 1  # 1 = A record (IPv4)
                if ':' in ip:
                    record_type = 28  # 28 = AAAA record (IPv6)
                
                # Create a new DNS record
                from models import DNSRecord
                dns_record = DNSRecord(ip, record_type)
                
                # Add to DNS records
                hostname_lower = hostname.lower()
                if hostname_lower not in self.hosts_file.dns_records:
                    self.hosts_file.dns_records[hostname_lower] = []
                
                # Only add if not already there
                if not any(r.address == ip for r in self.hosts_file.dns_records.get(hostname_lower, [])):
                    self.hosts_file.dns_records[hostname_lower].append(dns_record)
                
                # Update the IP to hostnames mapping
                if ip not in self.hosts_file.ip_to_hostnames:
                    self.hosts_file.ip_to_hostnames[ip] = []
                
                if hostname not in self.hosts_file.ip_to_hostnames[ip]:
                    self.hosts_file.ip_to_hostnames[ip].append(hostname)
                
                updated = True
        
        # If any updates were made, update the hosts file
        if updated:
            try:
                # Call the private method to update the hosts file
                if hasattr(self.hosts_file, '_update_hosts_file'):
                    self.hosts_file._update_hosts_file()
                    return {'status': 'success', 'message': 'Hostname updated successfully'}
                else:
                    return {'status': 'partial_success', 'message': 'Updated in memory, but could not update hosts file'}
            except Exception as e:
                logger.error(f"Error updating hosts file: {e}")
                return {'error': f'Failed to update hosts file: {str(e)}'}
        else:
            return {'status': 'no_change', 'message': 'No changes were needed'}


class APIServer:
    """Simple HTTP server for the API."""
    
    def __init__(self, hosts_file, port=8081, interface='0.0.0.0', auth_token=None):
        self.hosts_file = hosts_file
        self.port = port
        self.interface = interface
        self.server = None
        self.auth_token = auth_token
    
    def handler_class(self, *args, **kwargs):
        """Create a request handler with access to the hosts file."""
        return APIHandler(*args, hosts_file=self.hosts_file, auth_token=self.auth_token, **kwargs)
    
    def start(self):
        """Start the API server."""
        original_port = self.port
        
        # Try a range of ports if the initial one fails
        for attempt in range(10):  # Try up to 10 different ports
            try_port = original_port + attempt
            
            try:
                # Create a temporary socket to test if the port is available
                test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                test_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                
                # Set a short timeout to avoid hanging
                test_socket.settimeout(1)
                
                # Try binding to the port
                test_socket.bind((self.interface, try_port))
                test_socket.close()
                
                # Port is available, create the actual server
                self.port = try_port
                self.server = HTTPServer((self.interface, self.port), self.handler_class)
                self.server.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                
                # Log success
                if attempt > 0:
                    logger.info(f"Port {original_port} was unavailable, using port {self.port} instead")
                else:
                    logger.info(f"API server started on {self.interface}:{self.port}")
                
                # Start the server in a separate thread
                server_thread = threading.Thread(target=self.server.serve_forever, daemon=True)
                server_thread.start()
                
                return server_thread
            
            except OSError as e:
                # Close the test socket if it exists
                try:
                    test_socket.close()
                except:
                    pass
                
                if attempt == 9:  # Last attempt
                    logger.error(f"Failed to find an available port after 10 attempts. API server will not be available.")
                    raise RuntimeError(f"Could not find an available port for API server") from e
                
                # Only log for the first few attempts to avoid log spam
                if attempt < 3:
                    logger.warning(f"Port {try_port} is unavailable (Error: {e}), trying port {try_port + 1}")
            except Exception as e:
                logger.error(f"Error creating API server: {e}")
                raise
    
    def stop(self):
        """Stop the API server."""
        if self.server:
            try:
                self.server.shutdown()
                self.server.server_close()
                logger.info("API server stopped")
            except Exception as e:
                logger.error(f"Error stopping API server: {e}")
