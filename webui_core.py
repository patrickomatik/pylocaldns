#!/usr/bin/env python3
"""
Web UI Core Module for the DNS/DHCP Network Server

This module provides the base classes for the Web UI server.
"""

import socket
import logging
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime
from urllib.parse import parse_qs, urlparse

# Import our modules
from webui_models import DNSRecord
from webui_templates import HTML_HEADER, HTML_FOOTER, render_message

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('webui')


class WebUIHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the Web UI."""
    
    # Common port descriptions imported from port_scanner.py
    try:
        from port_scanner import PORT_SERVICES
        PORT_DESCRIPTIONS = PORT_SERVICES
    except ImportError:
        # Fallback if import fails
        PORT_DESCRIPTIONS = {
            22: "SSH",
            53: "DNS", 
            80: "HTTP",
            443: "HTTPS"
        }

    def __init__(self, *args, hosts_file=None, network_server=None, **kwargs):
        self.hosts_file = hosts_file
        self.network_server = network_server
        self.vendor_db = None
        
        # Try to initialize vendor database if available
        try:
            from vendor_db import VendorDB
            self.vendor_db = VendorDB()
            logger.info("MAC vendor database initialized with thread-safety")
        except Exception as e:
            logger.warning(f"Could not initialize MAC vendor database: {e}")
            
        # BaseHTTPRequestHandler calls do_GET inside __init__
        super().__init__(*args, **kwargs)

    def log_message(self, format, *args):
        """Override logging to use our logger."""
        logger.info("%s - - [%s] %s" % (self.client_address[0],
                                        self.log_date_time_string(),
                                        format % args))
                                        
    def _format_vendor(self, mac_address):
        """Format a MAC address vendor information into a user-friendly HTML display."""
        if not mac_address or mac_address == 'Unknown' or not hasattr(self, 'vendor_db') or self.vendor_db is None:
            return ''
            
        try:
            vendor_name = self.vendor_db.lookup_vendor(mac_address)
            if vendor_name:
                return f'<span class="badge badge-vendor" title="{vendor_name}">{vendor_name}</span>'
            return ''
        except Exception as e:
            logger.warning(f"Error looking up vendor for MAC {mac_address}: {e}")
            return ''
            
    def _format_ports(self, ports):
        """Format a list of port numbers into a user-friendly HTML display."""
        # Handle None or empty list
        if not ports:
            return "<span class='no-ports'>None detected</span>"
        
        # Ensure ports is a list of integers
        if isinstance(ports, str) and ',' in ports:
            # In case ports came as a comma-separated string
            try:
                ports = [int(p.strip()) for p in ports.split(',') if p.strip().isdigit()]
            except ValueError:
                pass
                
        # Make sure ports is a list, not a string
        if not isinstance(ports, (list, tuple, set)):
            try:
                ports = [int(ports)]
            except (ValueError, TypeError):
                return "<span class='no-ports'>Invalid port format</span>"
        
        # Group ports by service category
        categories = {
            'Web Services': [80, 443, 8080, 8443, 8000, 3000, 8081, 8082, 8083, 8001, 8002, 9000, 9001, 9002],
            'Remote Access': [22, 23, 3389, 5900, 5901, 5800, 2222],
            'File Sharing': [21, 445, 139, 2049, 548, 990, 989],
            'Database': [1433, 3306, 5432, 6379, 27017, 9200, 1521],
            'Email': [25, 587, 465, 110, 143, 993, 995],
            'Media': [32400, 8096, 8123, 554, 1900],
            'Network': [53, 67, 68, 123, 161, 5353, 5060, 5061],
            'Other': []
        }
        
        # Categorize ports
        categorized_ports = {cat: [] for cat in categories}
        
        for port in sorted(ports):
            # Convert to int if it's a string
            if isinstance(port, str) and port.isdigit():
                port = int(port)
            
            # Find category
            found_category = False
            for category, category_ports in categories.items():
                if port in category_ports:
                    categorized_ports[category].append(port)
                    found_category = True
                    break
            
            if not found_category:
                categorized_ports['Other'].append(port)
        
        # Build HTML
        result = ['<div class="port-list">']  
        
        for category, cat_ports in categorized_ports.items():
            if not cat_ports:  # Skip empty categories
                continue
                
            # Add category header if there are ports in this category
            result.append(f'<div class="port-category"><span class="port-category-name">{category}:</span> ')
            
            # Add ports
            port_spans = []
            for port in sorted(cat_ports):
                if port in self.PORT_DESCRIPTIONS:
                    service = self.PORT_DESCRIPTIONS[port]
                    port_spans.append(f"<span class='port port-known' title='{service}'>{port} ({service})</span>")
                else:
                    port_spans.append(f"<span class='port'>{port}</span>")
            
            result.append(", ".join(port_spans))
            result.append('</div>')
            
        result.append('</div>')
        return "\n".join(result)

    def _send_response(self, content, content_type='text/html'):
        """Send an HTTP response with the specified content."""
        self.send_response(200)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', len(content))
        self.end_headers()
        self.wfile.write(content)

    def _send_redirect(self, location):
        """Send a redirect response."""
        self.send_response(302)
        self.send_header('Location', location)
        self.end_headers()

    def _send_error(self, status_code, message):
        """Send an error response."""
        self.send_response(status_code)
        self.send_header('Content-Type', 'text/html')
        content = f"<html><body><h1>Error {status_code}</h1><p>{message}</p></body></html>".encode()
        self.send_header('Content-Length', len(content))
        self.end_headers()
        self.wfile.write(content)

    def _update_static_entry(self, mac, ip, original_ip, hostnames):
        """Update a static entry in the hosts file.
        
        This handles both MAC-based entries and DNS-only entries.
        For MAC-based entries, the MAC address must exist in the hosts file.
        For DNS-only entries (mac is empty string), only the IP is needed.
        """
        # Handle DNS-only entries (no MAC address)
        if not mac:
            # Update hostname to IP mappings
            if original_ip in self.hosts_file.ip_to_hostnames:
                # Remove the original IP from the hostname mapping
                del self.hosts_file.ip_to_hostnames[original_ip]
            
            # Add the new hostname mapping and DNS records
            if hostnames:
                self.hosts_file.add_dns_only_entry(ip, hostnames)
            
            return
        
        # Handle MAC-based entries
        if mac not in self.hosts_file.mac_to_ip:
            raise ValueError(f"MAC address {mac} not found")

        # Remove old IP mapping
        self.hosts_file.mac_to_ip[mac] = ip

        # Update hostname to IP mappings
        if original_ip in self.hosts_file.ip_to_hostnames:
            # Remove the original IP from the hostname mapping
            del self.hosts_file.ip_to_hostnames[original_ip]

        # Add the new hostname mapping
        if hostnames:
            self.hosts_file.ip_to_hostnames[ip] = hostnames

            # Update DNS records
            for hostname in hostnames:
                # Remove old records for this hostname
                if hostname.lower() in self.hosts_file.dns_records:
                    self.hosts_file.dns_records[hostname.lower()] = []

                # Add new record
                record_type = 1  # Assume IPv4 for simplicity
                if ':' in ip:
                    record_type = 28  # IPv6

                dns_record = DNSRecord(ip, record_type)
                self.hosts_file.dns_records[hostname.lower()].append(dns_record)

        # Update the hosts file
        self._update_hosts_file()

    def _update_hosts_file(self):
        """Update the hosts file on disk with current entries.
        
        This method now directly delegates to the HostsFile._update_hosts_file method,
        which maintains a consistent format for the hosts file.
        """
        if not self.hosts_file or not self.hosts_file.file_path:
            return
            
        # Use the hosts_file's built-in method to update the file
        self.hosts_file._update_hosts_file()
        
        # Force reload the hosts file to ensure we have the latest data
        self.hosts_file.last_modified = 0
        self.hosts_file.load_file()
        
    def do_GET(self):
        """Handle GET requests."""
        # Import the necessary modules based on the request path
        if self.path == '/' or self.path.startswith('/?'):
            # Import the home page rendering function
            from webui_home import render_home_page
            render_home_page(self)
        elif self.path.startswith('/dashboard-content'):
            from webui_home import render_dashboard_content
            render_dashboard_content(self)
        elif self.path.startswith('/add'):
            from webui_edit import render_add_page
            render_add_page(self)
        elif self.path.startswith('/edit'):
            # Check if it's an IP or MAC based edit
            query = parse_qs(urlparse(self.path).query)
            mac = query.get('mac', [''])[0]
            ip = query.get('ip', [''])[0]
            
            if not mac and not ip:
                # Send a 400 error if neither MAC nor IP is provided
                self._send_error(400, "MAC address or IP address is required")
                return
            
            # Otherwise, proceed with edit
            from webui_edit import render_edit_page
            render_edit_page(self)
        elif self.path.startswith('/edit-lease'):
            from webui_edit import render_edit_lease_page
            render_edit_lease_page(self)
        elif self.path.startswith('/delete'):
            # Check if it's a DNS-only entry (has IP parameter but no MAC)
            query = parse_qs(urlparse(self.path).query)
            ip = query.get('ip', [''])[0]
            mac = query.get('mac', [''])[0]
            
            if ip and not mac:
                from webui_handlers import handle_delete_dns_entry
                handle_delete_dns_entry(self)
            else:
                from webui_handlers import handle_delete_request
                handle_delete_request(self)
        elif self.path.startswith('/delete-lease'):
            from webui_handlers import handle_delete_lease_request
            handle_delete_lease_request(self)
        elif self.path.startswith('/scan'):
            from webui_scan import render_scan_page
            render_scan_page(self)
        elif self.path.startswith('/settings'):
            from webui_settings import render_settings_page
            render_settings_page(self)
        else:
            self._send_error(404, "Page not found")
            
    def do_POST(self):
        """Handle POST requests."""
        if self.path.startswith('/add'):
            from webui_handlers import handle_add_request
            handle_add_request(self)
        elif self.path.startswith('/update'):
            from webui_handlers import handle_update_request
            handle_update_request(self)
        elif self.path.startswith('/update-lease'):
            from webui_handlers import handle_update_lease_request
            handle_update_lease_request(self)
        elif self.path.startswith('/scan'):
            from webui_scan import handle_scan_request
            handle_scan_request(self)
        elif self.path.startswith('/scan-ports'):
            from webui_scan import handle_scan_ports_request
            handle_scan_ports_request(self)
        elif self.path.startswith('/settings'):
            from webui_settings import handle_settings_request
            handle_settings_request(self)
        elif self.path.startswith('/save-settings'):
            from webui_settings import handle_settings_request
            handle_settings_request(self)
        else:
            self._send_error(404, "Page not found")


class WebUIServer:
    """Simple HTTP server for the web UI."""

    def __init__(self, hosts_file, port=8080, interface='0.0.0.0', network_server=None):
        self.hosts_file = hosts_file
        self.port = port
        self.interface = interface
        self.server = None
        self.handler = None
        self.network_server = network_server

    def handler_class(self, *args, **kwargs):
        """Create a request handler with access to the hosts file."""
        return WebUIHandler(*args, hosts_file=self.hosts_file, network_server=self.network_server, **kwargs)

    def start(self):
        """Start the web UI server."""
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
                    logger.info(f"Web UI server started on {self.interface}:{self.port}")

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
                    logger.error(f"Failed to find an available port after 10 attempts. Web UI will not be available.")
                    raise RuntimeError(f"Could not find an available port for Web UI") from e

                # Only log for the first few attempts to avoid log spam
                if attempt < 3:
                    logger.warning(f"Port {try_port} is unavailable (Error: {e}), trying port {try_port + 1}")
            except Exception as e:
                logger.error(f"Error creating Web UI server: {e}")
                raise

    def stop(self):
        """Stop the web UI server."""
        if self.server:
            try:
                self.server.shutdown()
                self.server.server_close()
                logger.info("Web UI server stopped")
            except Exception as e:
                logger.error(f"Error stopping Web UI server: {e}")
