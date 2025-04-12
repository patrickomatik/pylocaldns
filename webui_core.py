#!/usr/bin/env python3
"""
Web UI Core Module for the DNS/DHCP Network Server

This module provides the base classes for the Web UI server.
"""

import os
import socket
import logging
import threading
import re
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime

# Setup logging
logger = logging.getLogger('webui')

# HTML templates
HTML_HEADER = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Server Admin</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            color: #333;
        }
        h1, h2 {
            color: #2c3e50;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }
        th, td {
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
        }
        th {
            background-color: #f2f2f2;
            font-weight: bold;
        }
        tr:nth-child(even) {
            background-color: #f9f9f9;
        }
        tr:hover {
            background-color: #f1f1f1;
        }
        .btn {
            display: inline-block;
            padding: 6px 12px;
            margin-bottom: 0;
            font-size: 14px;
            font-weight: 400;
            line-height: 1.42857143;
            text-align: center;
            white-space: nowrap;
            vertical-align: middle;
            cursor: pointer;
            border: 1px solid transparent;
            border-radius: 4px;
            color: #fff;
            background-color: #337ab7;
            text-decoration: none;
        }
        .btn-edit {
            background-color: #5cb85c;
        }
        .btn-delete {
            background-color: #d9534f;
        }
        .btn-add {
            background-color: #5bc0de;
            margin-bottom: 20px;
        }
        .btn-scan {
            background-color: #f0ad4e;
            margin-bottom: 20px;
        }
        form {
            background: #f9f9f9;
            padding: 20px;
            border: 1px solid #ddd;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
        }
        input[type="text"], select {
            width: 100%;
            padding: 8px;
            margin-bottom: 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
            box-sizing: border-box;
        }
        .form-group {
            margin-bottom: 15px;
        }
        .message {
            padding: 10px;
            margin-bottom: 15px;
            border-radius: 4px;
        }
        .success {
            background-color: #dff0d8;
            border: 1px solid #d6e9c6;
            color: #3c763d;
        }
        .error {
            background-color: #f2dede;
            border: 1px solid #ebccd1;
            color: #a94442;
        }
        .nav {
            background-color: #2c3e50;
            overflow: hidden;
            margin-bottom: 20px;
        }
        .nav a {
            float: left;
            display: block;
            color: white;
            text-align: center;
            padding: 14px 16px;
            text-decoration: none;
        }
        .nav a:hover {
            background-color: #ddd;
            color: black;
        }
        .nav a.active {
            background-color: #4CAF50;
            color: white;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        .time-info {
            font-size: 0.8em;
            color: #777;
        }
        .badge {
            display: inline-block;
            min-width: 10px;
            padding: 3px 7px;
            font-size: 12px;
            font-weight: 700;
            line-height: 1;
            color: #fff;
            text-align: center;
            white-space: nowrap;
            vertical-align: middle;
            background-color: #777;
            border-radius: 10px;
        }
        .badge-info {
            background-color: #5bc0de;
        }
        .badge-warning {
            background-color: #f0ad4e;
        }
        .badge-success {
            background-color: #5cb85c;
        }
        
        /* Port styling */
        .port-list {
            font-size: 0.9em;
        }
        .port {
            display: inline-block;
            padding: 2px 5px;
            margin: 1px;
            border-radius: 3px;
            background-color: #f8f8f8;
            border: 1px solid #ddd;
        }
        .port-known {
            background-color: #e8f7ff;
            border-color: #bde3ff;
            color: #0066cc;
            cursor: help;
        }
        .no-ports {
            color: #999;
            font-style: italic;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="nav">
            <a href="/" class="active">Dashboard</a>
            <a href="/add">Add New Entry</a>
            <a href="/scan">Scan Network</a>
            <a href="/settings">Settings</a>
        </div>
"""

HTML_FOOTER = """
    </div>
    <script>
        // Add any JavaScript here
        function confirmDelete(mac) {
            return confirm('Are you sure you want to delete the entry for MAC: ' + mac + '?');
        }

        // Auto-refresh the page every 30 seconds
        setTimeout(function() {
            location.reload();
        }, 30000);
    </script>
</body>
</html>
"""


# Make sure DNSRecord class is available to the WebUI module
class DNSRecord:
    def __init__(self, address, record_type):
        self.address = address
        self.record_type = record_type
        self.ttl = 300  # Default TTL if not specified


class WebUIHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the Web UI."""
    
    # Common port descriptions (add more as needed)
    PORT_DESCRIPTIONS = {
        20: "FTP (Data)",
        21: "FTP (Control)",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        123: "NTP",
        139: "NetBIOS",
        143: "IMAP",
        161: "SNMP",
        443: "HTTPS",
        445: "SMB",
        465: "SMTPS",
        587: "SMTP (Submission)",
        993: "IMAPS",
        995: "POP3S",
        1194: "OpenVPN",
        1433: "MS SQL",
        1723: "PPTP",
        3306: "MySQL",
        3389: "RDP",
        5000: "UPnP",
        5432: "PostgreSQL",
        5900: "VNC",
        8080: "HTTP (Alt)",
        8443: "HTTPS (Alt)"
    }

    def __init__(self, *args, hosts_file=None, network_server=None, **kwargs):
        self.hosts_file = hosts_file
        self.network_server = network_server
        self.vendor_db = None
        
        # Try to initialize vendor database if available
        try:
            from vendor_db import VendorDB
            self.vendor_db = VendorDB()
            logger.info("MAC vendor database initialized")
        except Exception as e:
            logger.warning(f"Could not initialize MAC vendor database: {e}")
            
        # BaseHTTPRequestHandler calls do_GET inside __init__
        super().__init__(*args, **kwargs)

    def log_message(self, format, *args):
        """Override logging to use our logger."""
        logger.info("%s - - [%s] %s" % (self.client_address[0],
                                        self.log_date_time_string(),
                                        format % args))
                                        
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
            
        result = []
        for port in sorted(ports):
            # Convert to int if it's a string
            if isinstance(port, str) and port.isdigit():
                port = int(port)
                
            if port in self.PORT_DESCRIPTIONS:
                service = self.PORT_DESCRIPTIONS[port]
                result.append(f"<span class='port port-known' title='{service}'>{port} ({service})</span>")
            else:
                result.append(f"<span class='port'>{port}</span>")
                
        return "<div class='port-list'>" + ", ".join(result) + "</div>"

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
        """Update a static entry in the hosts file."""
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
        """Update the hosts file on disk with current entries."""
        if not self.hosts_file or not self.hosts_file.file_path:
            return

        # Read the original file to preserve comments and formatting
        original_lines = []
        with open(self.hosts_file.file_path, 'r') as f:
            original_lines = f.readlines()

        # Extract comments and non-entry lines
        comments_and_blanks = []
        for line in original_lines:
            stripped = line.strip()
            if not stripped or stripped.startswith('#'):
                comments_and_blanks.append(line)

        # Create new entries
        entries = []
        for mac, ip in self.hosts_file.mac_to_ip.items():
            hostnames = self.hosts_file.ip_to_hostnames.get(ip, [])
            if hostnames:
                entries.append(f"{ip} {' '.join(hostnames)} [MAC={mac}]\n")
            else:
                entries.append(f"{ip} - [MAC={mac}]\n")

        # Create additional DNS entries (without MAC addresses)
        for ip, hostnames in self.hosts_file.ip_to_hostnames.items():
            # Skip if this IP is already covered by a MAC entry
            if any(ip == mac_ip for mac_ip in self.hosts_file.mac_to_ip.values()):
                continue

            entries.append(f"{ip} {' '.join(hostnames)}\n")

        # Start with a header comment
        output = ["# Hosts file updated by Network Server Web UI\n",
                  f"# Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n",
                  "#\n",
                  "# Format for DNS entries:\n",
                  "# <IP address> <hostname1> [hostname2] [hostname3] ...\n",
                  "#\n",
                  "# Format for DHCP entries with MAC address:\n",
                  "# <IP address> <hostname1> [hostname2] ... [MAC=aa:bb:cc:dd:ee:ff]\n",
                  "#\n"]

        # Add some original comments if available
        for i, line in enumerate(comments_and_blanks):
            if i < 5:  # Limit to avoid duplicating too many comments
                output.append(line)

        # Add a separator
        output.append("\n# Static and dynamic entries\n")

        # Add all the entries
        output.extend(entries)

        # Write the updated file
        with open(self.hosts_file.file_path, 'w') as f:
            f.writelines(output)

        # Force reload the hosts file
        self.hosts_file.last_modified = 0
        self.hosts_file.load_file()


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
