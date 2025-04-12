#!/usr/bin/env python3
"""
Web UI Module for the DNS/DHCP Network Server

This module provides a simple web interface for:
- Viewing MAC addresses, allocated IPs, and DNS names
- Editing DNS names for devices
- Adding new static entries
- Managing DHCP leases
- Configuring DHCP and network settings
"""

import os
import json
import logging
import threading
import time
import ipaddress
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse
import socket
import re
import ip_utils

# Setup logging
logger = logging.getLogger('webui')

# Default DHCP lease time (24 hours in seconds)
DEFAULT_LEASE_TIME = 86400

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
        # BaseHTTPRequestHandler calls do_GET inside __init__
        super().__init__(*args, **kwargs)

    def log_message(self, format, *args):
        """Override logging to use our logger."""
        logger.info("%s - - [%s] %s" % (self.client_address[0],
                                        self.log_date_time_string(),
                                        format % args))
                                        
    def _format_ports(self, ports):
        """Format a list of port numbers into a user-friendly HTML display."""
        if not ports:
            return "<span class='no-ports'>None detected</span>"
            
        result = []
        for port in sorted(ports):
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

    def _render_home_page(self, message=None, message_type=None):
        """Render the home page."""
        static_entries = []
        dynamic_leases = []

        # Get static entries from hosts file
        if self.hosts_file:
            for mac, ip in self.hosts_file.mac_to_ip.items():
                hostnames = self.hosts_file.get_hostnames_for_ip(ip)
                
                # Check for port information in hostnames
                ports = []
                display_hostnames = []
                for hostname in hostnames:
                    if hostname.startswith('ports-'):
                        try:
                            # Extract port numbers from the tag
                            port_list = hostname[6:].split(',')
                            ports = [int(p) for p in port_list if p.isdigit()]
                        except (ValueError, IndexError):
                            pass
                    elif hostname != 'preallocated':
                        display_hostnames.append(hostname)
                
                entry = {
                    'mac': mac,
                    'ip': ip,
                    'hostnames': ', '.join(display_hostnames) if display_hostnames else '-',
                    'ports': ports
                }
                
                static_entries.append(entry)

            # Get dynamic leases
            for mac, lease in self.hosts_file.leases.items():
                if not lease.is_expired():
                    hostnames = self.hosts_file.get_hostnames_for_ip(lease.ip_address)
                    remaining = int(lease.expiry_time - time.time())
                    hours, remainder = divmod(remaining, 3600)
                    minutes, seconds = divmod(remainder, 60)
                    
                    # Check for port information in hostnames
                    ports = []
                    display_hostnames = []
                    for hostname in hostnames:
                        if hostname.startswith('ports-'):
                            try:
                                # Extract port numbers from the tag
                                port_list = hostname[6:].split(',')
                                ports = [int(p) for p in port_list if p.isdigit()]
                            except (ValueError, IndexError):
                                pass
                        elif hostname != 'preallocated':
                            display_hostnames.append(hostname)

                    dynamic_leases.append({
                        'mac': mac,
                        'ip': lease.ip_address,
                        'hostnames': ', '.join(display_hostnames) if display_hostnames else '-',
                        'hostname': lease.hostname or '-',
                        'expires': f"{hours}h {minutes}m {seconds}s",
                        'ports': ports
                    })

        # Build the page content
        content = HTML_HEADER

        # Display message if any
        if message:
            content += f'<div class="message {message_type}">{message}</div>'

        content += """
            <h1>Network Server Admin</h1>
            <p>View and manage MAC, IP, and DNS entries.</p>

            <h2>Static Entries</h2>
        """

        if static_entries:
            content += """
            <table>
                <tr>
                    <th>MAC Address</th>
                    <th>IP Address</th>
                    <th>Hostnames</th>
                    <th>Open Ports</th>
                    <th>Actions</th>
                </tr>
            """

            for entry in static_entries:
                content += f"""
                <tr>
                    <td>{entry['mac']}</td>
                    <td>{entry['ip']}</td>
                    <td>{entry['hostnames']}</td>
                    <td>
                        {self._format_ports(entry['ports'])}
                    </td>
                    <td>
                        <a href="/edit?mac={entry['mac']}" class="btn btn-edit">Edit</a>
                        <a href="/delete?mac={entry['mac']}" class="btn btn-delete" onclick="return confirmDelete('{entry['mac']}')">Delete</a>
                    </td>
                </tr>
                """

            content += "</table>"
        else:
            content += "<p>No static entries found.</p>"

        content += "<a href='/add' class='btn btn-add'>Add New Entry</a>"

        content += "<h2>DHCP Leases</h2>"

        if dynamic_leases:
            content += """
            <table>
                <tr>
                    <th>MAC Address</th>
                    <th>IP Address</th>
                    <th>Hostname</th>
                    <th>DNS Names</th>
                    <th>Open Ports</th>
                    <th>Expires In</th>
                    <th>Actions</th>
                </tr>
            """

            for lease in dynamic_leases:
                content += f"""
                <tr>
                    <td>{lease['mac']}</td>
                    <td>{lease['ip']}</td>
                    <td>{lease['hostname']}</td>
                    <td>{lease['hostnames']}</td>
                    <td>
                        {self._format_ports(lease['ports'])}
                    </td>
                    <td>{lease['expires']}</td>
                    <td>
                        <a href="/edit-lease?mac={lease['mac']}" class="btn btn-edit">Edit</a>
                        <a href="/delete-lease?mac={lease['mac']}" class="btn btn-delete" onclick="return confirmDelete('{lease['mac']}')">Delete</a>
                    </td>
                </tr>
                """

            content += "</table>"
        else:
            content += "<p>No active DHCP leases found.</p>"

        content += HTML_FOOTER
        return content.encode()

    def _render_edit_page(self, mac_address):
        """Render the edit page for a MAC address."""
        if not self.hosts_file:
            return self._send_error(500, "Hosts file not available")

        ip_address = self.hosts_file.get_ip_for_mac(mac_address)
        if not ip_address:
            return self._send_error(404, f"No entry found for MAC: {mac_address}")

        hostnames = self.hosts_file.get_hostnames_for_ip(ip_address)

        return self._render_edit_page_with_data(mac_address, ip_address, ip_address, hostnames)

    def _render_edit_page_with_data(self, mac_address, original_ip, ip_address, hostnames, error_message=None):
        """Render the edit page with the given data and optional error message."""
        content = HTML_HEADER

        # Display error message if any
        if error_message:
            content += f'<div class="message error">{error_message}</div>'

        content += f"""
            <h1>Edit Entry</h1>
            <form method="post" action="/update">
                <input type="hidden" name="mac" value="{mac_address}">
                <input type="hidden" name="original_ip" value="{original_ip}">

                <div class="form-group">
                    <label for="mac">MAC Address:</label>
                    <input type="text" id="mac" name="mac_display" value="{mac_address}" disabled>
                </div>

                <div class="form-group">
                    <label for="ip">IP Address:</label>
                    <input type="text" id="ip" name="ip" value="{ip_address}" required>
                </div>

                <div class="form-group">
                    <label for="hostnames">Hostnames (comma-separated):</label>
                    <input type="text" id="hostnames" name="hostnames" value="{', '.join(hostnames) if hostnames else ''}">
                </div>

                <div class="form-group">
                    <button type="submit" class="btn">Update</button>
                    <a href="/" class="btn" style="background-color: #777;">Cancel</a>
                </div>
            </form>
        """
        content += HTML_FOOTER
        return content.encode()

    def _render_add_page(self):
        """Render the page for adding a new entry."""
        return self._render_add_page_with_data('', '', [], None)

    def _render_add_page_with_data(self, mac, ip, hostnames, error_message=None):
        """Render the add page with the given data and optional error message."""
        content = HTML_HEADER

        # Display error message if any
        if error_message:
            content += f'<div class="message error">{error_message}</div>'

        content += f"""
            <h1>Add New Entry</h1>
            <form method="post" action="/add">
                <div class="form-group">
                    <label for="mac">MAC Address (format: xx:xx:xx:xx:xx:xx):</label>
                    <input type="text" id="mac" name="mac" value="{mac}" placeholder="00:11:22:33:44:55" required>
                </div>

                <div class="form-group">
                    <label for="ip">IP Address:</label>
                    <input type="text" id="ip" name="ip" value="{ip}" placeholder="192.168.1.100" required>
                </div>

                <div class="form-group">
                    <label for="hostnames">Hostnames (comma-separated):</label>
                    <input type="text" id="hostnames" name="hostnames" value="{', '.join(hostnames) if hostnames else ''}" placeholder="device.local, device">
                </div>

                <div class="form-group">
                    <button type="submit" class="btn">Add Entry</button>
                    <a href="/" class="btn" style="background-color: #777;">Cancel</a>
                </div>
            </form>
        """
        content += HTML_FOOTER
        return content.encode()

    def _render_edit_lease_page(self, mac_address):
        """Render the edit page for a DHCP lease."""
        if not self.hosts_file:
            return self._send_error(500, "Hosts file not available")

        lease = self.hosts_file.get_lease(mac_address)
        if not lease:
            return self._send_error(404, f"No lease found for MAC: {mac_address}")

        hostnames = self.hosts_file.get_hostnames_for_ip(lease.ip_address)

        return self._render_edit_lease_page_with_data(mac_address, lease, hostnames, str(lease.lease_time))

    def _render_edit_lease_page_with_data(self, mac_address, lease, hostnames, lease_time, error_message=None,
                                          make_static=False):
        """Render the edit lease page with the given data and optional error message."""
        content = HTML_HEADER

        # Display error message if any
        if error_message:
            content += f'<div class="message error">{error_message}</div>'

        # Check if make_static should be checked
        make_static_checked = "checked" if make_static else ""

        content += f"""
            <h1>Edit DHCP Lease</h1>
            <form method="post" action="/update-lease">
                <input type="hidden" name="mac" value="{mac_address}">

                <div class="form-group">
                    <label for="mac">MAC Address:</label>
                    <input type="text" id="mac" name="mac_display" value="{mac_address}" disabled>
                </div>

                <div class="form-group">
                    <label for="ip">IP Address:</label>
                    <input type="text" id="ip" name="ip" value="{lease.ip_address}" required>
                </div>

                <div class="form-group">
                    <label for="hostname">Hostname:</label>
                    <input type="text" id="hostname" name="hostname" value="{lease.hostname or ''}">
                </div>

                <div class="form-group">
                    <label for="hostnames">DNS Names (comma-separated):</label>
                    <input type="text" id="hostnames" name="hostnames" value="{', '.join(hostnames) if hostnames else ''}">
                </div>

                <div class="form-group">
                    <label for="lease_time">Lease Time (seconds):</label>
                    <input type="text" id="lease_time" name="lease_time" value="{lease_time}">
                </div>

                <div class="form-group">
                    <label>
                        <input type="checkbox" name="make_static" value="yes" {make_static_checked}> Convert to static entry
                    </label>
                </div>

                <div class="form-group">
                    <button type="submit" class="btn">Update</button>
                    <a href="/" class="btn" style="background-color: #777;">Cancel</a>
                </div>
            </form>
        """
        content += HTML_FOOTER
        return content.encode()

    def _render_settings_page(self, error_message=None):
        """Render the settings page."""

        # Default values or current configuration
        dhcp_range_start = ""
        dhcp_range_end = ""
        subnet_mask = "255.255.255.0"
        router_ip = ""
        dns_servers = "8.8.8.8, 8.8.4.4"
        lease_time = str(DEFAULT_LEASE_TIME)
        dhcp_enabled = "checked"

        # Get values from the network server if available
        server = getattr(self, 'network_server', None)
        if server:
            if hasattr(server, 'dhcp_server') and server.dhcp_server:
                if hasattr(server.dhcp_server, 'subnet_mask'):
                    subnet_mask = server.dhcp_server.subnet_mask

                if hasattr(server.dhcp_server, 'router'):
                    router_ip = server.dhcp_server.router or ""

                if hasattr(server.dhcp_server, 'dns_servers'):
                    dns_servers = ", ".join(server.dhcp_server.dns_servers) if server.dhcp_server.dns_servers else ""

                if hasattr(server.dhcp_server, 'lease_time'):
                    lease_time = str(server.dhcp_server.lease_time)

            # DHCP range
            if hasattr(server.hosts, 'dhcp_range') and server.hosts.dhcp_range:
                dhcp_range_start, dhcp_range_end = server.hosts.dhcp_range

            # DHCP enabled status
            dhcp_enabled = "checked" if server.dhcp_enable else ""

        content = HTML_HEADER

        # Display error message if any
        if error_message:
            content += f'<div class="message error">{error_message}</div>'

        content += f"""
            <h1>Network Server Settings</h1>
            <p>Configure DHCP and network settings</p>

            <form method="post" action="/save-settings">
                <div class="form-group">
                    <label>
                        <input type="checkbox" name="dhcp_enabled" value="yes" {dhcp_enabled}> Enable DHCP Server
                    </label>
                </div>

                <h2>DHCP Settings</h2>

                <div class="form-group">
                    <label for="dhcp_range_start">DHCP IP Range Start:</label>
                    <input type="text" id="dhcp_range_start" name="dhcp_range_start" value="{dhcp_range_start}" placeholder="192.168.1.100">
                </div>

                <div class="form-group">
                    <label for="dhcp_range_end">DHCP IP Range End:</label>
                    <input type="text" id="dhcp_range_end" name="dhcp_range_end" value="{dhcp_range_end}" placeholder="192.168.1.200">
                </div>

                <div class="form-group">
                    <label for="subnet_mask">Subnet Mask:</label>
                    <input type="text" id="subnet_mask" name="subnet_mask" value="{subnet_mask}" placeholder="255.255.255.0">
                </div>

                <div class="form-group">
                    <label for="router_ip">Default Gateway/Router IP:</label>
                    <input type="text" id="router_ip" name="router_ip" value="{router_ip}" placeholder="192.168.1.1">
                </div>

                <div class="form-group">
                    <label for="dns_servers">DNS Servers (comma-separated):</label>
                    <input type="text" id="dns_servers" name="dns_servers" value="{dns_servers}" placeholder="8.8.8.8, 8.8.4.4">
                </div>

                <div class="form-group">
                    <label for="lease_time">Default Lease Time (seconds):</label>
                    <input type="text" id="lease_time" name="lease_time" value="{lease_time}" placeholder="86400">
                </div>

                <div class="form-group">
                    <button type="submit" class="btn">Save Settings</button>
                    <a href="/" class="btn" style="background-color: #777;">Cancel</a>
                </div>

                <p class="time-info">Note: Some changes may require restarting the server to take effect.</p>
            </form>
        """

        content += HTML_FOOTER
        return content.encode()

    def do_GET(self):
        """Handle GET requests."""
        parsed_url = urlparse(self.path)
        path = parsed_url.path
        query = parse_qs(parsed_url.query)

        try:
            if path == '/' or path == '/index.html' or path == '/static' or path == '/leases':
                # All these paths show the home page for now
                content = self._render_home_page()
                self._send_response(content)
            
            elif path == '/scan':
                content = self._render_scan_page(
                    message=query.get('message', [''])[0] if 'message' in query else None,
                    message_type=query.get('type', [''])[0] if 'type' in query else None
                )
                self._send_response(content)

            elif path == '/edit':
                if 'mac' not in query:
                    self._send_error(400, "MAC address is required")
                    return

                mac = query['mac'][0]
                content = self._render_edit_page(mac)
                self._send_response(content)

            elif path == '/edit-lease':
                if 'mac' not in query:
                    self._send_error(400, "MAC address is required")
                    return

                mac = query['mac'][0]
                content = self._render_edit_lease_page(mac)
                self._send_response(content)

            elif path == '/add':
                content = self._render_add_page()
                self._send_response(content)

            elif path == '/settings':
                content = self._render_settings_page()
                self._send_response(content)

            elif path == '/delete':
                if 'mac' not in query:
                    self._send_error(400, "MAC address is required")
                    return

                mac = query['mac'][0]
                if self.hosts_file:
                    # Delete the static entry from hosts file
                    # This is just removing it from memory, we'll update the file later
                    ip = self.hosts_file.get_ip_for_mac(mac)
                    if ip and mac in self.hosts_file.mac_to_ip:
                        del self.hosts_file.mac_to_ip[mac]
                        self._update_hosts_file()
                        self._send_redirect('/?message=Entry+deleted+successfully&type=success')
                    else:
                        self._send_error(404, f"No entry found for MAC: {mac}")
                else:
                    self._send_error(500, "Hosts file not available")

            elif path == '/delete-lease':
                if 'mac' not in query:
                    self._send_error(400, "MAC address is required")
                    return

                mac = query['mac'][0]
                if self.hosts_file:
                    # Release the lease
                    self.hosts_file.release_lease(mac)
                    self._send_redirect('/?message=Lease+released+successfully&type=success')
                else:
                    self._send_error(500, "Hosts file not available")

            else:
                self._send_error(404, "Page not found")

        except Exception as e:
            logger.error(f"Error handling GET request: {e}")
            self._send_error(500, f"Internal server error: {str(e)}")

    def do_POST(self):
        """Handle POST requests."""
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length).decode('utf-8')
        form_data = parse_qs(post_data)

        try:
            if self.path == '/update':
                # Update an existing entry
                if 'mac' not in form_data or 'ip' not in form_data:
                    self._send_error(400, "MAC and IP addresses are required")
                    return

                mac = form_data['mac'][0]
                ip = form_data['ip'][0]
                original_ip = form_data['original_ip'][0]

                # Get hostnames as a list
                hostnames = []
                if 'hostnames' in form_data and form_data['hostnames'][0]:
                    hostnames = [h.strip() for h in form_data['hostnames'][0].split(',') if h.strip()]

                # Validate IP address before proceeding
                try:
                    ipaddress.ip_address(ip)
                except ValueError:
                    # Render the edit page again with an error message
                    error_content = self._render_edit_page_with_data(
                        mac,
                        original_ip,
                        ip,  # The invalid IP they entered
                        hostnames,
                        "Invalid IP address format. Please enter a valid IPv4 or IPv6 address."
                    )
                    return self._send_response(error_content)

                if self.hosts_file:
                    # Update the entry
                    self._update_static_entry(mac, ip, original_ip, hostnames)
                    self._send_redirect('/?message=Entry+updated+successfully&type=success')
                else:
                    self._send_error(500, "Hosts file not available")

            elif self.path == '/add':
                # Add a new entry
                if 'mac' not in form_data or 'ip' not in form_data:
                    self._send_error(400, "MAC and IP addresses are required")
                    return

                mac = form_data['mac'][0]
                ip = form_data['ip'][0]

                # Get hostnames as a list
                hostnames = []
                if 'hostnames' in form_data and form_data['hostnames'][0]:
                    hostnames = [h.strip() for h in form_data['hostnames'][0].split(',') if h.strip()]

                # Validate data before proceeding
                errors = []

                # Validate IP
                try:
                    ipaddress.ip_address(ip)
                except ValueError:
                    errors.append("Invalid IP address format. Please enter a valid IPv4 or IPv6 address.")

                # Validate MAC
                if not re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', mac):
                    errors.append("Invalid MAC address format. Please use format like 00:11:22:33:44:55.")

                if self.hosts_file and mac.lower() in self.hosts_file.mac_to_ip:
                    errors.append(f"An entry with MAC {mac} already exists.")

                if errors:
                    # Re-render the add page with errors
                    error_content = self._render_add_page_with_data(mac, ip, hostnames, "<br>".join(errors))
                    return self._send_response(error_content)

                if self.hosts_file:
                    # Add to hosts file
                    self.hosts_file.mac_to_ip[mac.lower()] = ip
                    if hostnames:
                        self.hosts_file.ip_to_hostnames[ip] = hostnames
                        for hostname in hostnames:
                            # Create DNS record
                            record_type = 1  # Assume IPv4 for simplicity
                            if ':' in ip:
                                record_type = 28  # IPv6

                            dns_record = DNSRecord(ip, record_type)
                            self.hosts_file.dns_records[hostname.lower()].append(dns_record)

                    # Update the hosts file
                    self._update_hosts_file()
                    self._send_redirect('/?message=Entry+added+successfully&type=success')
                else:
                    self._send_error(500, "Hosts file not available")

            elif self.path == '/update-lease':
                # Update a DHCP lease
                if 'mac' not in form_data or 'ip' not in form_data:
                    self._send_error(400, "MAC and IP addresses are required")
                    return

                mac = form_data['mac'][0].lower()
                ip = form_data['ip'][0]
                hostname = form_data['hostname'][0] if 'hostname' in form_data and form_data['hostname'][0] else None

                # Check if make_static was checked
                make_static = 'make_static' in form_data and form_data['make_static'][0] == 'yes'

                # Handle lease time with validation
                lease_time_str = form_data['lease_time'][0] if 'lease_time' in form_data else ""
                lease_time = 86400  # Default

                # Get hostnames as a list
                hostnames = []
                if 'hostnames' in form_data and form_data['hostnames'][0]:
                    hostnames = [h.strip() for h in form_data['hostnames'][0].split(',') if h.strip()]

                # Validate lease time
                if lease_time_str:
                    try:
                        lease_time = int(lease_time_str)
                        if lease_time <= 0:
                            raise ValueError("Lease time must be positive")
                    except ValueError as e:
                        # Get the lease
                        lease = self.hosts_file.get_lease(mac)
                        if not lease:
                            self._send_error(404, f"No lease found for MAC: {mac}")
                            return

                        # Re-render with error
                        error_content = self._render_edit_lease_page_with_data(
                            mac,
                            lease,
                            hostnames,
                            lease_time_str,
                            "Invalid lease time. Please enter a positive number of seconds.",
                            make_static
                        )
                        return self._send_response(error_content)

                # Validate IP address
                try:
                    ipaddress.ip_address(ip)
                except ValueError:
                    # Get the lease
                    lease = self.hosts_file.get_lease(mac)
                    if not lease:
                        self._send_error(404, f"No lease found for MAC: {mac}")
                        return

                    # Re-render with error
                    error_content = self._render_edit_lease_page_with_data(
                        mac,
                        lease,
                        hostnames,
                        lease_time_str,
                        "Invalid IP address format. Please enter a valid IPv4 or IPv6 address.",
                        make_static
                    )
                    return self._send_response(error_content)

                if self.hosts_file:
                    # Get the existing lease
                    lease = self.hosts_file.get_lease(mac)
                    if not lease:
                        self._send_error(404, f"No lease found for MAC: {mac}")
                        return

                    if make_static:
                        # Add as a static entry
                        self.hosts_file.mac_to_ip[mac] = ip
                        if hostnames:
                            self.hosts_file.ip_to_hostnames[ip] = hostnames
                            for hostname in hostnames:
                                # Create DNS record
                                record_type = 1  # Assume IPv4 for simplicity
                                if ':' in ip:
                                    record_type = 28  # IPv6

                                dns_record = DNSRecord(ip, record_type)
                                self.hosts_file.dns_records[hostname.lower()].append(dns_record)

                        # Release the lease
                        self.hosts_file.release_lease(mac)
                    else:
                        # Update the lease
                        self.hosts_file.add_or_update_lease(mac, ip, hostname, lease_time)

                        # Update DNS records if specified
                        if hostnames:
                            # Clear existing DNS entries for this IP
                            for hostname_list in self.hosts_file.ip_to_hostnames.values():
                                for hostname in list(hostname_list):
                                    for record in list(self.hosts_file.dns_records.get(hostname.lower(), [])):
                                        if record.address == ip:
                                            self.hosts_file.dns_records[hostname.lower()].remove(record)

                            # Add new DNS entries
                            self.hosts_file.ip_to_hostnames[ip] = hostnames
                            for hostname in hostnames:
                                record_type = 1  # Assume IPv4 for simplicity
                                if ':' in ip:
                                    record_type = 28  # IPv6

                                dns_record = DNSRecord(ip, record_type)
                                self.hosts_file.dns_records[hostname.lower()].append(dns_record)

                    # Update the hosts file
                    self._update_hosts_file()
                    self._send_redirect('/?message=Lease+updated+successfully&type=success')
                else:
                    self._send_error(500, "Hosts file not available")

            elif self.path == '/scan':
                self._handle_scan_request()
                
            elif self.path == '/save-settings':
                # Save DHCP settings
                # Extract data from form
                dhcp_enabled = 'dhcp_enabled' in form_data and form_data['dhcp_enabled'][0] == 'yes'

                # Only process these if DHCP is enabled
                dhcp_range_start = form_data.get('dhcp_range_start', [''])[0].strip()
                dhcp_range_end = form_data.get('dhcp_range_end', [''])[0].strip()
                subnet_mask = form_data.get('subnet_mask', ['255.255.255.0'])[0].strip()
                router_ip = form_data.get('router_ip', [''])[0].strip()
                dns_servers_str = form_data.get('dns_servers', ['8.8.8.8, 8.8.4.4'])[0]
                lease_time_str = form_data.get('lease_time', ['86400'])[0]

                # Validate inputs
                errors = []

                # If DHCP is enabled, validate all DHCP settings
                if dhcp_enabled:
                    # Validate IP range
                    if not dhcp_range_start or not dhcp_range_end:
                        errors.append("DHCP IP range start and end are required when DHCP is enabled.")
                    else:
                        try:
                            # Validate IP addresses
                            start_ip = ipaddress.IPv4Address(dhcp_range_start)
                            end_ip = ipaddress.IPv4Address(dhcp_range_end)

                            # Check that start is before end
                            if start_ip > end_ip:
                                errors.append("DHCP range start IP must be less than or equal to end IP.")
                        except ValueError:
                            errors.append("Invalid IP address in DHCP range. Please enter valid IPv4 addresses.")

                    # Validate subnet mask
                    try:
                        # Just check that it's a valid IPv4 address - not perfect but catches most errors
                        ipaddress.IPv4Address(subnet_mask)
                    except ValueError:
                        errors.append("Invalid subnet mask. Please enter a valid IPv4 subnet mask.")

                    # Validate router IP if provided
                    if router_ip:
                        try:
                            ipaddress.IPv4Address(router_ip)
                        except ValueError:
                            errors.append("Invalid router IP address. Please enter a valid IPv4 address.")

                    # Validate DNS servers
                    dns_servers = [s.strip() for s in dns_servers_str.split(',') if s.strip()]
                    for dns in dns_servers:
                        try:
                            ipaddress.ip_address(dns)
                        except ValueError:
                            errors.append(f"Invalid DNS server IP: {dns}. Please enter valid IP addresses.")

                    # Validate lease time
                    try:
                        lease_time = int(lease_time_str)
                        if lease_time <= 0:
                            errors.append("Lease time must be a positive number of seconds.")
                    except ValueError:
                        errors.append("Invalid lease time. Please enter a valid number of seconds.")

                # If there are errors, re-render the settings page with error messages
                if errors:
                    error_content = self._render_settings_page("<br>".join(errors))
                    return self._send_response(error_content)

                # Settings look good, store them in a config file
                config = {
                    'dhcp_enabled': dhcp_enabled,
                    'dhcp_range': [dhcp_range_start, dhcp_range_end] if dhcp_enabled else None,
                    'subnet_mask': subnet_mask,
                    'router_ip': router_ip,
                    'dns_servers': dns_servers,
                    'lease_time': int(lease_time_str)
                }

                # Save the config - in a real implementation, you'd update the server's config
                # and potentially restart services
                success_message = "Settings saved successfully. "

                # If we have access to the network server, update its settings directly
                if self.network_server and hasattr(self.network_server, 'dhcp_server'):
                    restart_needed = False

                    # Update DHCP range in hosts file
                    if hasattr(self.hosts_file, 'dhcp_range') and self.hosts_file.dhcp_range != config['dhcp_range']:
                        self.hosts_file.dhcp_range = config['dhcp_range']
                        if config['dhcp_range']:
                            self.hosts_file._setup_dhcp_range(config['dhcp_range'])
                        restart_needed = True

                    # Update subnet mask
                    if hasattr(self.network_server.dhcp_server, 'subnet_mask'):
                        self.network_server.dhcp_server.subnet_mask = config['subnet_mask']
                        restart_needed = True

                    # Update router IP
                    if hasattr(self.network_server.dhcp_server, 'router'):
                        self.network_server.dhcp_server.router = config['router_ip']
                        restart_needed = True

                    # Update DNS servers
                    if hasattr(self.network_server.dhcp_server, 'dns_servers'):
                        self.network_server.dhcp_server.dns_servers = config['dns_servers']
                        restart_needed = True

                    # Update lease time
                    if hasattr(self.network_server.dhcp_server, 'default_lease_time'):
                        self.network_server.dhcp_server.default_lease_time = config['lease_time']
                        restart_needed = True

                    # Update DHCP enable status
                    if hasattr(self.network_server, 'dhcp_enable') and self.network_server.dhcp_enable != config[
                        'dhcp_enabled']:
                        restart_needed = True

                    # If settings were changed that require restart
                    if restart_needed:
                        success_message += "Some changes will take effect after restarting the server."

                self._send_redirect(f'/?message={success_message}&type=success')

            else:
                self._send_error(404, "Page not found")

        except Exception as e:
            logger.error(f"Error handling POST request: {e}")
            self._send_error(500, f"Internal server error: {str(e)}")

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

    def _render_scan_page(self, message=None, message_type=None):
        """Render the network scan page."""
        content = HTML_HEADER

        # Display message if any
        if message:
            content += f'<div class="message {message_type}">{message}</div>'

        content += """
            <h1>Network Scanner</h1>
            <p>Scan your network to discover devices and prevent IP conflicts</p>
            
            <form method="post" action="/scan">
                <p>This will scan the entire DHCP range for active devices. Discovered devices will be added to the 
                configuration automatically. This process may take a few minutes depending on the size of your network.</p>
                
                <div class="form-group">
                    <button type="submit" class="btn btn-scan">Start Network Scan</button>
                    <a href="/" class="btn" style="background-color: #777;">Cancel</a>
                </div>
            </form>
        """
        
        # Show previous scan results if available
        if hasattr(self, 'scan_results') and self.scan_results:
            content += """
                <h2>Previous Scan Results</h2>
                <table>
                    <tr>
                        <th>IP Address</th>
                        <th>MAC Address</th>
                        <th>Status</th>
                        <th>Open Ports</th>
                        <th>Actions</th>
                    </tr>
            """
            
            for ip, data in self.scan_results.items():
                mac = data.get('mac', 'Unknown')
                status = data.get('status', 'Discovered')
                
                status_badge = ''
                if status == 'Added':
                    status_badge = '<span class="badge badge-success">Added</span>'
                elif status == 'Already Configured':
                    status_badge = '<span class="badge badge-info">Already Configured</span>'
                elif status == 'Pre-allocated':
                    status_badge = '<span class="badge badge-warning">Pre-allocated</span>'
                else:
                    status_badge = '<span class="badge">Discovered</span>'
                
                # Only show Edit button if we have a valid MAC address
                edit_button = ''
                if mac and mac != 'Unknown':
                    edit_button = f'<a href="/edit?mac={mac}" class="btn btn-edit">Edit</a>'
                
                # Get port information
                ports = data.get('ports', [])
                
                content += f"""
                    <tr>
                        <td>{ip}</td>
                        <td>{mac}</td>
                        <td>{status_badge}</td>
                        <td>
                            {self._format_ports(ports)}
                        </td>
                        <td>
                            {edit_button}
                        </td>
                    </tr>
                """
            
            content += "</table>"
        
        content += HTML_FOOTER
        return content.encode()

    def _handle_scan_request(self):
        """Handle a network scan request."""
        if not self.hosts_file or not self.hosts_file.dhcp_range:
            return self._send_error(400, "DHCP range not configured. Please set up a DHCP range in Settings first.")
        
        try:
            # Set up a place to store results for display
            self.scan_results = {}
            
            # Define progress callback to track scan progress
            def progress_callback(scanned, total):
                # Update the class-level scan_progress for display in subsequent page loads
                if not hasattr(self, 'scan_progress'):
                    self.scan_progress = (0, 0)
                self.scan_progress = (scanned, total)
            
            # Start the scan in a new thread so we can return a response to the user
            def scan_thread():
                try:
                    # Import scan functionality from ip_utils
                    import ip_utils
                    
                    # Perform the scan
                    discovered = ip_utils.scan_network_async(self.hosts_file.dhcp_range, callback=progress_callback)
                    
                    # Process results for display
                    for ip, mac in discovered.items():
                        status = "Discovered"
                        
                        # Check if it's already in our configuration
                        if ip in self.hosts_file.reserved_ips:
                            status = "Already Configured"
                        elif self.hosts_file.get_hostnames_for_ip(ip) and "preallocated" in self.hosts_file.get_hostnames_for_ip(ip):
                            status = "Pre-allocated"
                        else:
                            # This is a newly discovered device, add it as pre-allocated
                            self.hosts_file._add_preallocated_ip(ip)
                            status = "Added"
                        
                        # Get the open ports from the device info
                        ports = device_info.get('ports', [])
                        
                        self.scan_results[ip] = {
                            'mac': mac or 'Unknown',
                            'status': status,
                            'ports': ports
                        }
                    
                    # Update the hosts file on disk
                    self._update_hosts_file()
                    
                    # Clear progress
                    self.scan_progress = (0, 0)
                except Exception as e:
                    logger.error(f"Error in scan thread: {e}")
            
            # Start the scan thread
            threading.Thread(target=scan_thread, daemon=True).start()
            
            # Redirect to the scan page with a message
            self._send_redirect('/scan?message=Network+scan+started.+This+may+take+a+few+minutes.&type=success')
        except Exception as e:
            logger.error(f"Error handling scan request: {e}")
            self._send_error(500, f"Error starting network scan: {str(e)}")
            
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