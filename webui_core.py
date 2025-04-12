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
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" integrity="sha512-9usAa10IRO0HhonpyAIVpjrylPvoDwiPUiKdWk5t3PyolY1cOd4DSE0Ga+ri4AuTroPR5aQvXU9xC6qOPnzFeg==" crossorigin="anonymous" referrerpolicy="no-referrer" />
    <style>
        :root {
            --color-primary: #3b82f6;
            --color-primary-light: #93c5fd;
            --color-primary-dark: #1d4ed8;
            --color-secondary: #10b981;
            --color-secondary-light: #a7f3d0;
            --color-secondary-dark: #065f46;
            --color-danger: #ef4444;
            --color-danger-light: #fecaca;
            --color-warning: #f59e0b;
            --color-warning-light: #fde68a;
            --color-info: #6366f1;
            --color-info-light: #c7d2fe;
            --color-text: #1f2937;
            --color-text-light: #6b7280;
            --color-background: #ffffff;
            --color-background-alt: #f9fafb;
            --color-border: #e5e7eb;
            --color-nav-bg: #1e293b;
            --color-nav-text: #f8fafc;
            --color-nav-active: #3b82f6;
            --color-card-bg: #ffffff;
            --radius-sm: 0.25rem;
            --radius-md: 0.375rem;
            --radius-lg: 0.5rem;
            --shadow-sm: 0 1px 2px 0 rgba(0, 0, 0, 0.05);
            --shadow-md: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
            --shadow-lg: 0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05);
        }
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            line-height: 1.6;
            color: var(--color-text);
            background-color: var(--color-background-alt);
            margin: 0;
            padding: 0;
        }
        h1, h2, h3, h4, h5, h6 {
            color: var(--color-text);
            margin-bottom: 1rem;
            font-weight: 600;
            line-height: 1.3;
        }
        h1 {
            font-size: 1.75rem;
            margin-top: 0.5rem;
        }
        h2 {
            font-size: 1.375rem;
            margin-top: 1.5rem;
        }
        p {
            margin-bottom: 1rem;
        }
        .container {
            max-width: 1280px;
            margin: 0 auto;
            padding: 0 1rem;
        }
        .content-container {
            background-color: var(--color-card-bg);
            border-radius: var(--radius-lg);
            box-shadow: var(--shadow-md);
            padding: 1.5rem;
            margin-bottom: 1.5rem;
        }
        /* Table Styles */
        table {
            width: 100%;
            border-collapse: separate;
            border-spacing: 0;
            margin-bottom: 1.5rem;
            border-radius: var(--radius-md);
            overflow: hidden;
            box-shadow: var(--shadow-sm);
        }
        thead {
            background-color: var(--color-background-alt);
        }
        th {
            text-align: left;
            padding: 0.75rem 1rem;
            font-weight: 600;
            color: var(--color-text);
            border-bottom: 1px solid var(--color-border);
            text-transform: uppercase;
            font-size: 0.75rem;
            letter-spacing: 0.05em;
        }
        td {
            padding: 0.875rem 1rem;
            border-bottom: 1px solid var(--color-border);
            vertical-align: middle;
        }
        tr:last-child td {
            border-bottom: none;
        }
        tr:hover {
            background-color: rgba(240, 240, 250, 0.5);
        }
        /* Button Styles */
        .btn {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            padding: 0.5rem 1rem;
            font-weight: 500;
            font-size: 0.875rem;
            border-radius: var(--radius-md);
            border: none;
            text-decoration: none;
            cursor: pointer;
            transition: all 0.2s ease;
            box-shadow: var(--shadow-sm);
            column-gap: 0.5rem;
            color: var(--color-nav-text);
            background-color: var(--color-primary);
        }
        .btn:hover {
            box-shadow: var(--shadow-md);
            opacity: 0.9;
        }
        .btn:active {
            transform: translateY(1px);
        }
        .btn-sm {
            padding: 0.375rem 0.75rem;
            font-size: 0.75rem;
        }
        .btn-primary {
            background-color: var(--color-primary);
            color: white;
        }
        .btn-secondary {
            background-color: var(--color-secondary);
            color: white;
        }
        .btn-edit {
            background-color: var(--color-secondary);
            color: white;
        }
        .btn-delete {
            background-color: var(--color-danger);
            color: white;
        }
        .btn-add {
            background-color: var(--color-primary);
            color: white;
            margin-bottom: 1.5rem;
            margin-top: 0.5rem;
        }
        .btn-scan {
            background-color: var(--color-warning);
            color: white;
            margin-bottom: 1.5rem;
        }
        .btn-plain {
            background-color: #f3f4f6;
            color: var(--color-text);
        }
        .btn-group {
            display: flex;
            gap: 0.5rem;
        }
        /* Form Styles */
        form {
            background-color: var(--color-card-bg);
            padding: 1.5rem;
            border-radius: var(--radius-lg);
            box-shadow: var(--shadow-md);
            margin-bottom: 1.5rem;
        }
        label {
            display: block;
            margin-bottom: 0.5rem;
            font-weight: 500;
            color: var(--color-text);
        }
        input[type="text"], 
        input[type="password"], 
        input[type="email"],
        select,
        textarea {
            width: 100%;
            padding: 0.75rem;
            margin-bottom: 1rem;
            border: 1px solid var(--color-border);
            border-radius: var(--radius-md);
            background-color: #fff;
            color: var(--color-text);
            font-size: 0.875rem;
            transition: border-color 0.15s ease;
        }
        input:focus, select:focus, textarea:focus {
            outline: none;
            border-color: var(--color-primary-light);
            box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.2);
        }
        .form-group {
            margin-bottom: 1.25rem;
        }
        .checkbox-group {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            margin-bottom: 1rem;
        }
        .checkbox-group input[type="checkbox"] {
            width: 1rem;
            height: 1rem;
        }
        .checkbox-group label {
            margin-bottom: 0;
            font-weight: normal;
        }
        /* Message Styling */
        .message {
            padding: 1rem;
            margin-bottom: 1.5rem;
            border-radius: var(--radius-md);
            box-shadow: var(--shadow-sm);
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }
        .message i {
            font-size: 1.25rem;
        }
        .success {
            background-color: var(--color-secondary-light);
            border-left: 4px solid var(--color-secondary);
            color: var(--color-secondary-dark);
        }
        .error {
            background-color: var(--color-danger-light);
            border-left: 4px solid var(--color-danger);
            color: var(--color-danger);
        }
        .warning {
            background-color: var(--color-warning-light);
            border-left: 4px solid var(--color-warning);
            color: var(--color-text);
        }
        .info {
            background-color: var(--color-info-light);
            border-left: 4px solid var(--color-info);
            color: var(--color-text);
        }
        /* Navigation */
        .nav {
            background-color: var(--color-nav-bg);
            box-shadow: var(--shadow-md);
            position: sticky;
            top: 0;
            z-index: 10;
            margin-bottom: 2rem;
        }
        .nav-container {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 0.75rem 1.5rem;
            max-width: 1280px;
            margin: 0 auto;
        }
        .nav-brand {
            display: flex;
            align-items: center;
            font-size: 1.25rem;
            font-weight: 600;
            color: var(--color-nav-text);
            text-decoration: none;
            gap: 0.5rem;
        }
        .nav-links {
            display: flex;
            list-style: none;
            margin: 0;
            padding: 0;
            gap: 0.5rem;
        }
        .nav-links a {
            color: var(--color-nav-text);
            text-decoration: none;
            padding: 0.5rem 1rem;
            border-radius: var(--radius-md);
            font-weight: 500;
            transition: background-color 0.2s;
        }
        .nav-links a:hover {
            background-color: rgba(255, 255, 255, 0.1);
        }
        .nav-links a.active {
            background-color: var(--color-nav-active);
            color: white;
        }
        .nav-toggle {
            display: none;
            background: none;
            border: none;
            color: var(--color-nav-text);
            font-size: 1.5rem;
            cursor: pointer;
        }
        /* Utility Classes */
        .mt-0 { margin-top: 0; }
        .mt-1 { margin-top: 0.25rem; }
        .mt-2 { margin-top: 0.5rem; }
        .mt-3 { margin-top: 1rem; }
        .mt-4 { margin-top: 1.5rem; }
        .mt-5 { margin-top: 2rem; }
        .mb-0 { margin-bottom: 0; }
        .mb-1 { margin-bottom: 0.25rem; }
        .mb-2 { margin-bottom: 0.5rem; }
        .mb-3 { margin-bottom: 1rem; }
        .mb-4 { margin-bottom: 1.5rem; }
        .mb-5 { margin-bottom: 2rem; }
        .text-center { text-align: center; }
        .text-right { text-align: right; }
        .text-sm { font-size: 0.875rem; }
        .text-xs { font-size: 0.75rem; }
        .text-muted { color: var(--color-text-light); }
        .flex { display: flex; }
        .flex-col { flex-direction: column; }
        .items-center { align-items: center; }
        .justify-between { justify-content: space-between; }
        .gap-1 { gap: 0.25rem; }
        .gap-2 { gap: 0.5rem; }
        .gap-3 { gap: 1rem; }
        /* Badge Styling */
        .badge {
            display: inline-flex;
            align-items: center;
            padding: 0.25rem 0.5rem;
            font-size: 0.75rem;
            font-weight: 500;
            border-radius: 9999px;
            vertical-align: middle;
            white-space: nowrap;
            line-height: 1;
        }
        .badge-info {
            background-color: var(--color-info-light);
            color: var(--color-info);
        }
        .badge-warning {
            background-color: var(--color-warning-light);
            color: var(--color-warning);
        }
        .badge-success {
            background-color: var(--color-secondary-light);
            color: var(--color-secondary-dark);
        }
        .badge-danger {
            background-color: var(--color-danger-light);
            color: var(--color-danger);
        }
        .badge-vendor {
            background-color: #f3e8ff;
            color: #7e22ce;
            margin-left: 0.375rem;
        }
        /* Port styling */
        .port-list {
            font-size: 0.875rem;
            max-width: 100%;
            max-height: 250px;
            overflow-y: auto;
            border: 1px solid var(--color-border);
            border-radius: var(--radius-md);
            padding: 0.75rem;
            background-color: var(--color-background-alt);
        }
        .port-category {
            margin-bottom: 0.625rem;
            padding: 0.375rem;
            border-bottom: 1px solid var(--color-border);
        }
        .port-category:last-child {
            border-bottom: none;
            margin-bottom: 0;
        }
        .port-category-name {
            font-weight: 600;
            color: var(--color-text);
            margin-right: 0.5rem;
        }
        .port {
            display: inline-flex;
            align-items: center;
            padding: 0.25rem 0.5rem;
            margin: 0.125rem;
            border-radius: var(--radius-sm);
            background-color: #f9fafb;
            border: 1px solid var(--color-border);
            font-size: 0.75rem;
        }
        .port-known {
            background-color: #eff6ff;
            border-color: #bfdbfe;
            color: #2563eb;
            cursor: help;
        }
        .no-ports {
            color: var(--color-text-light);
            font-style: italic;
            font-size: 0.875rem;
        }
        /* Card styling */
        .card {
            background-color: var(--color-card-bg);
            border-radius: var(--radius-lg);
            box-shadow: var(--shadow-md);
            margin-bottom: 1.5rem;
            overflow: hidden;
        }
        .card-header {
            padding: 1rem 1.5rem;
            background-color: var(--color-background-alt);
            border-bottom: 1px solid var(--color-border);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .card-title {
            margin: 0;
            font-size: 1.125rem;
            color: var(--color-text);
            font-weight: 600;
        }
        .card-body {
            padding: 1.5rem;
        }
        /* Spinner */
        .spinner {
            display: inline-block;
            width: 1em;
            height: 1em;
            border: 2px solid rgba(0, 0, 0, 0.1);
            border-top-color: var(--color-primary);
            border-radius: 50%;
            animation: spin 1s linear infinite;
        }
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
        .htmx-indicator {
            display: none;
            margin-left: 0.5rem;
            color: var(--color-text-light);
            align-items: center;
            gap: 0.5rem;
        }
        .htmx-request .htmx-indicator {
            display: inline-flex;
        }
        /* Responsive */
        @media (max-width: 768px) {
            .nav-toggle {
                display: block;
            }
            .nav-links {
                display: none;
                position: absolute;
                top: 100%;
                left: 0;
                right: 0;
                flex-direction: column;
                background-color: var(--color-nav-bg);
                padding: 0.5rem 0;
                box-shadow: var(--shadow-md);
            }
            .nav-links.active {
                display: flex;
            }
            .nav-links a {
                display: block;
                padding: 0.75rem 1.5rem;
                border-radius: 0;
            }
            .btn-group {
                flex-direction: column;
            }
            table {
                display: block;
                overflow-x: auto;
            }
            .card-header {
                flex-direction: column;
                align-items: flex-start;
                gap: 0.75rem;
            }
        }
    </style>
</head>
<body>
    <header class="nav">
        <div class="nav-container">
            <a href="/" class="nav-brand">
                <i class="fas fa-network-wired"></i>
                <span>PyLocalDNS</span>
            </a>
            <button class="nav-toggle">
                <i class="fas fa-bars"></i>
            </button>
            <ul class="nav-links">
                <li><a href="/" class="active"><i class="fas fa-tachometer-alt"></i> Dashboard</a></li>
                <li><a href="/add"><i class="fas fa-plus"></i> Add Entry</a></li>
                <li><a href="/scan"><i class="fas fa-search"></i> Scan Network</a></li>
                <li><a href="/settings"><i class="fas fa-cog"></i> Settings</a></li>
            </ul>
        </div>
    </header>
    <div class="container">
"""

HTML_FOOTER = """
    </div>
    <footer class="mt-5 mb-3 text-center text-muted text-sm">
        <p>PyLocalDNS - Lightweight DNS & DHCP Server</p>
    </footer>
    <script>
        // Mobile navigation toggle
        document.querySelector('.nav-toggle').addEventListener('click', function() {
            document.querySelector('.nav-links').classList.toggle('active');
        });
        
        // Set active nav link based on current page
        document.addEventListener('DOMContentLoaded', function() {
            const currentPath = window.location.pathname;
            const navLinks = document.querySelectorAll('.nav-links a');
            
            navLinks.forEach(link => {
                link.classList.remove('active');
                if (link.getAttribute('href') === currentPath) {
                    link.classList.add('active');
                } else if (currentPath === '/' && link.getAttribute('href') === '/') {
                    link.classList.add('active');
                }
            });
        });
        
        // Confirmation dialogs
        function confirmDelete(mac) {
            return confirm('Are you sure you want to delete the entry for MAC: ' + mac + '?');
        }
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
        67: "DHCP (Server)",
        68: "DHCP (Client)",
        80: "HTTP",
        88: "Kerberos",
        110: "POP3",
        111: "NFS/RPC",
        115: "SFTP",
        119: "NNTP",
        123: "NTP",
        135: "RPC",
        137: "NetBIOS Name",
        138: "NetBIOS Datagram",
        139: "NetBIOS Session",
        143: "IMAP",
        161: "SNMP",
        162: "SNMP Trap",
        179: "BGP",
        389: "LDAP",
        427: "SLP",
        443: "HTTPS",
        445: "SMB/CIFS",
        464: "Kerberos",
        465: "SMTPS",
        500: "IKE/IPsec",
        515: "LPD/LPR",
        548: "AFP",
        554: "RTSP",
        587: "SMTP (Submission)",
        631: "IPP",
        636: "LDAPS",
        989: "FTPS (Data)",
        990: "FTPS (Control)",
        993: "IMAPS",
        995: "POP3S",
        1194: "OpenVPN",
        1433: "MS SQL",
        1521: "Oracle DB",
        1701: "L2TP",
        1723: "PPTP",
        1883: "MQTT",
        1900: "UPNP",
        2049: "NFS",
        2082: "cPanel",
        2083: "cPanel SSL",
        2222: "SSH (Alt)",
        2375: "Docker API",
        2376: "Docker API (SSL)",
        3000: "Grafana",
        3306: "MySQL",
        3389: "RDP",
        3724: "Blizzard Games",
        3478: "STUN/TURN",
        5000: "UPnP",
        5001: "Synology DSM",
        5060: "SIP",
        5222: "XMPP",
        5353: "mDNS",
        5432: "PostgreSQL",
        5683: "CoAP",
        5900: "VNC",
        5984: "CouchDB",
        6379: "Redis",
        6881: "BitTorrent",
        8000: "Web Alt",
        8080: "HTTP Proxy",
        8083: "Proxy",
        8086: "InfluxDB",
        8096: "Jellyfin",
        8123: "Home Assistant",
        8443: "HTTPS Alt",
        8883: "MQTT (SSL)",
        9000: "Portainer",
        9090: "Prometheus",
        9091: "Transmission",
        9100: "Printer Job",
        9200: "Elasticsearch",
        27017: "MongoDB",
        32400: "Plex",
        51820: "WireGuard"
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
