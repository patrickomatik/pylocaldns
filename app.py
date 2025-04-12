#!/usr/bin/env python3
"""
Flask Web UI for the PyLocalDNS Server

This module provides a Flask web application for managing the PyLocalDNS server.
It replaces the custom HTTP server with a more robust Flask implementation.
"""

import os
import logging
import threading
import time
import re
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify

# Import route handlers
from flask_routes import routes

# Import host file manager
from hosts_file import HostsFile

# Import port database utilities if available
try:
    from port_database import get_port_db, PortDatabase
    USE_PORT_DB = True
except ImportError:
    USE_PORT_DB = False
    get_port_db = lambda: None

# Import vendor database if available
try:
    from vendor_db import VendorDB
    HAS_VENDOR_DB = True
except ImportError:
    HAS_VENDOR_DB = False
    
# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('flask_webui')

# Create Flask app
app = Flask(__name__, 
            template_folder='templates',
            static_folder='static')
app.secret_key = os.environ.get('FLASK_SECRET_KEY', os.urandom(24))

# Register blueprint
app.register_blueprint(routes)

# Initialize vendor database for context processor using thread-local storage
vendor_db = None
if HAS_VENDOR_DB:
    try:
        vendor_db = VendorDB()
        logger.info("MAC vendor database initialized with thread-safety")
    except Exception as e:
        logger.warning(f"Could not initialize MAC vendor database: {e}")

# Common port descriptions
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

# Context processors
@app.context_processor
def utility_processor():
    """Add utility functions to Jinja2 context."""
    def format_vendor(mac_address):
        """Format a MAC address vendor information."""
        if not mac_address or mac_address == 'Unknown' or not vendor_db:
            return ''
            
        try:
            vendor_name = vendor_db.lookup_vendor(mac_address)
            if vendor_name:
                return f'<span class="badge badge-vendor" title="{vendor_name}">{vendor_name}</span>'
            return ''
        except Exception as e:
            logger.warning(f"Error looking up vendor for MAC {mac_address}: {e}")
            return ''
            
    def format_ports(ports):
        """Format a list of port numbers into a user-friendly HTML display."""
        if not ports:
            return "<span class='no-ports'>None detected</span>"
        
        # Ensure ports is a list of integers
        if isinstance(ports, str) and ',' in ports:
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
            'Remote Access': [22, 23, 3389, 5900, 5901, 5800, 5000, 5001, 2222, 2200, 222],
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
                if port in PORT_DESCRIPTIONS:
                    service = PORT_DESCRIPTIONS[port]
                    port_spans.append(f"<span class='port port-known' title='{service}'>{port} ({service})</span>")
                else:
                    port_spans.append(f"<span class='port'>{port}</span>")
            
            result.append("".join(port_spans))
            result.append('</div>')
            
        result.append('</div>')
        return "".join(result)
            
    return dict(format_vendor=format_vendor, format_ports=format_ports)

# Global variables
hosts_file = None
network_server = None

# Initialize Flask server
def init_flask_server(hosts_file_obj, network_server_obj, port=8080, host='0.0.0.0'):
    """Initialize the Flask server with the hosts file and network server objects."""
    global hosts_file, network_server
    hosts_file = hosts_file_obj
    network_server = network_server_obj
    
    # Configure Flask
    app.config['HOST'] = host
    app.config['PORT'] = port
    
    # Add hosts_file and network_server to app config for route handlers
    app.config['HOSTS_FILE'] = hosts_file
    app.config['NETWORK_SERVER'] = network_server
    app.config['SCAN_RESULTS'] = {}
    
    # Set the template folder path for flask
    app.template_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')
    app.static_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static')
    
    return app

# Main function for standalone testing
if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Flask Web UI for PyLocalDNS')
    parser.add_argument('--hosts-file', required=True, help='Path to the hosts file')
    parser.add_argument('--port', type=int, default=8080, help='Web UI port (default: 8080)')
    parser.add_argument('--interface', default='0.0.0.0', help='Interface to bind to (default: 0.0.0.0)')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    
    args = parser.parse_args()
    
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.setLevel(logging.DEBUG)
    
    # Create the hosts file manager
    hosts_file = HostsFile(args.hosts_file)
    
    # Initialize Flask server
    app.config['HOST'] = args.interface
    app.config['PORT'] = args.port
    app.config['HOSTS_FILE'] = hosts_file
    app.config['NETWORK_SERVER'] = None
    app.config['SCAN_RESULTS'] = {}
    
    # Run the Flask app
    app.run(host=args.interface, port=args.port, debug=args.debug, threaded=True)
