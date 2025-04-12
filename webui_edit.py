#!/usr/bin/env python3
"""
Web UI Edit Page Module

This module provides functions for rendering edit-related pages in the Web UI.
"""

import time
import logging
from urllib.parse import parse_qs, urlparse
from webui_templates import HTML_HEADER, HTML_FOOTER, render_message

# Setup logging
logger = logging.getLogger('webui_edit')

# Default lease time (24 hours in seconds)
DEFAULT_LEASE_TIME = 86400


def render_add_page(handler):
    """Render the add entry page."""
    content = render_add_page_with_data(handler)
    handler._send_response(content.encode())


def render_add_page_with_data(handler, mac="", ip="", hostnames="", errors=None):
    """Render the add entry page with pre-filled data and optional error messages."""
    content = HTML_HEADER
    
    # Add page title
    content += """
    <h1>Add New Entry</h1>
    """
    
    # Add error messages if any
    if errors:
        error_msg = "<br>".join(errors)
        content += render_message(error_msg, "error")
    
    # Add form
    content += f"""
    <form method="post" action="/add">
        <div class="form-group">
            <label for="mac">MAC Address (optional):</label>
            <input type="text" id="mac" name="mac" value="{mac}" placeholder="00:11:22:33:44:55">
        </div>
        
        <div class="form-group">
            <label for="ip">IP Address:</label>
            <input type="text" id="ip" name="ip" value="{ip}" placeholder="192.168.1.100" required>
        </div>
        
        <div class="form-group">
            <label for="hostnames">Hostnames (comma-separated):</label>
            <input type="text" id="hostnames" name="hostnames" value="{hostnames}" placeholder="server.local, server">
        </div>
        
        <div class="form-group">
            <button type="submit" class="btn btn-primary">
                <i class="fas fa-save"></i> Save Entry
            </button>
            <a href="/" class="btn btn-plain">
                <i class="fas fa-times"></i> Cancel
            </a>
        </div>
    </form>
    """
    
    content += HTML_FOOTER
    return content


def render_edit_page(handler):
    """Render the edit entry page."""
    # Parse query parameters
    query = parse_qs(urlparse(handler.path).query)
    mac = query.get('mac', [''])[0]
    ip = query.get('ip', [''])[0]
    
    # Check for necessary parameters
    if not handler.hosts_file:
        handler._send_redirect("/?message=Hosts+file+not+available&type=error")
        return
    
    # Handle missing parameters
    if not mac and not ip:
        handler._send_error(400, "MAC address or IP address is required")
        return
    
    # Handle IP-only edit (DNS-only entries)
    if not mac and ip:
        hostnames = handler.hosts_file.get_hostnames_for_ip(ip)
        # Filter out port-related and preallocated hostnames for display
        display_hostnames = ', '.join([h for h in hostnames if not h.startswith('ports-') and h != 'preallocated']) if hostnames else ''
        
        content = render_edit_page_with_data(handler, '', ip, ip, display_hostnames)
        handler._send_response(content.encode())
        return
    
    # Handle MAC-based edit
    ip_address = handler.hosts_file.get_ip_for_mac(mac)
    if not ip_address:
        handler._send_error(404, f"No entry found for MAC address: {mac}")
        return
        
    hostnames = handler.hosts_file.get_hostnames_for_ip(ip_address)
    # Filter out port-related and preallocated hostnames for display
    display_hostnames = ', '.join([h for h in hostnames if not h.startswith('ports-') and h != 'preallocated']) if hostnames else ''
    
    content = render_edit_page_with_data(handler, mac, ip_address, ip_address, display_hostnames)
    handler._send_response(content.encode())


def render_edit_page_with_data(handler, mac_address, original_ip, ip_address, hostnames, error_message=None):
    """Render the edit entry page with pre-filled data."""
    content = HTML_HEADER
    
    # Add page title
    content += f"""
    <h1>Edit Entry</h1>
    """
    
    # Add error message if any
    if error_message:
        content += render_message(error_message, "error")
    
    # Add form
    content += f"""
    <form method="post" action="/update">
        <input type="hidden" name="mac" value="{mac_address}">
        <input type="hidden" name="original_ip" value="{original_ip}">
        
        <div class="form-group">
            <label for="ip">IP Address:</label>
            <input type="text" id="ip" name="ip" value="{ip_address}" placeholder="192.168.1.100" required>
        </div>
        
        <div class="form-group">
            <label for="hostnames">Hostnames (comma-separated):</label>
            <input type="text" id="hostnames" name="hostnames" value="{hostnames}" placeholder="server.local, server">
        </div>
        
        <div class="form-group">
            <button type="submit" class="btn btn-primary">
                <i class="fas fa-save"></i> Update Entry
            </button>
            <a href="/" class="btn btn-plain">
                <i class="fas fa-times"></i> Cancel
            </a>
        </div>
    </form>
    """
    
    content += HTML_FOOTER
    return content


def render_edit_lease_page(handler):
    """Render the edit lease page."""
    # Parse query parameters
    query = parse_qs(urlparse(handler.path).query)
    mac = query.get('mac', [''])[0]
    
    if not mac:
        handler._send_redirect("/?message=MAC+address+is+required&type=error")
        return
    
    if not handler.hosts_file:
        handler._send_redirect("/?message=Hosts+file+not+available&type=error")
        return
        
    lease = handler.hosts_file.get_lease(mac)
    if not lease:
        handler._send_redirect(f"/?message=No+lease+found+for+MAC:+{mac}&type=error")
        return
        
    hostnames = handler.hosts_file.get_hostnames_for_ip(lease.ip_address)
    # Filter out port-related and preallocated hostnames for display
    display_hostnames = ', '.join([h for h in hostnames if not h.startswith('ports-') and h != 'preallocated']) if hostnames else ''
    
    content = render_edit_lease_page_with_data(handler, mac, lease, display_hostnames, lease.lease_time)
    handler._send_response(content.encode())


def render_edit_lease_page_with_data(handler, mac_address, lease, hostnames, lease_time, error_message=None,
                                    hostname=None):
    """Render the edit lease page with pre-filled data."""
    if hostname is None:
        hostname = lease.hostname or ""
    
    content = HTML_HEADER
    
    # Add page title
    content += f"""
    <h1>Edit DHCP Lease</h1>
    """
    
    # Add error message if any
    if error_message:
        content += render_message(error_message, "error")
    
    # Calculate expiry time
    remaining = int(lease.expiry_time - time.time())
    hours, remainder = divmod(remaining, 3600)
    minutes, seconds = divmod(remainder, 60)
    expiry_display = f"{hours}h {minutes}m {seconds}s"
    
    # Add lease details
    content += f"""
    <div class="content-container mb-4">
        <h2>Lease Details</h2>
        <p><strong>MAC Address:</strong> {mac_address}</p>
        <p><strong>Current IP:</strong> {lease.ip_address}</p>
        <p><strong>Hostname:</strong> {hostname if hostname else 'Not specified'}</p>
        <p><strong>Expires in:</strong> {expiry_display}</p>
    </div>
    """
    
    # Add form
    content += f"""
    <form method="post" action="/update-lease">
        <input type="hidden" name="mac" value="{mac_address}">
        
        <div class="form-group">
            <label for="ip">IP Address:</label>
            <input type="text" id="ip" name="ip" value="{lease.ip_address}" placeholder="192.168.1.100" required>
        </div>
        
        <div class="form-group">
            <label for="hostname">Client Hostname:</label>
            <input type="text" id="hostname" name="hostname" value="{hostname}" placeholder="(Optional)">
        </div>
        
        <div class="form-group">
            <label for="hostnames">DNS Hostnames (comma-separated):</label>
            <input type="text" id="hostnames" name="hostnames" value="{hostnames}" placeholder="client.local, client">
        </div>
        
        <div class="form-group">
            <label for="lease_time">Lease Time (seconds):</label>
            <input type="number" id="lease_time" name="lease_time" value="{lease_time}" min="60" placeholder="86400">
        </div>
        
        <div class="checkbox-group mb-4">
            <input type="checkbox" id="make_static" name="make_static" value="yes">
            <label for="make_static">Convert to static entry</label>
        </div>
        
        <div class="form-group">
            <button type="submit" class="btn btn-primary">
                <i class="fas fa-save"></i> Update Lease
            </button>
            <a href="/" class="btn btn-plain">
                <i class="fas fa-times"></i> Cancel
            </a>
        </div>
    </form>
    """
    
    content += HTML_FOOTER
    return content
