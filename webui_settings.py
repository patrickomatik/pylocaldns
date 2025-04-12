#!/usr/bin/env python3
"""
Web UI Settings Page Module

This module provides functions for rendering and handling settings-related pages.
"""

import logging
import cgi
from webui_templates import HTML_HEADER, HTML_FOOTER, render_message

# Setup logging
logger = logging.getLogger('webui_settings')

# Default lease time (24 hours in seconds)
DEFAULT_LEASE_TIME = 86400


def render_settings_page(handler, error_message=None):
    """Render the settings page."""
    # Default values or current configuration
    dhcp_range_start = ""
    dhcp_range_end = ""
    subnet_mask = "255.255.255.0"
    router_ip = ""
    dns_servers = "8.8.8.8, 8.8.4.4"
    lease_time = str(DEFAULT_LEASE_TIME)
    dhcp_enabled = True
    
    # Get values from the network server if available
    if handler.network_server:
        if hasattr(handler.network_server, 'dhcp_server') and handler.network_server.dhcp_server:
            if hasattr(handler.network_server.dhcp_server, 'subnet_mask'):
                subnet_mask = handler.network_server.dhcp_server.subnet_mask
            
            if hasattr(handler.network_server.dhcp_server, 'router'):
                router_ip = handler.network_server.dhcp_server.router or ""
            
            if hasattr(handler.network_server.dhcp_server, 'dns_servers'):
                dns_servers = ", ".join(handler.network_server.dhcp_server.dns_servers) if handler.network_server.dhcp_server.dns_servers else ""
            
            if hasattr(handler.network_server.dhcp_server, 'lease_time'):
                lease_time = str(handler.network_server.dhcp_server.lease_time)
        
        # DHCP range
        if hasattr(handler.hosts_file, 'dhcp_range') and handler.hosts_file.dhcp_range:
            dhcp_range_start, dhcp_range_end = handler.hosts_file.dhcp_range
        
        # DHCP enabled status
        dhcp_enabled = handler.network_server.dhcp_enable if hasattr(handler.network_server, 'dhcp_enable') else True
    
    content = HTML_HEADER
    
    # Add page title
    content += """
    <h1>Server Settings</h1>
    """
    
    # Add error message if any
    if error_message:
        content += render_message(error_message, "error")
    
    # Add form
    content += f"""
    <form method="post" action="/settings">
        <div class="card mb-4">
            <div class="card-header">
                <h2 class="card-title">DHCP Server Settings</h2>
            </div>
            <div class="card-body">
                <div class="checkbox-group mb-4">
                    <input type="checkbox" id="dhcp_enabled" name="dhcp_enabled" value="yes" {"checked" if dhcp_enabled else ""}>
                    <label for="dhcp_enabled">Enable DHCP Server</label>
                </div>
                
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
                    <label for="router_ip">Default Router (Gateway):</label>
                    <input type="text" id="router_ip" name="router_ip" value="{router_ip}" placeholder="192.168.1.1">
                </div>
                
                <div class="form-group">
                    <label for="dns_servers">DNS Servers (comma-separated):</label>
                    <input type="text" id="dns_servers" name="dns_servers" value="{dns_servers}" placeholder="8.8.8.8, 8.8.4.4">
                </div>
                
                <div class="form-group">
                    <label for="lease_time">Default Lease Time (seconds):</label>
                    <input type="number" id="lease_time" name="lease_time" value="{lease_time}" min="60" placeholder="86400">
                </div>
            </div>
        </div>
        
        <div class="form-group">
            <button type="submit" class="btn btn-primary">
                <i class="fas fa-save"></i> Save Settings
            </button>
            <a href="/" class="btn btn-plain">
                <i class="fas fa-times"></i> Cancel
            </a>
        </div>
    </form>
    """
    
    content += HTML_FOOTER
    handler._send_response(content.encode())


def handle_settings_request(handler):
    """Handle a request to update settings."""
    # Parse the form data
    form = cgi.FieldStorage(
        fp=handler.rfile,
        headers=handler.headers,
        environ={
            'REQUEST_METHOD': 'POST',
            'CONTENT_TYPE': handler.headers['Content-Type']
        }
    )
    
    # Extract data from form
    dhcp_enabled = form.getvalue('dhcp_enabled') == 'yes'
    
    # Only process these if DHCP is enabled
    dhcp_range_start = form.getvalue('dhcp_range_start', '').strip()
    dhcp_range_end = form.getvalue('dhcp_range_end', '').strip()
    subnet_mask = form.getvalue('subnet_mask', '255.255.255.0').strip()
    router_ip = form.getvalue('router_ip', '').strip()
    dns_servers_str = form.getvalue('dns_servers', '8.8.8.8, 8.8.4.4')
    lease_time_str = form.getvalue('lease_time', '86400')
    
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
                from ipaddress import IPv4Address
                start_ip = IPv4Address(dhcp_range_start)
                end_ip = IPv4Address(dhcp_range_end)
                
                # Check that start is before end
                if start_ip > end_ip:
                    errors.append("DHCP range start IP must be less than or equal to end IP.")
            except ValueError:
                errors.append("Invalid IP address in DHCP range. Please enter valid IPv4 addresses.")
        
        # Validate subnet mask
        try:
            # Just check that it's a valid IPv4 address - not perfect but catches most errors
            from ipaddress import IPv4Address
            IPv4Address(subnet_mask)
        except ValueError:
            errors.append("Invalid subnet mask. Please enter a valid IPv4 subnet mask.")
        
        # Validate router IP if provided
        if router_ip:
            try:
                from ipaddress import IPv4Address
                IPv4Address(router_ip)
            except ValueError:
                errors.append("Invalid router IP address. Please enter a valid IPv4 address.")
        
        # Validate DNS servers
        dns_servers = [s.strip() for s in dns_servers_str.split(',') if s.strip()]
        for dns in dns_servers:
            try:
                from ipaddress import ip_address
                ip_address(dns)
            except ValueError:
                errors.append(f"Invalid DNS server IP: {dns}. Please enter valid IP addresses.")
        
        # Validate lease time
        try:
            lease_time = int(lease_time_str)
            if lease_time <= 0:
                errors.append("Lease time must be a positive number of seconds.")
        except ValueError:
            errors.append("Invalid lease time. Please enter a valid number of seconds.")
    
    if errors:
        # Render the settings page with errors
        error_message = "<br>".join(errors)
        render_settings_page_with_errors(handler, error_message, dhcp_enabled, dhcp_range_start, dhcp_range_end,
                                        subnet_mask, router_ip, dns_servers_str, lease_time_str)
        return
    
    # Settings look good, store them
    config = {
        'dhcp_enabled': dhcp_enabled,
        'dhcp_range': [dhcp_range_start, dhcp_range_end] if dhcp_enabled else None,
        'subnet_mask': subnet_mask,
        'router_ip': router_ip,
        'dns_servers': [s.strip() for s in dns_servers_str.split(',') if s.strip()],
        'lease_time': int(lease_time_str)
    }
    
    # If we have access to the network server, update its settings directly
    restart_needed = False
    
    if handler.network_server and hasattr(handler.network_server, 'dhcp_server'):
        # Update DHCP range in hosts file
        if hasattr(handler.hosts_file, 'dhcp_range') and handler.hosts_file.dhcp_range != config['dhcp_range']:
            handler.hosts_file.dhcp_range = config['dhcp_range']
            if config['dhcp_range']:
                handler.hosts_file._setup_dhcp_range(config['dhcp_range'])
            restart_needed = True
        
        # Update subnet mask
        if hasattr(handler.network_server.dhcp_server, 'subnet_mask'):
            handler.network_server.dhcp_server.subnet_mask = config['subnet_mask']
            restart_needed = True
        
        # Update router IP
        if hasattr(handler.network_server.dhcp_server, 'router'):
            handler.network_server.dhcp_server.router = config['router_ip']
            restart_needed = True
        
        # Update DNS servers
        if hasattr(handler.network_server.dhcp_server, 'dns_servers'):
            handler.network_server.dhcp_server.dns_servers = config['dns_servers']
            restart_needed = True
        
        # Update lease time
        if hasattr(handler.network_server.dhcp_server, 'default_lease_time'):
            handler.network_server.dhcp_server.default_lease_time = config['lease_time']
            restart_needed = True
        
        # Update DHCP enable status
        if hasattr(handler.network_server, 'dhcp_enable') and handler.network_server.dhcp_enable != config['dhcp_enabled']:
            restart_needed = True
    
    # Redirect with appropriate message
    if restart_needed:
        handler._send_redirect("/?message=Settings+saved+successfully.+Some+changes+will+take+effect+after+restarting+the+server.&type=success")
    else:
        handler._send_redirect("/?message=Settings+saved+successfully&type=success")


def render_settings_page_with_errors(handler, error_message, dhcp_enabled, dhcp_range_start, dhcp_range_end,
                                     subnet_mask, router_ip, dns_servers, lease_time):
    """Render the settings page with error messages and pre-filled data."""
    content = HTML_HEADER
    
    # Add page title
    content += """
    <h1>Server Settings</h1>
    """
    
    # Add error messages
    content += render_message(error_message, "error")
    
    # Add form
    content += f"""
    <form method="post" action="/settings">
        <div class="card mb-4">
            <div class="card-header">
                <h2 class="card-title">DHCP Server Settings</h2>
            </div>
            <div class="card-body">
                <div class="checkbox-group mb-4">
                    <input type="checkbox" id="dhcp_enabled" name="dhcp_enabled" value="yes" {"checked" if dhcp_enabled else ""}>
                    <label for="dhcp_enabled">Enable DHCP Server</label>
                </div>
                
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
                    <label for="router_ip">Default Router (Gateway):</label>
                    <input type="text" id="router_ip" name="router_ip" value="{router_ip}" placeholder="192.168.1.1">
                </div>
                
                <div class="form-group">
                    <label for="dns_servers">DNS Servers (comma-separated):</label>
                    <input type="text" id="dns_servers" name="dns_servers" value="{dns_servers}" placeholder="8.8.8.8, 8.8.4.4">
                </div>
                
                <div class="form-group">
                    <label for="lease_time">Default Lease Time (seconds):</label>
                    <input type="number" id="lease_time" name="lease_time" value="{lease_time}" min="60" placeholder="86400">
                </div>
            </div>
        </div>
        
        <div class="form-group">
            <button type="submit" class="btn btn-primary">
                <i class="fas fa-save"></i> Save Settings
            </button>
            <a href="/" class="btn btn-plain">
                <i class="fas fa-times"></i> Cancel
            </a>
        </div>
    </form>
    """
    
    content += HTML_FOOTER
    handler._send_response(content.encode())
