#!/usr/bin/env python3
"""
Web UI Home Page Module

This module provides functions for rendering the home page of the Web UI.
"""

import re
import time
import logging
from urllib.parse import parse_qs
from webui_templates import HTML_HEADER, HTML_FOOTER, render_message

# Setup logging
logger = logging.getLogger('webui_home')

# Try to import port database utilities
try:
    from port_database import get_port_db
    from port_scanner import refresh_port_data
    USE_PORT_DB = True
except ImportError:
    logger.warning("Port database module not available")
    USE_PORT_DB = False
    get_port_db = lambda: None
    refresh_port_data = lambda ip, force=False: []


def render_home_page(handler):
    """Render the home page with static entries and DHCP leases."""
    # Parse query parameters for message display
    message = None
    message_type = "info"
    
    if "?" in handler.path:
        query = parse_qs(handler.path.split("?")[1])
        message = query.get("message", [""])[0]
        message_type = query.get("type", ["info"])[0]
    
    # Check for HTMX request
    is_htmx = 'HX-Request' in handler.headers
    
    if is_htmx:
        # For HTMX requests, render just the dashboard content
        content = render_dashboard_content_html(handler)
    else:
        # For full page requests, render the entire page
        # Get static entries and dynamic leases
        static_entries = []
        dynamic_leases = []

        # Parse port database flag
        port_db = get_port_db() if USE_PORT_DB else None

        # Get static entries from hosts file
        if handler.hosts_file:
            for mac, ip in handler.hosts_file.mac_to_ip.items():
                hostnames = handler.hosts_file.get_hostnames_for_ip(ip)
                
                # Get port information from the database or hosts file
                ports = get_ports_for_ip(handler, ip, hostnames, port_db)
                
                # Filter out port tags from display hostnames
                display_hostnames = [h for h in hostnames if not h.startswith('ports-') and h != 'preallocated']
                
                entry = {
                    'mac': mac,
                    'ip': ip,
                    'hostnames': ', '.join(display_hostnames) if display_hostnames else '-',
                    'ports': ports
                }
                
                static_entries.append(entry)

            # Get dynamic leases
            for mac, lease in handler.hosts_file.leases.items():
                if not lease.is_expired():
                    hostnames = handler.hosts_file.get_hostnames_for_ip(lease.ip_address)
                    remaining = int(lease.expiry_time - time.time())
                    hours, remainder = divmod(remaining, 3600)
                    minutes, seconds = divmod(remainder, 60)
                    
                    # Get port information (similar to static entries)
                    ports = get_ports_for_ip(handler, lease.ip_address, hostnames, port_db)
                    
                    # Filter display hostnames
                    display_hostnames = [h for h in hostnames if not h.startswith('ports-') and h != 'preallocated']

                    dynamic_leases.append({
                        'mac': mac,
                        'ip': lease.ip_address,
                        'hostnames': ', '.join(display_hostnames) if display_hostnames else '-',
                        'hostname': lease.hostname or '-',
                        'expires': f"{hours}h {minutes}m {seconds}s",
                        'ports': ports
                    })
                    
        # Render the full page
        content = HTML_HEADER
        
        # Add message if any
        if message:
            content += render_message(message, message_type)
        
        # Add dashboard content
        content += f"""
        <div>
            <div class="flex justify-between items-center mb-4">
                <h1>Dashboard</h1>
                <div class="flex gap-2">
                    <a href="/add" class="btn btn-add">
                        <i class="fas fa-plus"></i> Add Entry
                    </a>
                    <a href="/scan" class="btn btn-scan">
                        <i class="fas fa-search"></i> Scan Network
                    </a>
                    <button class="btn btn-primary" hx-get="/dashboard-content" hx-target="#dashboard-content" hx-swap="innerHTML">
                        <i class="fas fa-sync-alt"></i> Refresh
                        <span class="htmx-indicator">
                            <span class="spinner"></span> Loading...
                        </span>
                    </button>
                </div>
            </div>
            
            <div id="dashboard-content" hx-trigger="every 10s">
        """
        
        # Add the actual dashboard content
        content += render_dashboard_content_html(handler)
        
        content += """
            </div>
        </div>
        """
        
        content += HTML_FOOTER
    
    # Send the response
    handler._send_response(content.encode())


def render_dashboard_content(handler):
    """
    Render just the dashboard content for HTMX requests.
    """
    content = render_dashboard_content_html(handler)
    handler._send_response(content.encode())


def render_dashboard_content_html(handler):
    """
    Generate the HTML for the dashboard content.
    """
    static_entries = []
    dynamic_leases = []
    
    port_db = get_port_db() if USE_PORT_DB else None

    # Get static entries from hosts file
    if handler.hosts_file:
        # Get MAC-based entries
        for mac, ip in handler.hosts_file.mac_to_ip.items():
            hostnames = handler.hosts_file.get_hostnames_for_ip(ip)
            
            # Get port information from the database or hosts file
            ports = get_ports_for_ip(handler, ip, hostnames, port_db)
            
            # Filter out port tags from display hostnames
            display_hostnames = [h for h in hostnames if not h.startswith('ports-') and h != 'preallocated']
            
            entry = {
                'mac': mac,
                'ip': ip,
                'hostnames': ', '.join(display_hostnames) if display_hostnames else '-',
                'ports': ports,
                'has_mac': True
            }
            
            static_entries.append(entry)
        
        # Get DNS-only entries (no MAC address)
        mac_ips = set(handler.hosts_file.mac_to_ip.values())
        for ip, hostnames in handler.hosts_file.ip_to_hostnames.items():
            # Skip if this IP is already covered by a MAC entry
            if ip in mac_ips:
                continue
                
            # Get port information
            ports = get_ports_for_ip(handler, ip, hostnames, port_db)
            
            # Filter out port tags from display hostnames
            display_hostnames = [h for h in hostnames if not h.startswith('ports-') and h != 'preallocated']
            
            entry = {
                'mac': 'N/A',  # No MAC for DNS-only entries
                'ip': ip,
                'hostnames': ', '.join(display_hostnames) if display_hostnames else '-',
                'ports': ports,
                'has_mac': False
            }
            
            static_entries.append(entry)

        # Get dynamic leases
        for mac, lease in handler.hosts_file.leases.items():
            if not lease.is_expired():
                hostnames = handler.hosts_file.get_hostnames_for_ip(lease.ip_address)
                remaining = int(lease.expiry_time - time.time())
                hours, remainder = divmod(remaining, 3600)
                minutes, seconds = divmod(remainder, 60)
                
                # Get port information (similar to static entries)
                ports = get_ports_for_ip(handler, lease.ip_address, hostnames, port_db)
                
                # Filter display hostnames
                display_hostnames = [h for h in hostnames if not h.startswith('ports-') and h != 'preallocated']

                dynamic_leases.append({
                    'mac': mac,
                    'ip': lease.ip_address,
                    'hostnames': ', '.join(display_hostnames) if display_hostnames else '-',
                    'hostname': lease.hostname or '-',
                    'expires': f"{hours}h {minutes}m {seconds}s",
                    'ports': ports
                })
                
    # Render the static entries section
    content = f"""
    <div class="content-container mb-4">
        <h2 class="mb-3">Static Entries</h2>
        
        <table>
            <thead>
                <tr>
                    <th>MAC Address</th>
                    <th>IP Address</th>
                    <th>Hostnames</th>
                    <th>Open Ports</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
    """
    
    if static_entries:
        for entry in static_entries:
            vendor_badge = handler._format_vendor(entry['mac'])
            ports_display = handler._format_ports(entry['ports'])
            
            content += f"""
            <tr>
                <td>{entry['mac']}{vendor_badge if entry['has_mac'] else ''}{'' if entry['has_mac'] else ' <span class="badge badge-info">DNS Only</span>'}</td>
                <td>{entry['ip']}</td>
                <td>{entry['hostnames']}</td>
                <td>{ports_display}</td>
                <td>
                    <div class="btn-group">
                        {'<a href="/edit?mac=' + entry['mac'] + '" class="btn btn-sm btn-edit"><i class="fas fa-edit"></i> Edit</a>' if entry['has_mac'] else '<a href="/edit?ip=' + entry['ip'] + '" class="btn btn-sm btn-edit"><i class="fas fa-edit"></i> Edit</a>'}
                        {'<a href="/delete?mac=' + entry['mac'] + '" class="btn btn-sm btn-delete" onclick="return confirmDelete(\'' + entry['mac'] + '\');"><i class="fas fa-trash"></i> Delete</a>' if entry['has_mac'] else '<a href="/delete?ip=' + entry['ip'] + '" class="btn btn-sm btn-delete" onclick="return confirmDelete(\'' + entry['ip'] + '\');"><i class="fas fa-trash"></i> Delete</a>'}
                    </div>
                </td>
            </tr>
            """
    else:
        content += f"""
        <tr>
            <td colspan="5" class="text-center">No static entries found.</td>
        </tr>
        """
        
    content += """
            </tbody>
        </table>
    </div>
    """
    
    # Render the dynamic leases section
    content += f"""
    <div class="content-container">
        <div class="flex justify-between items-center mb-3">
            <h2 class="mb-0">DHCP Leases</h2>
            {"<form method='POST' action='/scan-ports'><button type='submit' class='btn btn-sm btn-secondary'><i class='fas fa-network-wired'></i> Scan All Ports</button></form>" if USE_PORT_DB else ""}
        </div>
        
        <table>
            <thead>
                <tr>
                    <th>MAC Address</th>
                    <th>IP Address</th>
                    <th>Hostnames</th>
                    <th>Open Ports</th>
                    <th>Expires In</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
    """
    
    if dynamic_leases:
        for lease in dynamic_leases:
            vendor_badge = handler._format_vendor(lease['mac'])
            ports_display = handler._format_ports(lease['ports'])
            
            content += f"""
            <tr>
                <td>{lease['mac']}{vendor_badge}</td>
                <td>{lease['ip']}</td>
                <td>{lease['hostnames']}</td>
                <td>{ports_display}</td>
                <td>{lease['expires']}</td>
                <td>
                    <div class="btn-group">
                        <a href="/edit-lease?mac={lease['mac']}" class="btn btn-sm btn-edit">
                            <i class="fas fa-edit"></i> Edit
                        </a>
                        <a href="/delete-lease?mac={lease['mac']}" class="btn btn-sm btn-delete" onclick="return confirmDelete('{lease['mac']}')">
                            <i class="fas fa-trash"></i> Delete
                        </a>
                    </div>
                </td>
            </tr>
            """
    else:
        content += f"""
        <tr>
            <td colspan="6" class="text-center">No active DHCP leases found.</td>
        </tr>
        """
        
    content += """
            </tbody>
        </table>
    </div>
    """
    
    return content


def get_ports_for_ip(handler, ip, hostnames, port_db=None):
    """
    Get port information for an IP address from the port database or hosts file.
    
    Args:
        handler: The WebUIHandler instance
        ip: The IP address to get ports for
        hostnames: List of hostnames for the IP
        port_db: Optional PortDatabase instance
        
    Returns:
        List of port numbers
    """
    # Get port information from the database if available
    ports = []
    if port_db:
        # Try to refresh port data - the function will use cached data if available
        try:
            ports = refresh_port_data(ip)
        except Exception as e:
            logger.error(f"Error refreshing port data for {ip}: {e}")
    
    # If database not available or refresh failed, fall back to the hosts file method
    if not ports and hostnames:
        # Extract port information from hostnames if any has 'ports-' prefix
        for hostname in hostnames:
            if hostname.startswith('ports-'):
                try:
                    # Extract port numbers from the tag
                    port_list = hostname[6:].split(',')
                    ports = [int(p) for p in port_list if p.isdigit()]
                except (ValueError, IndexError):
                    # Fallback: try to parse as a single string with numbers
                    try:
                        port_nums = re.findall(r'\d+', hostname[6:])
                        if port_nums:
                            ports = [int(p) for p in port_nums]
                    except Exception:
                        pass
    
    return ports
