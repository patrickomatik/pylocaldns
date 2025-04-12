#!/usr/bin/env python3
"""
Web UI Page Rendering Module for the DNS/DHCP Network Server

This module provides methods for rendering the HTML pages of the Web UI.
"""

import time
import ipaddress
import re
import logging
from webui_core import HTML_HEADER, HTML_FOOTER

# Import the port database
try:
    from port_database import get_port_db
    from ip_utils import get_device_ports_from_db, refresh_port_data, PORT_SERVICES
    USE_PORT_DB = True
except ImportError:
    USE_PORT_DB = False
    get_port_db = lambda: None
    get_device_ports_from_db = lambda ip: []
    refresh_port_data = lambda ip, force=False: []
    PORT_SERVICES = {}

# Setup logging
logger = logging.getLogger('webui_pages')

# Default DHCP lease time (24 hours in seconds)
DEFAULT_LEASE_TIME = 86400


def render_home_page(self, message=None, message_type=None, htmx_request=False):
    """Render the home page."""
    static_entries = []
    dynamic_leases = []

    port_db = get_port_db() if USE_PORT_DB else None

    # Get static entries from hosts file
    if self.hosts_file:
        for mac, ip in self.hosts_file.mac_to_ip.items():
            hostnames = self.hosts_file.get_hostnames_for_ip(ip)
            
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
        for mac, lease in self.hosts_file.leases.items():
            if not lease.is_expired():
                hostnames = self.hosts_file.get_hostnames_for_ip(lease.ip_address)
                remaining = int(lease.expiry_time - time.time())
                hours, remainder = divmod(remaining, 3600)
                minutes, seconds = divmod(remainder, 60)
                
                # Get port information (similar to static entries)
                ports = []
                if port_db:
                    try:
                        ports = refresh_port_data(lease.ip_address)
                    except Exception as e:
                        logger.error(f"Error refreshing port data for {lease.ip_address}: {e}")
                
                # Fall back to hosts file method if needed
                if not ports and hostnames:
                    for hostname in hostnames:
                        if hostname.startswith('ports-'):
                            try:
                                port_list = hostname[6:].split(',')
                                ports = [int(p) for p in port_list if p.isdigit()]
                            except (ValueError, IndexError):
                                try:
                                    port_nums = re.findall(r'\d+', hostname[6:])
                                    if port_nums:
                                        ports = [int(p) for p in port_nums]
                                except Exception:
                                    pass
                
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

    # If this is an HTMX request, only return the tables
    if htmx_request:
        return _render_home_page_content(self, static_entries, dynamic_leases).encode()

    # Build the full page content
    content = HTML_HEADER

    # Include HTMX library
    content = content.replace('</head>',
                            '    <script src="https://unpkg.com/htmx.org@1.9.10"></script>\n</head>')

    # Display message if any
    if message:
        icon_class = {
            'success': 'fa-check-circle',
            'error': 'fa-exclamation-circle',
            'warning': 'fa-exclamation-triangle',
            'info': 'fa-info-circle'
        }.get(message_type, 'fa-info-circle')
        
        content += f'''
        <div class="message {message_type}">
            <i class="fas {icon_class}"></i>
            <div>{message}</div>
        </div>'''

    content += """
        <div class="content-container">
            <div class="flex justify-between items-center mb-3">
                <div>
                    <h1 class="mt-0">Network Dashboard</h1>
                    <p class="mb-0 text-muted">Manage your local DNS and DHCP entries</p>
                </div>
                <div class="flex gap-2">
                    <a href="/scan" class="btn btn-secondary">
                        <i class="fas fa-search"></i> Scan Network
                    </a>
                    <a href="/add" class="btn btn-primary">
                        <i class="fas fa-plus"></i> Add Entry
                    </a>
                </div>
            </div>
            
            <div id="dashboard-content" hx-get="/dashboard-content" hx-trigger="every 10s" hx-swap="innerHTML">
    """
    
    # Add the tables
    content += _render_home_page_content(self, static_entries, dynamic_leases)
    
    content += """
            </div>
        </div>
    """
    
    content += HTML_FOOTER
    
    return content.encode()


def _render_home_page_content(self, static_entries, dynamic_leases):
    """Render just the tables for the home page (for HTMX updates)."""
    # Static entries section
    content = """
        <div class="card mb-4">
            <div class="card-header">
                <h2 class="card-title"><i class="fas fa-server"></i> Static Entries</h2>
                <div>
                    <span class="badge badge-info">{count} Entries</span>
                </div>
            </div>
            <div class="card-body">
    """.format(count=len(static_entries))

    if static_entries:
        content += """
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

        for entry in static_entries:
            content += f"""
                <tr>
                    <td>
                        <div class="flex items-center gap-2">
                            <i class="fas fa-microchip text-muted text-sm"></i>
                            <span>{entry['mac']}</span>
                            {self._format_vendor(entry['mac']) if hasattr(self, '_format_vendor') else ''}
                        </div>
                    </td>
                    <td>
                        <code>{entry['ip']}</code>
                    </td>
                    <td>{entry['hostnames']}</td>
                    <td>
                        {self._format_ports(entry['ports']) if hasattr(self, '_format_ports') else ', '.join(map(str, entry['ports'])) if entry['ports'] else '<span class="text-muted">None detected</span>'}
                    </td>
                    <td>
                        <div class="btn-group">
                            <a href="/edit?mac={entry['mac']}" class="btn btn-sm btn-edit">
                                <i class="fas fa-edit"></i> Edit
                            </a>
                            <a href="/delete?mac={entry['mac']}" class="btn btn-sm btn-delete" onclick="return confirmDelete('{entry['mac']}')">
                                <i class="fas fa-trash"></i> Delete
                            </a>
                        </div>
                    </td>
                </tr>
            """

        content += """
                </tbody>
            </table>
        """
    else:
        content += """
            <div class="text-center py-4">
                <i class="fas fa-info-circle text-muted" style="font-size: 3rem;"></i>
                <p class="mt-3">No static entries found. Add a new entry to get started.</p>
                <a href='/add' class='btn btn-primary mt-2'>
                    <i class="fas fa-plus"></i> Add New Entry
                </a>
            </div>
        """

    content += """
            </div>
        </div>
    """

    # DHCP Leases section
    content += """
        <div class="card mb-4">
            <div class="card-header">
                <h2 class="card-title"><i class="fas fa-exchange-alt"></i> DHCP Leases</h2>
                <div>
                    <span class="badge badge-info">{count} Active Leases</span>
                </div>
            </div>
            <div class="card-body">
    """.format(count=len(dynamic_leases))

    if dynamic_leases:
        content += """
            <table>
                <thead>
                    <tr>
                        <th>MAC Address</th>
                        <th>IP Address</th>
                        <th>Hostname</th>
                        <th>DNS Names</th>
                        <th>Open Ports</th>
                        <th>Expires In</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
        """

        for lease in dynamic_leases:
            content += f"""
                <tr>
                    <td>
                        <div class="flex items-center gap-2">
                            <i class="fas fa-laptop text-muted text-sm"></i>
                            <span>{lease['mac']}</span>
                            {self._format_vendor(lease['mac']) if hasattr(self, '_format_vendor') else ''}
                        </div>
                    </td>
                    <td><code>{lease['ip']}</code></td>
                    <td>{lease['hostname']}</td>
                    <td>{lease['hostnames']}</td>
                    <td>
                        {self._format_ports(lease['ports']) if hasattr(self, '_format_ports') else ', '.join(map(str, lease['ports'])) if lease['ports'] else '<span class="text-muted">None detected</span>'}
                    </td>
                    <td>
                        <span class="badge badge-warning">{lease['expires']}</span>
                    </td>
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

        content += """
                </tbody>
            </table>
        """
    else:
        content += """
            <div class="text-center py-4">
                <i class="fas fa-plug text-muted" style="font-size: 3rem;"></i>
                <p class="mt-3">No active DHCP leases found. Devices will appear here when they request IP addresses.</p>
            </div>
        """

    content += """
            </div>
        </div>
    """
        
    # Add button to force refresh ports if using database
    if USE_PORT_DB:
        content += """
        <div class="card">
            <div class="card-header">
                <h2 class="card-title"><i class="fas fa-network-wired"></i> Network Tools</h2>
            </div>
            <div class="card-body text-center">
                <button class="btn btn-primary" hx-post="/scan-ports" hx-target="#dashboard-content" hx-indicator="#scan-indicator">
                    <i class="fas fa-sync"></i> Refresh Open Ports
                </button>
                <span id="scan-indicator" class="htmx-indicator">
                    <i class="fas fa-circle-notch fa-spin"></i> Scanning ports...
                </span>
                <p class="text-muted text-sm mt-2">Refresh detected open ports on all network devices.</p>
            </div>
        </div>
        """
        
    return content


def render_edit_page(self, mac_address):
    """Render the edit page for a MAC address."""
    if not self.hosts_file:
        return self._send_error(500, "Hosts file not available")

    ip_address = self.hosts_file.get_ip_for_mac(mac_address)
    if not ip_address:
        return self._send_error(404, f"No entry found for MAC: {mac_address}")

    hostnames = self.hosts_file.get_hostnames_for_ip(ip_address)

    return render_edit_page_with_data(self, mac_address, ip_address, ip_address, hostnames)


def render_edit_page_with_data(self, mac_address, original_ip, ip_address, hostnames, error_message=None):
    """Render the edit page with the given data and optional error message."""
    content = HTML_HEADER

    # Display error message if any
    if error_message:
        content += f'''
        <div class="message error">
            <i class="fas fa-exclamation-circle"></i>
            <div>{error_message}</div>
        </div>'''

    content += f"""
        <div class="content-container">
            <div class="flex justify-between items-center mb-4">
                <div>
                    <h1 class="mt-0">Edit Entry</h1>
                    <p class="mb-0 text-muted">Update device information</p>
                </div>
            </div>
            
            <div class="card">
                <div class="card-header">
                    <h2 class="card-title"><i class="fas fa-edit"></i> Edit Device</h2>
                </div>
                <div class="card-body">
                    <form method="post" action="/update">
                        <input type="hidden" name="mac" value="{mac_address}">
                        <input type="hidden" name="original_ip" value="{original_ip}">

                        <div class="form-group">
                            <label for="mac">MAC Address:</label>
                            <div class="flex items-center gap-2">
                                <input type="text" id="mac" name="mac_display" value="{mac_address}" disabled class="mb-0">
                                {self._format_vendor(mac_address) if hasattr(self, '_format_vendor') else ''}
                            </div>
                            <p class="text-muted text-sm mt-1 mb-0">MAC addresses cannot be changed</p>
                        </div>

                        <div class="form-group">
                            <label for="ip">IP Address:</label>
                            <input type="text" id="ip" name="ip" value="{ip_address}" required placeholder="192.168.1.100">
                        </div>

                        <div class="form-group">
                            <label for="hostnames">Hostnames (comma-separated):</label>
                            <input type="text" id="hostnames" name="hostnames" value="{', '.join([h for h in hostnames if not h.startswith('ports-') and h != 'preallocated']) if hostnames else ''}" 
                                placeholder="device.local, mydevice">
                            <p class="text-muted text-sm mt-1 mb-0">Add multiple hostnames separated by commas</p>
                        </div>

                        <div class="form-group mb-0 flex gap-2">
                            <button type="submit" class="btn btn-primary">
                                <i class="fas fa-save"></i> Update
                            </button>
                            <a href="/" class="btn btn-plain">
                                <i class="fas fa-times"></i> Cancel
                            </a>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    """
    content += HTML_FOOTER
    return content.encode()


def render_add_page(self):
    """Render the page for adding a new entry."""
    return render_add_page_with_data(self, '', '', [], None)


def render_add_page_with_data(self, mac, ip, hostnames, error_message=None):
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


def render_edit_lease_page(self, mac_address):
    """Render the edit page for a DHCP lease."""
    if not self.hosts_file:
        return self._send_error(500, "Hosts file not available")

    lease = self.hosts_file.get_lease(mac_address)
    if not lease:
        return self._send_error(404, f"No lease found for MAC: {mac_address}")

    hostnames = self.hosts_file.get_hostnames_for_ip(lease.ip_address)

    return render_edit_lease_page_with_data(self, mac_address, lease, hostnames, str(lease.lease_time))


def render_edit_lease_page_with_data(self, mac_address, lease, hostnames, lease_time, error_message=None,
                                      make_static=False):
    """Render the edit lease page with the given data and optional error message."""
    content = HTML_HEADER

    # Display error message if any
    if error_message:
        content += f'''
        <div class="message error">
            <i class="fas fa-exclamation-circle"></i>
            <div>{error_message}</div>
        </div>'''

    # Check if make_static should be checked
    make_static_checked = "checked" if make_static else ""

    # Filter out port-related hostnames for display
    display_hostnames = [h for h in hostnames if not h.startswith('ports-') and h != 'preallocated']

    content += f"""
        <div class="content-container">
            <div class="flex justify-between items-center mb-4">
                <div>
                    <h1 class="mt-0">Edit DHCP Lease</h1>
                    <p class="mb-0 text-muted">Modify dynamic lease settings</p>
                </div>
            </div>
            
            <div class="card">
                <div class="card-header">
                    <h2 class="card-title"><i class="fas fa-exchange-alt"></i> Edit Lease</h2>
                </div>
                <div class="card-body">
                    <form method="post" action="/update-lease">
                        <input type="hidden" name="mac" value="{mac_address}">

                        <div class="form-group">
                            <label for="mac">MAC Address:</label>
                            <div class="flex items-center gap-2">
                                <input type="text" id="mac" name="mac_display" value="{mac_address}" disabled class="mb-0">
                                {self._format_vendor(mac_address) if hasattr(self, '_format_vendor') else ''}
                            </div>
                            <p class="text-muted text-sm mt-1 mb-0">MAC addresses cannot be changed</p>
                        </div>

                        <div class="form-group">
                            <label for="ip">IP Address:</label>
                            <input type="text" id="ip" name="ip" value="{lease.ip_address}" required placeholder="192.168.1.100">
                        </div>

                        <div class="form-group">
                            <label for="hostname">DHCP Hostname:</label>
                            <input type="text" id="hostname" name="hostname" value="{lease.hostname or ''}" placeholder="client-hostname">
                            <p class="text-muted text-sm mt-1 mb-0">Hostname provided by the client during DHCP request</p>
                        </div>

                        <div class="form-group">
                            <label for="hostnames">DNS Names (comma-separated):</label>
                            <input type="text" id="hostnames" name="hostnames" value="{', '.join(display_hostnames) if display_hostnames else ''}" placeholder="device.local, mydevice">
                            <p class="text-muted text-sm mt-1 mb-0">Additional DNS names for this device</p>
                        </div>

                        <div class="form-group">
                            <label for="lease_time">Lease Time (seconds):</label>
                            <input type="text" id="lease_time" name="lease_time" value="{lease_time}" placeholder="86400">
                            <p class="text-muted text-sm mt-1 mb-0">Default is 86400 seconds (24 hours)</p>
                        </div>

                        <div class="checkbox-group">
                            <input type="checkbox" id="make_static" name="make_static" value="yes" {make_static_checked}>
                            <label for="make_static">Convert to static entry</label>
                        </div>
                        <p class="text-muted text-sm mt-0 mb-3">Static entries are permanently reserved</p>

                        <div class="form-group mb-0 flex gap-2">
                            <button type="submit" class="btn btn-primary">
                                <i class="fas fa-save"></i> Update
                            </button>
                            <a href="/" class="btn btn-plain">
                                <i class="fas fa-times"></i> Cancel
                            </a>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    """
    content += HTML_FOOTER
    return content.encode()


def render_settings_page(self, error_message=None):
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
        content += f'''
        <div class="message error">
            <i class="fas fa-exclamation-circle"></i>
            <div>{error_message}</div>
        </div>'''

    content += f"""
        <div class="content-container">
            <div class="flex justify-between items-center mb-4">
                <div>
                    <h1 class="mt-0">Settings</h1>
                    <p class="mb-0 text-muted">Configure DHCP and network settings</p>
                </div>
            </div>
            
            <div class="card">
                <div class="card-header">
                    <h2 class="card-title"><i class="fas fa-cog"></i> Network Configuration</h2>
                </div>
                <div class="card-body">
                    <form method="post" action="/save-settings">
                        <div class="checkbox-group mb-4">
                            <input type="checkbox" id="dhcp_enabled" name="dhcp_enabled" value="yes" {dhcp_enabled}>
                            <label for="dhcp_enabled">Enable DHCP Server</label>
                        </div>

                        <h3><i class="fas fa-network-wired"></i> DHCP Settings</h3>

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
                            <p class="text-muted text-sm mt-1 mb-0">Default is 86400 seconds (24 hours)</p>
                        </div>

                        <div class="form-group mb-0 flex gap-2">
                            <button type="submit" class="btn btn-primary">
                                <i class="fas fa-save"></i> Save Settings
                            </button>
                            <a href="/" class="btn btn-plain">
                                <i class="fas fa-times"></i> Cancel
                            </a>
                        </div>

                        <p class="text-muted text-sm mt-4">Note: Some changes may require restarting the server to take effect.</p>
                    </form>
                </div>
            </div>
        </div>
    """

    content += HTML_FOOTER
    return content.encode()
