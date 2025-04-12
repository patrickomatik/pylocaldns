#!/usr/bin/env python3
"""
Web UI Page Rendering Module for the DNS/DHCP Network Server

This module provides methods for rendering the HTML pages of the Web UI.
"""

import time
import ipaddress
import re
from webui_core import HTML_HEADER, HTML_FOOTER

# Default DHCP lease time (24 hours in seconds)
DEFAULT_LEASE_TIME = 86400


def render_home_page(self, message=None, message_type=None):
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
                        # Fallback: try to parse as a single string with numbers
                        try:
                            # Try to extract numbers from the hostname
                            port_nums = re.findall(r'\d+', hostname[6:])
                            if port_nums:
                                ports = [int(p) for p in port_nums]
                        except Exception:
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
                            # Fallback: try to parse as a single string with numbers
                            try:
                                # Try to extract numbers from the hostname
                                port_nums = re.findall(r'\d+', hostname[6:])
                                if port_nums:
                                    ports = [int(p) for p in port_nums]
                            except Exception:
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
