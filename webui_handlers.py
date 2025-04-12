#!/usr/bin/env python3
"""
Web UI Request Handlers Module for the DNS/DHCP Network Server

This module provides methods for handling HTTP requests to the Web UI.
"""

import re
import logging
import ipaddress
from urllib.parse import parse_qs, urlparse

# Import port database utilities if available
try:
    from port_database import get_port_db
    from ip_utils import refresh_port_data, scan_client_ports, get_active_devices_with_ports
    USE_PORT_DB = True
except ImportError:
    USE_PORT_DB = False
    get_port_db = lambda: None
import socket

# Import page rendering methods
from webui_pages import (
    render_home_page, render_edit_page, render_edit_lease_page,
    render_add_page, render_settings_page, render_edit_page_with_data,
    render_add_page_with_data, render_edit_lease_page_with_data
)

# Import scan page methods
from webui_scan import render_scan_page, handle_scan_request

# Import DNSRecord class (to be used in do_POST)
from webui_core import DNSRecord

# Setup logging
logger = logging.getLogger('webui_handlers')


def do_GET(self):
    """Handle GET requests."""
    parsed_url = urlparse(self.path)
    path = parsed_url.path
    query = parse_qs(parsed_url.query)

    try:
        if path == '/' or path == '/index.html' or path == '/static' or path == '/leases':
            # Check if this is an HTMX request
            is_htmx = 'HX-Request' in self.headers
            # All these paths show the home page for now
            content = render_home_page(self, htmx_request=is_htmx)
            self._send_response(content)
        
        elif path == '/dashboard-content':
            # This endpoint returns only the dashboard content for HTMX updates
            content = render_home_page(self, htmx_request=True)
            self._send_response(content)
        
        elif path == '/scan':
            content = render_scan_page(
                self,
                message=query.get('message', [''])[0] if 'message' in query else None,
                message_type=query.get('type', [''])[0] if 'type' in query else None
            )
            self._send_response(content)

        elif path == '/edit':
            if 'mac' not in query:
                self._send_error(400, "MAC address is required")
                return

            mac = query['mac'][0]
            content = render_edit_page(self, mac)
            self._send_response(content)

        elif path == '/edit-lease':
            if 'mac' not in query:
                self._send_error(400, "MAC address is required")
                return

            mac = query['mac'][0]
            content = render_edit_lease_page(self, mac)
            self._send_response(content)

        elif path == '/add':
            content = render_add_page(self)
            self._send_response(content)

        elif path == '/settings':
            content = render_settings_page(self)
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
                error_content = render_edit_page_with_data(
                    self,
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
                error_content = render_add_page_with_data(self, mac, ip, hostnames, "<br>".join(errors))
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
                    error_content = render_edit_lease_page_with_data(
                        self,
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
                error_content = render_edit_lease_page_with_data(
                    self,
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
            handle_scan_request(self)
            
        elif self.path == '/scan-ports':
            # Scan for open ports on all known devices
            if USE_PORT_DB:
                # Get all devices from the hosts file
                devices = []
                
                # Add static entries
                for mac, ip in self.hosts_file.mac_to_ip.items():
                    devices.append(ip)
                
                # Add dynamic leases
                for mac, lease in self.hosts_file.leases.items():
                    if not lease.is_expired():
                        devices.append(lease.ip_address)
                
                # Remove duplicates
                devices = list(set(devices))
                
                # Refresh ports for all devices
                for ip in devices:
                    try:
                        # Run a fresh scan
                        scan_client_ports(ip)
                    except Exception as e:
                        logger.error(f"Error scanning ports for {ip}: {e}")
                
                # Return the updated dashboard content
                content = render_home_page(self, htmx_request=True)
                self._send_response(content)
            else:
                # If database is not available, just refresh the page
                self._send_redirect('/?message=Port+scanning+requires+database+support&type=error')

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
                error_content = render_settings_page(self, "<br>".join(errors))
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
                if hasattr(self.network_server, 'dhcp_enable') and self.network_server.dhcp_enable != config['dhcp_enabled']:
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
