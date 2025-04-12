#!/usr/bin/env python3
"""
Web UI Request Handlers Module

This module provides functions for handling various HTTP requests.
"""

import time
import logging
from urllib.parse import parse_qs, urlparse
import cgi
import re

# Setup logging
logger = logging.getLogger('webui_handlers')

# Default lease time (24 hours in seconds)
DEFAULT_LEASE_TIME = 86400


def handle_add_request(handler):
    """Handle a request to add a new entry."""
    # Parse the form data
    form = cgi.FieldStorage(
        fp=handler.rfile,
        headers=handler.headers,
        environ={
            'REQUEST_METHOD': 'POST',
            'CONTENT_TYPE': handler.headers['Content-Type']
        }
    )
    
    # Extract form fields
    mac = form.getvalue('mac', '').strip().lower()
    ip = form.getvalue('ip', '').strip()
    hostnames_str = form.getvalue('hostnames', '').strip()
    
    # Convert hostnames string to list
    hostnames = [h.strip() for h in hostnames_str.split(',') if h.strip()]
    
    # Validate data
    errors = []
    
    # Validate MAC address if provided
    if mac and not re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', mac):
        errors.append("Invalid MAC address format. Please use format like 00:11:22:33:44:55.")
    
    # Validate IP address
    try:
        from ipaddress import ip_address as validate_ip
        validate_ip(ip)
    except ValueError:
        errors.append("Invalid IP address format. Please enter a valid IPv4 or IPv6 address.")
    
    # Check if MAC already exists
    if mac and handler.hosts_file and mac in handler.hosts_file.mac_to_ip:
        errors.append(f"An entry with MAC {mac} already exists.")
    
    if errors:
        # There were errors, so re-render the add page with error messages
        from webui_edit import render_add_page_with_data
        render_add_page_with_data(handler, mac, ip, hostnames_str, errors)
        return
    
    # Add to hosts file
    if handler.hosts_file:
        # Only add MAC-to-IP mapping if MAC is provided
        if mac:
            handler.hosts_file.mac_to_ip[mac] = ip
            
        if hostnames:
            handler.hosts_file.ip_to_hostnames[ip] = hostnames
            
            # Create DNS records
            for hostname in hostnames:
                # Create DNS record
                if ':' in ip:  # IPv6
                    handler.hosts_file.add_aaaa_record(hostname, ip)
                else:  # IPv4
                    handler.hosts_file.add_a_record(hostname, ip)
        
        # Update the hosts file
        handler._update_hosts_file()
        
        # Redirect to home with success message
        handler._send_redirect("/?message=Entry+added+successfully&type=success")
    else:
        # Hosts file not available
        handler._send_redirect("/?message=Hosts+file+not+available&type=error")


def handle_update_request(handler):
    """Handle a request to update an existing entry."""
    # Parse the form data
    form = cgi.FieldStorage(
        fp=handler.rfile,
        headers=handler.headers,
        environ={
            'REQUEST_METHOD': 'POST',
            'CONTENT_TYPE': handler.headers['Content-Type']
        }
    )
    
    # Extract form fields
    mac = form.getvalue('mac', '').strip().lower()
    ip = form.getvalue('ip', '').strip()
    original_ip = form.getvalue('original_ip', '').strip()
    hostnames_str = form.getvalue('hostnames', '').strip()
    
    # Convert hostnames string to list
    hostnames = [h.strip() for h in hostnames_str.split(',') if h.strip()]
    
    # Validate IP address
    try:
        from ipaddress import ip_address as validate_ip
        validate_ip(ip)
    except ValueError:
        # Render edit page with error
        from webui_edit import render_edit_page_with_data
        render_edit_page_with_data(
            handler,
            mac,
            original_ip,
            ip,
            hostnames_str,
            "Invalid IP address format. Please enter a valid IPv4 or IPv6 address."
        )
        return
    
    if handler.hosts_file:
        try:
            # Update the entry
            handler._update_static_entry(mac, ip, original_ip, hostnames)
            handler._send_redirect("/?message=Entry+updated+successfully&type=success")
        except ValueError as e:
            handler._send_redirect(f"/?message=Error+updating+entry:+{str(e)}&type=error")
    else:
        handler._send_redirect("/?message=Hosts+file+not+available&type=error")


def handle_update_lease_request(handler):
    """Handle a request to update a DHCP lease."""
    # Parse the form data
    form = cgi.FieldStorage(
        fp=handler.rfile,
        headers=handler.headers,
        environ={
            'REQUEST_METHOD': 'POST',
            'CONTENT_TYPE': handler.headers['Content-Type']
        }
    )
    
    # Extract form fields
    mac = form.getvalue('mac', '').strip().lower()
    ip = form.getvalue('ip', '').strip()
    hostname = form.getvalue('hostname', '').strip()
    hostnames_str = form.getvalue('hostnames', '').strip()
    lease_time_str = form.getvalue('lease_time', '').strip()
    make_static = form.getvalue('make_static') == 'yes'
    
    # Convert hostnames string to list
    hostnames = [h.strip() for h in hostnames_str.split(',') if h.strip()]
    
    # Set default lease time
    lease_time = DEFAULT_LEASE_TIME
    
    # Validate lease time
    if lease_time_str:
        try:
            lease_time = int(lease_time_str)
            if lease_time <= 0:
                raise ValueError("Lease time must be positive")
        except ValueError:
            handler._send_redirect(f"/edit-lease?mac={mac}&message=Invalid+lease+time.+Please+enter+a+positive+number+of+seconds.&type=error")
            return
    
    # Validate IP address
    try:
        from ipaddress import ip_address as validate_ip
        validate_ip(ip)
    except ValueError:
        handler._send_redirect(f"/edit-lease?mac={mac}&message=Invalid+IP+address+format&type=error")
        return
    
    if handler.hosts_file:
        # Get the existing lease
        lease = handler.hosts_file.get_lease(mac)
        if not lease:
            handler._send_redirect(f"/?message=No+lease+found+for+MAC:+{mac}&type=error")
            return
        
        if make_static:
            # Add as a static entry
            handler.hosts_file.mac_to_ip[mac] = ip
            if hostnames:
                handler.hosts_file.ip_to_hostnames[ip] = hostnames
                for hostname in hostnames:
                    # Create DNS record
                    if ':' in ip:  # IPv6
                        handler.hosts_file.add_aaaa_record(hostname, ip)
                    else:  # IPv4
                        handler.hosts_file.add_a_record(hostname, ip)
            
            # Release the lease
            handler.hosts_file.release_lease(mac)
        else:
            # Update the lease
            handler.hosts_file.add_or_update_lease(mac, ip, hostname, lease_time)
            
            # Update DNS records if specified
            if hostnames:
                # Clear existing DNS entries for this IP
                for hostname_list in handler.hosts_file.ip_to_hostnames.values():
                    for hostname in list(hostname_list):
                        for record in list(handler.hosts_file.dns_records.get(hostname.lower(), [])):
                            if record.address == ip:
                                handler.hosts_file.dns_records[hostname.lower()].remove(record)
                
                # Add new DNS entries
                handler.hosts_file.ip_to_hostnames[ip] = hostnames
                for hostname in hostnames:
                    # Create DNS record
                    if ':' in ip:  # IPv6
                        handler.hosts_file.add_aaaa_record(hostname, ip)
                    else:  # IPv4
                        handler.hosts_file.add_a_record(hostname, ip)
        
        # Update the hosts file
        handler._update_hosts_file()
        handler._send_redirect("/?message=Lease+updated+successfully&type=success")
    else:
        handler._send_redirect("/?message=Hosts+file+not+available&type=error")


def handle_delete_request(handler):
    """Handle a request to delete an entry."""
    # Parse query parameters
    query = parse_qs(urlparse(handler.path).query)
    mac = query.get('mac', [''])[0]
    
    if not mac:
        handler._send_redirect("/?message=MAC+address+is+required&type=error")
        return
    
    if handler.hosts_file:
        # Delete the static entry from hosts file
        ip = handler.hosts_file.get_ip_for_mac(mac)
        if ip and mac in handler.hosts_file.mac_to_ip:
            del handler.hosts_file.mac_to_ip[mac]
            handler._update_hosts_file()
            handler._send_redirect("/?message=Entry+deleted+successfully&type=success")
        else:
            handler._send_redirect(f"/?message=No+entry+found+for+MAC:+{mac}&type=error")
    else:
        handler._send_redirect("/?message=Hosts+file+not+available&type=error")


def handle_delete_dns_entry(handler):
    """Handle a request to delete a DNS-only entry."""
    # Parse query parameters
    query = parse_qs(urlparse(handler.path).query)
    ip = query.get('ip', [''])[0]
    
    if not ip:
        handler._send_redirect("/?message=IP+address+is+required&type=error")
        return
    
    if handler.hosts_file:
        # Try to delete the DNS entry
        if handler.hosts_file.delete_dns_only_entry(ip):
            handler._send_redirect("/?message=DNS+entry+deleted+successfully&type=success")
        else:
            # If deletion failed, provide error message
            if ip not in handler.hosts_file.ip_to_hostnames:
                handler._send_redirect(f"/?message=No+entry+found+for+IP:+{ip}&type=error")
            elif any(ip == mac_ip for mac_ip in handler.hosts_file.mac_to_ip.values()):
                handler._send_redirect(f"/?message=Cannot+delete+DNS+entry+for+IP+{ip}+because+it+is+associated+with+a+MAC+address&type=error")
            else:
                handler._send_redirect(f"/?message=Failed+to+delete+DNS+entry+for+IP:+{ip}&type=error")
    else:
        handler._send_redirect("/?message=Hosts+file+not+available&type=error")


def handle_delete_lease_request(handler):
    """Handle a request to delete a DHCP lease."""
    # Parse query parameters
    query = parse_qs(urlparse(handler.path).query)
    mac = query.get('mac', [''])[0]
    
    if not mac:
        handler._send_redirect("/?message=MAC+address+is+required&type=error")
        return
    
    if handler.hosts_file:
        # Release the lease
        if handler.hosts_file.release_lease(mac):
            handler._send_redirect("/?message=Lease+released+successfully&type=success")
        else:
            handler._send_redirect(f"/?message=No+lease+found+for+MAC:+{mac}&type=error")
    else:
        handler._send_redirect("/?message=Hosts+file+not+available&type=error")
