#!/usr/bin/env python3
"""
Flask Route Handlers for PyLocalDNS

This module provides all the Flask route handlers for the PyLocalDNS web interface.
It replaces the custom HTTP server implementation with Flask routes.
"""

import os
import logging
import threading
import time
import re
import cgi
from datetime import datetime
from urllib.parse import parse_qs, urlparse
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, Blueprint, current_app

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('flask_routes')

# Default lease time (24 hours in seconds)
DEFAULT_LEASE_TIME = 86400

# Create Blueprint for routes
routes = Blueprint('routes', __name__)

# Import port database utilities if available
try:
    from port_database import get_port_db
    from port_scanner import refresh_port_data, scan_client_ports
    USE_PORT_DB = True
except ImportError:
    logger.warning("Port database module not available")
    USE_PORT_DB = False
    get_port_db = lambda: None
    refresh_port_data = lambda ip, force=False: []
    scan_client_ports = lambda ip: []

# Try to import network scanning utilities
try:
    from network_scanner import scan_network_async
    SCAN_AVAILABLE = True
except ImportError:
    # Use fallback scanning
    try:
        from ip_utils import scan_network_async
        SCAN_AVAILABLE = True
    except ImportError:
        SCAN_AVAILABLE = False
        logger.warning("Network scanning functionality not available")
        scan_network_async = lambda ip_range, callback=None, use_db=False: {}

# Try to import vendor database if available
try:
    from vendor_db import VendorDB
    vendor_db = VendorDB()
    HAS_VENDOR_DB = True
    logger.info("MAC vendor database initialized")
except ImportError:
    HAS_VENDOR_DB = False
    vendor_db = None
    logger.warning("MAC vendor database not available")


#
# Helper Functions
#
def get_ports_for_ip(ip, hostnames, port_db=None):
    """
    Get port information for an IP address from the port database or hosts file.
    
    Args:
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


def _update_static_entry(hosts_file, mac, ip, original_ip, hostnames):
    """Update a static entry in the hosts file."""
    if mac not in hosts_file.mac_to_ip:
        raise ValueError(f"MAC address {mac} not found")

    # Remove old IP mapping
    hosts_file.mac_to_ip[mac] = ip

    # Update hostname to IP mappings
    if original_ip in hosts_file.ip_to_hostnames:
        # Remove the original IP from the hostname mapping
        del hosts_file.ip_to_hostnames[original_ip]

    # Add the new hostname mapping
    if hostnames:
        hosts_file.ip_to_hostnames[ip] = hostnames

        # Update DNS records
        for hostname in hostnames:
            # Remove old records for this hostname
            if hostname.lower() in hosts_file.dns_records:
                hosts_file.dns_records[hostname.lower()] = []

            # Add new record
            if ':' in ip:  # IPv6
                hosts_file.add_aaaa_record(hostname, ip)
            else:  # IPv4
                hosts_file.add_a_record(hostname, ip)

    # Update the hosts file
    _update_hosts_file(hosts_file)


def _update_hosts_file(hosts_file):
    """Update the hosts file on disk with current entries."""
    if not hosts_file or not hosts_file.file_path:
        return

    # Read the original file to preserve comments and formatting
    original_lines = []
    with open(hosts_file.file_path, 'r') as f:
        original_lines = f.readlines()

    # Extract comments and non-entry lines
    comments_and_blanks = []
    for line in original_lines:
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            comments_and_blanks.append(line)

    # Create new entries
    entries = []
    for mac, ip in hosts_file.mac_to_ip.items():
        hostnames = hosts_file.ip_to_hostnames.get(ip, [])
        if hostnames:
            entries.append(f"{ip} {' '.join(hostnames)} [MAC={mac}]\n")
        else:
            entries.append(f"{ip} - [MAC={mac}]\n")

    # Create additional DNS entries (without MAC addresses)
    for ip, hostnames in hosts_file.ip_to_hostnames.items():
        # Skip if this IP is already covered by a MAC entry
        if any(ip == mac_ip for mac_ip in hosts_file.mac_to_ip.values()):
            continue

        entries.append(f"{ip} {' '.join(hostnames)}\n")

    # Start with a header comment
    output = ["# Hosts file updated by PyLocalDNS Web UI\n",
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
    with open(hosts_file.file_path, 'w') as f:
        f.writelines(output)

    # Force reload the hosts file
    hosts_file.last_modified = 0
    hosts_file.load_file()


#
# Route Handlers
#
@routes.route('/')
def home():
    """Render the home page with static entries and DHCP leases."""
    message = request.args.get('message')
    message_type = request.args.get('type', 'info')
    
    return render_template('home_flask.html', 
                           message=message,
                           message_type=message_type,
                           use_port_db=USE_PORT_DB)
    

@routes.route('/dashboard-content')
def dashboard_content():
    """Return just the dashboard content for HTMX requests without full page."""
    # Get hosts file from the app context
    hosts_file = current_app.config['HOSTS_FILE']
    
    # Check if this is an HTMX request
    is_htmx = 'HX-Request' in request.headers
    
    # Get static entries and dynamic leases
    static_entries = []
    dynamic_leases = []
    
    port_db = get_port_db() if USE_PORT_DB else None

    # Get static entries from hosts file
    if hosts_file:
        for mac, ip in hosts_file.mac_to_ip.items():
            hostnames = hosts_file.get_hostnames_for_ip(ip)
            
            # Get port information from the database or hosts file
            ports = get_ports_for_ip(ip, hostnames, port_db)
            
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
        for mac, lease in hosts_file.leases.items():
            if not lease.is_expired():
                hostnames = hosts_file.get_hostnames_for_ip(lease.ip_address)
                remaining = int(lease.expiry_time - time.time())
                hours, remainder = divmod(remaining, 3600)
                minutes, seconds = divmod(remainder, 60)
                
                # Get port information (similar to static entries)
                ports = get_ports_for_ip(lease.ip_address, hostnames, port_db)
                
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
    
    return render_template('home_content.html', 
                        static_entries=static_entries, 
                        dynamic_leases=dynamic_leases,
                        use_port_db=USE_PORT_DB)


@routes.route('/add', methods=['GET', 'POST'])
def add_entry():
    """Add a new DNS/DHCP entry."""
    # Get hosts file from the app context
    hosts_file = current_app.config['HOSTS_FILE']
    
    if request.method == 'POST':
        # Extract form data
        mac = request.form.get('mac', '').strip().lower()
        ip = request.form.get('ip', '').strip()
        hostnames_str = request.form.get('hostnames', '').strip()
        
        # Convert hostnames string to list
        hostnames = [h.strip() for h in hostnames_str.split(',') if h.strip()]
        
        # Validate data
        errors = []
        
        # Validate MAC address
        if not re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', mac):
            errors.append("Invalid MAC address format. Please use format like 00:11:22:33:44:55.")
        
        # Validate IP address
        try:
            from ipaddress import ip_address as validate_ip
            validate_ip(ip)
        except ValueError:
            errors.append("Invalid IP address format. Please enter a valid IPv4 or IPv6 address.")
        
        # Check if MAC already exists
        if hosts_file and mac in hosts_file.mac_to_ip:
            errors.append(f"An entry with MAC {mac} already exists.")
        
        if errors:
            return render_template('add.html', mac=mac, ip=ip, hostnames=hostnames_str, errors=errors)
        
        # Add to hosts file
        if hosts_file:
            hosts_file.mac_to_ip[mac] = ip
            if hostnames:
                hosts_file.ip_to_hostnames[ip] = hostnames
                
                # Create DNS records
                for hostname in hostnames:
                    # Create DNS record
                    if ':' in ip:  # IPv6
                        hosts_file.add_aaaa_record(hostname, ip)
                    else:  # IPv4
                        hosts_file.add_a_record(hostname, ip)
            
            # Update the hosts file
            _update_hosts_file(hosts_file)
            flash("Entry added successfully", "success")
            return redirect(url_for('routes.home'))
        else:
            flash("Hosts file not available", "error")
            return redirect(url_for('routes.home'))
    
    return render_template('add.html')


@routes.route('/edit')
def edit_entry():
    """Edit an existing DNS/DHCP entry."""
    # Get hosts file from the app context
    hosts_file = current_app.config['HOSTS_FILE']
    
    mac = request.args.get('mac')
    if not mac:
        flash("MAC address is required", "error")
        return redirect(url_for('routes.home'))
    
    if not hosts_file:
        flash("Hosts file not available", "error")
        return redirect(url_for('routes.home'))
        
    ip_address = hosts_file.get_ip_for_mac(mac)
    if not ip_address:
        flash(f"No entry found for MAC: {mac}", "error")
        return redirect(url_for('routes.home'))
        
    hostnames = hosts_file.get_hostnames_for_ip(ip_address)
    # Filter out port-related and preallocated hostnames for display
    display_hostnames = ', '.join([h for h in hostnames if not h.startswith('ports-') and h != 'preallocated']) if hostnames else ''
    
    return render_template('edit.html', 
                          mac=mac, 
                          ip=ip_address, 
                          original_ip=ip_address, 
                          hostnames=display_hostnames)


@routes.route('/update', methods=['POST'])
def update_entry():
    """Update an existing DNS/DHCP entry."""
    # Get hosts file from the app context
    hosts_file = current_app.config['HOSTS_FILE']
    
    mac = request.form.get('mac', '').strip()
    ip = request.form.get('ip', '').strip()
    original_ip = request.form.get('original_ip', '').strip()
    hostnames_str = request.form.get('hostnames', '').strip()
    
    # Convert hostnames string to list
    hostnames = [h.strip() for h in hostnames_str.split(',') if h.strip()]
    
    # Validate IP address
    try:
        from ipaddress import ip_address as validate_ip
        validate_ip(ip)
    except ValueError:
        flash("Invalid IP address format", "error")
        return render_template('edit.html', 
                              mac=mac, 
                              ip=ip, 
                              original_ip=original_ip, 
                              hostnames=hostnames_str,
                              error="Invalid IP address format. Please enter a valid IPv4 or IPv6 address.")
    
    if hosts_file:
        # Update the entry
        _update_static_entry(hosts_file, mac, ip, original_ip, hostnames)
        flash("Entry updated successfully", "success")
        return redirect(url_for('routes.home'))
    else:
        flash("Hosts file not available", "error")
        return redirect(url_for('routes.home'))


@routes.route('/delete')
def delete_entry():
    """Delete a DNS/DHCP entry."""
    # Get hosts file from the app context
    hosts_file = current_app.config['HOSTS_FILE']
    
    mac = request.args.get('mac')
    if not mac:
        flash("MAC address is required", "error")
        return redirect(url_for('routes.home'))
    
    if hosts_file:
        # Delete the static entry from hosts file
        ip = hosts_file.get_ip_for_mac(mac)
        if ip and mac in hosts_file.mac_to_ip:
            del hosts_file.mac_to_ip[mac]
            _update_hosts_file(hosts_file)
            flash("Entry deleted successfully", "success")
            return redirect(url_for('routes.home'))
        else:
            flash(f"No entry found for MAC: {mac}", "error")
            return redirect(url_for('routes.home'))
    else:
        flash("Hosts file not available", "error")
        return redirect(url_for('routes.home'))


@routes.route('/edit-lease')
def edit_lease():
    """Edit a DHCP lease."""
    # Get hosts file from the app context
    hosts_file = current_app.config['HOSTS_FILE']
    
    mac = request.args.get('mac')
    if not mac:
        flash("MAC address is required", "error")
        return redirect(url_for('routes.home'))
    
    if not hosts_file:
        flash("Hosts file not available", "error")
        return redirect(url_for('routes.home'))
        
    lease = hosts_file.get_lease(mac)
    if not lease:
        flash(f"No lease found for MAC: {mac}", "error")
        return redirect(url_for('routes.home'))
        
    hostnames = hosts_file.get_hostnames_for_ip(lease.ip_address)
    # Filter out port-related and preallocated hostnames for display
    display_hostnames = ', '.join([h for h in hostnames if not h.startswith('ports-') and h != 'preallocated']) if hostnames else ''
    
    return render_template('edit_lease.html', 
                          mac=mac, 
                          lease=lease,
                          hostnames=display_hostnames,
                          lease_time=lease.lease_time)


@routes.route('/update-lease', methods=['POST'])
def update_lease():
    """Update a DHCP lease."""
    # Get hosts file from the app context
    hosts_file = current_app.config['HOSTS_FILE']
    
    mac = request.form.get('mac', '').strip()
    ip = request.form.get('ip', '').strip()
    hostname = request.form.get('hostname', '').strip()
    hostnames_str = request.form.get('hostnames', '').strip()
    lease_time_str = request.form.get('lease_time', '').strip()
    make_static = request.form.get('make_static') == 'yes'
    
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
            flash("Invalid lease time. Please enter a positive number of seconds.", "error")
            return redirect(url_for('routes.edit_lease', mac=mac))
    
    # Validate IP address
    try:
        from ipaddress import ip_address as validate_ip
        validate_ip(ip)
    except ValueError:
        flash("Invalid IP address format", "error")
        return redirect(url_for('routes.edit_lease', mac=mac))
    
    if hosts_file:
        # Get the existing lease
        lease = hosts_file.get_lease(mac)
        if not lease:
            flash(f"No lease found for MAC: {mac}", "error")
            return redirect(url_for('routes.home'))
        
        if make_static:
            # Add as a static entry
            hosts_file.mac_to_ip[mac] = ip
            if hostnames:
                hosts_file.ip_to_hostnames[ip] = hostnames
                for hostname in hostnames:
                    # Create DNS record
                    if ':' in ip:  # IPv6
                        hosts_file.add_aaaa_record(hostname, ip)
                    else:  # IPv4
                        hosts_file.add_a_record(hostname, ip)
            
            # Release the lease
            hosts_file.release_lease(mac)
        else:
            # Update the lease
            hosts_file.add_or_update_lease(mac, ip, hostname, lease_time)
            
            # Update DNS records if specified
            if hostnames:
                # Clear existing DNS entries for this IP
                for hostname_list in hosts_file.ip_to_hostnames.values():
                    for hostname in list(hostname_list):
                        for record in list(hosts_file.dns_records.get(hostname.lower(), [])):
                            if record.address == ip:
                                hosts_file.dns_records[hostname.lower()].remove(record)
                
                # Add new DNS entries
                hosts_file.ip_to_hostnames[ip] = hostnames
                for hostname in hostnames:
                    # Create DNS record
                    if ':' in ip:  # IPv6
                        hosts_file.add_aaaa_record(hostname, ip)
                    else:  # IPv4
                        hosts_file.add_a_record(hostname, ip)
        
        # Update the hosts file
        _update_hosts_file(hosts_file)
        flash("Lease updated successfully", "success")
        return redirect(url_for('routes.home'))
    else:
        flash("Hosts file not available", "error")
        return redirect(url_for('routes.home'))


@routes.route('/delete-lease')
def delete_lease():
    """Delete a DHCP lease."""
    # Get hosts file from the app context
    hosts_file = current_app.config['HOSTS_FILE']
    
    mac = request.args.get('mac')
    if not mac:
        flash("MAC address is required", "error")
        return redirect(url_for('routes.home'))
    
    if hosts_file:
        # Release the lease
        hosts_file.release_lease(mac)
        flash("Lease released successfully", "success")
        return redirect(url_for('routes.home'))
    else:
        flash("Hosts file not available", "error")
        return redirect(url_for('routes.home'))


@routes.route('/scan')
def scan_network():
    """Render the network scan page."""
    message = request.args.get('message')
    message_type = request.args.get('type', 'info')
    
    # Get scan results from application state
    scan_results = current_app.config.get('SCAN_RESULTS', {})
    
    return render_template('scan.html', 
                          message=message, 
                          message_type=message_type,
                          scan_results=scan_results)


@routes.route('/scan', methods=['POST'])
def handle_scan_request():
    """Handle a request to scan the network."""
    # Get hosts file from the app context
    hosts_file = current_app.config['HOSTS_FILE']
    
    if not hosts_file or not hosts_file.dhcp_range:
        flash("DHCP range not configured. Please set up a DHCP range in Settings first.", "error")
        return redirect(url_for('routes.scan_network'))
    
    if not SCAN_AVAILABLE:
        flash("Network scanning functionality is not available. Please install required modules.", "error")
        return redirect(url_for('routes.scan_network'))
    
    try:
        # Start the scan in a new thread so we can return a response to the user
        def scan_thread():
            try:
                # Get the DHCP range for scanning
                if not hosts_file.dhcp_range or len(hosts_file.dhcp_range) != 2:
                    logger.error("Invalid DHCP range")
                    return
                    
                ip_range = tuple(hosts_file.dhcp_range)
                
                # Define a progress callback
                def progress_callback(scanned, total):
                    logger.info(f"Scan progress: {scanned}/{total} ({int(scanned/total*100)}%)")
                
                # Perform the scan
                discovered = scan_network_async(ip_range, callback=progress_callback, use_db=USE_PORT_DB)
                
                # Process results for display
                scan_results = {}
                for ip, device_info in discovered.items():
                    status = "Discovered"
                    mac = device_info.get('mac')
                    ports = device_info.get('ports', [])
                    
                    # Check if it's already in our configuration
                    if hosts_file.get_ip_for_mac(mac) == ip if mac else False:
                        status = "Already Configured"
                    elif hosts_file.get_hostnames_for_ip(ip) and "preallocated" in hosts_file.get_hostnames_for_ip(ip):
                        status = "Pre-allocated"
                    else:
                        # This is a newly discovered device, add it as pre-allocated
                        # Also add to port database if available
                        if USE_PORT_DB:
                            db = get_port_db()
                            try:
                                # Add device to database
                                db.add_or_update_device(ip, device_info.get('mac'))
                                
                                # Add ports to database
                                if 'ports' in device_info and device_info['ports']:
                                    port_list = device_info['ports']
                                    db.bulk_update_ports(ip, port_list)
                            except Exception as e:
                                logger.error(f"Error updating port database for {ip}: {e}")
                        
                        # Add to hosts file as preallocated
                        # First try using the standardized method if available
                        if hasattr(hosts_file, '_add_preallocated_ip'):
                            hosts_file._add_preallocated_ip(ip, device_info)
                        else:
                            # Fallback method: add to ip_to_hostnames with 'preallocated' tag
                            hosts_file.ip_to_hostnames[ip] = ['preallocated']
                        status = "Added"
                    
                    scan_results[ip] = {
                        'mac': mac or 'Unknown',
                        'status': status,
                        'ports': ports
                    }
                
                # Store results in application config
                current_app.config['SCAN_RESULTS'] = scan_results
                
                # Update the hosts file
                _update_hosts_file(hosts_file)
            except Exception as e:
                logger.error(f"Error in scan thread: {e}")
        
        # Start the scan thread
        threading.Thread(target=scan_thread, daemon=True).start()
        
        # Redirect with message
        flash("Network scan started. This may take a few minutes.", "success")
        return redirect(url_for('routes.scan_network'))
    except Exception as e:
        logger.error(f"Error handling scan request: {e}")
        flash(f"Error starting network scan: {str(e)}", "error")
        return redirect(url_for('routes.scan_network'))


@routes.route('/scan-ports', methods=['POST'])
def scan_ports():
    """Scan for open ports on all known devices."""
    # Get hosts file from the app context
    hosts_file = current_app.config['HOSTS_FILE']
    
    if USE_PORT_DB:
        try:
            # Get all devices from the hosts file
            devices = []
            
            # Add static entries
            for mac, ip in hosts_file.mac_to_ip.items():
                devices.append(ip)
            
            # Add dynamic leases
            for mac, lease in hosts_file.leases.items():
                if not lease.is_expired():
                    devices.append(lease.ip_address)
            
            # Remove duplicates
            devices = list(set(devices))
            
            # Scan ports for all devices in a separate thread
            def scan_thread():
                try:
                    for ip in devices:
                        try:
                            # Run a fresh scan
                            scan_client_ports(ip)
                            logger.info(f"Port scan completed for {ip}")
                        except Exception as e:
                            logger.error(f"Error scanning ports for {ip}: {e}")
                except Exception as e:
                    logger.error(f"Error in port scan thread: {e}")
            
            # Start the scan thread
            threading.Thread(target=scan_thread, daemon=True).start()
            
            # If it's an HTMX request, return just the dashboard content
            if 'HX-Request' in request.headers:
                return dashboard_content()
            
            # Redirect with success message
            flash("Port scan started. Results will be updated as they become available.", "success")
            return redirect(url_for('routes.home'))
        except Exception as e:
            logger.error(f"Error starting port scan: {e}")
            flash(f"Error starting port scan: {str(e)}", "error")
            return redirect(url_for('routes.home'))
    else:
        flash("Port scanning requires database support", "error")
        
        # If it's an HTMX request
        if 'HX-Request' in request.headers:
            return dashboard_content()
        
        return redirect(url_for('routes.home'))


@routes.route('/settings', methods=['GET', 'POST'])
def settings():
    """Render the settings page."""
    # Get hosts file and network server from the app context
    hosts_file = current_app.config['HOSTS_FILE']
    network_server = current_app.config['NETWORK_SERVER']
    
    if request.method == 'POST':
        # Extract data from form
        dns_enabled = request.form.get('dns_enabled') == 'yes'
        dhcp_enabled = request.form.get('dhcp_enabled') == 'yes'
        
        # Only process these if DHCP is enabled
        dhcp_range_start = request.form.get('dhcp_range_start', '').strip()
        dhcp_range_end = request.form.get('dhcp_range_end', '').strip()
        subnet_mask = request.form.get('subnet_mask', '255.255.255.0').strip()
        router_ip = request.form.get('router_ip', '').strip()
        dns_servers_str = request.form.get('dns_servers', '8.8.8.8, 8.8.4.4')
        lease_time_str = request.form.get('lease_time', '86400')
        
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
            flash("Settings validation failed", "error")
            return render_template('settings.html', 
                                  dns_enabled=dns_enabled,
                                  dhcp_enabled=dhcp_enabled,
                                  dhcp_range_start=dhcp_range_start,
                                  dhcp_range_end=dhcp_range_end,
                                  subnet_mask=subnet_mask,
                                  router_ip=router_ip,
                                  dns_servers=dns_servers_str,
                                  lease_time=lease_time_str,
                                  errors=errors)
        
        # Settings look good, store them in a config file
        config = {
            'dns_enabled': dns_enabled,
            'dhcp_enabled': dhcp_enabled,
            'dhcp_range': [dhcp_range_start, dhcp_range_end] if dhcp_enabled else None,
            'subnet_mask': subnet_mask,
            'router_ip': router_ip,
            'dns_servers': [s.strip() for s in dns_servers_str.split(',') if s.strip()],
            'lease_time': int(lease_time_str)
        }
        
        # If we have access to the network server, update its settings directly
        if network_server:
            restart_needed = False
            
            # Update DNS settings
            if hasattr(network_server, 'dns_enable') and network_server.dns_enable != config['dns_enabled']:
                network_server.set_dns_enabled(config['dns_enabled'])
                restart_needed = True
            
            # Update DHCP range in hosts file
            if hasattr(hosts_file, 'dhcp_range') and hosts_file.dhcp_range != config['dhcp_range']:
                hosts_file.dhcp_range = config['dhcp_range']
                if config['dhcp_range']:
                    hosts_file._setup_dhcp_range(config['dhcp_range'])
                restart_needed = True
            
            # Update subnet mask
            if hasattr(network_server, 'dhcp_server') and network_server.dhcp_server and hasattr(network_server.dhcp_server, 'subnet_mask'):
                network_server.dhcp_server.subnet_mask = config['subnet_mask']
                restart_needed = True
            
            # Update router IP
            if hasattr(network_server, 'dhcp_server') and network_server.dhcp_server and hasattr(network_server.dhcp_server, 'router'):
                network_server.dhcp_server.router = config['router_ip']
                restart_needed = True
            
            # Update DNS servers
            if hasattr(network_server, 'dhcp_server') and network_server.dhcp_server and hasattr(network_server.dhcp_server, 'dns_servers'):
                network_server.dhcp_server.dns_servers = config['dns_servers']
                restart_needed = True
            
            # Update lease time
            if hasattr(network_server, 'dhcp_server') and network_server.dhcp_server and hasattr(network_server.dhcp_server, 'default_lease_time'):
                network_server.dhcp_server.default_lease_time = config['lease_time']
                restart_needed = True
            
            # Update DHCP enable status
            if hasattr(network_server, 'dhcp_enable') and network_server.dhcp_enable != config['dhcp_enabled']:
                restart_needed = True
            
            # If settings were changed that require restart
            if restart_needed:
                flash("Settings saved successfully. Some changes will take effect after restarting the server.", "success")
            else:
                flash("Settings saved successfully", "success")
        else:
            flash("Settings saved successfully", "success")
        
        return redirect(url_for('routes.home'))
    
    # GET request - display current settings
    # Default values or current configuration
    dhcp_range_start = ""
    dhcp_range_end = ""
    subnet_mask = "255.255.255.0"
    router_ip = ""
    dns_servers = "8.8.8.8, 8.8.4.4"
    lease_time = str(DEFAULT_LEASE_TIME)
    dhcp_enabled = True
    dns_enabled = True
    
    # Get values from the network server if available
    if network_server:
        # DNS enabled status
        dns_enabled = network_server.dns_enable if hasattr(network_server, 'dns_enable') else True
        
        if hasattr(network_server, 'dhcp_server') and network_server.dhcp_server:
            if hasattr(network_server.dhcp_server, 'subnet_mask'):
                subnet_mask = network_server.dhcp_server.subnet_mask
            
            if hasattr(network_server.dhcp_server, 'router'):
                router_ip = network_server.dhcp_server.router or ""
            
            if hasattr(network_server.dhcp_server, 'dns_servers'):
                dns_servers = ", ".join(network_server.dhcp_server.dns_servers) if network_server.dhcp_server.dns_servers else ""
            
            if hasattr(network_server.dhcp_server, 'lease_time'):
                lease_time = str(network_server.dhcp_server.lease_time)
        
        # DHCP range
        if hasattr(hosts_file, 'dhcp_range') and hosts_file.dhcp_range:
            dhcp_range_start, dhcp_range_end = hosts_file.dhcp_range
        
        # DHCP enabled status
        dhcp_enabled = network_server.dhcp_enable if hasattr(network_server, 'dhcp_enable') else True
    
    return render_template('settings.html',
                          dns_enabled=dns_enabled,
                          dhcp_enabled=dhcp_enabled,
                          dhcp_range_start=dhcp_range_start,
                          dhcp_range_end=dhcp_range_end,
                          subnet_mask=subnet_mask,
                          router_ip=router_ip,
                          dns_servers=dns_servers,
                          lease_time=lease_time)


# API Endpoints
@routes.route('/api/health-check', methods=['GET'])
def api_health_check():
    """API endpoint for health checks."""
    # Get network server from the app context
    network_server = current_app.config['NETWORK_SERVER']
    hosts_file = current_app.config['HOSTS_FILE']
    
    return jsonify({
        'status': 'ok',
        'dns_server': True if network_server and network_server.dns_server else False,
        'dhcp_server': True if network_server and network_server.dhcp_server else False,
        'web_ui': True,
        'hosts_file': True if hosts_file else False
    })
