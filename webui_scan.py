#!/usr/bin/env python3
"""
Web UI Network Scanning Module

This module provides functions for rendering scan pages and handling scan requests.
"""

import logging
import threading
from urllib.parse import parse_qs, urlparse
from webui_templates import HTML_HEADER, HTML_FOOTER, render_message

# Setup logging
logger = logging.getLogger('webui_scan')

# Try to import scanning utilities
try:
    from network_scanner import scan_network_async
    from port_scanner import scan_client_ports
    from port_database import get_port_db
    USE_PORT_DB = True
except ImportError:
    # Use fallback scanning
    USE_PORT_DB = False
    from ip_utils import scan_network_async, scan_client_ports
    get_port_db = lambda: None
    logger.warning("Using fallback scanning utilities")


def render_scan_page(handler):
    """Render the network scan page."""
    # Parse query parameters for message display
    message = None
    message_type = "info"
    
    if "?" in handler.path:
        query = parse_qs(handler.path.split("?")[1])
        message = query.get("message", [""])[0]
        message_type = query.get("type", ["info"])[0]
    
    # Get scan results if available
    scan_results = {}
    if hasattr(handler, 'scan_results'):
        scan_results = handler.scan_results
    
    content = HTML_HEADER
    
    # Add message if any
    if message:
        content += render_message(message, message_type)
    
    # Add scan instructions and form
    content += """
    <div class="content-container mb-4">
        <h1>Network Scanner</h1>
        <p class="mb-3">
            Scan your network to discover devices and automatically add them to the configuration.
            This helps prevent IP conflicts and makes it easier to configure your network.
        </p>
        
        <form method="post" action="/scan">
            <button type="submit" class="btn btn-primary">
                <i class="fas fa-search"></i> Start Network Scan
            </button>
        </form>
    </div>
    """
    
    # Add scan results if available
    if scan_results:
        content += """
        <div class="content-container">
            <h2>Scan Results</h2>
            <table>
                <thead>
                    <tr>
                        <th>IP Address</th>
                        <th>MAC Address</th>
                        <th>Status</th>
                        <th>Open Ports</th>
                    </tr>
                </thead>
                <tbody>
        """
        
        # Add each scan result
        for ip, info in sorted(scan_results.items()):
            mac = info.get('mac', 'Unknown')
            status = info.get('status', 'Discovered')
            ports = info.get('ports', [])
            
            # Format the MAC address vendor information
            vendor_badge = handler._format_vendor(mac)
            
            # Format the ports information
            ports_display = handler._format_ports(ports)
            
            # Determine status badge class
            status_class = {
                'Discovered': 'badge-info',
                'Already Configured': 'badge-success',
                'Pre-allocated': 'badge-warning',
                'Added': 'badge-primary'
            }.get(status, 'badge-info')
            
            content += f"""
            <tr>
                <td>{ip}</td>
                <td>{mac}{vendor_badge}</td>
                <td><span class="badge {status_class}">{status}</span></td>
                <td>{ports_display}</td>
            </tr>
            """
        
        content += """
                </tbody>
            </table>
            
            <div class="mt-4">
                <p>
                    <strong>Note:</strong> Newly discovered devices are automatically pre-allocated in your configuration
                    to prevent IP conflicts. You can edit these entries as needed.
                </p>
                <a href="/" class="btn btn-primary mt-3">
                    <i class="fas fa-arrow-left"></i> Return to Dashboard
                </a>
            </div>
        </div>
        """
    
    content += HTML_FOOTER
    handler._send_response(content.encode())


def handle_scan_request(handler):
    """Handle a request to scan the network."""
    if not handler.hosts_file or not handler.hosts_file.dhcp_range:
        handler._send_redirect("/scan?message=DHCP+range+not+configured.+Please+set+up+a+DHCP+range+in+Settings+first.&type=error")
        return
    
    try:
        # Start the scan in a new thread so we can return a response to the user
        def scan_thread():
            try:
                # Get the DHCP range for scanning
                if not handler.hosts_file.dhcp_range or len(handler.hosts_file.dhcp_range) != 2:
                    logger.error("Invalid DHCP range")
                    return
                    
                ip_range = tuple(handler.hosts_file.dhcp_range)
                
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
                    if handler.hosts_file.get_ip_for_mac(mac) == ip if mac else False:
                        status = "Already Configured"
                    elif handler.hosts_file.get_hostnames_for_ip(ip) and "preallocated" in handler.hosts_file.get_hostnames_for_ip(ip):
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
                        if hasattr(handler.hosts_file, '_add_preallocated_ip'):
                            handler.hosts_file._add_preallocated_ip(ip, device_info)
                        else:
                            # Fallback method: add to ip_to_hostnames with 'preallocated' tag
                            handler.hosts_file.ip_to_hostnames[ip] = ['preallocated']
                        status = "Added"
                    
                    scan_results[ip] = {
                        'mac': mac or 'Unknown',
                        'status': status,
                        'ports': ports
                    }
                
                # Store results for display
                handler.scan_results = scan_results
                
                # Update the hosts file
                handler._update_hosts_file()
            except Exception as e:
                logger.error(f"Error in scan thread: {e}")
        
        # Start the scan thread
        threading.Thread(target=scan_thread, daemon=True).start()
        
        # Redirect with message
        handler._send_redirect("/scan?message=Network+scan+started.+This+may+take+a+few+minutes.&type=success")
    except Exception as e:
        logger.error(f"Error handling scan request: {e}")
        handler._send_redirect(f"/scan?message=Error+starting+network+scan:+{str(e)}&type=error")


def handle_scan_ports_request(handler):
    """Handle a request to scan ports on all known devices."""
    if USE_PORT_DB:
        try:
            # Get all devices from the hosts file
            devices = []
            
            # Add static entries
            for mac, ip in handler.hosts_file.mac_to_ip.items():
                devices.append(ip)
            
            # Add dynamic leases
            for mac, lease in handler.hosts_file.leases.items():
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
            
            # Redirect with success message
            handler._send_redirect("/?message=Port+scan+started.+Results+will+be+updated+as+they+become+available.&type=success")
        except Exception as e:
            logger.error(f"Error starting port scan: {e}")
            handler._send_redirect(f"/?message=Error+starting+port+scan:+{str(e)}&type=error")
    else:
        handler._send_redirect("/?message=Port+scanning+requires+database+support&type=error")
