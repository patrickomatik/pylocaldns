#!/usr/bin/env python3
"""
Web UI Network Scanning Module for the DNS/DHCP Network Server

This module provides methods for scanning the network and displaying the results.
"""

import threading
import logging
import re
from datetime import datetime
from webui_core import HTML_HEADER, HTML_FOOTER

# Try to import port database functions
try:
    from port_database import get_port_db
    USE_PORT_DB = True
except ImportError:
    USE_PORT_DB = False
    get_port_db = lambda: None

# Setup logging
logger = logging.getLogger('webui_scan')


def render_scan_page(self, message=None, message_type=None):
    """Render the network scan page."""
    content = HTML_HEADER

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
            <div class="flex justify-between items-center mb-4">
                <div>
                    <h1 class="mt-0">Network Scanner</h1>
                    <p class="mb-0 text-muted">Discover devices and prevent IP conflicts</p>
                </div>
            </div>
            
            <div class="card mb-4">
                <div class="card-header">
                    <h2 class="card-title"><i class="fas fa-search"></i> Scan Network</h2>
                </div>
                <div class="card-body">
                    <form method="post" action="/scan">
                        <p>This will scan the entire DHCP range for active devices. Discovered devices will be added to the 
                        configuration automatically. This process may take a few minutes depending on the size of your network.</p>
                        
                        <div class="form-group mb-0 text-center">
                            <button type="submit" class="btn btn-warning">
                                <i class="fas fa-search"></i> Start Network Scan
                            </button>
                            <a href="/" class="btn btn-plain">
                                <i class="fas fa-times"></i> Cancel
                            </a>
                        </div>
                    </form>
                </div>
            </div>
    """
    
    # Show previous scan results if available
    if hasattr(self, 'scan_results') and self.scan_results:
        content += """
            <div class="card">
                <div class="card-header">
                    <h2 class="card-title"><i class="fas fa-list"></i> Previous Scan Results</h2>
                    <div>
                        <span class="badge badge-info">{count} Devices</span>
                    </div>
                </div>
                <div class="card-body">
                    <table>
                        <thead>
                            <tr>
                                <th>IP Address</th>
                                <th>MAC Address</th>
                                <th>Status</th>
                                <th>Open Ports</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
        """.format(count=len(self.scan_results))
        
        for ip, data in self.scan_results.items():
            mac = data.get('mac', 'Unknown')
            status = data.get('status', 'Discovered')
            
            status_badge_class = {
                'Added': 'badge-success',
                'Already Configured': 'badge-info',
                'Pre-allocated': 'badge-warning'
            }.get(status, 'badge-secondary')
            
            status_badge = f'<span class="badge {status_badge_class}">{status}</span>'
            
            # Only show Edit button if we have a valid MAC address
            edit_button = ''
            if mac and mac != 'Unknown':
                edit_button = f'''
                <a href="/edit?mac={mac}" class="btn btn-sm btn-edit">
                    <i class="fas fa-edit"></i> Edit
                </a>'''
            
            # Get port information
            ports = data.get('ports', [])
            
            content += f"""
                            <tr>
                                <td><code>{ip}</code></td>
                                <td>
                                    <div class="flex items-center gap-2">
                                        <i class="fas fa-network-wired text-muted text-sm"></i>
                                        <span>{mac}</span>
                                        {self._format_vendor(mac) if hasattr(self, '_format_vendor') else ''}
                                    </div>
                                </td>
                                <td>{status_badge}</td>
                                <td>
                                    {self._format_ports(ports) if hasattr(self, '_format_ports') else ', '.join(map(str, ports)) if ports else '<span class="text-muted">None detected</span>'}
                                </td>
                                <td>
                                    {edit_button}
                                </td>
                            </tr>
            """
        
        content += """
                        </tbody>
                    </table>
                </div>
            </div>
        """
    
    content += "</div>" # Close content-container
    content += HTML_FOOTER
    return content.encode()


def handle_scan_request(self):
    """Handle a network scan request."""
    if not self.hosts_file or not self.hosts_file.dhcp_range:
        return self._send_error(400, "DHCP range not configured. Please set up a DHCP range in Settings first.")
    
    try:
        # Set up a place to store results for display
        self.scan_results = {}
        
        # Define progress callback to track scan progress
        def progress_callback(scanned, total):
            # Update the class-level scan_progress for display in subsequent page loads
            if not hasattr(self, 'scan_progress'):
                self.scan_progress = (0, 0)
            self.scan_progress = (scanned, total)
        
        # Start the scan in a new thread so we can return a response to the user
        def scan_thread():
            try:
                # Perform the scan
                discovered = self.hosts_file.scan_network()
                
                # Process results for display
                for ip, device_info in discovered.items():
                    status = "Discovered"
                    mac = device_info.get('mac')
                    ports = device_info.get('ports', [])
                    
                    # Check if it's already in our configuration
                    if ip in self.hosts_file.reserved_ips:
                        status = "Already Configured"
                    elif self.hosts_file.get_hostnames_for_ip(ip) and "preallocated" in self.hosts_file.get_hostnames_for_ip(ip):
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
                        
                        # Add to hosts file
                        self.hosts_file._add_preallocated_ip(ip, device_info)
                        status = "Added"
                    
                    self.scan_results[ip] = {
                        'mac': mac or 'Unknown',
                        'status': status,
                        'ports': ports
                    }
                
                # Update the hosts file on disk
                self._update_hosts_file()
                
                # Clear progress
                self.scan_progress = (0, 0)
            except Exception as e:
                logger.error(f"Error in scan thread: {e}")
        
        # Start the scan thread
        threading.Thread(target=scan_thread, daemon=True).start()
        
        # Redirect to the scan page with a message
        self._send_redirect('/scan?message=Network+scan+started.+This+may+take+a+few+minutes.&type=success')
    except Exception as e:
        logger.error(f"Error handling scan request: {e}")
        self._send_error(500, f"Error starting network scan: {str(e)}")
