#!/usr/bin/env python3
"""
Web UI Network Scanning Module for the DNS/DHCP Network Server

This module provides methods for scanning the network and displaying the results.
"""

import threading
import logging
import re
from webui_core import HTML_HEADER, HTML_FOOTER

# Setup logging
logger = logging.getLogger('webui_scan')


def render_scan_page(self, message=None, message_type=None):
    """Render the network scan page."""
    content = HTML_HEADER

    # Display message if any
    if message:
        content += f'<div class="message {message_type}">{message}</div>'

    content += """
        <h1>Network Scanner</h1>
        <p>Scan your network to discover devices and prevent IP conflicts</p>
        
        <form method="post" action="/scan">
            <p>This will scan the entire DHCP range for active devices. Discovered devices will be added to the 
            configuration automatically. This process may take a few minutes depending on the size of your network.</p>
            
            <div class="form-group">
                <button type="submit" class="btn btn-scan">Start Network Scan</button>
                <a href="/" class="btn" style="background-color: #777;">Cancel</a>
            </div>
        </form>
    """
    
    # Show previous scan results if available
    if hasattr(self, 'scan_results') and self.scan_results:
        content += """
            <h2>Previous Scan Results</h2>
            <table>
                <tr>
                    <th>IP Address</th>
                    <th>MAC Address</th>
                    <th>Status</th>
                    <th>Open Ports</th>
                    <th>Actions</th>
                </tr>
        """
        
        for ip, data in self.scan_results.items():
            mac = data.get('mac', 'Unknown')
            status = data.get('status', 'Discovered')
            
            status_badge = ''
            if status == 'Added':
                status_badge = '<span class="badge badge-success">Added</span>'
            elif status == 'Already Configured':
                status_badge = '<span class="badge badge-info">Already Configured</span>'
            elif status == 'Pre-allocated':
                status_badge = '<span class="badge badge-warning">Pre-allocated</span>'
            else:
                status_badge = '<span class="badge">Discovered</span>'
            
            # Only show Edit button if we have a valid MAC address
            edit_button = ''
            if mac and mac != 'Unknown':
                edit_button = f'<a href="/edit?mac={mac}" class="btn btn-edit">Edit</a>'
            
            # Get port information
            ports = data.get('ports', [])
            
            content += f"""
                <tr>
                    <td>{ip}</td>
                    <td>{mac}</td>
                    <td>{status_badge}</td>
                    <td>
                        {self._format_ports(ports)}
                    </td>
                    <td>
                        {edit_button}
                    </td>
                </tr>
            """
        
        content += "</table>"
    
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
