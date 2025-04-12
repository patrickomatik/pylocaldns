"""
Network scanning functionality for the Web UI

This code should be added to the WebUIHandler class in webui.py
"""

def _render_scan_page(self, message=None, message_type=None):
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
            
            content += f"""
                <tr>
                    <td>{ip}</td>
                    <td>{mac}</td>
                    <td>{status_badge}</td>
                    <td>
                        <a href="/edit?mac={mac}" class="btn btn-edit">Edit</a>
                    </td>
                </tr>
            """
        
        content += "</table>"
    
    content += HTML_FOOTER
    return content.encode()

def _handle_scan_request(self):
    """Handle a network scan request."""
    if not self.hosts_file or not self.hosts_file.dhcp_range:
        return self._send_error(400, "DHCP range not configured. Please set up a DHCP range in Settings first.")
    
    try:
        # Set up a place to store results for display
        scan_results = {}
        
        # Define progress callback to track scan progress
        def progress_callback(scanned, total):
            # Update the class-level scan_results for display in subsequent page loads
            if hasattr(self, 'scan_progress'):
                self.scan_progress = (scanned, total)
        
        # Start the scan in a new thread so we can return a response to the user
        def scan_thread():
            try:
                discovered = self.hosts_file.scan_network()
                
                # Process results for display
                for ip, mac in discovered.items():
                    status = "Discovered"
                    
                    # Check if it's already in our configuration
                    if ip in self.hosts_file.reserved_ips:
                        status = "Already Configured"
                    elif "preallocated" in self.hosts_file.get_hostnames_for_ip(ip):
                        status = "Pre-allocated"
                    else:
                        # This is a newly added device
                        status = "Added"
                    
                    scan_results[ip] = {
                        'mac': mac or 'Unknown',
                        'status': status
                    }
                
                # Store results for display
                self.scan_results = scan_results
                self.scan_progress = (0, 0)  # Clear progress
            except Exception as e:
                logger.error(f"Error in scan thread: {e}")
        
        # Start the scan thread
        threading.Thread(target=scan_thread, daemon=True).start()
        
        # Redirect to the scan page with a message
        self._send_redirect('/scan?message=Network+scan+started.+This+may+take+a+few+minutes.&type=success')
    except Exception as e:
        logger.error(f"Error handling scan request: {e}")
        self._send_error(500, f"Error starting network scan: {str(e)}")

"""
In the do_GET method, add:

elif path == '/scan':
    content = self._render_scan_page(
        message=query.get('message', [''])[0] if 'message' in query else None,
        message_type=query.get('type', [''])[0] if 'type' in query else None
    )
    self._send_response(content)

In the do_POST method, add:

elif self.path == '/scan':
    self._handle_scan_request()
"""
