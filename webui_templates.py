#!/usr/bin/env python3
"""
Web UI HTML Templates

This module provides the HTML templates for the Web UI.
"""

# Import CSS styles
from webui_css import WEBUI_CSS

# HTML header template with CSS included
HTML_HEADER = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Server Admin</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" integrity="sha512-9usAa10IRO0HhonpyAIVpjrylPvoDwiPUiKdWk5t3PyolY1cOd4DSE0Ga+ri4AuTroPR5aQvXU9xC6qOPnzFeg==" crossorigin="anonymous" referrerpolicy="no-referrer" />
    <script src="https://unpkg.com/htmx.org@1.9.6"></script>
    <style>
{WEBUI_CSS}
    </style>
</head>
<body>
    <header class="nav">
        <div class="nav-container">
            <a href="/" class="nav-brand">
                <i class="fas fa-network-wired"></i>
                <span>PyLocalDNS</span>
            </a>
            <button class="nav-toggle">
                <i class="fas fa-bars"></i>
            </button>
            <ul class="nav-links">
                <li><a href="/" class="active"><i class="fas fa-tachometer-alt"></i> Dashboard</a></li>
                <li><a href="/add"><i class="fas fa-plus"></i> Add Entry</a></li>
                <li><a href="/scan"><i class="fas fa-search"></i> Scan Network</a></li>
                <li><a href="/settings"><i class="fas fa-cog"></i> Settings</a></li>
            </ul>
        </div>
    </header>
    <div class="container">
"""

# HTML footer template with JavaScript
HTML_FOOTER = """
    </div>
    <footer class="mt-5 mb-3 text-center text-muted text-sm">
        <p>PyLocalDNS - Lightweight DNS & DHCP Server</p>
    </footer>
    <script>
        // Mobile navigation toggle
        document.querySelector('.nav-toggle').addEventListener('click', function() {
            document.querySelector('.nav-links').classList.toggle('active');
        });
        
        // Set active nav link based on current page
        document.addEventListener('DOMContentLoaded', function() {
            const currentPath = window.location.pathname;
            const navLinks = document.querySelectorAll('.nav-links a');
            
            navLinks.forEach(link => {
                link.classList.remove('active');
                if (link.getAttribute('href') === currentPath) {
                    link.classList.add('active');
                } else if (currentPath === '/' && link.getAttribute('href') === '/') {
                    link.classList.add('active');
                }
            });
        });
        
        // Confirmation dialogs
        function confirmDelete(mac) {
            return confirm('Are you sure you want to delete the entry for MAC: ' + mac + '?');
        }
        
        // HTMX auto-refresh for dashboard
        document.addEventListener('DOMContentLoaded', function() {
            // Check if we're on the dashboard page
            if (window.location.pathname === '/') {
                // Set up auto-refresh every 10 seconds
                const dashboardContent = document.getElementById('dashboard-content');
                if (dashboardContent) {
                    setInterval(() => {
                        htmx.trigger('#dashboard-content', 'refresh');
                    }, 10000);
                }
            }
        });
    </script>
</body>
</html>
"""

# Message templates for various status messages
def render_message(message, message_type="info"):
    """Render a message with the appropriate styling."""
    if not message:
        return ""
        
    icon_class = {
        'success': 'fa-check-circle',
        'error': 'fa-exclamation-circle',
        'warning': 'fa-exclamation-triangle',
        'info': 'fa-info-circle'
    }.get(message_type, 'fa-info-circle')
    
    return f"""
    <div class="message {message_type}">
        <i class="fas {icon_class}"></i>
        <span>{message}</span>
    </div>
    """
