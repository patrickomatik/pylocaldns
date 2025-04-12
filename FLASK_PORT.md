# PyLocalDNS Flask Port

This document describes the Flask port implementation for PyLocalDNS, replacing the custom HTTP server with a more robust Flask-based web interface.

## Overview

The Flask port provides several advantages over the custom HTTP server:

1. Improved routing system using Flask's URL routing
2. Better template rendering with Jinja2
3. Flash messages for user feedback
4. Proper static file handling
5. Better error handling
6. HTMX integration for dynamic content updates
7. More maintainable code structure

## Implementation Files

- `app.py` - Main Flask application with routes and handlers
- `network_server_flask.py` - Network server implementation that integrates with Flask
- `templates/base_flask.html` - Base template for Flask UI
- `templates/home_flask.html` - Home page template for Flask UI
- `static/css/styles.css` - CSS styles extracted from the inline styles
- `static/js/scripts.js` - JavaScript functions

## Usage

To run the Flask-based server:

```bash
./run_flask_server.sh
```

This will start the server with default settings. Add `--debug` for debug logging:

```bash
./run_flask_server.sh --debug
```

## Command Line Options

The server supports the following command line options:

- `--hosts-file PATH` - Path to the hosts file (required)
- `--dns-port PORT` - DNS port to listen on (default: 53)
- `--dhcp-enable` - Enable DHCP server
- `--dhcp-range RANGE` - DHCP IP range (format: 192.168.1.100-192.168.1.200)
- `--dhcp-subnet MASK` - DHCP subnet mask (default: 255.255.255.0)
- `--dhcp-router IP` - DHCP default gateway/router IP
- `--dhcp-dns SERVERS` - DHCP DNS servers (comma-separated)
- `--dhcp-lease-time TIME` - DHCP lease time in seconds (default: 86400)
- `--webui-enable` - Enable web UI
- `--webui-port PORT` - Web UI port (default: 8080)
- `--api-enable` - Enable API server
- `--api-port PORT` - API server port (default: 8081)
- `--api-token TOKEN` - API authentication token
- `--interface INTERFACE` - Interface to bind to (default: 0.0.0.0)
- `--debug` - Enable debug logging

## Features

The Flask port maintains all features of the original web UI:

- View static DNS entries and DHCP leases
- Add, edit, and delete DNS entries
- Edit and release DHCP leases
- Scan the network for devices
- Configure DHCP settings
- Port scanning and display of open ports

Additional features in the Flask port:

- HTMX integration for auto-refreshing dashboard
- API endpoints for programmatic access
- Improved mobile responsiveness
- Better feedback with flash messages
- Proper handling of concurrent requests

## Architecture

The Flask port uses a modular architecture where:

1. `network_server_flask.py` handles the core DNS/DHCP functionality and lifecycle
2. `app.py` provides the web interface and API endpoints
3. Templates, CSS, and JavaScript are separated into their own files
4. Static file serving is handled by Flask's built-in server

## Migration Notes

When migrating from the custom HTTP server to Flask:

1. Templates now extend `base_flask.html` instead of `base.html`
2. URL generation uses `url_for()` instead of hardcoded paths
3. Inline styles have been moved to external CSS
4. Page refreshing uses HTMX instead of meta refresh
5. Form submissions use proper POST handling
