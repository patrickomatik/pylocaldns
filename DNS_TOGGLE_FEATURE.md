# DNS Service Toggle Feature

This document describes the implementation of the DNS service toggle feature in PyLocalDNS.

## Overview

The DNS service toggle feature allows users to enable or disable the DNS server functionality directly from the web interface. This is useful for:

1. Using PyLocalDNS as a DHCP-only server when another DNS server is present on the network
2. Temporarily disabling DNS services for testing or network changes
3. Configuring the application for different deployment scenarios

## Implementation

The feature was implemented with the following changes:

1. Modified the `NetworkServer` class to:
   - Add `dns_enable` property (default: True)
   - Add methods to start, stop, and toggle the DNS server
   - Update initialization to support disabling DNS by default
   - Add command-line flag for disabling DNS (`--dns-disable`)

2. Updated the settings UI to:
   - Add a DNS server enable/disable checkbox
   - Properly reflect the current state of the DNS service
   - Support updating the DNS service state

3. Enhanced the settings route handler to:
   - Extract and validate the DNS enable/disable setting
   - Update the DNS server state in real-time
   - Provide feedback to the user about the change

## Usage

### Web UI

1. Navigate to the Settings page
2. Under "Service Settings", you'll find an "Enable DNS Server" checkbox
3. Toggle the checkbox to enable or disable the DNS server
4. Click "Save Settings" to apply the changes

### Command Line

When starting the PyLocalDNS server from the command line, you can use the `--dns-disable` flag to start with the DNS service disabled:

```bash
python network_server_flask.py --hosts-file /path/to/hosts.txt --dns-disable
```

This will start the server with the DNS service disabled, while still allowing the DHCP service (if enabled) and Web UI to function normally.

## Technical Details

### Dynamic Service Management

The feature implements dynamic control of the DNS service which means:

1. The DNS server can be stopped and started without restarting the entire application
2. Changes take effect immediately after saving settings
3. The state is preserved across page refreshes and navigation within the web UI

### Implementation Classes

#### NetworkServer

The core functionality is implemented in the `NetworkServer` class with these methods:

- `start_dns_server()`: Initializes and starts the DNS server if enabled
- `stop_dns_server()`: Stops the running DNS server
- `set_dns_enabled(enabled)`: Changes the DNS server state based on the parameter

#### Flask Routes

The settings route in `flask_routes.py` handles:

1. Retrieving the current DNS server state
2. Receiving user input from the form
3. Applying changes to the server
4. Providing feedback to the user

## Behavior

When toggling the DNS service:

1. **Enabling**: The DNS server starts immediately and begins serving requests
2. **Disabling**: The DNS server stops immediately and no longer responds to DNS queries

## Compatibility

This feature is backward compatible with existing configurations and scripts. The default behavior remains the same (DNS enabled), and the feature only changes behavior when explicitly used.

## Future Enhancements

Potential future enhancements could include:

1. DNS forwarding options when the server is enabled
2. DNS service status indicators in the UI
3. DNS service statistics (query counts, response times, etc.)
4. More granular DNS configuration options
