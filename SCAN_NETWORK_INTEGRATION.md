# Network Scanning Integration

This document describes the integration of the network scanning functionality in the PyLocalDNS WebUI.

## Overview

The network scanning feature allows users to discover devices on their local network from the WebUI. The feature is integrated through several components:

1. `webui_scan.py` - Contains the core scanning functionality
2. `webui.py` - Imports and connects the scanning functions
3. `ip_utils.py` - Provides the low-level network scanning utilities

## Key Components

### WebUI Integration

The scan network feature is accessible through:

- **UI Button**: Available on the home page
- **Scan Page**: `/scan` route displays scan form and results
- **Scan Request**: POST to `/scan` initiates the scan process

### Scan Implementation

The scan process uses `scan_network_async` from `ip_utils.py`, which provides:

- Multi-threaded scanning for performance
- IP range scanning using start and end addresses
- Progress callback for UI feedback
- Port scanning to detect open services
- MAC address discovery
- Port database integration for persistent storage

### Port Database Integration

The scan process also integrates with the port database when available:

- Discovered ports are stored in the database
- MAC address and device information is persisted
- Historical port data is preserved
- Services are identified based on port numbers

## Usage

1. Navigate to the `/scan` page from the UI
2. Click "Start Network Scan" to begin the scanning process
3. The scan will run in the background and display results when complete
4. Discovered devices will be added to the configuration as pre-allocated entries

## Code Structure

```
webui.py
  └─ Imports and connects WebUIHandler with scan functions
     └─ WebUIHandler._render_scan_page = render_scan_page
     └─ WebUIHandler._handle_scan_request = handle_scan_request

webui_scan.py
  ├─ render_scan_page() - Renders the scan page UI
  └─ handle_scan_request() - Processes scan requests
     └─ Uses scan_network_async() to perform the actual scan
     
ip_utils.py
  ├─ scan_network_async() - Performs network scanning asynchronously
  ├─ scan_client_ports() - Checks for open ports on a specific device
  ├─ is_ip_in_use() - Checks if an IP address is active on the network
  └─ get_mac_from_arp() - Retrieves MAC address for an IP
```

## Testing

The integration includes comprehensive tests:

- `tests/test_webui_scan_routes.py` tests the WebUI routes for network scanning
- `tests/run_webui_scan_tests.sh` script runs the tests

The tests verify:
- The scan page renders correctly
- The scan process works as expected
- Results are shown properly in the UI

## Troubleshooting

Common issues and solutions:

1. **Scan doesn't find devices**: Ensure DHCP range is properly configured
2. **Port data not showing**: Check if port database is enabled
3. **MAC addresses not found**: System may require root privileges for ARP lookups
4. **Scan taking too long**: Adjust the scan range to a smaller subset of IPs
