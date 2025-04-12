# PyLocalDNS Flask API Endpoints

This document describes the API endpoints available in the Flask port of PyLocalDNS.

## Web UI Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Home page with dashboard |
| `/dashboard-content` | GET | Dashboard content for HTMX updates |
| `/add` | GET/POST | Add a new DNS/DHCP entry |
| `/edit` | GET | Edit an existing DNS/DHCP entry |
| `/update` | POST | Update an existing DNS/DHCP entry |
| `/delete` | GET | Delete a DNS/DHCP entry |
| `/edit-lease` | GET | Edit a DHCP lease |
| `/update-lease` | POST | Update a DHCP lease |
| `/delete-lease` | GET | Delete a DHCP lease |
| `/scan` | GET/POST | Scan the network for devices |
| `/scan-ports` | POST | Scan for open ports on all known devices |
| `/settings` | GET/POST | Configure DHCP settings |

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/refresh-dashboard` | GET | Refresh the dashboard content |
| `/api/health-check` | GET | Check the health of the server |

## Common URL Parameters

These parameters are used across multiple endpoints:

- `mac` - MAC address for device identification (used in edit, delete, edit-lease, delete-lease)
- `message` - Message to display to the user (used in home, scan)
- `type` - Type of message (info, success, error, warning) (used in home, scan)

## Example API Usage

### Health Check

```bash
curl http://localhost:8080/api/health-check
```

Response:
```json
{
  "status": "ok",
  "dns_server": true,
  "dhcp_server": true,
  "web_ui": true,
  "hosts_file": true
}
```

### Refresh Dashboard

```bash
curl http://localhost:8080/api/refresh-dashboard
```

Response: HTML content of the dashboard

## HTMX Integration

The Flask port includes HTMX integration for dynamic content updates without full page reloads.

HTMX attributes used:
- `hx-get`: Performs a GET request to the specified URL
- `hx-post`: Performs a POST request to the specified URL
- `hx-trigger`: Defines when the request should be triggered
- `hx-target`: Defines the element to update with the response
- `hx-swap`: Defines how to swap the response content
- `hx-indicator`: Defines a loading indicator

Example HTMX usage in the dashboard:
```html
<div id="dashboard-content" 
     hx-get="/dashboard-content" 
     hx-trigger="every 10s" 
     hx-swap="innerHTML">
  <!-- Dashboard content -->
</div>
```

This automatically refreshes the dashboard content every 10 seconds without reloading the entire page.
