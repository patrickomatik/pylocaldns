# PyLocalDNS Flask Templates

This document provides information about the templates used in the Flask implementation of PyLocalDNS.

## Base Template

`base_flask.html` - The main base template that all other templates extend. It includes:

- HTML structure with proper meta tags
- CSS and JavaScript imports
- Navigation bar with links to main sections
- Flash message handling
- Footer

## Page Templates

The following templates are used for specific pages in the application:

1. `home_flask.html` - The main dashboard page
   - Shows static DNS entries
   - Shows DHCP leases
   - Provides links to add entries and scan the network
   - Uses HTMX for automatic content refresh

2. `home_content.html` - The content portion of the dashboard
   - Designed to be loaded via HTMX for partial page updates
   - Contains tables of static entries and DHCP leases
   - Includes network tools section

3. `add.html` - Form for adding new DNS/DHCP entries
   - Fields for MAC address, IP address, and hostnames
   - Validation feedback for any input errors

4. `edit.html` - Form for editing existing DNS entries
   - Pre-filled with current values
   - MAC address is displayed but not editable

5. `edit_lease.html` - Form for editing DHCP leases
   - Allows changing IP, hostname, and lease time
   - Option to convert a dynamic lease to a static entry

6. `scan.html` - Network scanning interface
   - Button to initiate a network scan
   - Displays results of previous scans
   - Shows discovered devices with their status

7. `settings.html` - DHCP and network configuration
   - Toggle for enabling/disabling DHCP
   - Fields for DHCP range, subnet mask, router, etc.
   - Save button to apply changes

8. `error.html` - Error page template
   - Displays error code and message
   - Link to return to the dashboard

## URL Generation

All templates use Flask's `url_for()` function to generate URLs, ensuring that:

1. Links are always correct even if the URL structure changes
2. Blueprint prefixes are properly included
3. Active state of navigation links is correctly detected

Example:
```html
<a href="{{ url_for('routes.home') }}" class="{{ 'active' if request.path == url_for('routes.home') else '' }}">
```

## HTMX Integration

The templates use HTMX for dynamic content updates:

- The dashboard automatically refreshes every 10 seconds
- Port scanning updates the dashboard content without a full page reload
- Loading indicators show during operations

Example:
```html
<div id="dashboard-content" hx-get="{{ url_for('routes.dashboard_content') }}" hx-trigger="every 10s" hx-swap="innerHTML">
```

## Styling

All templates use external CSS from `static/css/styles.css`, providing:

- Consistent color scheme and typography
- Responsive layout for desktop and mobile
- Card-based design for content sections
- Form styling with clear labels and feedback
- Table styling for data display

## JavaScript

The templates include JavaScript from `static/js/scripts.js`, which provides:

- Mobile navigation toggle
- Confirmation dialogs for delete actions
- Dashboard refresh functionality

## Customization

To customize the appearance:

1. Modify `static/css/styles.css` to change colors, spacing, etc.
2. Update the templates directly to change layout or content
3. Add new JavaScript functions to `static/js/scripts.js` for behavior

## Form Handling

All forms use proper `method="post"` and Blueprint-prefixed action URLs:

```html
<form method="post" action="{{ url_for('routes.add_entry') }}">
```

This ensures that form submissions are handled by the correct route handler.
