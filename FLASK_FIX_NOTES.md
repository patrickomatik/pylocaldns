# PyLocalDNS Flask Fix Notes

This document explains the changes made to fix the Flask implementation in PyLocalDNS.

## Issue Summary

The application was experiencing a routing error `Could not build url for endpoint 'home'` due to improper handling of Blueprint routes in the templates. The Flask routes were defined in a Blueprint named 'routes', but the templates were referencing the endpoints without the Blueprint prefix.

## Changes Made

1. Updated `base_flask.html`:
   - Fixed navigation links to use proper Blueprint-prefixed routes
   - Updated active page detection to use URL matching with `url_for()`

2. Updated content templates (`home_flask.html`, `home_content.html`):
   - Ensured all `url_for()` calls included the Blueprint name (e.g., `routes.home`)
   - Fixed HTMX links to use proper Blueprint routes

3. Updated form templates (`add.html`, `edit.html`, `edit_lease.html`, `settings.html`):
   - Updated form action URLs to use Blueprint-prefixed routes
   - Fixed cancel button links

4. Updated `scan.html` template:
   - Changed template extension from base.html to base_flask.html
   - Updated form actions to use Blueprint routes
   - Fixed action links to use proper Blueprint prefixes

5. Updated `error.html` template:
   - Fixed the extends clause to use base_flask.html directly instead of a variable
   - Updated the dashboard return link to use Blueprint prefixing

## Blueprint Routes

All routes in the application are defined in a Blueprint named 'routes'. This means that all URL generation using `url_for()` must include the Blueprint name as a prefix to the route name. For example:

```python
# Correct
url_for('routes.home')

# Incorrect - will cause "Could not build url for endpoint 'home'" error
url_for('home')
```

## URL Matching

The navigation active state detection was also updated to use URL comparison with `url_for()` instead of hardcoded paths:

```html
<!-- Correct -->
<a href="{{ url_for('routes.home') }}" class="{{ 'active' if request.path == url_for('routes.home') else '' }}">

<!-- Incorrect - will not detect active state correctly -->
<a href="{{ url_for('routes.home') }}" class="{{ 'active' if request.path == '/' else '' }}">
```

## HTMX Integration

HTMX endpoint URLs were also updated to use proper Blueprint route names:

```html
<!-- Correct -->
<div id="dashboard-content" hx-get="{{ url_for('routes.dashboard_content') }}" hx-trigger="every 10s">

<!-- Incorrect -->
<div id="dashboard-content" hx-get="/dashboard-content" hx-trigger="every 10s">
```

## Form Actions

Form action URLs were updated to use Blueprint-prefixed routes:

```html
<!-- Correct -->
<form method="post" action="{{ url_for('routes.add_entry') }}">

<!-- Incorrect -->
<form method="post" action="/add">
```

## Conclusion

These changes ensure that all URL generation in the application correctly uses the Blueprint prefix, preventing routing errors and ensuring proper functionality. The application should now be able to generate URLs correctly for all routes.
