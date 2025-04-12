#!/usr/bin/env python3
"""
Web UI Module for the DNS/DHCP Network Server

This module provides a simple web interface for:
- Viewing MAC addresses, allocated IPs, and DNS names
- Editing DNS names for devices
- Adding new static entries
- Managing DHCP leases
- Configuring DHCP and network settings
- Scanning the network for devices
"""

import logging
import re
from typing import Dict, Any, List

# Import core components
from webui_core import WebUIHandler, WebUIServer

# Import page rendering methods
from webui_pages import (
    render_home_page, render_edit_page, render_edit_lease_page,
    render_add_page, render_settings_page, render_edit_page_with_data,
    render_add_page_with_data, render_edit_lease_page_with_data
)

# Import network scanning functionality
from webui_scan import render_scan_page, handle_scan_request

# Import request handlers
from webui_handlers import do_GET, do_POST

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('webui')

# Add the request handlers to the WebUIHandler class
WebUIHandler.do_GET = do_GET
WebUIHandler.do_POST = do_POST

# Add page rendering methods to the WebUIHandler class
WebUIHandler._render_home_page = render_home_page
WebUIHandler._render_edit_page = render_edit_page
WebUIHandler._render_edit_page_with_data = render_edit_page_with_data
WebUIHandler._render_add_page = render_add_page
WebUIHandler._render_add_page_with_data = render_add_page_with_data
WebUIHandler._render_edit_lease_page = render_edit_lease_page
WebUIHandler._render_edit_lease_page_with_data = render_edit_lease_page_with_data
WebUIHandler._render_settings_page = render_settings_page

# Add network scanning methods to the WebUIHandler class
WebUIHandler._render_scan_page = render_scan_page
WebUIHandler._handle_scan_request = handle_scan_request

# Export the WebUIServer class for use by external modules
__all__ = ['WebUIServer']
