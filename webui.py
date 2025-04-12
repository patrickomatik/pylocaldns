#!/usr/bin/env python3
"""
Web UI Integration Module for the DNS/DHCP Network Server

This module provides the main entry point for the Web UI.
"""

import logging

# Import refactored modules
from webui_core import WebUIHandler, WebUIServer
from webui_models import DNSRecord
from webui_templates import HTML_HEADER, HTML_FOOTER, render_message
import webui_home
import webui_edit
import webui_handlers
import webui_scan
import webui_settings

# Setup logging
logger = logging.getLogger('webui')

# Export the WebUIServer class for use by external modules
__all__ = ['WebUIServer']

# Set version
__version__ = '1.0.0'
