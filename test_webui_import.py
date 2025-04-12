#!/usr/bin/env python3
"""Test script to verify that the refactored webui module can be imported."""

import sys
import os

# Add the project directory to the path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Try to import the WebUIServer from the webui module
try:
    from webui import WebUIServer
    print("Successfully imported WebUIServer from webui module")
except ImportError as e:
    print(f"Error importing WebUIServer: {e}")
    sys.exit(1)

print("All imports successful!")
