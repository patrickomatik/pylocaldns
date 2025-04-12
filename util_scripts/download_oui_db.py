#!/usr/bin/env python3
"""
OUI Database Downloader

This script downloads the latest OUI (Organizationally Unique Identifier) database
from the IEEE website and processes it into our local vendor database.
"""

import os
import sys
import logging

# Add parent directory to Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import the vendor database module
from vendor_db import VendorDB

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('download_oui_db')

def main():
    """Download and process the IEEE OUI database."""
    try:
        logger.info("Starting OUI database download and processing...")
        
        # Initialize the vendor database
        db = VendorDB(auto_update=False)
        
        # Update the database
        success = db.update_database()
        
        if success:
            logger.info("OUI database successfully updated")
        else:
            logger.error("Failed to update OUI database")
            return 1
            
        # Close the database connection
        db.close()
        
        return 0
        
    except Exception as e:
        logger.error(f"Error: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
