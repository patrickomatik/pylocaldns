#!/usr/bin/env python3
"""
MAC Vendor Database

This module manages the SQLite database for mapping MAC address prefixes
to manufacturer names. It downloads and processes the official IEEE OUI
database to create local lookups.
"""

import os
import re
import sys
import sqlite3
import logging
import urllib.request
import tempfile
import time
from typing import Optional, Dict, List, Tuple

# Setup logging
logger = logging.getLogger('vendor_db')

# URL for the IEEE OUI (Organizationally Unique Identifier) database
IEEE_OUI_URL = "http://standards-oui.ieee.org/oui/oui.txt"

# Default database path relative to this file
DEFAULT_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'mac_vendors.db')

class VendorDB:
    """Manages the MAC vendor database."""
    
    def __init__(self, db_path: str = DEFAULT_DB_PATH, auto_update: bool = True):
        """
        Initialize the vendor database.
        
        Args:
            db_path: Path to the SQLite database file
            auto_update: Whether to automatically update the database if it's missing or older than 30 days
        """
        self.db_path = db_path
        self.conn = None
        
        # Create or connect to the database
        self._ensure_db_exists()
        
        # Check if we need to update the database
        if auto_update and self._should_update_db():
            self.update_database()
    
    def _ensure_db_exists(self) -> None:
        """Ensure the database file exists and has the correct schema."""
        try:
            self.conn = sqlite3.connect(self.db_path)
            cursor = self.conn.cursor()
            
            # Check if the vendors table exists
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='vendors'")
            table_exists = cursor.fetchone() is not None
            
            if not table_exists:
                logger.info(f"Creating new MAC vendor database at {self.db_path}")
                # Create the table
                cursor.execute('''
                CREATE TABLE vendors (
                    mac_prefix TEXT PRIMARY KEY,
                    vendor_name TEXT NOT NULL,
                    last_updated INTEGER NOT NULL
                )
                ''')
                
                # Create index on mac_prefix for fast lookups
                cursor.execute("CREATE INDEX idx_mac_prefix ON vendors(mac_prefix)")
                
                # Create metadata table for tracking database info
                cursor.execute('''
                CREATE TABLE metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
                ''')
                
                # Initialize metadata
                timestamp = int(time.time())
                cursor.execute(
                    "INSERT INTO metadata (key, value) VALUES (?, ?)",
                    ("last_updated", str(timestamp))
                )
                
                self.conn.commit()
        except sqlite3.Error as e:
            logger.error(f"Database error: {e}")
            if self.conn:
                self.conn.close()
                self.conn = None
            raise
    
    def _should_update_db(self) -> bool:
        """Check if the database should be updated."""
        if not os.path.exists(self.db_path):
            return True
            
        try:
            cursor = self.conn.cursor()
            cursor.execute("SELECT value FROM metadata WHERE key='last_updated'")
            result = cursor.fetchone()
            
            if not result:
                return True
                
            last_updated = int(result[0])
            current_time = int(time.time())
            
            # Update if older than 30 days
            return (current_time - last_updated) > (30 * 24 * 60 * 60)
            
        except (sqlite3.Error, ValueError) as e:
            logger.warning(f"Error checking database update status: {e}")
            return True
    
    def update_database(self) -> bool:
        """
        Update the database with the latest IEEE OUI data.
        
        Returns:
            True if update was successful, False otherwise
        """
        try:
            logger.info("Downloading latest MAC vendor database from IEEE...")
            
            # Create a temporary file for downloading
            with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                temp_path = temp_file.name
            
            # Download the OUI file
            urllib.request.urlretrieve(IEEE_OUI_URL, temp_path)
            
            # Process the downloaded file
            vendors = self._parse_oui_file(temp_path)
            
            # Remove the temporary file
            os.unlink(temp_path)
            
            if not vendors:
                logger.error("Failed to parse IEEE OUI file or no data found")
                return False
                
            logger.info(f"Parsed {len(vendors)} vendor entries from IEEE database")
            
            # Update the database
            timestamp = int(time.time())
            cursor = self.conn.cursor()
            
            # Begin transaction
            self.conn.execute("BEGIN TRANSACTION")
            
            try:
                # Clear existing data
                cursor.execute("DELETE FROM vendors")
                
                # Insert new data
                for mac_prefix, vendor_name in vendors.items():
                    cursor.execute(
                        "INSERT INTO vendors (mac_prefix, vendor_name, last_updated) VALUES (?, ?, ?)",
                        (mac_prefix, vendor_name, timestamp)
                    )
                
                # Update metadata
                cursor.execute(
                    "UPDATE metadata SET value = ? WHERE key = 'last_updated'",
                    (str(timestamp),)
                )
                
                # Commit changes
                self.conn.commit()
                logger.info("MAC vendor database updated successfully")
                return True
                
            except Exception as e:
                # Rollback on error
                self.conn.rollback()
                logger.error(f"Error updating vendor database: {e}")
                return False
                
        except Exception as e:
            logger.error(f"Error updating vendor database: {e}")
            return False
    
    def _parse_oui_file(self, file_path: str) -> Dict[str, str]:
        """
        Parse the IEEE OUI file format.
        
        Args:
            file_path: Path to the downloaded OUI file
            
        Returns:
            Dictionary mapping MAC prefixes to vendor names
        """
        vendors = {}
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                # Regular expression to match OUI entries
                # Format: 00-50-C2   (hex)		IEEE Registration Authority
                pattern = re.compile(r'^([0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2})\s+\(hex\)\s+(.+)$')
                
                for line in f:
                    match = pattern.match(line.strip())
                    if match:
                        mac_prefix = match.group(1).replace('-', ':').lower()
                        vendor_name = match.group(2).strip()
                        vendors[mac_prefix] = vendor_name
                        
            return vendors
        except Exception as e:
            logger.error(f"Error parsing OUI file: {e}")
            return {}
    
    def lookup_vendor(self, mac_address: str) -> Optional[str]:
        """
        Look up the vendor name for a MAC address.
        
        Args:
            mac_address: MAC address to look up (any format)
            
        Returns:
            Vendor name if found, None otherwise
        """
        if not mac_address:
            return None
            
        try:
            # Normalize MAC address format
            mac = self._normalize_mac(mac_address)
            if not mac:
                return None
                
            # Extract the OUI (first 3 bytes)
            oui = ':'.join(mac.split(':')[:3])
            
            # Query the database
            cursor = self.conn.cursor()
            cursor.execute("SELECT vendor_name FROM vendors WHERE mac_prefix = ?", (oui,))
            result = cursor.fetchone()
            
            return result[0] if result else None
            
        except Exception as e:
            logger.error(f"Error looking up vendor for MAC {mac_address}: {e}")
            return None
    
    def _normalize_mac(self, mac_address: str) -> Optional[str]:
        """
        Normalize a MAC address to a standard format.
        
        Args:
            mac_address: MAC address in any format
            
        Returns:
            Normalized MAC address (xx:xx:xx:xx:xx:xx format) or None if invalid
        """
        if not mac_address:
            return None
            
        # Remove any non-hex characters
        mac = re.sub(r'[^0-9a-fA-F]', '', mac_address)
        
        # Check if we have a valid MAC address
        if len(mac) != 12:
            return None
            
        # Convert to xx:xx:xx:xx:xx:xx format
        return ':'.join([mac[i:i+2].lower() for i in range(0, 12, 2)])
    
    def close(self) -> None:
        """Close the database connection."""
        if self.conn:
            self.conn.close()
            self.conn = None
    
    def __del__(self) -> None:
        """Destructor to ensure the database connection is closed."""
        self.close()


# Simple command-line interface for testing
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    db = VendorDB()
    
    if len(sys.argv) > 1:
        if sys.argv[1] == '--update':
            db.update_database()
        else:
            # Lookup a MAC address
            vendor = db.lookup_vendor(sys.argv[1])
            if vendor:
                print(f"Vendor: {vendor}")
            else:
                print("Vendor not found")
    else:
        print("Usage:")
        print("  vendor_db.py <mac_address>   Look up a MAC address vendor")
        print("  vendor_db.py --update        Update the vendor database")
