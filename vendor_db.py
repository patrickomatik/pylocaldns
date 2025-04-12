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
import threading
from typing import Optional, Dict, List, Tuple

# Setup logging
logger = logging.getLogger('vendor_db')

# URLs for the MAC vendor database
# Primary URL (IEEE)
IEEE_OUI_URL = "https://standards-oui.ieee.org/oui/oui.txt"
# Backup URLs in case primary fails
BACKUP_URLS = [
    "https://gitlab.com/wireshark/wireshark/-/raw/master/manuf",
    "https://raw.githubusercontent.com/wireshark/wireshark/master/manuf"
]

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
        self.lock = threading.RLock()  # Thread lock for database access
        self.local_storage = threading.local()  # Thread-local storage for connections
        
        # Create or connect to the database
        self._ensure_db_exists()
        
        # Check if we need to update the database
        if auto_update and self._should_update_db():
            self.update_database()
    
    def _get_connection(self):
        """Get a thread-specific SQLite connection."""
        if not hasattr(self.local_storage, 'conn') or self.local_storage.conn is None:
            self.local_storage.conn = sqlite3.connect(self.db_path)
        return self.local_storage.conn
    
    def _ensure_db_exists(self) -> None:
        """Ensure the database file exists and has the correct schema."""
        with self.lock:
            try:
                conn = self._get_connection()
                cursor = conn.cursor()
                
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
                    
                    conn.commit()
            except sqlite3.Error as e:
                logger.error(f"Database error: {e}")
                raise
    
    def _should_update_db(self) -> bool:
        """Check if the database should be updated."""
        if not os.path.exists(self.db_path):
            return True
            
        try:
            with self.lock:
                conn = self._get_connection()
                cursor = conn.cursor()
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
        Update the database with the latest MAC vendor data.
        Tries multiple sources in case the primary source fails.
        
        Returns:
            True if update was successful, False otherwise
        """
        # List of URLs to try, starting with the primary
        urls_to_try = [IEEE_OUI_URL] + BACKUP_URLS
        
        for url_index, url in enumerate(urls_to_try):
            try:
                source_name = "IEEE" if url_index == 0 else f"backup source {url_index}"
                logger.info(f"Downloading MAC vendor database from {source_name}...")
                
                # Create a temporary file for downloading
                with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                    temp_path = temp_file.name
                
                # Download the file
                try:
                    # Add a user agent to avoid being blocked
                    headers = {'User-Agent': 'Mozilla/5.0 (compatible; PyLocalDNS/1.0)'}
                    req = urllib.request.Request(url, headers=headers)
                    with urllib.request.urlopen(req, timeout=30) as response:
                        with open(temp_path, 'wb') as out_file:
                            out_file.write(response.read())
                except Exception as download_error:
                    logger.warning(f"Failed to download from {source_name}: {download_error}")
                    try:
                        os.unlink(temp_path)  # Clean up the temp file
                    except:
                        pass
                    continue  # Try the next URL
                
                # Process the downloaded file
                if url_index == 0:  # IEEE format
                    vendors = self._parse_oui_file(temp_path)
                else:  # Wireshark format
                    vendors = self._parse_wireshark_file(temp_path)
                
                # Remove the temporary file
                os.unlink(temp_path)
                
                if not vendors:
                    logger.warning(f"Failed to parse file from {source_name} or no data found")
                    continue  # Try the next URL
                    
                logger.info(f"Parsed {len(vendors)} vendor entries from {source_name}")
                
                # Update the database
                timestamp = int(time.time())
                
                with self.lock:
                    conn = self._get_connection()
                    cursor = conn.cursor()
                    
                    # Begin transaction
                    conn.execute("BEGIN TRANSACTION")
                    
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
                        conn.commit()
                        logger.info(f"MAC vendor database updated successfully using {source_name}")
                        return True
                        
                    except Exception as e:
                        # Rollback on error
                        conn.rollback()
                        logger.error(f"Error updating vendor database from {source_name}: {e}")
                        continue  # Try the next URL
                    
            except Exception as e:
                logger.error(f"Error processing {source_name}: {e}")
                continue  # Try the next URL
        
        # If we get here, all sources failed
        logger.error("All sources failed when updating the MAC vendor database")
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
            
    def _parse_wireshark_file(self, file_path: str) -> Dict[str, str]:
        """
        Parse the Wireshark manuf file format.
        
        Args:
            file_path: Path to the downloaded Wireshark manuf file
            
        Returns:
            Dictionary mapping MAC prefixes to vendor names
        """
        vendors = {}
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                # Format examples from Wireshark manuf file:
                # 00:00:00	00:00:00	Officially Xerox, but 0:0:0:0:0:0 is more common
                # 00:00:01	00:00:01	SuperLAN-2U
                # 00:00:02	00:00:02	BBN (was internal usage only, no longer used)
                # ... or without the second column:
                # 00:00:0F	Digital Equipment Corporation
                # 00:00:10	Sytek
                
                # Skip comment lines and empty lines
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    # Split the line into parts
                    parts = line.split('\t')
                    
                    if len(parts) < 2:
                        continue
                    
                    # Extract MAC prefix and vendor name
                    mac_prefix = parts[0].lower()
                    
                    # Handle different formats
                    if len(parts) >= 3:
                        # Format with two MAC columns: prefix, mask, vendor
                        vendor_name = parts[2].strip()
                    else:
                        # Format with just one MAC column: prefix, vendor
                        vendor_name = parts[1].strip()
                    
                    # Convert to our standard format (xx:xx:xx)
                    mac_prefix = mac_prefix.replace('-', ':')
                    
                    # Skip full MAC addresses (we only want prefixes)
                    if mac_prefix.count(':') > 2:
                        continue
                    
                    # Skip masks and other non-standard entries
                    if '/' in mac_prefix or '::' in mac_prefix:
                        continue
                    
                    # Ensure we have a properly formatted MAC prefix (xx:xx:xx)
                    parts = mac_prefix.split(':')
                    if len(parts) < 3:
                        # Pad with zeros if needed
                        while len(parts) < 3:
                            parts.append('00')
                        mac_prefix = ':'.join(parts)
                    
                    vendors[mac_prefix] = vendor_name
                
            return vendors
        except Exception as e:
            logger.error(f"Error parsing Wireshark file: {e}")
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
            
            # Query the database using thread-local connection
            with self.lock:
                conn = self._get_connection()
                cursor = conn.cursor()
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
        with self.lock:
            if hasattr(self.local_storage, 'conn') and self.local_storage.conn:
                self.local_storage.conn.close()
                self.local_storage.conn = None
    
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
