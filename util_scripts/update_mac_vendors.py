#!/usr/bin/env python3
# This file should be made executable with: chmod +x update_mac_vendors.py
"""
MAC Vendor Database Update Utility

This script updates the MAC vendor database with the latest information from the IEEE.
It can be run manually or scheduled as a cron job to keep the database up to date.
"""

import os
import sys
import logging
import argparse
import tempfile
import time
import urllib.request

# Add parent directory to the path so we can import modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vendor_db import VendorDB

# Primary URL (IEEE)
IEEE_OUI_URL = "https://standards-oui.ieee.org/oui/oui.txt"
# Backup URLs in case primary fails
WIRESHARK_URLS = [
    "https://gitlab.com/wireshark/wireshark/-/raw/master/manuf",
    "https://raw.githubusercontent.com/wireshark/wireshark/master/manuf"
]

def custom_update(db, source):
    """Update the database from a specific source."""
    if source == 'ieee':
        print("Using IEEE database only...")
        success = update_from_ieee(db)
    elif source == 'wireshark':
        print("Using Wireshark database only...")
        success = update_from_wireshark(db)
    else:  # 'all'
        print("Trying all sources in order...")
        # Try IEEE first
        success = update_from_ieee(db)
        if not success:
            # Try Wireshark as backup
            print("IEEE source failed, trying Wireshark sources...")
            success = update_from_wireshark(db)
    
    return success

def update_from_ieee(db):
    """Update from IEEE database only."""
    try:
        # Create a temporary file for downloading
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_path = temp_file.name
        
        # Download the file
        print(f"Downloading from IEEE source: {IEEE_OUI_URL}...")
        
        # Add a user agent to avoid being blocked
        headers = {'User-Agent': 'Mozilla/5.0 (compatible; PyLocalDNS/1.0)'}
        req = urllib.request.Request(IEEE_OUI_URL, headers=headers)
        
        try:
            with urllib.request.urlopen(req, timeout=30) as response:
                with open(temp_path, 'wb') as out_file:
                    out_file.write(response.read())
        except Exception as e:
            print(f"Error downloading from IEEE: {e}")
            try:
                os.unlink(temp_path)  # Clean up temp file
            except:
                pass
            return False
        
        # Process the downloaded file
        vendors = db._parse_oui_file(temp_path)
        
        # Remove the temporary file
        try:
            os.unlink(temp_path)
        except:
            pass
        
        if not vendors:
            print("Failed to parse IEEE OUI file or no data found")
            return False
            
        print(f"Parsed {len(vendors)} vendor entries from IEEE database")
        
        # Update the database
        return update_database_with_vendors(db, vendors)
    
    except Exception as e:
        print(f"Error updating from IEEE: {e}")
        return False

def update_from_wireshark(db):
    """Update from Wireshark database only."""
    try:
        # Create a temporary file for downloading
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_path = temp_file.name
        
        # Try each Wireshark source
        success = False
        for i, url in enumerate(WIRESHARK_URLS):
            print(f"Trying Wireshark source #{i+1}: {url}...")
            
            # Add a user agent to avoid being blocked
            headers = {'User-Agent': 'Mozilla/5.0 (compatible; PyLocalDNS/1.0)'}
            req = urllib.request.Request(url, headers=headers)
            
            try:
                with urllib.request.urlopen(req, timeout=30) as response:
                    with open(temp_path, 'wb') as out_file:
                        out_file.write(response.read())
                success = True
                break
            except Exception as e:
                print(f"Error downloading from {url}: {e}")
                if i == len(WIRESHARK_URLS) - 1:
                    try:
                        os.unlink(temp_path)  # Clean up temp file
                    except:
                        pass
                    return False
                continue
        
        if not success:
            return False
        
        # Process the downloaded file
        vendors = db._parse_wireshark_file(temp_path)
        
        # Remove the temporary file
        try:
            os.unlink(temp_path)
        except:
            pass
        
        if not vendors:
            print("Failed to parse Wireshark file or no data found")
            return False
            
        print(f"Parsed {len(vendors)} vendor entries from Wireshark database")
        
        # Update the database
        return update_database_with_vendors(db, vendors)
    
    except Exception as e:
        print(f"Error updating from Wireshark: {e}")
        return False

def update_database_with_vendors(db, vendors):
    """Update the database with the given vendors."""
    try:
        timestamp = int(time.time())
        cursor = db.conn.cursor()
        
        # Begin transaction
        db.conn.execute("BEGIN TRANSACTION")
        
        try:
            # Clear existing data
            cursor.execute("DELETE FROM vendors")
            
            # Insert new data
            print(f"Adding {len(vendors)} vendor entries to database...")
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
            db.conn.commit()
            print("MAC vendor database updated successfully")
            return True
            
        except Exception as e:
            # Rollback on error
            db.conn.rollback()
            print(f"Error updating vendor database: {e}")
            return False
            
    except Exception as e:
        print(f"Error updating database: {e}")
        return False

def main():
    # Parse arguments
    parser = argparse.ArgumentParser(description='Update MAC vendor database')
    parser.add_argument('--force', action='store_true', 
                        help='Force update even if the database is up to date')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Enable verbose logging')
    parser.add_argument('--source', choices=['ieee', 'wireshark', 'all'], default='all',
                        help='Select the source to use (default: try all sources in order)')
    args = parser.parse_args()

    # Configure logging
    log_level = logging.INFO if args.verbose else logging.WARNING
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Initialize vendor database
    db = VendorDB(auto_update=False)
    
    # Check if we should update
    should_update = args.force or db._should_update_db()
    
    if should_update:
        print("Updating MAC vendor database...")
        success = custom_update(db, args.source)
        if success:
            print("MAC vendor database updated successfully!")
        else:
            print("Failed to update MAC vendor database. Check logs for details.")
            return 1
    else:
        print("MAC vendor database is up to date. Use --force to update anyway.")
    
    # Test the database
    print("\nTesting MAC vendor database:")
    test_macs = [
        '00:50:c2:00:00:00',  # IEEE Registration Authority
        '00:1A:11:00:00:00',  # Google
        '00:1B:63:00:00:00',  # Apple
        'F8:FF:C2:00:00:00',  # Samsung
        '00:25:9C:00:00:00',  # Cisco
        '00:50:BA:00:00:00',  # D-Link
        'AC:87:A3:00:00:00',  # Huawei
    ]
    
    for mac in test_macs:
        vendor = db.lookup_vendor(mac)
        print(f"MAC: {mac} => Vendor: {vendor or 'Unknown'}")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
