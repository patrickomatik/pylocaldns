#!/usr/bin/env python3
"""
Test MAC Vendor Database functionality
"""

import os
import sys
import unittest
import sqlite3
import tempfile

# Add parent directory to the path so we can import modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vendor_db import VendorDB

class TestVendorDB(unittest.TestCase):
    """Test the VendorDB class."""

    def setUp(self):
        """Create a test database with some test data."""
        # Create a temporary database file
        self.temp_db = tempfile.NamedTemporaryFile(delete=False)
        self.temp_db.close()
        
        # Create a test database
        self.conn = sqlite3.connect(self.temp_db.name)
        cursor = self.conn.cursor()
        
        # Create tables
        cursor.execute('''
        CREATE TABLE vendors (
            mac_prefix TEXT PRIMARY KEY,
            vendor_name TEXT NOT NULL,
            last_updated INTEGER NOT NULL
        )
        ''')
        
        cursor.execute("CREATE INDEX idx_mac_prefix ON vendors(mac_prefix)")
        
        cursor.execute('''
        CREATE TABLE metadata (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
        ''')
        
        # Insert metadata
        cursor.execute("INSERT INTO metadata (key, value) VALUES ('last_updated', '1609459200')")
        
        # Insert some test data
        test_data = [
            ('00:11:22', 'Test Vendor 1', 1609459200),
            ('aa:bb:cc', 'Test Vendor 2', 1609459200),
            ('11:22:33', 'Test Vendor 3', 1609459200),
        ]
        
        cursor.executemany(
            "INSERT INTO vendors (mac_prefix, vendor_name, last_updated) VALUES (?, ?, ?)",
            test_data
        )
        
        self.conn.commit()
        self.conn.close()
        
        # Create the VendorDB instance with our test database
        self.db = VendorDB(db_path=self.temp_db.name, auto_update=False)

    def tearDown(self):
        """Clean up the test database."""
        self.db.close()
        os.unlink(self.temp_db.name)

    def test_lookup_vendor(self):
        """Test looking up vendors from the database."""
        # Test with exact OUI
        self.assertEqual(self.db.lookup_vendor('00:11:22:33:44:55'), 'Test Vendor 1')
        self.assertEqual(self.db.lookup_vendor('aa:bb:cc:dd:ee:ff'), 'Test Vendor 2')
        
        # Test with different format (dashes)
        self.assertEqual(self.db.lookup_vendor('00-11-22-33-44-55'), 'Test Vendor 1')
        
        # Test with different format (no separators)
        self.assertEqual(self.db.lookup_vendor('001122334455'), 'Test Vendor 1')
        
        # Test with uppercase
        self.assertEqual(self.db.lookup_vendor('00:11:22:33:44:55'.upper()), 'Test Vendor 1')
        
        # Test with unknown OUI
        self.assertIsNone(self.db.lookup_vendor('ff:ff:ff:ff:ff:ff'))
        
        # Test with invalid MAC
        self.assertIsNone(self.db.lookup_vendor('not a mac'))
        self.assertIsNone(self.db.lookup_vendor(''))
        self.assertIsNone(self.db.lookup_vendor(None))

    def test_normalize_mac(self):
        """Test normalizing MAC addresses."""
        # Test with normal MAC
        self.assertEqual(self.db._normalize_mac('00:11:22:33:44:55'), '00:11:22:33:44:55')
        
        # Test with dashes
        self.assertEqual(self.db._normalize_mac('00-11-22-33-44-55'), '00:11:22:33:44:55')
        
        # Test with no separators
        self.assertEqual(self.db._normalize_mac('001122334455'), '00:11:22:33:44:55')
        
        # Test with uppercase
        self.assertEqual(self.db._normalize_mac('00:11:22:33:44:55'.upper()), '00:11:22:33:44:55')
        
        # Test with invalid MAC
        self.assertIsNone(self.db._normalize_mac('not a mac'))
        self.assertIsNone(self.db._normalize_mac(''))
        self.assertIsNone(self.db._normalize_mac(None))


if __name__ == '__main__':
    unittest.main()
