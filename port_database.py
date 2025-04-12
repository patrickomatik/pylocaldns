#!/usr/bin/env python3
"""
Port Database Module

This module provides a SQLite database for storing and retrieving
information about open ports on network devices.
"""

import os
import time
import sqlite3
import logging
from typing import List, Dict, Tuple, Optional, Any, Set
from datetime import datetime

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('port_database')

# Default database location
DEFAULT_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'ports.db')

# Schema definition - tables and columns
SCHEMA = {
    'devices': '''
        CREATE TABLE IF NOT EXISTS devices (
            ip_address TEXT PRIMARY KEY,
            mac_address TEXT,
            hostname TEXT,
            first_seen TIMESTAMP NOT NULL,
            last_seen TIMESTAMP NOT NULL,
            active INTEGER NOT NULL DEFAULT 1
        )
    ''',
    'ports': '''
        CREATE TABLE IF NOT EXISTS ports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT NOT NULL,
            port_number INTEGER NOT NULL,
            service_name TEXT,
            first_detected TIMESTAMP NOT NULL,
            last_detected TIMESTAMP NOT NULL,
            active INTEGER NOT NULL DEFAULT 1,
            UNIQUE(ip_address, port_number),
            FOREIGN KEY(ip_address) REFERENCES devices(ip_address) ON DELETE CASCADE
        )
    ''',
    'port_scan_history': '''
        CREATE TABLE IF NOT EXISTS port_scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_time TIMESTAMP NOT NULL,
            devices_found INTEGER NOT NULL,
            ports_found INTEGER NOT NULL
        )
    '''
}

# Indexes for performance
INDEXES = [
    'CREATE INDEX IF NOT EXISTS idx_devices_mac ON devices(mac_address)',
    'CREATE INDEX IF NOT EXISTS idx_devices_active ON devices(active)',
    'CREATE INDEX IF NOT EXISTS idx_ports_ip_active ON ports(ip_address, active)',
    'CREATE INDEX IF NOT EXISTS idx_ports_port ON ports(port_number)',
    'CREATE INDEX IF NOT EXISTS idx_ports_active ON ports(active)'
]


class PortDatabase:
    """Manages a SQLite database for storing information about open ports on network devices."""
    
    def __init__(self, db_path=None):
        """Initialize the database connection and ensure tables exist."""
        self.db_path = db_path or DEFAULT_DB_PATH
        self.conn = None
        self._connect()
        self._create_schema()
    
    def _connect(self):
        """Connect to the SQLite database."""
        try:
            # Enable foreign key constraints
            self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self.conn.execute("PRAGMA foreign_keys = ON")
            # Set WAL mode for better concurrency - important for real-time updates
            self.conn.execute("PRAGMA journal_mode = WAL")
            self.conn.row_factory = sqlite3.Row
            logger.info(f"Connected to port database at {self.db_path}")
        except sqlite3.Error as e:
            logger.error(f"Error connecting to database: {e}")
            raise
    
    def _create_schema(self):
        """Create the database schema if it doesn't already exist."""
        cursor = self.conn.cursor()
        
        # Create tables
        for table_name, create_sql in SCHEMA.items():
            try:
                cursor.execute(create_sql)
                logger.debug(f"Created or verified table: {table_name}")
            except sqlite3.Error as e:
                logger.error(f"Error creating table {table_name}: {e}")
                raise
        
        # Create indexes
        for index_sql in INDEXES:
            try:
                cursor.execute(index_sql)
            except sqlite3.Error as e:
                logger.error(f"Error creating index: {e}")
                raise
        
        self.conn.commit()
        logger.info("Database schema initialized")
    
    def close(self):
        """Close the database connection."""
        if self.conn:
            self.conn.close()
            logger.info("Database connection closed")
    
    def add_or_update_device(self, ip_address: str, mac_address: Optional[str] = None, 
                           hostname: Optional[str] = None) -> None:
        """
        Add a new device or update an existing one.
        
        Args:
            ip_address: The IP address of the device
            mac_address: The MAC address of the device (optional)
            hostname: A hostname for the device (optional)
        """
        cursor = self.conn.cursor()
        now = datetime.now()
        
        try:
            # Check if the device already exists
            cursor.execute("SELECT * FROM devices WHERE ip_address = ?", (ip_address,))
            device = cursor.fetchone()
            
            if device:
                # Update existing device
                update_sql = """
                UPDATE devices SET
                    last_seen = ?,
                    active = 1
                """
                params = [now]
                
                # Only update MAC and hostname if provided
                if mac_address:
                    update_sql += ", mac_address = ?"
                    params.append(mac_address)
                if hostname:
                    update_sql += ", hostname = ?"
                    params.append(hostname)
                
                update_sql += " WHERE ip_address = ?"
                params.append(ip_address)
                
                cursor.execute(update_sql, params)
                logger.debug(f"Updated device: {ip_address}")
            else:
                # Add new device
                cursor.execute("""
                    INSERT INTO devices 
                    (ip_address, mac_address, hostname, first_seen, last_seen)
                    VALUES (?, ?, ?, ?, ?)
                """, (ip_address, mac_address, hostname, now, now))
                logger.info(f"Added new device: {ip_address}")
            
            self.conn.commit()
        except sqlite3.Error as e:
            logger.error(f"Error adding/updating device {ip_address}: {e}")
            self.conn.rollback()
            raise
    
    def add_or_update_port(self, ip_address: str, port_number: int,
                          service_name: Optional[str] = None) -> None:
        """
        Add or update a port entry for a device.
        
        Args:
            ip_address: The IP address of the device
            port_number: The port number that is open
            service_name: The name of the service running on this port (optional)
        """
        cursor = self.conn.cursor()
        now = datetime.now()
        
        try:
            # Make sure the device exists first
            self.add_or_update_device(ip_address)
            
            # Check if the port entry already exists
            cursor.execute("""
                SELECT * FROM ports
                WHERE ip_address = ? AND port_number = ?
            """, (ip_address, port_number))
            port = cursor.fetchone()
            
            if port:
                # Update existing port entry
                cursor.execute("""
                    UPDATE ports SET
                        last_detected = ?,
                        active = 1,
                        service_name = COALESCE(?, service_name)
                    WHERE ip_address = ? AND port_number = ?
                """, (now, service_name, ip_address, port_number))
                logger.debug(f"Updated port {port_number} for device {ip_address}")
            else:
                # Add new port entry
                cursor.execute("""
                    INSERT INTO ports
                    (ip_address, port_number, service_name, first_detected, last_detected)
                    VALUES (?, ?, ?, ?, ?)
                """, (ip_address, port_number, service_name, now, now))
                logger.debug(f"Added new port {port_number} for device {ip_address}")
            
            self.conn.commit()
        except sqlite3.Error as e:
            logger.error(f"Error adding/updating port {port_number} for {ip_address}: {e}")
            self.conn.rollback()
            raise
    
    def bulk_update_ports(self, ip_address: str, port_numbers: List[int],
                         service_names: Optional[Dict[int, str]] = None) -> None:
        """
        Update multiple ports for a device in a single transaction.
        
        Args:
            ip_address: The IP address of the device
            port_numbers: List of open port numbers
            service_names: Dict mapping port numbers to service names (optional)
        """
        service_names = service_names or {}
        cursor = self.conn.cursor()
        now = datetime.now()
        
        try:
            # Make sure the device exists first
            self.add_or_update_device(ip_address)
            
            # Mark all existing ports for this device as inactive
            cursor.execute("""
                UPDATE ports SET active = 0
                WHERE ip_address = ?
            """, (ip_address,))
            
            # Add or update each port
            for port in port_numbers:
                service = service_names.get(port)
                
                # Check if this port already exists
                cursor.execute("""
                    SELECT * FROM ports
                    WHERE ip_address = ? AND port_number = ?
                """, (ip_address, port))
                port_entry = cursor.fetchone()
                
                if port_entry:
                    # Update existing port
                    cursor.execute("""
                        UPDATE ports SET
                            last_detected = ?,
                            active = 1,
                            service_name = COALESCE(?, service_name)
                        WHERE ip_address = ? AND port_number = ?
                    """, (now, service, ip_address, port))
                else:
                    # Add new port
                    cursor.execute("""
                        INSERT INTO ports
                        (ip_address, port_number, service_name, first_detected, last_detected)
                        VALUES (?, ?, ?, ?, ?)
                    """, (ip_address, port, service, now, now))
            
            self.conn.commit()
            logger.info(f"Updated {len(port_numbers)} ports for device {ip_address}")
        except sqlite3.Error as e:
            logger.error(f"Error bulk updating ports for {ip_address}: {e}")
            self.conn.rollback()
            raise
    
    def record_scan(self, devices_found: int, ports_found: int) -> None:
        """
        Record a port scan in the history.
        
        Args:
            devices_found: Number of devices found in this scan
            ports_found: Number of open ports found in this scan
        """
        cursor = self.conn.cursor()
        now = datetime.now()
        
        try:
            cursor.execute("""
                INSERT INTO port_scan_history
                (scan_time, devices_found, ports_found)
                VALUES (?, ?, ?)
            """, (now, devices_found, ports_found))
            self.conn.commit()
            logger.info(f"Recorded scan: {devices_found} devices, {ports_found} ports")
        except sqlite3.Error as e:
            logger.error(f"Error recording scan history: {e}")
            self.conn.rollback()
    
    def get_devices(self, active_only=True) -> List[Dict]:
        """
        Get a list of all devices.
        
        Args:
            active_only: If True, only return active devices
            
        Returns:
            List of device dictionaries
        """
        cursor = self.conn.cursor()
        
        try:
            if active_only:
                cursor.execute("SELECT * FROM devices WHERE active = 1 ORDER BY last_seen DESC")
            else:
                cursor.execute("SELECT * FROM devices ORDER BY last_seen DESC")
            
            return [dict(row) for row in cursor.fetchall()]
        except sqlite3.Error as e:
            logger.error(f"Error getting devices: {e}")
            return []
    
    def get_device(self, ip_address: str) -> Optional[Dict]:
        """
        Get a specific device by IP address.
        
        Args:
            ip_address: The IP address to look up
            
        Returns:
            Device dictionary or None if not found
        """
        cursor = self.conn.cursor()
        
        try:
            cursor.execute("SELECT * FROM devices WHERE ip_address = ?", (ip_address,))
            device = cursor.fetchone()
            return dict(device) if device else None
        except sqlite3.Error as e:
            logger.error(f"Error getting device {ip_address}: {e}")
            return None
    
    def get_device_by_mac(self, mac_address: str) -> Optional[Dict]:
        """
        Get a specific device by MAC address.
        
        Args:
            mac_address: The MAC address to look up
            
        Returns:
            Device dictionary or None if not found
        """
        cursor = self.conn.cursor()
        
        try:
            cursor.execute("SELECT * FROM devices WHERE mac_address = ?", (mac_address,))
            device = cursor.fetchone()
            return dict(device) if device else None
        except sqlite3.Error as e:
            logger.error(f"Error getting device by MAC {mac_address}: {e}")
            return None
    
    def get_ports_for_device(self, ip_address: str, active_only=True) -> List[Dict]:
        """
        Get all ports for a specific device.
        
        Args:
            ip_address: The IP address of the device
            active_only: If True, only return active ports
            
        Returns:
            List of port dictionaries
        """
        cursor = self.conn.cursor()
        
        try:
            if active_only:
                cursor.execute("""
                    SELECT * FROM ports
                    WHERE ip_address = ? AND active = 1
                    ORDER BY port_number
                """, (ip_address,))
            else:
                cursor.execute("""
                    SELECT * FROM ports
                    WHERE ip_address = ?
                    ORDER BY port_number
                """, (ip_address,))
            
            return [dict(row) for row in cursor.fetchall()]
        except sqlite3.Error as e:
            logger.error(f"Error getting ports for {ip_address}: {e}")
            return []
    
    def get_device_with_ports(self, ip_address: str) -> Dict[str, Any]:
        """
        Get a device along with its open ports.
        
        Args:
            ip_address: The IP address of the device
            
        Returns:
            Dictionary with device info and ports list
        """
        device = self.get_device(ip_address)
        if not device:
            return {}
        
        ports = self.get_ports_for_device(ip_address)
        device['ports'] = ports
        return device
    
    def get_all_devices_with_ports(self, active_only=True) -> List[Dict[str, Any]]:
        """
        Get all devices along with their open ports.
        
        Args:
            active_only: If True, only return active devices and ports
            
        Returns:
            List of device dictionaries with ports included
        """
        devices = self.get_devices(active_only)
        
        for device in devices:
            device['ports'] = self.get_ports_for_device(device['ip_address'], active_only)
        
        return devices
    
    def mark_device_inactive(self, ip_address: str) -> None:
        """
        Mark a device as inactive.
        
        Args:
            ip_address: The IP address of the device
        """
        cursor = self.conn.cursor()
        
        try:
            cursor.execute("""
                UPDATE devices SET active = 0
                WHERE ip_address = ?
            """, (ip_address,))
            self.conn.commit()
            logger.info(f"Marked device {ip_address} as inactive")
        except sqlite3.Error as e:
            logger.error(f"Error marking device {ip_address} inactive: {e}")
            self.conn.rollback()
    
    def get_services_for_port(self, port_number: int) -> List[str]:
        """
        Get all known service names for a port number.
        
        Args:
            port_number: The port number to look up
            
        Returns:
            List of service names
        """
        cursor = self.conn.cursor()
        
        try:
            cursor.execute("""
                SELECT DISTINCT service_name FROM ports
                WHERE port_number = ? AND service_name IS NOT NULL
            """, (port_number,))
            
            services = cursor.fetchall()
            return [service['service_name'] for service in services]
        except sqlite3.Error as e:
            logger.error(f"Error getting services for port {port_number}: {e}")
            return []
    
    def get_port_counts(self) -> Dict[str, int]:
        """
        Get statistics about the ports in the database.
        
        Returns:
            Dictionary with port statistics
        """
        cursor = self.conn.cursor()
        stats = {}
        
        try:
            # Total ports
            cursor.execute("SELECT COUNT(*) as count FROM ports WHERE active = 1")
            stats['total_ports'] = cursor.fetchone()['count']
            
            # Ports per device
            cursor.execute("""
                SELECT 
                    AVG(port_count) as avg_ports,
                    MAX(port_count) as max_ports
                FROM (
                    SELECT 
                        ip_address, 
                        COUNT(*) as port_count
                    FROM ports
                    WHERE active = 1
                    GROUP BY ip_address
                )
            """)
            row = cursor.fetchone()
            stats['avg_ports_per_device'] = row['avg_ports']
            stats['max_ports_per_device'] = row['max_ports']
            
            # Most common ports
            cursor.execute("""
                SELECT 
                    port_number, 
                    COUNT(*) as count
                FROM ports
                WHERE active = 1
                GROUP BY port_number
                ORDER BY count DESC
                LIMIT 10
            """)
            stats['common_ports'] = {row['port_number']: row['count'] for row in cursor.fetchall()}
            
            return stats
        except sqlite3.Error as e:
            logger.error(f"Error getting port statistics: {e}")
            return {}


# Create a global instance of the database for easy imports
_port_db = None

def get_port_db() -> PortDatabase:
    """Get or create the global PortDatabase instance."""
    global _port_db
    if _port_db is None:
        _port_db = PortDatabase()
    return _port_db


if __name__ == "__main__":
    # Simple test code when run directly
    db = get_port_db()
    
    # Add a test device
    db.add_or_update_device("192.168.1.100", "00:11:22:33:44:55", "test-device")
    
    # Add some test ports
    db.add_or_update_port("192.168.1.100", 80, "HTTP")
    db.add_or_update_port("192.168.1.100", 443, "HTTPS")
    db.add_or_update_port("192.168.1.100", 22, "SSH")
    
    # Get the device with ports
    device = db.get_device_with_ports("192.168.1.100")
    print(f"Device: {device['ip_address']} ({device['mac_address']})")
    
    print("Open ports:")
    for port in device['ports']:
        print(f"  {port['port_number']}: {port['service_name']}")
    
    print("All devices:")
    for d in db.get_all_devices_with_ports():
        print(f"{d['ip_address']} ({d['mac_address']}): {len(d['ports'])} ports")
