#!/usr/bin/env python3
"""
Web UI Models for the DNS/DHCP Network Server

This module provides data models used by the Web UI.
"""

import logging

# Setup logging
logger = logging.getLogger('webui_models')

class DNSRecord:
    """
    Class representing a DNS record.
    
    Attributes:
        address: The IP address for the record
        record_type: The DNS record type (1 for A, 28 for AAAA)
    """
    def __init__(self, address, record_type):
        self.address = address
        self.record_type = record_type
    
    def __str__(self):
        record_type_name = "A" if self.record_type == 1 else "AAAA" if self.record_type == 28 else str(self.record_type)
        return f"{record_type_name} record: {self.address}"
