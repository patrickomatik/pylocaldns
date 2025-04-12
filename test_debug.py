#!/usr/bin/env python3
"""
Debug test for IP preallocation

This simplified test focuses only on the pre-allocation feature
without using the full unittest framework.
"""

import os
import tempfile
import ip_utils
from hosts_file import HostsFile

# Setup a simple hosts file
fd, hosts_path = tempfile.mkstemp()
os.close(fd)

with open(hosts_path, 'w') as f:
    f.write("""# Test hosts file
192.168.1.10 server1.local server1 [MAC=00:11:22:33:44:55]
""")

# Initialize the hosts file with DHCP range
dhcp_range = ('192.168.1.100', '192.168.1.200')
hosts_file = HostsFile(hosts_path, dhcp_range)

# Save the original is_ip_in_use function
original_is_ip_in_use = ip_utils.is_ip_in_use
original_get_mac_from_arp = ip_utils.get_mac_from_arp

# Create a mock is_ip_in_use function that always returns True for 192.168.1.105
def mock_is_ip_in_use(ip_address, timeout=1.0):
    print(f"Mock checking if IP {ip_address} is in use")
    if ip_address == '192.168.1.105':
        print(f"IP {ip_address} is reported as IN USE by mock")
        return True
    return False

# Create a mock get_mac_from_arp function
def mock_get_mac_from_arp(ip_address):
    print(f"Mock getting MAC for IP {ip_address}")
    if ip_address == '192.168.1.105':
        print(f"Returning mock MAC 01:23:45:67:89:ab for IP {ip_address}")
        return '01:23:45:67:89:ab'
    return None

# Apply mocks
ip_utils.is_ip_in_use = mock_is_ip_in_use
ip_utils.get_mac_from_arp = mock_get_mac_from_arp

try:
    print("\n--- Initial state ---")
    print(f"Available IPs count: {len(hosts_file.available_ips)}")
    print(f"Reserved IPs: {hosts_file.reserved_ips}")
    print(f"Is 192.168.1.105 in available_ips? {('yes' if '192.168.1.105' in hosts_file.available_ips else 'no')}")
    
    # Ensure 192.168.1.105 is in available IPs
    if '192.168.1.105' not in hosts_file.available_ips:
        hosts_file.available_ips.add('192.168.1.105')
        print("Added 192.168.1.105 to available IPs")
    
    print("\n--- Testing _add_preallocated_ip directly ---")
    # Call the _add_preallocated_ip method directly
    hosts_file._add_preallocated_ip('192.168.1.105')
    
    print(f"After _add_preallocated_ip, reserved IPs: {hosts_file.reserved_ips}")
    print(f"Is 192.168.1.105 in reserved_ips? {('yes' if '192.168.1.105' in hosts_file.reserved_ips else 'no')}")
    print(f"MAC to IP mapping: {hosts_file.mac_to_ip}")
    print(f"Is 192.168.1.105 in available_ips? {('yes' if '192.168.1.105' in hosts_file.available_ips else 'no')}")
    
    print("\n--- Testing allocate_ip with different MAC ---")
    # Now try allocate_ip with a different MAC
    allocated_ip = hosts_file.allocate_ip('ff:ff:ff:ff:ff:ff')
    print(f"Allocated IP: {allocated_ip}")
    print(f"Reserved IPs: {hosts_file.reserved_ips}")
    print(f"MAC to IP mapping: {hosts_file.mac_to_ip}")
    
finally:
    # Restore original functions
    ip_utils.is_ip_in_use = original_is_ip_in_use
    ip_utils.get_mac_from_arp = original_get_mac_from_arp
    
    # Clean up
    os.remove(hosts_path)
