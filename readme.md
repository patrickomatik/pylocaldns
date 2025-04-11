# Network Server (DNS + DHCP)

A lightweight Python server that provides both DNS and DHCP services using a shared configuration file. The server resolves domain names and assigns IP addresses based on MAC addresses from a local hosts file.

## Features

- **DNS Service**:
  - Resolves domain names using a local hosts file
  - Supports both IPv4 (A records) and IPv6 (AAAA records)
  - Acts as an authoritative DNS server for configured domains

- **DHCP Service**:
  - Assigns IP addresses to clients based on MAC address
  - Supports static IP reservations via MAC address in the hosts file
  - Dynamic IP allocation from a configurable IP range
  - Provides network configuration (subnet, gateway, DNS servers)
  - Complete DHCP protocol support (DISCOVER, OFFER, REQUEST, ACK, etc.)

- **Web UI**:
  - Simple browser-based management interface
  - View all MAC address, IP, and hostname mappings
  - Add and edit DNS entries for devices
  - Convert dynamic DHCP leases to static entries
  - Manage DHCP leases

- **Common Features**:
  - Single configuration file for both services
  - Automatic reloading when the hosts file changes
  - No external dependencies (uses standard Python libraries only)
  - Multithreaded design to handle multiple requests simultaneously
  - MAC address to hostname mapping
  - Detailed logging

## Requirements

- Python 3.6 or higher
- Root/Administrator privileges (if using the default ports 53 for DNS and 67/68 for DHCP)

## Installation

No additional dependencies are required beyond the Python standard library.

```bash
# Clone or download the repository
git clone https://github.com/yourusername/network-server.git
cd network-server

# Make the script executable
chmod +x network_server.py
```

## Usage

### Basic Usage

```bash
# Run just the DNS server
sudo python network_server.py --hosts-file /path/to/hosts.txt

# Run both DNS and DHCP servers
sudo python network_server.py --hosts-file /path/to/hosts.txt --dhcp-enable --dhcp-range 192.168.1.100-192.168.1.200

# Run with Web UI
sudo python network_server.py --hosts-file /path/to/hosts.txt --dhcp-enable --dhcp-range 192.168.1.100-192.168.1.200 --webui-enable
```

The server requires root privileges if you're using the standard DNS (53) and DHCP (67/68) ports.

### Command Line Options

```
# Common options
--hosts-file PATH     Path to the hosts file (required)
--interface IP        Interface to bind to (default: 0.0.0.0)
--debug               Enable debug logging

# DNS options
--dns-port PORT       DNS port to listen on (default: 53)

# DHCP options
--dhcp-enable         Enable DHCP server
--dhcp-range RANGE    DHCP IP range (format: 192.168.1.100-192.168.1.200)
--dhcp-subnet MASK    DHCP subnet mask (default: 255.255.255.0)
--dhcp-router IP      DHCP default gateway/router IP
--dhcp-dns IPs        DHCP DNS servers (comma-separated)
--dhcp-lease-time SEC DHCP lease time in seconds (default: 86400)

# Web UI options
--webui-enable        Enable web UI for management
--webui-port PORT     Web UI port (default: 8080)
```

### Web UI

When enabled, the Web UI is accessible at:

```
http://<server-ip>:8080/
```

The Web UI provides:
- A table of all static entries (MAC, IP, hostname)
- A table of current DHCP leases
- Ability to add new static entries
- Ability to edit/update hostname information
- Convert dynamic leases to static entries

### Example

```bash
# Run on non-privileged ports for testing (requires root on Linux for ports <1024)
python network_server.py --hosts-file ./hosts.txt --dns-port 5353 --interface 127.0.0.1

# Run as a full network server with DHCP and Web UI
sudo python network_server.py --hosts-file /etc/custom_hosts \
  --dhcp-enable --dhcp-range 192.168.1.100-192.168.1.200 \
  --dhcp-router 192.168.1.1 --webui-enable --webui-port 8080
```

## Hosts File Format

The hosts file uses an extended format that supports both DNS entries and DHCP MAC address reservations:

```
# Comments start with a hash
# Format for DNS entries:
# <IP address> <hostname1> [hostname2] [hostname3] ...
#
# Format for DHCP entries with MAC address:
# <IP address> <hostname1> [hostname2] ... [MAC=aa:bb:cc:dd:ee:ff]

# IPv4 examples with MAC addresses for DHCP
192.168.1.10 server1.local server1 [MAC=00:11:22:33:44:55]
192.168.1.20 server2.local server2 [MAC=aa:bb:cc:dd:ee:ff]
192.168.1.30 db.local database

# IPv6 examples
2001:db8::1 ipv6server.local ipv6test [MAC=a1:b2:c3:d4:e5:f6]
2001:db8::2 ipv6db.local

# DHCP reservation without DNS entry
192.168.1.100 - [MAC=11:22:33:44:55:66]
```

Each line contains:
- An IP address (IPv4 or IPv6)
- One or more hostnames (or "-" if no hostname is needed)
- Optional MAC address in square brackets for DHCP reservations
- Optional comments starting with #

## Testing the Server

### Testing DNS

You can test the DNS server using `dig`, `nslookup`, or any other DNS lookup tool:

```bash
# Test using dig
dig @127.0.0.1 -p 5353 server1.local

# Test using nslookup
nslookup -port=5353 server1.local 127.0.0.1
```

### Testing DHCP

Testing DHCP typically requires a client on the same network. You can use:

- `dhclient` (Linux)
- `ipconfig /release` and `ipconfig /renew` (Windows)
- Network tools like `dhcping`

For monitoring DHCP traffic, you can use tools like:
- `tcpdump -i <interface> port 67 or port 68`
- Wireshark with a DHCP filter

## Integration with System

### Running as a Service (Systemd on Linux)

Create a file at `/etc/systemd/system/network-server.service`:

```
[Unit]
Description=Network Server (DNS + DHCP)
After=network.target

[Service]
ExecStart=/usr/bin/python3 /path/to/network_server.py --hosts-file /path/to/hosts.txt --dhcp-enable --dhcp-range 192.168.1.100-192.168.1.200 --webui-enable
Restart=on-failure
User=root

[Install]
WantedBy=multi-user.target
```

Then enable and start the service:

```bash
sudo systemctl enable network-server
sudo systemctl start network-server
```

## Client Configuration

### DNS Client Configuration

To use this as your primary DNS resolver:

1. Linux: Edit `/etc/resolv.conf` to add:
   ```
   nameserver 127.0.0.1
   ```

2. Windows:
   - Open Network Connections
   - Right-click your active connection and select Properties
   - Select "Internet Protocol Version 4 (TCP/IPv4)" and click Properties
   - Select "Use the following DNS server addresses" and enter your server IP

3. macOS:
   - Open System Preferences > Network
   - Select your active connection and click Advanced
   - Go to the DNS tab and add your server IP

### DHCP Client Configuration

Most systems are configured to use DHCP by default. To ensure clients use your DHCP server:

1. Make sure the DHCP server is the only one on your network segment
2. Configure any existing routers/gateways to forward DHCP requests to your server

## Limitations

- DNS service is limited to A and AAAA record types
- No recursive DNS resolution (only resolves domains in the hosts file)
- No DNS caching (each query checks the hosts file)
- No DHCP relay support (clients must be on the same network segment)
- Limited DHCP options support (basic network config only)
- No IPv6 DHCP (DHCPv6) support
- Basic authentication is not included in the Web UI

## Security Considerations

- The Web UI has no authentication - should only be used on trusted networks
- The server does not implement authentication or encryption for DNS/DHCP
- Should only be used on trusted networks
- Running as root/administrator is a security risk; consider using containers or least-privilege approaches

## License

MIT

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

   - Go to the DNS tab and add your server IP

### DHCP Client Configuration

Most systems are configured to use DHCP by default. To ensure clients use your DHCP server:

1. Make sure the DHCP server is the only one on your network segment
2. Configure any existing routers/gateways to forward DHCP requests to your server

## Limitations

- DNS service is limited to A and AAAA record types
- No recursive DNS resolution (only resolves domains in the hosts file)
- No DNS caching (each query checks the hosts file)
- No DHCP relay support (clients must be on the same network segment)
- Limited DHCP options support (basic network config only)
- No IPv6 DHCP (DHCPv6) support

## Security Considerations

- The server does not implement authentication or encryption
- Should only be used on trusted networks
- Running as root/administrator is a security risk; consider using containers or least-privilege approaches

## License

MIT

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
