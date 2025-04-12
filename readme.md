## Screenshots

### DNS Management Interface
![DNS Management Interface](screenshots/Screenshot%202025-04-12%20at%2019.40.54.png)

### DNS Entry Edit Screen
![DNS Entry Edit Screen](screenshots/Screenshot%202025-04-12%20at%2019.41.18.png)

## Advanced Features

### IP Address Usage Checking

The DHCP server includes a comprehensive IP address usage verification system that prevents address conflicts. Before allocating an IP address, the server checks if it's already in use on the network using multiple methods:

- **Ping Tests**: Sends ICMP pings to check for live devices
- **Port Scanning**: Checks common network ports for services
- **ARP Table Analysis**: Examines the system's ARP cache

If an IP address is found to be in use but not in our configuration, it's automatically marked as "pre-allocated" and removed from the DHCP pool. This prevents IP conflicts and ensures a stable network.

### MAC Vendor Identification

The server includes a built-in MAC address vendor database that identifies the manufacturer of network devices by their MAC address. This feature helps you:

- Quickly identify unknown devices on your network
- Recognize which type of device is connecting (phone, router, IoT device, etc.)
- Verify legitimacy of devices (helpful for securing your network)

The vendor database:
- Downloads and processes data from the official IEEE OUI database
- Automatically refreshes when older than 30 days
- Provides fast lookups of vendor information

You can manually update the database using the provided utility script:

```bash
# Update the MAC vendor database
python util_scripts/update_mac_vendors.py --force

# Test MAC vendor lookups
python vendor_db.py AA:BB:CC:DD:EE:FF
```

### Network Discovery

The server includes a network scanner that can discover all devices on your network:

```bash
# Scan your network and update the hosts file
python scan_network.py --hosts-file /path/to/hosts.txt

# Scan a specific IP range
python scan_network.py --hosts-file /path/to/hosts.txt --range 192.168.1.100-192.168.1.200
```

This is useful for:
- Setting up on an existing network with many devices
- Discovering unknown devices on your network
- Preventing IP conflicts before they happen

### Smart Client Handling

The DHCP server has intelligent handling for device requests:

- If a device is requesting its own current IP, the server will allow it
- If a device has changed its MAC address but is requesting the same IP, the server will update its records
- If a device is requesting an IP that's already in use by another device, the server will assign a different IP

This makes the server resilient to network changes and prevents disruptions.

### Remote DNS Management API

The server includes a simple HTTP API that allows devices to:

- Register themselves with the DNS server
- Update their hostname and IP mappings
- Lookup DNS records
- Perform reverse lookups

This feature is perfect for:
- Automatically registering devices on your network
- Dynamic DNS updates from remote hosts
- Integrating with scripts and automation tools

See the [API Documentation](api_readme.md) for details.

# Network Server (DNS + DHCP)

A lightweight Python server that provides both DNS and DHCP services using a shared configuration file. The server resolves domain names and assigns IP addresses based on MAC addresses from a local hosts file.

## Features

- **DNS Service**:
  - Resolves domain names using a local hosts file
  - Supports both IPv4 (A records) and IPv6 (AAAA records)
  - Acts as an authoritative DNS server for configured domains
  - Remote API for DNS record management

- **DHCP Service**:
  - Assigns IP addresses to clients based on MAC address
  - Supports static IP reservations via MAC address in the hosts file
  - Dynamic IP allocation from a configurable IP range
  - Provides network configuration (subnet, gateway, DNS servers)
  - Complete DHCP protocol support (DISCOVER, OFFER, REQUEST, ACK, etc.)

- **Web UI**:
  - Flask-based browser management interface
  - View all MAC address, IP, and hostname mappings
  - Add and edit DNS entries for devices
  - Convert dynamic DHCP leases to static entries
  - Manage DHCP leases
  - Network scanning functionality
  - Dynamic content updates with HTMX

- **DNS API**:
  - HTTP-based API for remote DNS management
  - Set hostname for an IP address
  - Look up IP addresses for a hostname
  - Reverse lookup hostname for an IP
  - Get a list of all DNS records
  - Optional authentication

- **Common Features**:
  - Single configuration file for both services
  - Automatic reloading when the hosts file changes
  - Detailed logging

## Requirements

- Python 3.6 or higher
- **Flask is required** for the web interface (no fallback available)
- Root/Administrator privileges (if using the default ports 53 for DNS and 67/68 for DHCP)

### Flask Requirement

PyLocalDNS requires Flask for its web interface. There is no fallback to a custom HTTP server.

```bash
# Install Flask and all dependencies
./install_flask.sh
```

For more details, see [FLASK_REQUIREMENT.md](FLASK_REQUIREMENT.md).

## Quick Start

```bash
# Install Flask and dependencies
./install_flask.sh

# Run the server with Flask web UI
./run_flask_server.sh
```

The Web UI will be available at http://localhost:8080

## Usage

### Basic Usage

```bash
# Run just the DNS server
sudo python network_server_flask.py --hosts-file /path/to/hosts.txt

# Run both DNS and DHCP servers
sudo python network_server_flask.py --hosts-file /path/to/hosts.txt --dhcp-enable --dhcp-range 192.168.1.100-192.168.1.200

# Run with Web UI
sudo python network_server_flask.py --hosts-file /path/to/hosts.txt --dhcp-enable --dhcp-range 192.168.1.100-192.168.1.200 --webui-enable

# Enable the DNS API
sudo python network_server_flask.py --hosts-file /path/to/hosts.txt --api-enable
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

# API options
--api-enable          Enable API server for remote management
--api-port PORT       API server port (default: 8081)
--api-token TOKEN     API authentication token (optional)
```

### Web UI

When enabled, the Flask-based Web UI is accessible at:

```
http://<server-ip>:8080/
```

The Web UI provides:
- A table of all static entries (MAC, IP, hostname)
- A table of current DHCP leases
- Ability to add new static entries
- Ability to edit/update hostname information
- Convert dynamic leases to static entries
- Network scanning functionality 
- Port scanning and display
- Dynamic content updates using HTMX

**Note:** Flask is required for the Web UI to function. See [FLASK_REQUIREMENT.md](FLASK_REQUIREMENT.md) for more information.

### DNS API

When enabled, the DNS API is accessible at:

```
http://<server-ip>:8081/api/
```

API endpoints:
- `GET /api/dns/records` - Get all DNS records
- `GET /api/dns/lookup?hostname=<hostname>` - Look up a hostname
- `GET /api/dns/reverse?ip=<ip>` - Perform a reverse lookup
- `POST /api/dns/set_hostname` - Set a hostname for an IP

See the [API Documentation](api_readme.md) for more details and example usage.

### Example

```bash
# Run on non-privileged ports for testing (requires root on Linux for ports <1024)
python network_server_flask.py --hosts-file ./hosts.txt --dns-port 5353 --interface 127.0.0.1

# Run as a full network server with DHCP, Web UI, and API
sudo python network_server_flask.py --hosts-file /etc/custom_hosts \
  --dhcp-enable --dhcp-range 192.168.1.100-192.168.1.200 \
  --dhcp-router 192.168.1.1 --webui-enable --api-enable
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

### Testing the API

The project includes a test script to verify API functionality:

```bash
# Start the server with API enabled
sudo python network_server_flask.py --hosts-file ./hosts.txt --api-enable

# Run the test script
./test_api.sh
```

You can also manually test with the client scripts:

```bash
# Set hostname using Python client
./dns_api_client.py --server http://localhost:8081 set --hostname mydevice.local

# Or using the curl client
./set_dns_curl.sh --server http://localhost:8081 --hostname mydevice.local
```

## Integration with System

### Running as a Service (Systemd on Linux)

Create a file at `/etc/systemd/system/network-server.service`:

```
[Unit]
Description=Network Server (DNS + DHCP)
After=network.target

[Service]
ExecStart=/usr/bin/python3 /path/to/network_server_flask.py --hosts-file /path/to/hosts.txt --dhcp-enable --dhcp-range 192.168.1.100-192.168.1.200 --webui-enable --api-enable
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

### Setting Up Automatic DNS Updates

You can create a cron job to automatically update your DNS entry:

```bash
# Edit your crontab
crontab -e

# Add a line to run the script every hour
0 * * * * /path/to/set_dns_entry.sh --server http://server_address:8081
```

This is useful for devices with dynamic IP addresses that need to maintain a consistent hostname.

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
- The DNS API does not use HTTPS by default
- Flask is required for the Web UI (no fallback server available)

## Security Considerations

- The Web UI and API have no authentication by default - use the `--api-token` option for API security
- The server does not implement encryption for DNS/DHCP communications
- Should only be used on trusted networks
- Running as root/administrator is a security risk; consider using containers or least-privilege approaches

## License

MIT

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
