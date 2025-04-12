# DNS API Implementation Summary

I've implemented a remote API that allows hosts to set their DNS entries using a bash script or curl. This enhancement makes it easy for devices to automatically register themselves with your DNS server.

## Files Created

1. **dns_api_client.py** - A Python client for the API that can be used from command line or imported into other scripts
2. **set_dns_entry.sh** - A bash script wrapper for the Python client
3. **set_dns_curl.sh** - A simpler bash script using only curl (no Python dependencies)
4. **test_api.sh** - A test script to verify API functionality
5. **api_readme.md** - Detailed documentation for the API

## Changes Made

1. **ip_utils.py** - Fixed the indentation issue in the `_get_mac_from_arp` method

2. **network_server.py**:
   - Added APIServer import
   - Updated NetworkServer class to support API functionality
   - Added API configuration parameters to the constructor
   - Added API server initialization and start/stop methods
   - Added command line arguments for API configuration

3. **readme.md** - Updated to include information about the new API features

## How It Works

The API server provides four main endpoints:

1. `GET /api/dns/records` - Lists all DNS records
2. `GET /api/dns/lookup?hostname=<hostname>` - Looks up a hostname to get its IP addresses
3. `GET /api/dns/reverse?ip=<ip>` - Performs a reverse lookup to get hostnames for an IP
4. `POST /api/dns/set_hostname` - Sets a hostname for an IP address (main endpoint)

The `set_hostname` endpoint accepts JSON data with:
- `ip`: The IP address to set (uses current IP if not provided)
- `hostname`: The hostname to set (uses current hostname if not provided)
- `mac`: Optional MAC address for DHCP reservations

## Using the API

### Basic Usage

To set a hostname for the current host:

```bash
./set_dns_entry.sh --server http://dns-server:8081
```

This will:
1. Detect your current IP address, hostname, and MAC address
2. Send them to the DNS server
3. Update the hosts file on the server

### Advanced Usage

The API supports various options:

```bash
# With the Python client
./dns_api_client.py --server http://dns-server:8081 set --hostname mydevice.local --ip 192.168.1.100

# With the curl script
./set_dns_curl.sh --server http://dns-server:8081 --hostname mydevice.local

# With curl directly
curl -X POST http://dns-server:8081/api/dns/set_hostname \
  -H "Content-Type: application/json" \
  -d '{"ip":"192.168.1.100","hostname":"mydevice.local"}'
```

### Security

The API server supports token-based authentication:

```bash
# Start server with authentication
python network_server.py --hosts-file ./hosts.txt --api-enable --api-token your_secret_token

# Use token with client
./set_dns_entry.sh --server http://dns-server:8081 --token your_secret_token
```

## Testing

You can test the API using the included script:

```bash
./test_api.sh
```

This will:
1. Set a test hostname for a test IP
2. Look up the hostname
3. Perform a reverse lookup on the IP
4. Verify all operations succeed

## Automation

You can set up a cron job to automatically update your DNS entry:

```bash
# Add to crontab to run every hour
0 * * * * /path/to/set_dns_entry.sh --server http://dns-server:8081
```

This is perfect for devices with dynamic IP addresses that need to maintain a consistent hostname.

## Notes for Production Use

1. Enable authentication with `--api-token` for security
2. Consider running the server behind a reverse proxy for HTTPS support
3. Use cron jobs or startup scripts to automatically register devices
4. The API server and clients are compatible with most Unix-like systems (Linux, macOS, BSD)
