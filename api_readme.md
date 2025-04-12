# DNS API Usage Guide

This guide explains how to use the DNS API to manage your domain name entries remotely.

## Enabling the API Server

When starting the network server, add the `--api-enable` flag to enable the API server:

```bash
sudo python network_server.py --hosts-file /path/to/hosts.txt --api-enable
```

By default, the API server listens on port 8081. You can change this using the `--api-port` option:

```bash
sudo python network_server.py --hosts-file /path/to/hosts.txt --api-enable --api-port 9000
```

You can also add an authentication token for security:

```bash
sudo python network_server.py --hosts-file /path/to/hosts.txt --api-enable --api-token your_secret_token
```

## Using the API Client

The project includes a Python client and a Bash script wrapper for easy access to the API.

### Using the Bash Script

The simplest way to update your DNS entry is using the provided script:

```bash
./set_dns_entry.sh --server http://server_address:8081
```

This will automatically detect your IP address, hostname, and MAC address, and register them with the DNS server.

You can also specify these values manually:

```bash
./set_dns_entry.sh --server http://server_address:8081 --hostname mycomputer.local --ip 192.168.1.100 --mac 00:11:22:33:44:55
```

If you've configured an authentication token, include it:

```bash
./set_dns_entry.sh --server http://server_address:8081 --token your_secret_token
```

### Using the Python Client Directly

The Python client offers more functionality:

```bash
# Set hostname (register in DNS)
python dns_api_client.py --server http://server_address:8081 set --hostname mycomputer.local

# Look up a hostname
python dns_api_client.py --server http://server_address:8081 lookup mycomputer.local

# Reverse lookup (get hostname for an IP)
python dns_api_client.py --server http://server_address:8081 reverse 192.168.1.100
```

## Using with curl (For Shell Scripts)

You can also interact with the API directly using curl:

### Setting a hostname

```bash
# Get your current IP address (optional)
IP_ADDRESS=$(hostname -I | awk '{print $1}')

# Set hostname
curl -X POST http://server_address:8081/api/dns/set_hostname \
  -H "Content-Type: application/json" \
  -d "{\"ip\":\"${IP_ADDRESS}\",\"hostname\":\"$(hostname).local\"}"
```

### Looking up a hostname

```bash
curl -G http://server_address:8081/api/dns/lookup \
  --data-urlencode "hostname=mycomputer.local"
```

### Reverse lookup

```bash
curl -G http://server_address:8081/api/dns/reverse \
  --data-urlencode "ip=192.168.1.100"
```

### Using authentication

If you've set up an authentication token, include it with your requests:

```bash
curl -X POST http://server_address:8081/api/dns/set_hostname \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your_secret_token" \
  -d "{\"ip\":\"192.168.1.100\",\"hostname\":\"mycomputer.local\"}"
```

## API Endpoints

The following API endpoints are available:

- `GET /api/dns/records` - List all DNS records
- `GET /api/dns/lookup?hostname=<hostname>` - Look up a hostname
- `GET /api/dns/reverse?ip=<ip>` - Reverse lookup an IP address
- `POST /api/dns/set_hostname` - Set a hostname for an IP address

## Automating DNS Updates

You can create a cron job to automatically update your DNS entry periodically:

```bash
# Edit your crontab
crontab -e

# Add a line to run the script every hour
0 * * * * /path/to/set_dns_entry.sh --server http://server_address:8081
```

This is useful for devices with dynamic IP addresses that need to maintain a consistent hostname.

## Security Considerations

- The API server does not use HTTPS by default, so it's recommended to use it only on your local network.
- Set up an authentication token if you're concerned about unauthorized changes.
- For additional security, consider using a firewall to restrict access to the API port.
