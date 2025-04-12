#!/usr/bin/env python3
"""
Network Services Server with Flask Web UI - Serves DNS and DHCP requests based on a local hosts file

This application acts as both a DNS server that resolves domain names to IP addresses
and a DHCP server that assigns IP addresses to devices based on MAC addresses.
Both services use a common hosts file for configuration.

Usage:
  python network_server_flask.py --hosts-file /path/to/hosts.txt [--dns-port 53]
                              [--dhcp-enable] [--dhcp-range 192.168.1.100-192.168.1.200]
                              [--dhcp-subnet 255.255.255.0] [--dhcp-router 192.168.1.1]
                              [--interface 0.0.0.0]
"""

import argparse
import logging
import os
import sys
import threading
import time
from typing import List

# Check if Flask is installed
try:
    from flask import Flask
except ImportError:
    print("Flask is required for the PyLocalDNS web UI.")
    print("Please install Flask with: pip install flask")
    sys.exit(1)

# Import API server
from api_server import APIServer

# Import local modules
from models import DEFAULT_LEASE_TIME
from hosts_file import HostsFile
from dns_server import DNSServer
from dhcp_server import DHCPServer
from utils import parse_ip_range, get_local_ips

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('network_server')


class NetworkServer:
    """Combined DNS and DHCP server with Flask Web UI."""

    def __init__(self, hosts_file: HostsFile, dns_port: int = 53,
                 interface: str = '0.0.0.0', dhcp_enable: bool = False,
                 subnet_mask: str = '255.255.255.0', router: str = None,
                 dns_servers: List[str] = None, webui_enable: bool = False,
                 webui_port: int = 8080, api_enable: bool = False,
                 api_port: int = 8081, api_token: str = None):
        self.hosts = hosts_file
        self.interface = interface
        self.dns_server = DNSServer(hosts_file, dns_port, interface)

        # DHCP server
        self.dhcp_enable = dhcp_enable
        self.dhcp_server = None

        if dhcp_enable:
            self.dhcp_server = DHCPServer(
                hosts_file,
                interface,
                subnet_mask,
                router,
                dns_servers
            )

        # Web UI
        self.webui_enable = webui_enable
        self.webui_port = webui_port
        self.webui_server = None
        self.actual_webui_port = None
        self.flask_app = None

        # API server
        self.api_enable = api_enable
        self.api_port = api_port
        self.api_token = api_token
        self.api_server = None
        self.actual_api_port = None

        if api_enable:
            self.api_server = APIServer(
                hosts_file,
                port=api_port,
                interface=interface,
                auth_token=api_token
            )

        # Initialize Flask WebUI if enabled
        if webui_enable:
            try:
                # Import and initialize the Flask application
                from app import init_flask_server
                self.flask_app = init_flask_server(
                    hosts_file_obj=hosts_file,
                    network_server_obj=self,
                    port=webui_port,
                    host=interface
                )
                logger.info("Flask Web UI initialized successfully")
            except ImportError as e:
                logger.error(f"Could not import Flask Web UI components: {e}")
                logger.error("Make sure Flask is installed with 'pip install flask'")
                logger.error("Flask is required for the Web UI functionality")
                # Terminate the application
                sys.exit(1)
            except Exception as e:
                logger.error(f"Web UI component error: {e}")
                logger.error("There appears to be a mismatch in the Flask WebUI components")
                logger.error("Flask is required for the Web UI functionality")
                # Terminate the application
                sys.exit(1)

    def start(self) -> None:
        """Start the network services."""
        # Start the DNS server in a new thread
        dns_thread = threading.Thread(target=self.dns_server.start, daemon=True)
        dns_thread.start()

        # Start the DHCP server if enabled
        if self.dhcp_enable and self.dhcp_server:
            dhcp_thread = threading.Thread(target=self.dhcp_server.start, daemon=True)
            dhcp_thread.start()

        # Start the Web UI if enabled
        webui_thread = None
        if self.webui_enable and self.flask_app:
            try:
                # Define a function to run the Flask app
                def run_flask_app():
                    self.flask_app.run(
                        host=self.interface,
                        port=self.webui_port,
                        debug=False,
                        use_reloader=False,
                        threaded=True
                    )
                
                # Start the Flask app in a new thread
                webui_thread = threading.Thread(target=run_flask_app, daemon=True)
                webui_thread.start()
                self.actual_webui_port = self.webui_port  # Store the actual port being used

                # Get local IP addresses to display more useful URLs
                local_ips = get_local_ips()

                # Display URLs for different interfaces
                logger.info(f"Flask Web UI available at:")
                logger.info(f"  - http://localhost:{self.actual_webui_port}/")
                for ip in local_ips:
                    logger.info(f"  - http://{ip}:{self.actual_webui_port}/")

            except Exception as e:
                logger.error(f"Failed to start Flask Web UI: {e}")
                logger.error("Flask Web UI is required for this application to function properly")
                sys.exit(1)
                
        # Start the API server if enabled
        api_thread = None
        if self.api_enable and self.api_server:
            try:
                api_thread = self.api_server.start()
                self.actual_api_port = self.api_server.port  # Store the actual port being used
                
                # Get local IP addresses to display more useful URLs
                local_ips = get_local_ips()
                
                # Display URLs for different interfaces
                logger.info(f"API server available at:")
                logger.info(f"  - http://localhost:{self.actual_api_port}/api/")
                for ip in local_ips:
                    logger.info(f"  - http://{ip}:{self.actual_api_port}/api/")
                    
                # Display usage example with the DNS client
                script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'set_dns_entry.sh')
                logger.info(f"To set DNS entries, use:")
                logger.info(f"  {script_path} --server http://localhost:{self.actual_api_port}")
                
            except Exception as e:
                logger.error(f"Failed to start API server: {e}")
                logger.info("Continuing without API server...")
                self.api_enable = False

        # Start a thread to monitor the hosts file for changes
        monitor_thread = threading.Thread(
            target=self._file_monitoring_thread,
            daemon=True
        )
        monitor_thread.start()

        try:
            # Keep the main thread alive
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()

    def stop(self) -> None:
        """Stop all network services."""
        logger.info("Stopping network services...")
        self.dns_server.stop()

        if self.dhcp_enable and self.dhcp_server:
            self.dhcp_server.stop()
            
        if self.api_enable and self.api_server:
            self.api_server.stop()

    def _file_monitoring_thread(self) -> None:
        """Thread function to periodically check for hosts file updates."""
        while True:
            try:
                self.hosts.check_for_updates()
                time.sleep(5)  # Check every 5 seconds
            except Exception as e:
                logger.error(f"Error in file monitoring thread: {e}")


def main() -> None:
    parser = argparse.ArgumentParser(description='Network Server with Flask Web UI - DNS and DHCP services using a local hosts file')

    # Common arguments
    parser.add_argument('--hosts-file', required=True, help='Path to the hosts file')
    parser.add_argument('--interface', default='0.0.0.0', help='Interface to bind to (default: 0.0.0.0)')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')

    # DNS specific arguments
    parser.add_argument('--dns-port', type=int, default=53, help='DNS port to listen on (default: 53)')

    # DHCP specific arguments
    parser.add_argument('--dhcp-enable', action='store_true', help='Enable DHCP server')
    parser.add_argument('--dhcp-range', help='DHCP IP range (format: 192.168.1.100-192.168.1.200)')
    parser.add_argument('--dhcp-subnet', default='255.255.255.0', help='DHCP subnet mask (default: 255.255.255.0)')
    parser.add_argument('--dhcp-router', help='DHCP default gateway/router IP (default: server IP)')
    parser.add_argument('--dhcp-dns', help='DHCP DNS servers (comma-separated, default: 8.8.8.8,8.8.4.4)')
    parser.add_argument('--dhcp-lease-time', type=int, default=DEFAULT_LEASE_TIME,
                        help=f'DHCP lease time in seconds (default: {DEFAULT_LEASE_TIME})')

    # Web UI arguments
    parser.add_argument('--webui-enable', action='store_true', help='Enable web UI for management')
    parser.add_argument('--webui-port', type=int, default=8080, help='Web UI port (default: 8080)')
    
    # API server arguments
    parser.add_argument('--api-enable', action='store_true', help='Enable API server for remote management')
    parser.add_argument('--api-port', type=int, default=8081, help='API server port (default: 8081)')
    parser.add_argument('--api-token', help='API authentication token (optional)')

    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.setLevel(logging.DEBUG)

    try:
        # Process DHCP range if DHCP is enabled
        dhcp_range = None
        if args.dhcp_enable:
            if not args.dhcp_range:
                logger.error("DHCP is enabled but no IP range specified. Use --dhcp-range")
                sys.exit(1)
            dhcp_range = parse_ip_range(args.dhcp_range)

        # Process DNS servers for DHCP
        dns_servers = None
        if args.dhcp_dns:
            dns_servers = [s.strip() for s in args.dhcp_dns.split(',')]

        # Create the hosts file manager
        hosts_file = HostsFile(args.hosts_file, dhcp_range)

        # Create and start the network server
        server = NetworkServer(
            hosts_file=hosts_file,
            dns_port=args.dns_port,
            interface=args.interface,
            dhcp_enable=args.dhcp_enable,
            subnet_mask=args.dhcp_subnet,
            router=args.dhcp_router,
            dns_servers=dns_servers,
            webui_enable=args.webui_enable,
            webui_port=args.webui_port,
            api_enable=args.api_enable,
            api_port=args.api_port,
            api_token=args.api_token
        )

        logger.info("Starting network services...")
        server.start()

    except KeyboardInterrupt:
        logger.info("Keyboard interrupt received, shutting down...")
        if 'server' in locals():
            server.stop()
    except Exception as e:
        logger.error(f"Unhandled exception: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
