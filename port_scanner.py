#!/usr/bin/env python3
"""
port_scanner.py - A simple TCP port scanner for penetration testing.

This script scans a target host for open TCP ports within a specified range.
It handles invalid hosts, timeouts, and connection errors without crashing.
"""

import socket
import sys
import argparse
from datetime import datetime


def resolve_target(target):
    """
    Resolve a hostname or IP address to an IP address.

    Args:
        target (str): Domain name or IP address.

    Returns:
        str: IP address of the target.

    Exits gracefully if resolution fails.
    """
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        print(f"[-] Error: Unable to resolve host '{target}'.")
        sys.exit(1)


def scan_port(ip, port, timeout):
    """
    Attempt to connect to a specific TCP port on the target IP.

    Args:
        ip (str): Target IP address.
        port (int): Port number to scan.
        timeout (float): Connection timeout in seconds.

    Returns:
        bool: True if port is open, False otherwise.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            return result == 0
    except socket.error:
        # Any socket error (e.g., unreachable) means the port is considered closed
        return False


def main():
    """Parse arguments, resolve target, scan ports, and display results."""
    parser = argparse.ArgumentParser(
        description="TCP port scanner for penetration testing.",
        usage="%(prog)s [-h] target [-s START_PORT] [-e END_PORT] [-t TIMEOUT]"
    )
    parser.add_argument(
        "target",
        help="Target IP address or domain name"
    )
    parser.add_argument(
        "-s", "--start-port",
        type=int,
        default=1,
        help="Starting port number (default: 1)"
    )
    parser.add_argument(
        "-e", "--end-port",
        type=int,
        default=1024,
        help="Ending port number (default: 1024)"
    )
    parser.add_argument(
        "-t", "--timeout",
        type=float,
        default=1.0,
        help="Connection timeout in seconds (default: 1.0)"
    )

    # If no arguments provided, fall back to interactive mode
    if len(sys.argv) == 1:
        print("No command-line arguments provided. Switching to interactive mode.\n")
        target = input("Enter target IP or domain: ").strip()
        try:
            start_port = int(input("Enter start port (default 1): ") or "1")
            end_port = int(input("Enter end port (default 1024): ") or "1024")
            timeout = float(input("Enter timeout in seconds (default 1.0): ") or "1.0")
        except ValueError:
            print("[-] Invalid port or timeout value. Using defaults (1-1024, timeout=1.0).")
            start_port, end_port, timeout = 1, 1024, 1.0
        args = argparse.Namespace(
            target=target,
            start_port=start_port,
            end_port=end_port,
            timeout=timeout
        )
    else:
        args = parser.parse_args()

    # Validate port range
    if args.start_port < 1:
        print("[-] Start port must be >= 1. Setting to 1.")
        args.start_port = 1
    if args.end_port > 65535:
        print("[-] End port exceeds maximum (65535). Setting to 65535.")
        args.end_port = 65535
    if args.start_port > args.end_port:
        print("[-] Start port cannot be greater than end port. Exiting.")
        sys.exit(1)

    # Resolve target to IP
    ip = resolve_target(args.target)
    print(f"[+] Target resolved: {args.target} -> {ip}")
    print(f"[+] Scanning ports {args.start_port} - {args.end_port} with timeout {args.timeout}s")
    print("[+] This may take a while...\n")
    start_time = datetime.now()

    open_ports = []
    try:
        for port in range(args.start_port, args.end_port + 1):
            if scan_port(ip, port, args.timeout):
                print(f"[+] Port {port}: OPEN")
                open_ports.append(port)
    except KeyboardInterrupt:
        print("\n[-] Scan interrupted by user.")
        sys.exit(0)

    end_time = datetime.now()
    duration = end_time - start_time

    # Summary
    print(f"\n[+] Scan completed in {duration.total_seconds():.2f} seconds")
    if open_ports:
        print(f"[+] Open ports found: {', '.join(map(str, open_ports))}")
    else:
        print("[-] No open ports found in the specified range.")


if __name__ == "__main__":
    main()