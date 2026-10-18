#!/usr/bin/env python3
"""Net Watch external exposure probe. Run from OUTSIDE the home network (the box).

  wan_probe.py --ip WAN_IP --confirmed-by-router

Plain TCP connect to a short list of commonly exposed ports. No payloads, no
login attempts, no service fingerprinting. Only ever point it at the WAN
address the owner's own router reported in this session.
"""
import argparse
import ipaddress
import socket
import sys
from concurrent.futures import ThreadPoolExecutor

PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 53: "dns", 80: "http", 443: "https",
    445: "smb", 554: "rtsp-camera", 1194: "openvpn-tcp", 1883: "mqtt",
    3389: "rdp", 5000: "synology-http", 5001: "synology-https", 5900: "vnc",
    7547: "tr-069", 8080: "http-alt", 8123: "home-assistant", 8443: "https-alt",
    8883: "mqtt-tls", 9000: "portainer", 32400: "plex",
}


def probe(ip, port, timeout):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return port, "open"
    except socket.timeout:
        return port, "filtered"
    except OSError:
        return port, "closed"


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--ip", required=True)
    p.add_argument("--confirmed-by-router", action="store_true",
                   help="required: the owner's router reported this WAN IP this session")
    p.add_argument("--timeout", type=float, default=2.0)
    a = p.parse_args()
    if not a.confirmed_by_router:
        print("REFUSED: confirm the WAN IP from the owner's router first")
        return 2
    try:
        ip = ipaddress.ip_address(a.ip)
    except ValueError:
        print("REFUSED: --ip must be a literal IP address (hostnames, including DDNS names, are refused)")
        return 2
    cgnat = ipaddress.ip_network("100.64.0.0/10")
    if ip.version == 4 and ip in cgnat:
        print("REFUSED: CGNAT address; inbound exposure is the ISP's, not testable from here")
        return 2
    if not ip.is_global or ip.is_multicast:
        print("REFUSED: not a public address")
        return 2
    with ThreadPoolExecutor(max_workers=8) as ex:
        results = sorted(ex.map(lambda pt: probe(str(ip), pt, a.timeout), PORTS))
    for port, state in results:
        print(f"{port}\t{PORTS[port]}\t{state}")
    opened = [p for p, s in results if s == "open"]
    print(f"open_count={len(opened)} open={','.join(map(str, opened)) or 'none'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
