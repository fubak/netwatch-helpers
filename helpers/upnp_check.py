#!/usr/bin/env python3
"""Net Watch UPnP IGD check (Linux, macOS, Windows). Read-only, no miniupnpc needed.

  upnp_check.py [--location URL] [--wait 3]

Sends one SSDP M-SEARCH for Internet Gateway Devices on the LAN, then for each
in-scope gateway reads its external IP and lists every port mapping
(GetGenericPortMappingEntry). Never adds or deletes mappings. Responses whose
LOCATION points outside scope.txt are ignored. --location skips SSDP.
"""
import argparse
import ipaddress
import os
import re
import socket
import sys
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [HERE, os.path.join(HERE, "..", "netwatch-setup")]
import nw_common as nw  # noqa: E402

ST = ["urn:schemas-upnp-org:device:InternetGatewayDevice:2", "urn:schemas-upnp-org:device:InternetGatewayDevice:1"]
SERVICES = ("WANIPConnection", "WANPPPConnection")
MAX_ENTRIES = 512


def ssdp(wait):
    locs = set()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    s.settimeout(wait)
    for st in ST:
        msg = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\n"
               f"MX: 2\r\nST: {st}\r\n\r\n").encode()
        s.sendto(msg, ("239.255.255.250", 1900))
    try:
        while True:
            data, _ = s.recvfrom(65535)
            m = re.search(rb"(?im)^location:\s*(\S+)", data)
            if m:
                locs.add(m.group(1).decode("ascii", "replace"))
    except socket.timeout:
        pass
    finally:
        s.close()
    return sorted(locs)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # a LAN device must not steer the scan host to another address


OPENER = urllib.request.build_opener(NoRedirect())


def fetch(url, data=None, headers=None):
    req = urllib.request.Request(url, data=data, headers=headers or {})
    with OPENER.open(req, timeout=10) as r:
        return r.read()


def strip_ns(root):
    for el in root.iter():
        if "}" in el.tag:
            el.tag = el.tag.split("}", 1)[1]
    return root


def control_url(location):
    root = strip_ns(ET.fromstring(fetch(location)))
    base = root.findtext("URLBase") or location
    for svc in root.iter("service"):
        stype = svc.findtext("serviceType") or ""
        if any(f":{s}:" in stype for s in SERVICES):
            return urllib.parse.urljoin(base, svc.findtext("controlURL") or ""), stype
    return "", ""


def soap(url, stype, action, args=""):
    body = (f'<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
            f's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>'
            f'<u:{action} xmlns:u="{stype}">{args}</u:{action}></s:Body></s:Envelope>').encode()
    hdr = {"Content-Type": 'text/xml; charset="utf-8"', "SOAPAction": f'"{stype}#{action}"'}
    root = strip_ns(ET.fromstring(fetch(url, body, hdr)))
    resp = root.find(f".//{action}Response")
    return {c.tag: (c.text or "") for c in resp} if resp is not None else {}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--location", default="")
    ap.add_argument("--wait", type=float, default=3.0)
    a = ap.parse_args()
    try:
        nets = nw.load_scope()
    except (FileNotFoundError, ValueError):
        print("SCOPE-FAIL: scope.txt missing or invalid")
        return 2
    default_gw, _ = nw.default_gateway()
    locs = [a.location] if a.location else ssdp(a.wait)
    if not locs:
        print("INFO no UPnP gateway answered (UPnP is off, or SSDP is blocked); confirm in the router UI")
        return 0
    for loc in locs:
        host = urllib.parse.urlparse(loc).hostname or ""
        try:
            ipaddress.ip_address(host)
        except ValueError:
            print(f"SKIP {loc}: LOCATION is not a literal IP")
            continue
        if nw.scope_problems([host], nets):
            print(f"SKIP {loc}: outside scope.txt")
            continue
        try:
            url, stype = control_url(loc)
        except Exception as e:  # noqa: BLE001
            print(f"WARN {loc}: description unreadable ({type(e).__name__})")
            continue
        if not url:
            print(f"INFO {host}: no WAN connection service")
            continue
        print(f"UPNP-ENABLED gateway={host} is_default_gateway={'yes' if host == default_gw else 'no'}")
        try:
            ext = soap(url, stype, "GetExternalIPAddress").get("NewExternalIPAddress", "")
            print(f"external_ip={ext or 'unknown'} (as reported by the router)")
        except Exception:  # noqa: BLE001
            print("external_ip=unknown")
        n = 0
        for i in range(MAX_ENTRIES):
            try:
                e = soap(url, stype, "GetGenericPortMappingEntry", f"<NewPortMappingIndex>{i}</NewPortMappingIndex>")
            except Exception:  # noqa: BLE001  (SOAP fault 713 = end of table)
                break
            if not e:
                break
            n += 1
            print("MAPPING\t{0}\t{1}\t-> {2}:{3}\tenabled={4}\tlease={5}\t{6}".format(
                e.get("NewProtocol", "?"), e.get("NewExternalPort", "?"), e.get("NewInternalClient", "?"),
                e.get("NewInternalPort", "?"), e.get("NewEnabled", "?"), e.get("NewLeaseDuration", "?"),
                e.get("NewPortMappingDescription", "")))
        print(f"summary gateway={host} mappings={n}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
