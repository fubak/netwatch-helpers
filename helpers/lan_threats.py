#!/usr/bin/env python3
"""Net Watch LAN threat checks (Linux, macOS, Windows). Read-only.

Gateway MAC drift (ARP spoofing), one MAC on several IPs, duplicate ARP replies
(Linux arp-scan only), and rogue DHCP servers (nmap broadcast-dhcp-discover,
needs raw-packet rights). Sends at most one DHCPDISCOVER, never a DHCPREQUEST.
Exit 1 when an ALERT is printed.
  lan_threats.py
"""
import collections
import ipaddress
import os
import re
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [HERE, os.path.join(HERE, "..", "netwatch-setup")]
import nw_common as nw  # noqa: E402

PRIV_HINT = {
    "linux": "owner may grant nmap cap_net_raw,cap_net_admin,cap_net_bind_service (netwatch-setup), or run it with sudo",
    "macos": "owner can run `sudo nmap --script broadcast-dhcp-discover` in Terminal and paste the result",
    "windows": "owner can run `nmap --script broadcast-dhcp-discover` in an Administrator PowerShell (needs Npcap) and paste the result",
}


def parse_dhcp_servers(text):
    return sorted(set(m.strip() for m in re.findall(r"Server Identifier:\s*([0-9.]+)", text)))


def linux_iface_cidr(iface):
    rc, out = nw.run(["ip", "-4", "-o", "addr", "show", "dev", iface, "scope", "global"], timeout=10)
    m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+/\d+)", out) if rc == 0 else None
    return str(ipaddress.ip_interface(m.group(1)).network) if m else ""


def main():
    osf = nw.os_family()
    home = nw.netwatch_home()
    status = 0
    gw, iface = nw.default_gateway(osf)
    if not gw:
        print("WARN no default route")
        return 1
    try:
        nets = nw.load_scope(home)
    except (FileNotFoundError, ValueError):
        print("SCOPE-FAIL: scope.txt missing or invalid")
        return 1
    if nw.scope_problems([gw], nets):
        print(f"SCOPE-FAIL: gateway {gw} not in scope.txt")
        return 1
    nw.run(nw.ping_command(gw, osf), timeout=5)  # refresh the neighbor entry
    rows, err = nw.neighbors(osf)
    if err:
        print(f"WARN neighbor table not readable: {err}")
    gwmac = next((m for ip, m in rows if ip == gw), "")
    print(f"os={osf} gateway={gw} iface={iface or '?'} mac={gwmac or 'unknown'}")

    base = os.path.join(home, "gateway_mac")
    if os.path.isfile(base):
        with open(base, encoding="utf-8-sig") as fh:
            want = nw.normalize_mac(fh.read().strip())
        if not gwmac:
            print("WARN gateway MAC unknown (no neighbor entry); cannot compare with baseline")
        elif gwmac != want:
            print(f"ALERT gateway-mac-changed expected={want or '?'} seen={gwmac} (possible ARP spoofing or hardware swap)")
            status = 1
        else:
            print("OK gateway MAC matches baseline")
    else:
        print("INFO no gateway_mac baseline; record it after the owner confirms the router")

    # IPv4 only: routers legitimately answer for IPv4 plus several IPv6 addresses.
    by_mac = collections.defaultdict(list)
    for ip, mac in rows:
        if nw.in_nets(ip, nets):
            by_mac[mac].append(ip)
    for mac, ips in sorted(by_mac.items()):
        if len(ips) > 1:
            print(f"WARN mac-on-multiple-ips {mac} {' '.join(sorted(ips))}")

    arp = shutil.which("arp-scan")
    if osf == "linux" and arp and iface:
        if nw.is_admin(osf) or "cap_net_raw" in nw.linux_caps(os.path.realpath(arp)):
            cidr = linux_iface_cidr(iface)
            if cidr and not nw.scope_problems([cidr], nets):
                rc, out = nw.run([arp, f"--interface={iface}", "--retry=2", cidr], timeout=300)
                if rc != 0:
                    print("SKIP duplicate ARP check: arp-scan failed")
                else:
                    dups = [ln for ln in out.splitlines() if "(DUP:" in ln]
                    for d in dups:
                        print(f"WARN duplicate-arp-reply {d.strip()}")
                    if not dups:
                        print("OK no duplicate ARP replies")
            else:
                print("SKIP duplicate ARP check: interface subnet not in scope.txt")
        else:
            print("SKIP duplicate ARP check: arp-scan lacks cap_net_raw (owner setup step)")
    else:
        print(f"SKIP duplicate ARP check: arp-scan not available on this {osf} host without elevation")

    nmap = nw.find_tool("nmap", osf)
    flags, raw_ok, why = nw.nmap_privilege(osf)
    if not nmap:
        print("SKIP rogue DHCP check: nmap not installed")
    elif not raw_ok:
        print(f"SKIP rogue DHCP check: {why}; {PRIV_HINT[osf]}")
    else:
        cmd = [nmap] + [f for f in flags if f == "--privileged"] + ["--script", "broadcast-dhcp-discover"]
        if osf == "linux" and iface:
            cmd[1:1] = ["-e", iface]
        rc, out = nw.run(cmd, timeout=120)
        servers = parse_dhcp_servers(out)
        print("dhcp_servers_seen=" + (",".join(servers) if servers else "none"))
        if not servers:
            print("INFO no DHCP offer captured; the probe may lack rights to bind UDP 68 or the port is busy. Use the controller's rogue DHCP detection instead.")
        exp = os.path.join(home, "expected_dhcp.txt")
        if not os.path.isfile(exp):
            print("INFO no expected_dhcp.txt baseline; cannot classify DHCP servers as rogue")
        else:
            with open(exp, encoding="utf-8-sig") as fh:
                expected = {ln.split("#", 1)[0].strip() for ln in fh if ln.split("#", 1)[0].strip()}
            for s in servers:
                if s not in expected:
                    print(f"ALERT rogue-dhcp server={s} not in expected_dhcp.txt")
                    status = 1
    return status


if __name__ == "__main__":
    sys.exit(main())
