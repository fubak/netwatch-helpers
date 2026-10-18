#!/usr/bin/env python3
"""Net Watch host discovery (Linux, macOS, Windows). Read-only, no port scan.

  discover.py CIDR [CIDR ...] [--no-ping-sweep] [--allow-large]

Order: passive neighbor table, arp-scan (Linux with cap_net_raw, or root, on-link
only), nmap -sn -T3 if installed, else a polite ping sweep (max /22 per CIDR
unless --allow-large). Then refreshes the neighbor table and builds inventory.json.
"""
import argparse
import concurrent.futures as cf
import datetime as dt
import ipaddress
import json
import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [HERE, os.path.join(HERE, "..", "netwatch-setup"), os.path.join(HERE, "..", "netwatch-asset-inventory")]
import nw_common as nw  # noqa: E402

SWEEP_MAX_HOSTS = 1024
SWEEP_WORKERS = 32


def save_neighbors(path, osf):
    rows, err = nw.neighbors(osf)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump([{"ip": ip, "mac": mac} for ip, mac in rows], fh, indent=1)
    if err:
        print(f"WARN neighbor table not readable: {err}")
    return rows


def on_link_iface_linux(cidr):
    first = str(ipaddress.ip_network(cidr, strict=False).network_address)
    rc, out = nw.run(["ip", "route", "get", first], timeout=10)
    if rc != 0:
        return ""
    words = out.split()
    if "via" in words or "dev" not in words:
        return ""
    return words[words.index("dev") + 1]


def arp_scan_ok(osf):
    # Linux only: macOS arp-scan needs sudo (the bot never elevates); Windows has none.
    tool = shutil.which("arp-scan")
    if not tool or osf != "linux":
        return None
    if nw.is_admin(osf):
        return tool
    if "cap_net_raw" in nw.linux_caps(os.path.realpath(tool)):
        return tool
    return None


def ping_sweep(net, osf, out_path):
    hosts = list(net.hosts()) if net.num_addresses > 2 else list(net)
    alive = []

    def probe(ip):
        rc, out = nw.run(nw.ping_command(str(ip), osf), timeout=5)
        return str(ip) if nw.ping_ok(rc, out, osf) else None

    with cf.ThreadPoolExecutor(max_workers=SWEEP_WORKERS) as ex:
        for r in ex.map(probe, hosts):
            if r:
                alive.append(r)
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(alive, fh, indent=1)
    return alive


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cidrs", nargs="+")
    ap.add_argument("--no-ping-sweep", action="store_true", help="skip the fallback ping sweep when nmap is missing")
    ap.add_argument("--allow-large", action="store_true", help="allow ping sweeps larger than /22")
    a = ap.parse_args()
    osf = nw.os_family()
    home = nw.netwatch_home()
    nw.require_scope(a.cidrs, home)

    out = os.path.join(home, "scans", dt.datetime.now().strftime("%Y%m%d-%H%M%S"))
    os.makedirs(out, exist_ok=True)
    print(f"scan_dir={out} os={osf}")

    save_neighbors(os.path.join(out, "neigh-before.json"), osf)
    nmap = nw.find_tool("nmap", osf)
    flags, raw_ok, why = nw.nmap_privilege(osf)
    arp = arp_scan_ok(osf)
    for cidr in a.cidrs:
        net = ipaddress.ip_network(cidr, strict=False)
        safe = cidr.replace("/", "_").replace(":", "-")
        if arp and net.version == 4:
            iface = on_link_iface_linux(cidr)
            if not iface:
                print(f"INFO {cidr} is not on-link from this host; ARP skipped")
            else:
                cmd = [arp, f"--interface={iface}", "--retry=2", cidr]
                rc, txt = nw.run(cmd, timeout=300)
                with open(os.path.join(out, f"arp-{safe}.txt"), "w", encoding="utf-8") as fh:
                    fh.write(txt)
                if rc != 0:
                    print(f"WARN arp-scan failed for {cidr} (rc={rc}); see arp-{safe}.txt")
        elif net.version == 4:
            print(f"INFO ARP sweep unavailable here ({osf}: arp-scan missing, unprivileged, or unsupported); using nmap or ping")
        if nmap:
            # -sn: host discovery only. -T3: polite timing for fragile IoT.
            cmd = [nmap] + flags + ["-sn", "-T3", "-oX", os.path.join(out, f"nmap-sn-{safe}.xml"), cidr]
            rc, txt = nw.run(cmd, timeout=900)
            if rc != 0:
                print(f"WARN nmap -sn failed for {cidr}: {txt.strip()[:200]}")
        elif not a.no_ping_sweep:
            if net.num_addresses > SWEEP_MAX_HOSTS and not a.allow_large:
                print(f"SKIP ping sweep of {cidr}: larger than /22; rerun with --allow-large after the owner agrees")
                continue
            alive = ping_sweep(net, osf, os.path.join(out, f"ping-{safe}.json"))
            print(f"INFO nmap missing; ping sweep of {cidr} found {len(alive)} responders (devices that block ping are missed)")
    if not nmap:
        print("WARN nmap not installed; results are thinner. See netwatch-setup for install options (ask the owner first).")
    save_neighbors(os.path.join(out, "neigh.json"), osf)

    import inventory  # same bin folder
    inventory.build(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
