#!/usr/bin/env python3
"""Net Watch internal port scan (Linux, macOS, Windows). Polite TCP connect scan.

  portscan.py TARGET [TARGET ...] [--top N] [--exclude IP[,IP]] [--version-light]

Scope-checked. Uses nmap -sT -T3 --top-ports N --open when nmap exists (connect
scans need no admin rights on any OS); otherwise a Python connect scan of common
ports (max 256 addresses). --version-light adds -sV --version-light and is allowed
only for single-host targets (owner-confirmed general-purpose hosts, never smart-home).
Results: NETWATCH_HOME/scans/ports-<time>.xml or .json, plus a summary on stdout.
"""
import argparse
import concurrent.futures as cf
import datetime as dt
import ipaddress
import json
import os
import socket
import sys
import xml.etree.ElementTree as ET

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [HERE, os.path.join(HERE, "..", "netwatch-setup")]
import nw_common as nw  # noqa: E402

COMMON = [21, 22, 23, 25, 53, 80, 81, 110, 111, 135, 139, 143, 443, 445, 554, 631, 1883, 1900, 2375, 3000,
          3306, 3389, 5000, 5001, 5432, 5900, 6379, 7547, 8000, 8008, 8080, 8081, 8123, 8443, 8883, 9000, 9100, 27017]
FALLBACK_MAX = 256


def summarize_nmap(path):
    rows = []
    try:
        root = ET.parse(path).getroot()
    except (ET.ParseError, OSError):
        return rows
    for h in root.findall("host"):
        addr = next((a.get("addr") for a in h.findall("address") if a.get("addrtype") in ("ipv4", "ipv6")), "?")
        for p in h.findall("ports/port"):
            st = p.find("state")
            if st is not None and st.get("state") == "open":
                svc = p.find("service")
                name = svc.get("name", "") if svc is not None else ""
                ver = " ".join(filter(None, [svc.get("product", ""), svc.get("version", "")])) if svc is not None else ""
                rows.append((addr, int(p.get("portid")), name, ver))
    return rows


def connect_scan(addrs):
    def probe(job):
        ip, port = job
        try:
            with socket.create_connection((ip, port), timeout=1.0):
                return (ip, port)
        except OSError:
            return None
    jobs = [(ip, p) for ip in addrs for p in COMMON]
    # 64 parallel connects keep a /24 fallback scan to a few minutes; each is a single SYN.
    with cf.ThreadPoolExecutor(max_workers=64) as ex:
        return [r for r in ex.map(probe, jobs) if r]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("targets", nargs="+")
    ap.add_argument("--top", type=int, default=200)
    ap.add_argument("--exclude", default="")
    ap.add_argument("--version-light", action="store_true")
    a = ap.parse_args()
    excludes = [e.strip() for e in a.exclude.split(",") if e.strip()]
    nw.require_scope(a.targets + excludes)
    if a.version_light and any(ipaddress.ip_network(t, strict=False).num_addresses > 1 for t in a.targets):
        print("REFUSED: --version-light only for single hosts the owner confirmed are general-purpose (NAS, PC, router)")
        return 2
    if not 1 <= a.top <= 1000:
        print("REFUSED: --top must be 1..1000")
        return 2
    osf = nw.os_family()
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    scans = os.path.join(nw.netwatch_home(), "scans")
    os.makedirs(scans, exist_ok=True)
    nmap = nw.find_tool("nmap", osf)
    if nmap:
        out = os.path.join(scans, f"ports-{stamp}.xml")
        flags, _, _ = nw.nmap_privilege(osf)  # --unprivileged on unelevated Windows/macOS hosts
        cmd = [nmap] + flags + ["-sT", "-T3", "--top-ports", str(a.top), "--open", "-oX", out]
        if a.version_light:
            cmd += ["-sV", "--version-light"]
        if excludes:
            cmd += ["--exclude", ",".join(excludes)]
        rc, txt = nw.run(cmd + a.targets, timeout=3600)
        if rc != 0:
            print(f"WARN nmap failed: {txt.strip()[:200]}")
        rows = summarize_nmap(out)
    else:
        addrs = []
        for t in a.targets:
            net = ipaddress.ip_network(t, strict=False)
            addrs += [str(x) for x in (net.hosts() if net.num_addresses > 2 else net)]
        addrs = [x for x in addrs if x not in excludes]
        if len(addrs) > FALLBACK_MAX:
            print(f"REFUSED: fallback scan limited to {FALLBACK_MAX} addresses; install nmap (ask the owner) or narrow the target")
            return 2
        print(f"INFO nmap missing; Python connect scan of {len(COMMON)} common ports")
        rows = [(ip, port, "", "") for ip, port in connect_scan(addrs)]
        out = os.path.join(scans, f"ports-{stamp}.json")
        with open(out, "w", encoding="utf-8") as fh:
            json.dump([{"ip": r[0], "port": r[1]} for r in rows], fh, indent=1)
    print(f"results={out}")
    def order(r):
        try:
            a_ = ipaddress.ip_address(r[0])
            return (a_.version, int(a_), r[1])
        except ValueError:
            return (9, 0, r[1])
    for ip, port, name, ver in sorted(rows, key=order):
        print(f"OPEN\t{ip}\t{port}\t{name}\t{ver}")
    print(f"summary open={len(rows)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
