#!/usr/bin/env python3
"""Net Watch asset inventory.

Works on Linux, macOS, and Windows (pure Python 3 standard library).
  inventory.py build SCAN_DIR    merge neighbor/arp-scan/nmap/ping output into SCAN_DIR/inventory.json
  inventory.py diff SCAN_DIR     compare SCAN_DIR/inventory.json with $NETWATCH_HOME/baseline.json
  inventory.py accept SCAN_DIR   make this scan the new baseline (keeps existing labels)
  inventory.py label MAC TEXT    set a friendly label on a baseline entry
  inventory.py forget MAC        remove a device the owner says is gone
  inventory.py summary SCAN_DIR [--json] [--no-controller] [--site NAME]
                                 counts plus a table of unnamed devices, joined with UniFi
                                 classic client names, OUI vendor, network and SSID (GET only,
                                 when UNIFI_HOST/UNIFI_USER/UNIFI_PASS are set; otherwise the
                                 newest topology/latest/unifi-classic-clients.json is used)
"""
import datetime as dt
import glob
import ipaddress
import json
import os
import re
import shutil
import sys
import xml.etree.ElementTree as ET

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [HERE, os.path.join(HERE, "..", "netwatch-setup")]
import nw_common as nw  # noqa: E402

MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")
ARP_LINE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F:]{17})\s*(.*)$")


def home():
    return nw.netwatch_home()


def randomized(mac):
    """Locally administered bit set: likely a private/randomized Wi-Fi MAC."""
    return int(mac.split(":")[0], 16) & 0x02 == 0x02


def add(hosts, ip, mac, vendor="", hostname="", source=""):
    mac = (mac or "").lower()
    key = mac if MAC_RE.match(mac) else f"ip:{ip}"
    h = hosts.setdefault(key, {"mac": mac if MAC_RE.match(mac) else "", "ips": [],
                               "vendor": "", "hostname": "", "sources": []})
    if ip and ip not in h["ips"]:
        h["ips"].append(ip)
    if vendor and not h["vendor"]:
        h["vendor"] = vendor.strip()
    if hostname and not h["hostname"]:
        h["hostname"] = hostname
    if source and source not in h["sources"]:
        h["sources"].append(source)
    if h["mac"]:
        h["randomized_mac"] = randomized(h["mac"])


def parse_neigh_json(path, hosts):
    """Normalized neighbor table written by discover.py on any OS."""
    try:
        with open(path, encoding="utf-8") as fh:
            rows = json.load(fh)
    except (OSError, ValueError):
        return
    for r in rows:
        mac = nw.normalize_mac(r.get("mac", ""))
        if r.get("ip") and mac:
            add(hosts, r["ip"], mac, source="neigh")


def parse_ping(path, hosts):
    try:
        with open(path, encoding="utf-8") as fh:
            ips = json.load(fh)
    except (OSError, ValueError):
        return
    for ip in ips:
        add(hosts, ip, "", source="ping")


def attach_macs(hosts):
    """Fold IP-only entries (ping, unprivileged nmap) into MAC entries learned from the neighbor table."""
    by_ip = {}
    for k, h in hosts.items():
        if h["mac"]:
            for ip in h["ips"]:
                by_ip[ip] = k
    for k in [k for k in hosts if k.startswith("ip:")]:
        ip = k[3:]
        if ip in by_ip:
            tgt, src = hosts[by_ip[ip]], hosts.pop(k)
            for s in src["sources"]:
                if s not in tgt["sources"]:
                    tgt["sources"].append(s)
            if src["hostname"] and not tgt["hostname"]:
                tgt["hostname"] = src["hostname"]


def parse_arp(path, hosts, dups):
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            m = ARP_LINE.match(line.strip())
            if m:
                ip, mac, rest = m.groups()
                if "(DUP:" in rest:
                    dups.append({"ip": ip, "mac": mac.lower(), "note": rest.strip()})
                    continue
                add(hosts, ip, mac, vendor=rest, source="arp-scan")


def parse_nmap(path, hosts):
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError:
        return
    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue
        ip = mac = vendor = name = ""
        for addr in host.findall("address"):
            if addr.get("addrtype") in ("ipv4", "ipv6"):
                ip = addr.get("addr", "")
            elif addr.get("addrtype") == "mac":
                mac = addr.get("addr", "")
                vendor = addr.get("vendor", "")
        hn = host.find("hostnames/hostname")
        if hn is not None:
            name = hn.get("name", "")
        add(hosts, ip, mac, vendor, name, "nmap")


def load_scope():
    """In-scope networks from scope.txt; empty list means no filtering possible."""
    try:
        return nw.load_scope(home())
    except (FileNotFoundError, ValueError):
        return []


def in_scope(ip, nets):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr.version == n.version and addr in n for n in nets)


def build(scan_dir):
    hosts, dups = {}, []
    for name in ("neigh-before.json", "neigh.json"):
        p = os.path.join(scan_dir, name)
        if os.path.isfile(p):
            parse_neigh_json(p, hosts)
    for p in glob.glob(os.path.join(scan_dir, "arp-*.txt")):
        parse_arp(p, hosts, dups)
    for p in glob.glob(os.path.join(scan_dir, "nmap-sn-*.xml")):
        parse_nmap(p, hosts)
    for p in glob.glob(os.path.join(scan_dir, "ping-*.json")):
        parse_ping(p, hosts)
    attach_macs(hosts)
    nets = load_scope()
    dropped = 0
    if nets:
        # The neighbor table also lists docker bridges, VPNs, and other interfaces.
        for key in list(hosts):
            h = hosts[key]
            h["ips"] = [ip for ip in h["ips"] if in_scope(ip, nets)]
            if not h["ips"]:
                del hosts[key]
                dropped += 1
    inv = {"scan_dir": scan_dir, "hosts": hosts, "arp_duplicates": dups, "out_of_scope_dropped": dropped}
    with open(os.path.join(scan_dir, "inventory.json"), "w", encoding="utf-8") as fh:
        json.dump(inv, fh, indent=2)
    print(f"hosts={len(hosts)} arp_duplicates={len(dups)} out_of_scope_dropped={dropped}")
    return inv


def load(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def diff(scan_dir):
    cur = load(os.path.join(scan_dir, "inventory.json"))["hosts"]
    bpath = os.path.join(home(), "baseline.json")
    if not os.path.isfile(bpath):
        print("NO-BASELINE: review this scan with the owner, then run accept")
        return 0
    base = load(bpath)["hosts"]
    new = [k for k in cur if k not in base]
    gone = [k for k in base if k not in cur]
    moved = [k for k in cur if k in base and sorted(cur[k]["ips"]) != sorted(base[k]["ips"])]
    for k in new:
        h = cur[k]
        flag = " randomized-MAC" if h.get("randomized_mac") else ""
        print(f"NEW\t{','.join(h['ips'])}\t{h['mac']}\t{h['vendor'] or '?'}\t{h['hostname']}{flag}")
    for k in gone:
        b = base[k]
        print(f"MISSING\t{','.join(b['ips'])}\t{b['mac']}\t{b.get('label', '')}\tlast_seen={b.get('last_seen', '?')}")
    for k in moved:
        print(f"IP-CHANGED\t{k}\t{','.join(base[k]['ips'])} -> {','.join(cur[k]['ips'])}\t{base[k].get('label', '')}")
    print(f"summary new={len(new)} missing={len(gone)} ip_changed={len(moved)}")
    return 0


def accept(scan_dir):
    """Merge the scan into the baseline. Devices not seen this time are kept."""
    cur = load(os.path.join(scan_dir, "inventory.json"))
    stamp = dt.datetime.now().astimezone().isoformat(timespec="seconds")
    bpath = os.path.join(home(), "baseline.json")
    base = {"hosts": {}}
    if os.path.isfile(bpath):
        base = load(bpath)
        shutil.copy2(bpath, bpath + ".prev")
    hosts = base.setdefault("hosts", {})
    for k, h in cur["hosts"].items():
        old = hosts.get(k, {})
        h["label"] = old.get("label", h.get("label", ""))
        h["first_seen"] = old.get("first_seen", stamp)
        h["last_seen"] = stamp
        hosts[k] = h
    base["updated"] = stamp
    base["last_scan_dir"] = scan_dir
    with open(bpath, "w", encoding="utf-8") as fh:
        json.dump(base, fh, indent=2)
    print(f"baseline merged ({len(cur['hosts'])} seen, {len(hosts)} total); previous kept as baseline.json.prev")
    return 0


def forget(mac):
    bpath = os.path.join(home(), "baseline.json")
    base = load(bpath)
    if base["hosts"].pop(mac.lower(), None) is None:
        print(f"not in baseline: {mac}")
        return 1
    with open(bpath, "w", encoding="utf-8") as fh:
        json.dump(base, fh, indent=2)
    print(f"forgot {mac.lower()}")
    return 0


def label(mac, text):
    bpath = os.path.join(home(), "baseline.json")
    base = load(bpath)
    key = mac.lower()
    if key not in base["hosts"]:
        print(f"not in baseline: {mac}")
        return 1
    base["hosts"][key]["label"] = text
    with open(bpath, "w", encoding="utf-8") as fh:
        json.dump(base, fh, indent=2)
    print(f"labeled {key}: {text}")
    return 0


# ---------------------------------------------------------------- summary
def _unifi_clients(site, use_controller):
    """(clients, source_note). GET /stat/sta through nw_http (read-only, redacted); falls back to the
    newest topology collection. Never prints credentials."""
    errors = []
    if use_controller:
        try:
            import nw_http  # same bin folder
            osf = nw.os_family()
            env = nw.env_file_path(osf)
            if os.path.isfile(env):
                vals, _probs = nw.load_env(env, osf)
                if vals.get("UNIFI_HOST") and vals.get("UNIFI_USER") and vals.get("UNIFI_PASS"):
                    st, raw = nw_http.call("unifi-classic", "GET", f"/api/s/{site}/stat/sta", vals)
                    vals = None
                    if 200 <= st < 300:
                        obj = nw.redact(json.loads(raw.decode("utf-8", "replace")))
                        data = obj.get("data", []) if isinstance(obj, dict) else []
                        return [c for c in data if isinstance(c, dict)], "unifi-classic live"
                    errors.append(f"HTTP {st}")
                else:
                    errors.append("UniFi classic login not set")
            else:
                errors.append("env file missing")
        except Exception as e:  # connector trouble is reported, not fatal
            errors.append(str(e)[:120])
    cached = os.path.join(home(), "topology", "latest", "unifi-classic-clients.json")
    if os.path.isfile(cached):
        try:
            obj = load(cached)
            data = obj.get("data", []) if isinstance(obj, dict) else obj
            note = "topology/latest cache"
            if errors:
                note += f" (live: {'; '.join(errors)})"
            return [c for c in data if isinstance(c, dict)], note
        except (OSError, ValueError):
            errors.append("cache unreadable")
    return [], "none (" + ("; ".join(errors) or "controller skipped") + ")"


def _clean(v, n=40):
    return re.sub(r"[\x00-\x1f\x7f]+", " ", str(v or "")).strip()[:n]


def summary(scan_dir, as_json=False, use_controller=True, site="default"):
    inv = load(os.path.join(scan_dir, "inventory.json"))
    hosts = inv.get("hosts", {})
    if isinstance(hosts, list):  # tolerate an older list shape
        hosts = {(h.get("mac") or f"ip:{(h.get('ips') or [''])[0]}"): h for h in hosts if isinstance(h, dict)}
    base = {}
    bpath = os.path.join(home(), "baseline.json")
    if os.path.isfile(bpath):
        base = load(bpath).get("hosts", {})
    clients, csrc = _unifi_clients(site, use_controller)
    by_mac = {nw.normalize_mac(c.get("mac")): c for c in clients if nw.normalize_mac(c.get("mac"))}
    by_ip = {c.get("ip"): c for c in clients if c.get("ip")}
    rows, matched, named = [], 0, 0
    sources_count = {}
    for key, h in hosts.items():
        ips = h.get("ips") or []
        mac = h.get("mac") or ""
        c = by_mac.get(mac) or next((by_ip[i] for i in ips if i in by_ip), None)
        if c is not None:
            matched += 1
        for src in h.get("sources", []):
            sources_count[src] = sources_count.get(src, 0) + 1
        name = _clean((c or {}).get("name")) or _clean((c or {}).get("hostname")) or _clean(h.get("hostname")) \
            or _clean(base.get(key, {}).get("label"))
        if name:
            named += 1
            continue
        net = _clean((c or {}).get("network"), 30)
        essid = _clean((c or {}).get("essid"), 32)
        rows.append({"ip": ",".join(ips), "mac": mac or "?",
                     "vendor": _clean(h.get("vendor")) or _clean((c or {}).get("oui")) or
                     ("randomized MAC" if h.get("randomized_mac") else "?"),
                     "network": " / ".join(x for x in (net, essid) if x) or ("wired" if (c or {}).get("is_wired") else "?"),
                     "sources": ",".join(h.get("sources", [])) + (",unifi" if c is not None else "")})
    scan_macs = {h.get("mac") for h in hosts.values() if h.get("mac")}
    only_unifi = [m for m in by_mac if m not in scan_macs]
    out = {"scan_dir": scan_dir, "hosts": len(hosts), "named": named, "unnamed": len(rows),
           "randomized_macs": sum(1 for h in hosts.values() if h.get("randomized_mac")),
           "arp_duplicates": len(inv.get("arp_duplicates", [])), "out_of_scope_dropped": inv.get("out_of_scope_dropped", 0),
           "by_source": sources_count, "controller": csrc, "controller_clients": len(clients),
           "matched_to_controller": matched, "controller_only": len(only_unifi), "unknowns": rows}
    if as_json:
        nw.print_json(out)
        return 0
    print(f"hosts={out['hosts']} named={named} unnamed={len(rows)} randomized_macs={out['randomized_macs']} "
          f"arp_duplicates={out['arp_duplicates']} out_of_scope_dropped={out['out_of_scope_dropped']}")
    print("by_source=" + ",".join(f"{k}:{v}" for k, v in sorted(sources_count.items())))
    print(f"controller={csrc} controller_clients={len(clients)} matched={matched} controller_only={len(only_unifi)}")
    if rows:
        print("== unnamed devices")
        print("ip\tmac\tvendor\tnetwork/ssid\tsources")
        for r in sorted(rows, key=lambda r: [int(x) if x.isdigit() else 0 for x in r["ip"].split(",")[0].split(".")]):
            print(f"{r['ip']}\t{r['mac']}\t{r['vendor']}\t{r['network']}\t{r['sources']}")
    return 0


def main(argv):
    if len(argv) < 3:
        print(__doc__)
        return 2
    cmd = argv[1]
    if cmd == "build":
        build(argv[2])
        return 0
    if cmd == "diff":
        return diff(argv[2])
    if cmd == "accept":
        return accept(argv[2])
    if cmd == "forget":
        return forget(argv[2])
    if cmd == "summary":
        opts = argv[3:]
        site = "default"
        if "--site" in opts:
            i = opts.index("--site")
            if i + 1 >= len(opts) or not re.fullmatch(r"[A-Za-z0-9_-]{1,40}", opts[i + 1]):
                print(__doc__)
                return 2
            site = opts[i + 1]
            opts = opts[:i] + opts[i + 2:]
        if any(o not in ("--json", "--no-controller") for o in opts):
            print(__doc__)
            return 2
        return summary(argv[2], "--json" in opts, "--no-controller" not in opts, site)
    if cmd == "label" and len(argv) >= 4:
        return label(argv[2], " ".join(argv[3:]))
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
