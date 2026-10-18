#!/usr/bin/env python3
"""Net Watch preflight: read-only checks of the scan host on Linux, macOS, or Windows.

Prints OS facts, which tools exist, privilege level, Net Watch files, env file
location and permissions, and which connector variables are set (never values).
Installs nothing. Usage:
  preflight.py                     full report
  preflight.py --suggest-scope     only the suggested home LAN CIDR (from this host's own
                                   address and netmask; nothing is scanned)
  preflight.py --detect            setup facts for one confirm card: LAN interface, IP/CIDR,
                                   default gateway, gateway MAC (neighbor table), vendor guess
                                   from the OUI, tools, linger/ufw/relay ports, env keys set or
                                   MISSING (never values). Add --json for JSON.
  preflight.py --env-template [--gear unifi|none] [--no-alerts]
                                   print an env file template with placeholders only; the
                                   gateway is prefilled. Never opens the env file and never writes.
  preflight.py --drift [--bin DIR] [--manifest FILE]
                                   sha256 of every helper in bin/ (default: the folder this script
                                   runs from) against MANIFEST.sha256 (default: bin/MANIFEST.sha256,
                                   shipped in the bundle). One OK/STALE/MISSING/EXTRA line per file;
                                   exit 0 clean, 1 drift, 2 manifest missing or unreadable. Read-only.
  preflight.py --health            one GREEN/YELLOW/RED line each: connectors, relay legs, last routine run,
                                   disk, open changes, drift, TLS settings. Read-only; exit 1 if any RED.
  preflight.py --mark-routine NAME record that routine NAME ran now (NETWATCH_HOME/state/routine-NAME.last)
  preflight.py --release-check --repo OWNER/NAME [--api URL] [--installed vX.Y.Z]
                                   read-only: compare the installed helper version with the latest GitHub
                                   release. Prints the result only; never downloads, and never takes a
                                   fingerprint from the API (a new one arrives only with an updated skill).
"""
import datetime as dt
import hashlib
import json
import os
import platform
import re
import shutil
import socket
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [HERE, os.path.join(HERE, "..", "netwatch-setup")]
import nw_common as nw  # noqa: E402

CONNECTOR_VARS = [
    "UNIFI_HOST", "UNIFI_API_KEY", "UNIFI_USER", "UNIFI_PASS",
    "OPNSENSE_URL", "OPNSENSE_KEY", "OPNSENSE_SECRET", "PFSENSE_URL", "PFSENSE_API_KEY",
    "SYNOLOGY_URL", "SYNOLOGY_USER", "SYNOLOGY_PASS",
    "OMADA_URL", "OMADA_CLIENT_ID", "OMADA_CLIENT_SECRET", "OMADA_OMADAC_ID",
    "PIHOLE_URL", "PIHOLE_PASSWORD", "ADGUARD_URL", "ADGUARD_USER", "ADGUARD_PASS",
    "HA_URL", "HA_TOKEN", "ASUS_SSH_HOST", "ASUS_SSH_USER", "ASUS_SSH_KEY",
    "FIREWALLA_MSP_DOMAIN", "FIREWALLA_TOKEN",
    "ALERT_INBOUND_TOKEN", "ALERT_SOURCES", "ROUTINE_WEBHOOK_URL", "ROUTINE_WEBHOOK_KEY",
]
TOOLS = {
    "linux": ["nmap", "arp-scan", "ssh", "ip", "ping", "nmcli"],
    "macos": ["nmap", "ssh", "arp", "ping", "route", "brew"],
    "windows": ["nmap", "ssh", "arp", "ping", "route", "icacls", "powershell", "pwsh", "winget", "choco"],
}
OPTIONAL_NOTE = {
    "linux": "arp-scan and nmcli are optional",
    "macos": "brew is only needed to install nmap",
    "windows": "winget/choco/pwsh are optional; arp-scan does not exist on Windows",
}
AI_CLIS = ["grok", "cursor-agent", "claude", "ollama", "gemini", "codex", "aider", "llm"]


def os_release():
    osf = nw.os_family()
    if osf == "linux":
        try:
            info = platform.freedesktop_os_release()
            return info.get("PRETTY_NAME", "Linux")
        except (OSError, AttributeError):
            return "Linux"
    if osf == "macos":
        return "macOS " + platform.mac_ver()[0]
    return f"Windows {platform.release()} ({platform.version()})"


def print_suggestion(osf):
    s = nw.suggest_scope(osf)
    print(f"local_ip={s['local_ip'] or 'none'} prefix={s['prefix'] or '?'} gateway={s['gateway'] or 'none'}")
    print(f"suggested_scope={s['suggest'] or 'none'} ({s['reason']})")


# ---------------------------------------------------------------- --detect / --env-template
# Small built-in OUI list for common home gateways; the nmap prefix file is used when present.
BUILTIN_OUI = {
    "Ubiquiti": ("68:d7:9a", "24:5a:4c", "74:83:c2", "78:8a:20", "80:2a:a8", "f0:9f:c2", "fc:ec:da", "18:e8:29",
                 "b4:fb:e4", "e0:63:da", "74:ac:b9", "70:a7:41", "d0:21:f9", "60:22:32", "9c:05:d6", "28:70:4e",
                 "d8:b3:70", "0c:ea:14", "ac:8b:a9", "94:2a:6f", "04:18:d6", "24:a4:3c", "dc:9f:db", "44:d9:e7",
                 "68:72:51", "00:27:22", "00:15:6d", "f4:92:bf", "1c:6a:1b", "e4:38:83", "84:78:48"),
}
NMAP_PREFIX_FILES = ("/usr/share/nmap/nmap-mac-prefixes", "/usr/local/share/nmap/nmap-mac-prefixes",
                     "/opt/homebrew/share/nmap/nmap-mac-prefixes",
                     r"C:\Program Files (x86)\Nmap\nmap-mac-prefixes", r"C:\Program Files\Nmap\nmap-mac-prefixes")
GEAR_BY_VENDOR = [(r"ubiquiti", "unifi"), (r"tp-?link", "tp-link (omada or consumer)"), (r"asustek|\basus", "asus"),
                  (r"eero", "eero"), (r"netgate", "pfsense"), (r"firewalla", "firewalla"), (r"netgear", "netgear")]
ALERT_KEYS = ["ALERT_SOURCES", "ALERT_INBOUND_TOKEN", "ROUTINE_WEBHOOK_URL", "ROUTINE_WEBHOOK_KEY"]
UNIFI_KEYS = ["UNIFI_HOST", "UNIFI_USER", "UNIFI_PASS", "UNIFI_API_KEY"]


def oui_vendor(mac):
    """(vendor, source) for a MAC; ('randomized', 'local bit') for locally administered addresses."""
    mac = nw.normalize_mac(mac)
    if not mac:
        return "", ""
    if int(mac[:2], 16) & 0x02:
        return "randomized or locally administered", "local bit"
    pfx = mac[:8]
    for path in NMAP_PREFIX_FILES:
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                want = pfx.replace(":", "").upper()
                for line in fh:
                    if line.startswith(want):
                        return line[6:].strip(), "nmap-mac-prefixes"
        except OSError:
            continue
    for vendor, prefixes in BUILTIN_OUI.items():
        if pfx in prefixes:
            return vendor, "builtin"
    return "", "unknown OUI"


def gear_guess(vendor):
    for pat, gear in GEAR_BY_VENDOR:
        if re.search(pat, vendor or "", re.I):
            return gear
    return ""


def _quiet(cmd, timeout=10):
    try:
        rc, out = nw.run(cmd, timeout=timeout)
    except Exception:
        return 1, ""
    return rc, out.strip()


def relay_listeners(osf, ports=(8787, 5514)):
    """Which local sockets already listen on the relay ports (Linux ss only; read-only)."""
    if osf != "linux" or not shutil.which("ss"):
        return "not checked"
    rc, out = _quiet(["ss", "-H", "-ltnu"])
    if rc != 0:
        return "not checked"
    hits = []
    for line in out.splitlines():
        f = line.split()
        if len(f) >= 5 and any(f[4].endswith(f":{p}") for p in ports):
            hits.append(f"{f[0]} {f[4]}")
    return ", ".join(hits) or "none"


def detect(osf):
    gw, iface = nw.default_gateway(osf)
    s = nw.suggest_scope(osf, gw_iface=(gw, iface))
    d = {"scan_host": socket.gethostname(), "os": osf, "release": os_release(), "python": platform.python_version(),
         "launcher": nw.python_cmd(osf), "user": nw.getpass.getuser(), "lan_iface": iface or "",
         "lan_ip": s["local_ip"], "prefix": s["prefix"],
         "lan_cidr": f"{s['local_ip']}/{s['prefix']}" if s["local_ip"] and s["prefix"] else "",
         "suggested_scope": s["suggest"], "scope_note": s["reason"], "default_gateway": gw or "",
         "gateway_mac": "", "gateway_vendor": "", "vendor_source": "", "gear_guess": "",
         "netwatch_home": nw.netwatch_home(), "tools": {}, "env_file": "", "env_state": "", "env_keys": {}}
    if gw:
        rows, _err = nw.neighbors(osf)
        mac = next((m for ip, m in rows if ip == gw), "")
        d["gateway_mac"] = mac
        if mac:
            d["gateway_vendor"], d["vendor_source"] = oui_vendor(mac)
            d["gear_guess"] = gear_guess(d["gateway_vendor"])
    for t in TOOLS[osf][:2] if osf == "linux" else TOOLS[osf][:1]:
        p = nw.find_tool(t, osf)
        state = "present" if p else "missing"
        if t == "arp-scan":
            state += " (optional)"
        if p and osf == "linux":
            caps = nw.linux_caps(os.path.realpath(p))
            state += " caps=" + ("cap_net_raw" if "cap_net_raw" in caps else "none")
        d["tools"][t] = state
    if osf == "linux":
        d["tools"]["traceroute"] = "present" if (shutil.which("traceroute") or shutil.which("tracepath")) else "missing (optional)"
        rc, out = _quiet(["loginctl", "show-user", nw.getpass.getuser(), "-p", "Linger"])
        d["linger"] = out.split("=", 1)[1] if rc == 0 and "=" in out else "unknown"
        state = re.compile(r"[a-z-]{2,20}")  # systemctl is-active prints one word; anything else is an error
        _rc, out = _quiet(["systemctl", "is-active", "ufw"])
        d["ufw"] = out if state.fullmatch(out) else "unknown"
        _rc, out = _quiet(["systemctl", "--user", "is-active", "netwatch-alertd"])
        d["relay_service"] = out if state.fullmatch(out) else "unknown"
        d["relay_port_listeners"] = relay_listeners(osf)
    env_path = nw.env_file_path(osf)
    d["env_file"] = env_path
    if not os.path.isfile(env_path):
        d["env_state"] = "missing"
    else:
        perm = nw.env_perm_problems(env_path, osf)
        d["env_state"] = "ok" if not perm else "PERMS-PROBLEM"
        vals, _probs = nw.load_env(env_path, osf)
        keys = UNIFI_KEYS + ALERT_KEYS + [k for k in CONNECTOR_VARS if k not in UNIFI_KEYS + ALERT_KEYS and vals.get(k)]
        d["env_keys"] = {k: ("set" if vals.get(k) else "MISSING") for k in keys}
        vals = None  # values are never kept or printed
    return d


def print_detect(d, as_json=False):
    if as_json:
        nw.print_json(d)
        return 0
    print("== detect (read-only; owner confirms)")
    for k in ("scan_host", "os", "release", "python", "launcher", "user", "netwatch_home", "lan_iface", "lan_ip",
              "lan_cidr", "suggested_scope", "scope_note", "default_gateway", "gateway_mac", "gateway_vendor",
              "vendor_source", "gear_guess"):
        print(f"{k}={d.get(k) if d.get(k) not in (None, '') else 'none'}")
    print("== tools")
    for t, v in d["tools"].items():
        print(f"{t}={v}")
    for k in ("linger", "ufw", "relay_service", "relay_port_listeners"):
        if k in d:
            print(f"{k}={d[k]}")
    print("== env file (set or MISSING only, never values)")
    print(f"env_file={d['env_file']} state={d['env_state']}")
    for k, v in d["env_keys"].items():
        print(f"{k}={v}")
    return 0


def env_template(osf, gear=None, alerts=True):
    """Placeholder-only env template. Never opens the env file."""
    gw, _ = nw.default_gateway(osf)
    gwip = gw or "GATEWAY_IP"
    if gear is None:
        mac = ""
        if gw:
            rows, _err = nw.neighbors(osf)
            mac = next((m for ip, m in rows if ip == gw), "")
        gear = "unifi" if gear_guess(oui_vendor(mac)[0]) == "unifi" else "none"
    env_path = nw.env_file_path(osf)
    lines = ["# Net Watch env file template (placeholders only). Edit values in your own editor.",
             "# Never paste these values in chat. One NAME=value per line; quotes optional.",
             f"# Location on this host: {env_path}"]
    if os.path.exists(env_path):
        lines.append("# NOTE: that file already exists. Do not overwrite it: run preflight.py --detect to see which")
        lines.append("# keys are MISSING and add only those lines.")
    if gear == "unifi":
        lines += ["", "# UniFi: local View Only admin named netwatch (classic API, used by the map and IDS events)",
                  f"UNIFI_HOST={gwip}", "UNIFI_USER=netwatch", "UNIFI_PASS=PUT_NETWATCH_PASSWORD_HERE",
                  "# Keep the next line only if the console uses its default self-signed certificate",
                  "UNIFI_VERIFY_SSL=false",
                  "# Optional Integration API key (carries the creating admin's role; skip by default)",
                  "# UNIFI_API_KEY=ONLY_IF_YOU_CREATED_ONE"]
    else:
        lines += ["", "# Gateway connector: add the names from your gear's connector skill here."]
    if alerts:
        launcher = nw.python_cmd(osf)
        lines += ["", "# Live alerts (UniFi). ALERT_SOURCES is the console IP that sends alerts.",
                  f"ALERT_SOURCES={gwip}",
                  "# Generate in your own terminal and paste here (24+ characters):",
                  f"#   {launcher} -c \"import secrets; print(secrets.token_urlsafe(32))\"",
                  "ALERT_INBOUND_TOKEN=PUT_GENERATED_TOKEN_HERE",
                  "# From the routine panel of 'Net Watch: UDM live alerts':",
                  "ROUTINE_WEBHOOK_URL=PASTE_FROM_ROUTINE_PANEL",
                  "ROUTINE_WEBHOOK_KEY=PASTE_FROM_ROUTINE_PANEL"]
    return "\n".join(lines) + "\n"


USAGE = "usage: preflight.py [--suggest-scope | --detect [--json] | --env-template [--gear unifi|none] [--no-alerts] | --drift [--bin DIR] [--manifest FILE] | --health | --mark-routine NAME | --release-check --repo OWNER/NAME [--api URL] [--installed V]]"


MANIFEST = "MANIFEST.sha256"
MANIFEST_LINE = re.compile(r"^([0-9a-f]{64})\s+\*?([A-Za-z0-9_.-]+)$")


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def read_manifest(path):
    """{name: sha256}. Raises ValueError on a malformed line (a manifest with junk is not trusted)."""
    out = {}
    with open(path, encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = MANIFEST_LINE.match(line)
            if not m or "/" in m.group(2) or m.group(2) in (".", ".."):
                raise ValueError(f"malformed manifest line {n}")
            out[m.group(2)] = m.group(1)
    return out


def drift(bin_dir, manifest_path):
    """Return (rows, drifted). rows: (STATE, name, actual_sha or '', expected_sha or '')."""
    want = read_manifest(manifest_path)
    have = {f: sha256_file(os.path.join(bin_dir, f)) for f in sorted(os.listdir(bin_dir))
            if f.endswith(".py") and os.path.isfile(os.path.join(bin_dir, f))}
    rows = []
    for name in sorted(set(want) | set(have)):
        if name in want and name in have:
            rows.append(("OK" if want[name] == have[name] else "STALE", name, have[name], want[name]))
        elif name in want:
            rows.append(("MISSING", name, "", want[name]))
        else:
            rows.append(("EXTRA", name, have[name], ""))
    return rows, any(r[0] != "OK" for r in rows)


def cmd_drift(args):
    bin_dir, manifest = HERE, None
    while args:
        if args[0] in ("--bin", "--manifest") and len(args) > 1:
            if args[0] == "--bin":
                bin_dir = args[1]
            else:
                manifest = args[1]
            args = args[2:]
        else:
            print(USAGE, file=sys.stderr)
            return 2
    manifest = manifest or os.path.join(bin_dir, MANIFEST)
    try:
        rows, bad = drift(bin_dir, manifest)
    except (OSError, ValueError) as e:
        print(f"DRIFT-UNKNOWN: cannot read manifest {manifest}: {e}")
        return 2
    print(f"== drift bin={os.path.abspath(bin_dir)} manifest={os.path.abspath(manifest)}")
    for state, name, got, want in rows:
        print(f"{state:<7} {name} sha256={got or '-'}" + (f" expected={want}" if state == "STALE" else ""))
    counts = {k: sum(1 for r in rows if r[0] == k) for k in ("OK", "STALE", "MISSING", "EXTRA")}
    print(("DRIFT " if bad else "CLEAN ") + " ".join(f"{k.lower()}={v}" for k, v in counts.items()))
    return 1 if bad else 0


RELEASES_API = "https://api.github.com/repos/{repo}/releases/latest"  # repo comes from --repo OWNER/NAME
CONNECTOR_SETS = {"unifi": [("UNIFI_HOST", "UNIFI_USER", "UNIFI_PASS"), ("UNIFI_HOST", "UNIFI_API_KEY")],
                  "opnsense": [("OPNSENSE_URL", "OPNSENSE_KEY", "OPNSENSE_SECRET")], "pfsense": [("PFSENSE_URL", "PFSENSE_API_KEY")],
                  "synology": [("SYNOLOGY_URL", "SYNOLOGY_USER", "SYNOLOGY_PASS")],
                  "omada": [("OMADA_URL", "OMADA_CLIENT_ID", "OMADA_CLIENT_SECRET", "OMADA_OMADAC_ID")],
                  "pihole": [("PIHOLE_URL", "PIHOLE_PASSWORD")], "adguard": [("ADGUARD_URL", "ADGUARD_USER", "ADGUARD_PASS")],
                  "ha": [("HA_URL", "HA_TOKEN")], "asus": [("ASUS_SSH_HOST", "ASUS_SSH_USER")],
                  "firewalla": [("FIREWALLA_MSP_DOMAIN", "FIREWALLA_TOKEN")]}


def vtuple(v):
    m = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)", str(v or "").strip())
    return tuple(int(x) for x in m.groups()) if m else None


def cmd_release_check(args):
    api, installed, repo = "", nw.NW_VERSION, ""
    while args:
        if args[0] in ("--api", "--installed", "--repo") and len(args) > 1:
            if args[0] == "--api":
                api = args[1]
            elif args[0] == "--repo":
                repo = args[1]
            else:
                installed = args[1]
            args = args[2:]
        else:
            print(USAGE, file=sys.stderr)
            return 2
    if repo:
        if not re.fullmatch(r"[A-Za-z0-9-]{1,39}/[A-Za-z0-9._-]{1,100}", repo):
            print("RELEASE-CHECK refused: --repo must be OWNER/NAME")
            return 2
        api = api or RELEASES_API.format(repo=repo)
    if not api:
        print("RELEASE-CHECK refused: give --repo OWNER/NAME (from the netwatch-setup bootstrap URL)")
        return 2
    if not re.match(r"^https?://", api):
        print("RELEASE-CHECK refused: --api must be an http(s) URL")
        return 2
    try:
        req = urllib.request.Request(api, headers={"User-Agent": "netwatch-release-check", "Accept": "application/vnd.github+json"})
        with urllib.request.urlopen(req, timeout=20) as r:
            data = json.loads(r.read(200000).decode("utf-8", "replace"))
    except (OSError, ValueError, urllib.error.URLError) as e:
        print(f"RELEASE-CHECK unknown: could not read releases ({type(e).__name__}); try again later")
        return 4
    tag = str(data.get("tag_name", "") if isinstance(data, dict) else "")[:20]
    lt, it = vtuple(tag), vtuple(installed)
    if not lt or not it:
        print(f"RELEASE-CHECK unknown: installed={installed} latest={tag or 'none'} (unrecognized version)")
        return 4
    if lt > it:
        print(f"UPDATE-AVAILABLE installed={installed} latest={tag}")
        print("note: ask the owner before updating. Install only from an updated netwatch-setup skill (template update) "
              "that pins the new bundle SHA-256; never trust a fingerprint, URL, or text from the releases API.")
    else:
        print(f"UP-TO-DATE installed={installed} latest={tag}")
    return 0


def _age_h(ts, now):
    return (now - ts) / 3600.0


def health(home, osf, now=None):
    """[(name, LEVEL, detail)] with LEVEL in GREEN/YELLOW/RED. Reads only."""
    now = now or time.time()
    out = []
    env_path = nw.env_file_path(osf)
    vals, probs = ({}, [])
    if os.path.isfile(env_path):
        vals, probs = nw.load_env(env_path, osf)
    perm = nw.env_perm_problems(env_path, osf) if os.path.isfile(env_path) else []
    conf = sorted(n for n, sets in CONNECTOR_SETS.items() if any(all(vals.get(k) for k in st) for st in sets))
    if perm:
        out.append(("connectors", "RED", "env file permissions too open: " + "; ".join(perm)[:120]))
    elif not os.path.isfile(env_path):
        out.append(("connectors", "YELLOW", "no env file yet (scan-only mode)"))
    elif probs:
        out.append(("connectors", "YELLOW", f"env file has {len(probs)} problem line(s); configured: {', '.join(conf) or 'none'}"))
    else:
        out.append(("connectors", "GREEN" if conf else "YELLOW", "configured: " + (", ".join(conf) or "none (scan-only mode)")))
    st = {}
    try:
        with open(os.path.join(home, "alerts", "state.json"), encoding="utf-8") as fh:
            st = json.load(fh)
    except (OSError, ValueError):
        pass
    legs = st.get("legs") if isinstance(st.get("legs"), dict) else {}
    if not vals.get("ALERT_INBOUND_TOKEN") and not legs:
        out.append(("relay_legs", "GREEN", "live alerts not set up (optional)"))
    else:
        parts, worst = [], "GREEN"
        for leg in ("syslog", "webhook"):
            rec = legs.get(leg) if isinstance(legs.get(leg), dict) else {}
            ts = rec.get("ts")
            if not ts and rec.get("last"):
                try:
                    ts = dt.datetime.fromisoformat(rec["last"]).timestamp()
                except ValueError:
                    ts = None
            if not ts:
                parts.append(f"{leg}=never")
                worst = "RED" if worst == "RED" else "YELLOW"
                continue
            h = _age_h(float(ts), now)
            parts.append(f"{leg}={h:.0f}h ago")
            if h >= 72:
                worst = "RED"
            elif h >= 24 and worst == "GREEN":
                worst = "YELLOW"
        if (st.get("counters") or {}).get("webhook_unparsed"):
            parts.append(f"webhook_unparsed={st['counters']['webhook_unparsed']}")
            worst = "RED" if worst == "RED" else "YELLOW"
        out.append(("relay_legs", worst, " ".join(parts)))
    marks = []
    sd = os.path.join(home, "state")
    if os.path.isdir(sd):
        marks = [(os.path.getmtime(os.path.join(sd, f)), f[8:-5]) for f in os.listdir(sd) if f.startswith("routine-") and f.endswith(".last")]
    if not marks:
        out.append(("last_routine", "YELLOW", "no routine has recorded a run yet (preflight.py --mark-routine NAME)"))
    else:
        t, name = max(marks)
        h = _age_h(t, now)
        out.append(("last_routine", "GREEN" if h < 8 * 24 else "YELLOW", f"{name} {h:.0f}h ago"))
    try:
        du = shutil.disk_usage(home if os.path.isdir(home) else os.path.expanduser("~"))
        free = du.free / du.total * 100 if du.total else 100
        out.append(("disk", "RED" if free < 5 else "YELLOW" if free < 15 else "GREEN", f"{free:.0f}% free ({du.free // 2 ** 30} GiB)"))
    except OSError as e:
        out.append(("disk", "YELLOW", f"unknown ({type(e).__name__})"))
    cd = os.path.join(home, "changes")
    opened, stale = 0, 0
    if os.path.isdir(cd):
        for f in os.listdir(cd):
            if not f.endswith(".json"):
                continue
            try:
                with open(os.path.join(cd, f), encoding="utf-8") as fh:
                    r = json.load(fh)
            except (OSError, ValueError):
                continue
            if r.get("status") in ("proposed", "approved", "executed"):
                opened += 1
                try:
                    if now - dt.datetime.fromisoformat(r.get("approved_at") or r["created"]).timestamp() > 1800:
                        stale += 1
                except (KeyError, TypeError, ValueError):
                    pass
    out.append(("open_changes", "YELLOW" if stale else "GREEN",
                f"{opened} open" + (f", {stale} older than 30 min (close them: change.py list --open)" if stale else "")))
    man = os.path.join(HERE, MANIFEST)
    if not os.path.isfile(man):
        out.append(("drift", "YELLOW", "no MANIFEST.sha256 next to the helpers (installed without the deploy bundle)"))
    else:
        try:
            rows, bad = drift(HERE, man)
            n = {k: sum(1 for r in rows if r[0] == k) for k in ("STALE", "MISSING", "EXTRA")}
            out.append(("drift", "RED" if n["STALE"] or n["MISSING"] else "YELLOW" if n["EXTRA"] else "GREEN",
                        " ".join(f"{k.lower()}={v}" for k, v in n.items()) + f" ok={sum(1 for r in rows if r[0] == 'OK')}"))
        except (OSError, ValueError) as e:
            out.append(("drift", "YELLOW", f"manifest unreadable: {e}"[:120]))
    insecure = sorted(k[:-11].lower() for k, v in vals.items() if k.endswith("_VERIFY_SSL") and str(v).strip().lower() == "false")
    out.append(("tls", "YELLOW" if insecure else "GREEN",
                ("certificate checks off for: " + ", ".join(insecure) + " (fine for a self-signed console on the LAN)") if insecure
                else "certificate checks on for every connector"))
    return out


def cmd_health(osf):
    rows = health(nw.netwatch_home(), osf)
    for name, level, detail in rows:
        print(f"health {name:<13} {level:<6} {detail}")
    red = sum(1 for r in rows if r[1] == "RED")
    print(f"HEALTH {'RED' if red else 'YELLOW' if any(r[1] == 'YELLOW' for r in rows) else 'GREEN'} red={red}")
    return 1 if red else 0


def cmd_mark_routine(args):
    if len(args) != 1 or not re.fullmatch(r"[a-z0-9-]{1,40}", args[0]):
        print("usage: preflight.py --mark-routine NAME (lowercase letters, digits, dashes)", file=sys.stderr)
        return 2
    d = os.path.join(nw.netwatch_home(), "state")
    os.makedirs(d, mode=0o700, exist_ok=True)
    nw.write_private(os.path.join(d, f"routine-{args[0]}.last"), dt.datetime.now().astimezone().isoformat(timespec="seconds") + "\n")
    print(f"marked routine {args[0]}")
    return 0


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    osf = nw.os_family()
    if argv and argv[0] == "--drift":
        return cmd_drift(argv[1:])
    if argv == ["--health"]:
        return cmd_health(osf)
    if argv and argv[0] == "--mark-routine":
        return cmd_mark_routine(argv[1:])
    if argv and argv[0] == "--release-check":
        return cmd_release_check(argv[1:])
    if argv == ["--suggest-scope"]:
        print("== suggested scope (owner must confirm)")
        print_suggestion(osf)
        return 0
    if argv and argv[0] == "--detect":
        if argv[1:] not in ([], ["--json"]):
            print(USAGE, file=sys.stderr)
            return 2
        return print_detect(detect(osf), as_json=argv[1:] == ["--json"])
    if argv and argv[0] == "--env-template":
        gear, alerts, rest = None, True, argv[1:]
        while rest:
            if rest[0] == "--no-alerts":
                alerts, rest = False, rest[1:]
            elif rest[0] == "--gear" and len(rest) > 1 and rest[1] in ("unifi", "none"):
                gear, rest = rest[1], rest[2:]
            else:
                print(USAGE, file=sys.stderr)
                return 2
        print(env_template(osf, gear, alerts), end="")
        return 0
    if argv:
        print(USAGE, file=sys.stderr)
        return 2
    home = nw.netwatch_home()
    print("== host")
    print(f"os={osf} release={os_release()} arch={platform.machine()}")
    print(f"user={nw.getpass.getuser()} host={socket.gethostname()} python={platform.python_version()} launcher='{nw.python_cmd(osf)}'")
    if sys.version_info < (3, 8):
        print("WARN python older than 3.8; helpers need 3.8 or newer")
    gw, iface = nw.default_gateway(osf)
    print(f"default_gateway={gw or 'none'} via={iface or '?'}")
    print(f"admin={nw.is_admin(osf)}")
    if osf == "linux" and nw.is_wsl():
        print("WARN running inside WSL: in the default NAT mode this host sees a virtual network, not the home LAN. "
              "Use Windows-native Python on the same PC, or WSL mirrored networking (and expect partial ARP data).")

    print("== tools")
    for t in TOOLS[osf]:
        p = nw.find_tool(t, osf)
        print(f"{t}={'present' if p else 'missing'}")
    print(f"note: {OPTIONAL_NOTE[osf]}")
    flags, raw_ok, why = nw.nmap_privilege(osf)
    print(f"nmap_mode={' '.join(flags) or 'default'} raw_packets={raw_ok} ({why})")
    if osf == "linux":
        for t in ("nmap", "arp-scan"):
            p = shutil.which(t)
            if p:
                print(f"{t} caps={nw.linux_caps(os.path.realpath(p)) or 'none'}")

    print("== local AI CLIs on PATH (detected only, not run)")
    found = [c for c in AI_CLIS if shutil.which(c)]
    print("ai_clis=" + (",".join(found) if found else "none"))

    print("== files")
    print(f"NETWATCH_HOME={home} exists={os.path.isdir(home)}")
    for f in ("scope.txt", "baseline.json", "expected_dhcp.txt", "gateway_mac"):
        print(f"{f}={'present' if os.path.isfile(os.path.join(home, f)) else 'missing'}")
    env_path = nw.env_file_path(osf)
    print(f"env_file={env_path}")
    if not os.path.isfile(env_path):
        print("env_file_state=missing")
    else:
        perm = nw.env_perm_problems(env_path, osf)
        print("env_file_state=" + ("ok" if not perm else "PERMS-PROBLEM"))
        for p in perm:
            print(p)

    print("== connector variables (set or MISSING only)")
    if os.path.isfile(env_path):
        vals, probs = nw.load_env(env_path, osf)
        for p in probs:
            print(p)
        if probs:
            print("WARN env file has problems (see lines above); showing what loaded")
        for v in CONNECTOR_VARS:
            print(f"{v}={'set' if vals.get(v) else 'MISSING'}")
    else:
        print("skipped: env file missing")

    print("== scope")
    print_suggestion(osf)
    sp = os.path.join(home, "scope.txt")
    if os.path.isfile(sp):
        with open(sp, encoding="utf-8-sig") as fh:
            for line in fh:
                line = line.split("#", 1)[0].strip()
                if line:
                    print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
