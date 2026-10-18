#!/usr/bin/env python3
"""Net Watch topology map (Linux, macOS, Windows; Python 3 standard library only; read-only).

  topology.py collect [--source unifi-classic|unifi-int|omada|none] [--site default]
        GET-only pulls of devices, clients, and networks through nw_http.py (redacted),
        saved under NETWATCH_HOME/topology/RUN/. Never writes to any device.
  topology.py build [--run DIR] [--scan DIR] [--traceroute] [--no-accept]
        merge controller data with the latest scan inventory (and optional traceroutes to
        in-scope addresses), classify every node, and write graph.json, topology.mmd,
        topology.html (self-contained, inline SVG), diff.json, and recommendations.md.
  topology.py run [collect and build options]   collect, then build
  topology.py show [--run DIR]                  print the summary of a built run

Device names, hostnames, and vendor strings come from the network and are untrusted:
they are escaped in HTML and stripped of syntax in Mermaid, and never interpreted.
"""
import argparse
import datetime as dt
import glob
import html
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

KINDS = ("gateway", "switch", "ap", "nas", "workstation", "phone", "iot", "camera", "smart-home", "unknown")
INFRA = ("gateway", "switch", "ap")
SMART_VENDORS = re.compile(r"rachio|pentair|screenlogic|\bkasa\b|tp-?link smart|signify|philips light|\bhue\b|chamberlain|myq|"  # generic-vendors
                           r"\badt\b|\bnest\b|ecobee|\bring\b|august home|\byale\b|lutron|wemo|meross|govee|tuya|smartthings|ezviz|"  # generic-vendors
                           r"sonoff|shelly|aqara|lifx|rheem|rainbird|hunter industries", re.I)
CAMERA_HINT = re.compile(r"hikvision|dahua|amcrest|reolink|wyze|axis comm|lorex|swann|eufy|arlo|foscam|uvc|g4 |g5 |"
                         r"camera|cam\b|doorbell|nest cam|ezviz", re.I)
NAS_HINT = re.compile(r"synology|qnap|western digital|wd my|asustor|terramaster|truenas|unraid|\bnas\b|drobo|buffalo", re.I)
PHONE_HINT = re.compile(r"iphone|ipad|pixel|galaxy|android|oneplus|motorola|xiaomi|huawei|oppo|redmi|phone", re.I)
WORK_HINT = re.compile(r"macbook|imac|mac-?mini|mac studio|desktop|laptop|-pc\b|\bpc\b|thinkpad|dell|lenovo|hewlett|\bhp\b|"
                       r"intel corporate|microsoft|asustek|gigabyte|micro-star|surface|workstation|ubuntu|fedora|debian|raspberry",
                       re.I)
IOT_HINT = re.compile(r"espressif|tuya|amazon|echo|alexa|roku|sonos|chromecast|google home|nest mini|apple tv|appletv|"
                      r"samsung tv|lg electronics|vizio|tcl|hisense|printer|brother|canon|epson|xbox|playstation|nintendo|"
                      r"ring|bose|denon|yamaha|withings|fitbit|murata|azurewave|realtek|texas instruments|silicon labs", re.I)
CAM_PORTS = {554, 8554, 37777, 34567}
NAS_PORTS = {5000, 5001, 548, 2049, 873}
WORK_PORTS = {3389, 5900, 22, 139}
PHONE_PORTS = {62078}
MAX_TRACE_TARGETS = 8
CLIENT_GROUP = 8      # Mermaid: collapse more than this many leaf clients under one parent
HTML_MAX_NODES = 600


def now():
    return dt.datetime.now().astimezone()


def topo_home():
    return os.path.join(nw.netwatch_home(), "topology")


def clean(text, n=60):
    """Printable, single-line, bounded text from untrusted device fields."""
    s = re.sub(r"[\x00-\x1f\x7f]+", " ", str(text or "")).strip()
    return s[:n]


def group_summary(counts, limit=48):
    """'4 unknown, 3 phone, +2 more' from {kind: count}; whole items only, never cut mid-word."""
    items = [f"{v} {re.sub(r'[^a-z0-9 -]', '', str(k).lower())}" for k, v in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))]
    out = []
    for i, it in enumerate(items):
        rest = len(items) - i - 1
        tail = f", +{rest} more" if rest else ""
        if out and len(", ".join(out + [it]) + tail) > limit:
            out.append(f"+{len(items) - i} more")
            break
        out.append(it)
    return ", ".join(out) or "?"


def mermaid_label(text):
    s = clean(text, 40)
    s = re.sub(r"[\"'`<>\[\]{}()|#;&\\%:=]", " ", s)
    return re.sub(r"\s+", " ", s).strip() or "?"


def load_json(path, default=None):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return default


def data_list(obj):
    if isinstance(obj, dict):
        obj = obj.get("data", obj.get("result", obj))
        if isinstance(obj, dict):
            obj = obj.get("data", obj.get("items", []))
    return obj if isinstance(obj, list) else []


# ---------------------------------------------------------------- collect
SOURCES = {
    "unifi-classic": [("devices", "/api/s/{site}/stat/device"), ("clients", "/api/s/{site}/stat/sta"),
                      ("networks", "/api/s/{site}/rest/networkconf")],
    "unifi-int": [("sites", "/v1/sites")],
    "omada": [("sites", "/sites?page=1&pageSize=100")],
}


def collect(source, site, run_dir, caller=None):
    """GET-only collection. caller(conn, method, path) -> (status, raw) for tests; defaults to nw_http.call."""
    os.makedirs(run_dir, exist_ok=True)
    meta = {"source": source, "site": site, "collected_at": now().isoformat(), "files": {}, "errors": []}
    if source == "none":
        nw.write_private(os.path.join(run_dir, "collect.json"), json.dumps(meta, indent=2))
        return meta
    if caller is None:
        import nw_http  # noqa: E402 (same bin folder)
        osf = nw.os_family()
        vals, probs = nw.load_env(nw.env_file_path(osf), osf)
        if probs and not vals:
            meta["errors"] += probs
            nw.write_private(os.path.join(run_dir, "collect.json"), json.dumps(meta, indent=2))
            return meta

        def caller(conn, method, path):
            return nw_http.call(conn, method, path, vals)

    def get(name, path):
        try:
            st, raw = caller(source, "GET", path)
        except Exception as e:  # connector failures are reported, not fatal
            meta["errors"].append(f"{name}: {str(e)[:160]}")
            return None
        if not 200 <= st < 300:
            meta["errors"].append(f"{name}: HTTP {st}")
            return None
        try:
            obj = nw.redact(json.loads(raw.decode("utf-8", "replace")))
        except ValueError:
            meta["errors"].append(f"{name}: non-JSON body")
            return None
        nw.write_private(os.path.join(run_dir, f"{source}-{name}.json"), json.dumps(obj))
        meta["files"][name] = f"{source}-{name}.json"
        return obj

    if source == "unifi-classic":
        for name, path in SOURCES[source]:
            get(name, path.format(site=site))
    elif source == "unifi-int":
        sites = data_list(get("sites", "/v1/sites"))
        sid = next((s.get("id") for s in sites if isinstance(s, dict) and
                    (s.get("internalReference") == site or s.get("name") == site)), None)
        sid = sid or (sites[0].get("id") if sites and isinstance(sites[0], dict) else None)
        if sid and re.fullmatch(r"[A-Za-z0-9-]{1,64}", str(sid)):
            devs = data_list(get("devices", f"/v1/sites/{sid}/devices?limit=200"))
            details = []
            for d in devs[:200]:
                did = d.get("id") if isinstance(d, dict) else None
                if did and re.fullmatch(r"[A-Za-z0-9-]{1,64}", str(did)):
                    try:
                        st, raw = caller(source, "GET", f"/v1/sites/{sid}/devices/{did}")
                        if 200 <= st < 300:
                            details.append(nw.redact(json.loads(raw.decode("utf-8", "replace"))))
                    except Exception as e:
                        meta["errors"].append(f"device {did}: {str(e)[:120]}")
            nw.write_private(os.path.join(run_dir, "unifi-int-device-details.json"), json.dumps({"data": details}))
            meta["files"]["device-details"] = "unifi-int-device-details.json"
            get("clients", f"/v1/sites/{sid}/clients?limit=1000")
            get("networks", f"/v1/sites/{sid}/networks?limit=200")  # newer versions only; failure is fine
        else:
            meta["errors"].append("sites: no site id found")
    elif source == "omada":
        sites = data_list(get("sites", "/sites?page=1&pageSize=100"))
        sid = next((s.get("siteId") for s in sites if isinstance(s, dict) and s.get("name") == site), None)
        sid = sid or (sites[0].get("siteId") if sites and isinstance(sites[0], dict) else None)
        if sid and re.fullmatch(r"[A-Za-z0-9-]{1,64}", str(sid)):
            get("devices", f"/sites/{sid}/devices?page=1&pageSize=1000")
            get("clients", f"/sites/{sid}/clients?page=1&pageSize=1000")
        else:
            meta["errors"].append("sites: no site id found")
    nw.write_private(os.path.join(run_dir, "collect.json"), json.dumps(meta, indent=2))
    return meta


# ---------------------------------------------------------------- traceroute (scope-checked)
def trace_command(ip, osf):
    if osf == "windows":
        return ["tracert", "-d", "-h", "6", "-w", "500", ip]
    if shutil.which("traceroute"):
        return ["traceroute", "-n", "-m", "6", "-w", "1", "-q", "1", ip]
    if osf == "linux" and shutil.which("tracepath"):
        return ["tracepath", "-n", "-m", "6", ip]
    return None


HOP = re.compile(r"^\s*(\d+)[:\s]")
IPV4 = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")


def parse_trace(text, target):
    """Ordered hop IPs (None for timeouts) from traceroute, tracepath, or tracert output."""
    hops = {}
    for line in text.splitlines():
        m = HOP.match(line)
        if not m:
            continue
        n = int(m.group(1))
        ips = [ip for ip in IPV4.findall(line[m.end():]) if _valid_ip(ip)]
        if n not in hops or (hops[n] is None and ips):
            hops[n] = ips[0] if ips else None
    return [hops[k] for k in sorted(hops)]


def _valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def run_traceroutes(targets, nets, run_dir, osf):
    results = {}
    for ip in targets[:MAX_TRACE_TARGETS]:
        if nw.scope_problems([ip], nets):
            results[ip] = {"skipped": "outside scope"}
            continue
        cmd = trace_command(ip, osf)
        if not cmd:
            results[ip] = {"skipped": "no traceroute/tracepath/tracert on this host"}
            continue
        rc, out = nw.run(cmd, timeout=60)
        results[ip] = {"hops": parse_trace(out, ip), "rc": rc}
    nw.write_private(os.path.join(run_dir, "traceroute.json"), json.dumps(results, indent=2))
    return results


# ---------------------------------------------------------------- classification
def load_smart_home(home):
    """NETWATCH_HOME/smart_home.txt: one MAC or IP per line, optional name after it (written from the profile)."""
    ids = {}
    path = os.path.join(home, "smart_home.txt")
    try:
        with open(path, encoding="utf-8-sig") as fh:
            for raw in fh:
                line = raw.split("#", 1)[0].strip()
                if not line:
                    continue
                key, _, name = line.partition(" ")
                mac = nw.normalize_mac(key)
                ids[mac or key.strip()] = name.strip()
    except OSError:
        pass
    return ids


def classify(node, ports=(), smart_ids=None, gateway_ip=""):
    """Return (kind, observe_only, reason). Controller roles win, then owner lists, then ports, then names/vendors."""
    smart_ids = smart_ids or {}
    text = " ".join(str(node.get(k) or "") for k in ("label", "hostname", "vendor", "model", "dev_family"))
    role = node.get("role", "")
    listed = node.get("mac") in smart_ids or any(ip in smart_ids for ip in node.get("ips", []))
    if role in INFRA:
        return role, False, "controller role"
    if gateway_ip and gateway_ip in node.get("ips", []):
        return "gateway", False, "default gateway"
    ports = set(ports or ())
    if listed:
        kind = "camera" if CAMERA_HINT.search(text) else "smart-home"
        return kind, True, "owner smart-home list"
    if SMART_VENDORS.search(text):
        kind = "camera" if CAMERA_HINT.search(text) else "smart-home"
        return kind, True, "smart-home vendor"
    if CAMERA_HINT.search(text) or ports & CAM_PORTS:
        return "camera", False, "camera name/vendor/RTSP port"
    if NAS_HINT.search(text) or (ports & NAS_PORTS and 445 in ports):
        return "nas", False, "NAS vendor/ports"
    if PHONE_HINT.search(text) or ports & PHONE_PORTS:
        return "phone", False, "phone name/port"
    if WORK_HINT.search(text) or ports & WORK_PORTS:
        return "workstation", False, "computer name/vendor/ports"
    if IOT_HINT.search(text):
        return "iot", False, "IoT vendor/name"
    if node.get("randomized_mac") and node.get("link") == "wireless":
        return "phone", False, "randomized MAC on Wi-Fi (likely phone/tablet/laptop)"
    return "unknown", False, "no identifying data"


# ---------------------------------------------------------------- graph building
UNIFI_TYPE_ROLE = {"ugw": "gateway", "udm": "gateway", "uxg": "gateway", "ucg": "gateway",
                   "usw": "switch", "uap": "ap", "ubb": "ap"}
# Model codes that start like a gateway but are access points (UniFi Beacon HD and other mesh/plug-in APs).
AP_MODEL_EXCEPTIONS = re.compile(r"^(udmb|udm-?b|udm-?beacon|ubb|uap-?beacon)", re.I)


def unifi_role(dev):
    """Controller role from the device type field first; model-name prefixes only when type is missing or unknown."""
    t = str(dev.get("type", "")).lower()
    model = str(dev.get("model", "")).lower().replace(" ", "")
    if AP_MODEL_EXCEPTIONS.match(model) or "beacon" in model:
        return "ap"  # narrow, known exceptions first: these report gateway-like model codes
    if t in UNIFI_TYPE_ROLE:
        return UNIFI_TYPE_ROLE[t]
    if model.startswith(("udm", "ucg", "uxg", "udr", "ux", "ugw")):
        return "gateway"
    if re.match(r"^us(w|l|m|f|c|\d)", model):
        return "switch"
    if model.startswith(("u6", "u7", "uap", "uk", "e7")):
        return "ap"
    return ""


def new_node(nid, **kw):
    n = {"id": nid, "label": "", "kind": "unknown", "observe_only": False, "mac": "", "ips": [], "vendor": "",
         "model": "", "firmware": "", "sources": [], "network": "", "vlan": None, "parent": "", "parent_port": None,
         "link": "", "signal": None, "managed": False, "upgradable": False, "role": "", "reason": ""}
    n.update(kw)
    return n


def merge(nodes, nid, **kw):
    n = nodes.get(nid) or new_node(nid)
    for k, v in kw.items():
        if k == "ips":
            for ip in v or []:
                if ip and ip not in n["ips"]:
                    n["ips"].append(ip)
        elif k == "sources":
            for s in v or []:
                if s not in n["sources"]:
                    n["sources"].append(s)
        elif v not in (None, "", [], False) and n.get(k) in (None, "", [], False, "unknown"):
            n[k] = v
    nodes[nid] = n
    return n


def node_id(mac, ip=""):
    m = nw.normalize_mac(mac or "")
    return m if m else (f"ip:{ip}" if ip else "")


def from_unifi_classic(run_dir, nodes, extra):
    devs = data_list(load_json(os.path.join(run_dir, "unifi-classic-devices.json"), {}))
    clients = data_list(load_json(os.path.join(run_dir, "unifi-classic-clients.json"), {}))
    nets = data_list(load_json(os.path.join(run_dir, "unifi-classic-networks.json"), {}))
    for net in nets:
        if not isinstance(net, dict) or net.get("purpose") in ("wan", "remote-user-vpn", "site-vpn", "vpn-client"):
            continue
        extra["networks"].append({"name": clean(net.get("name"), 40), "purpose": clean(net.get("purpose"), 20),
                                  "vlan": net.get("vlan") if net.get("vlan_enabled") or net.get("vlan") else None,
                                  "subnet": clean(net.get("ip_subnet"), 43), "id": clean(net.get("_id"), 40)})
    netname = {n["id"]: n["name"] for n in extra["networks"]}
    for d in devs:
        if not isinstance(d, dict):
            continue
        nid = node_id(d.get("mac"), d.get("ip"))
        if not nid:
            continue
        role = unifi_role(d)
        up = d.get("uplink") or {}
        parent = nw.normalize_mac(up.get("uplink_mac") or "")
        link = "wireless" if str(up.get("type", "")).lower() == "wireless" else ("wired" if parent else "")
        merge(nodes, nid, label=clean(d.get("name") or d.get("model")), mac=nw.normalize_mac(d.get("mac")),
              ips=[d.get("ip")] if d.get("ip") else [], model=clean(d.get("model"), 30), firmware=clean(d.get("version"), 30),
              sources=["unifi"], role=role, managed=True, parent=parent, parent_port=up.get("uplink_remote_port"),
              link=link, upgradable=bool(d.get("upgradable")), vendor="Ubiquiti")
        n = nodes[nid]
        n["state"] = d.get("state")
        if role == "gateway":
            wan = d.get("wan1") or {}
            n["wan_ip"] = clean(wan.get("ip"), 45)
        ports = []
        for p in d.get("port_table") or []:
            if isinstance(p, dict):
                ports.append({"idx": p.get("port_idx"), "up": bool(p.get("up")), "speed": p.get("speed"),
                              "full_duplex": p.get("full_duplex"), "uplink": bool(p.get("is_uplink")),
                              "name": clean(p.get("name"), 30)})
        n["ports"] = ports
        radios = []
        stats = {r.get("name"): r for r in d.get("radio_table_stats") or [] if isinstance(r, dict)}
        for r in d.get("radio_table") or []:
            if isinstance(r, dict):
                s = stats.get(r.get("name"), {})
                radios.append({"radio": clean(r.get("radio"), 8), "channel": s.get("channel", r.get("channel")),
                               "width": r.get("ht"), "utilization": s.get("cu_total"), "clients": s.get("num_sta")})
        n["radios"] = radios
        for l in d.get("lldp_table") or []:
            if not isinstance(l, dict):
                continue
            cmac = nw.normalize_mac(l.get("chassis_id") or "")
            if cmac and cmac != parent:
                extra["lldp"].append({"local": nid, "local_port": l.get("local_port_idx"), "neighbor": cmac,
                                      "neighbor_port": clean(l.get("port_id"), 30), "name": clean(l.get("system_name"), 40)})
    for c in clients:
        if not isinstance(c, dict):
            continue
        nid = node_id(c.get("mac"), c.get("ip"))
        if not nid:
            continue
        wired = bool(c.get("is_wired"))
        parent = nw.normalize_mac(c.get("sw_mac") if wired else c.get("ap_mac") or "") or ""
        net = netname.get(c.get("network_id")) or clean(c.get("network"), 40)
        merge(nodes, nid, label=clean(c.get("name") or c.get("hostname") or c.get("oui") or c.get("mac")),
              hostname=clean(c.get("hostname"), 60), mac=nw.normalize_mac(c.get("mac")),
              ips=[c.get("ip")] if c.get("ip") else [], vendor=clean(c.get("oui"), 40), sources=["unifi"],
              parent=parent, parent_port=c.get("sw_port") if wired else None, link="wired" if wired else "wireless",
              network=net, vlan=c.get("vlan"), signal=c.get("signal") if not wired else None,
              dev_family=clean(c.get("dev_family") or c.get("dev_cat"), 30), essid=clean(c.get("essid"), 32))


def from_unifi_int(run_dir, nodes, extra):
    details = data_list(load_json(os.path.join(run_dir, "unifi-int-device-details.json"), {}))
    devs = details or data_list(load_json(os.path.join(run_dir, "unifi-int-devices.json"), {}))
    clients = data_list(load_json(os.path.join(run_dir, "unifi-int-clients.json"), {}))
    nets = data_list(load_json(os.path.join(run_dir, "unifi-int-networks.json"), {}))
    for net in nets:
        if isinstance(net, dict):
            extra["networks"].append({"name": clean(net.get("name"), 40), "purpose": clean(net.get("management") or net.get("purpose"), 20),
                                      "vlan": net.get("vlanId"), "subnet": clean((net.get("ipv4Configuration") or {}).get("hostIpAddress"), 43),
                                      "id": clean(net.get("id"), 40)})
    idmap = {}
    for d in devs:
        if isinstance(d, dict):
            idmap[d.get("id")] = node_id(d.get("macAddress"), d.get("ipAddress"))
    for d in devs:
        if not isinstance(d, dict):
            continue
        nid = idmap.get(d.get("id"))
        if not nid:
            continue
        feats = [str(f).lower() for f in (d.get("features") or [])]
        model = clean(d.get("model"), 30)
        # Features describe what the device does; trust them before a model-name guess.
        role = "gateway" if "gateway" in feats else ("switch" if "switching" in feats else ("ap" if "accesspoint" in feats else ""))
        if not role:
            role = unifi_role({"model": model})
        up = d.get("uplink") or {}
        merge(nodes, nid, label=clean(d.get("name") or model), mac=nw.normalize_mac(d.get("macAddress")),
              ips=[d.get("ipAddress")] if d.get("ipAddress") else [], model=model, firmware=clean(d.get("firmwareVersion"), 30),
              sources=["unifi"], role=role, managed=True, parent=idmap.get(up.get("deviceId"), ""), vendor="Ubiquiti",
              link="wired" if up.get("deviceId") else "", upgradable=bool(d.get("firmwareUpdatable")))
        n = nodes[nid]
        n["state"] = d.get("state")
        n["ports"] = [{"idx": p.get("idx"), "up": str(p.get("state", "")).upper() == "UP", "speed": p.get("speedMbps"),
                       "full_duplex": None, "uplink": False, "name": ""}
                      for p in ((d.get("interfaces") or {}).get("ports") or []) if isinstance(p, dict)]
        n["radios"] = [{"radio": clean(r.get("frequencyGHz"), 8), "channel": r.get("channel"), "width": r.get("channelWidthMHz"),
                        "utilization": None, "clients": None}
                       for r in ((d.get("interfaces") or {}).get("radios") or []) if isinstance(r, dict)]
    for c in clients:
        if not isinstance(c, dict):
            continue
        nid = node_id(c.get("macAddress"), c.get("ipAddress"))
        if not nid:
            continue
        wired = str(c.get("type", "")).upper() == "WIRED"
        merge(nodes, nid, label=clean(c.get("name") or c.get("macAddress")), mac=nw.normalize_mac(c.get("macAddress")),
              ips=[c.get("ipAddress")] if c.get("ipAddress") else [], sources=["unifi"],
              parent=idmap.get(c.get("uplinkDeviceId"), ""), link="wired" if wired else "wireless")


def from_omada(run_dir, nodes, extra):
    devs = data_list(load_json(os.path.join(run_dir, "omada-devices.json"), {}))
    clients = data_list(load_json(os.path.join(run_dir, "omada-clients.json"), {}))
    for d in devs:
        if not isinstance(d, dict):
            continue
        nid = node_id(d.get("mac"), d.get("ip"))
        if not nid:
            continue
        t = str(d.get("type", "")).lower()
        role = {"gateway": "gateway", "switch": "switch", "ap": "ap"}.get(t, "")
        merge(nodes, nid, label=clean(d.get("name") or d.get("model")), mac=nw.normalize_mac(d.get("mac")),
              ips=[d.get("ip")] if d.get("ip") else [], model=clean(d.get("model"), 30), firmware=clean(d.get("firmwareVersion"), 30),
              sources=["omada"], role=role, managed=True, vendor="TP-Link Omada",
              parent=nw.normalize_mac(d.get("uplinkDeviceMac") or ""), upgradable=bool(d.get("needUpgrade")))
    for c in clients:
        if not isinstance(c, dict):
            continue
        nid = node_id(c.get("mac"), c.get("ip"))
        if not nid:
            continue
        wired = bool(c.get("wireless") is False)
        parent = nw.normalize_mac((c.get("switchMac") if wired else c.get("apMac")) or "")
        merge(nodes, nid, label=clean(c.get("name") or c.get("hostName") or c.get("mac")), mac=nw.normalize_mac(c.get("mac")),
              ips=[c.get("ip")] if c.get("ip") else [], sources=["omada"], parent=parent, parent_port=c.get("port"),
              link="wired" if wired else "wireless", vlan=c.get("vid"), network=clean(c.get("networkName") or c.get("ssid"), 40),
              signal=c.get("rssi"), vendor=clean(c.get("vendor"), 40))


def latest_scan_dir(home):
    dirs = [d for d in glob.glob(os.path.join(home, "scans", "*")) if os.path.isfile(os.path.join(d, "inventory.json"))]
    return max(dirs, key=os.path.getmtime) if dirs else ""


def open_ports(home, keep=10):
    """ip -> set(open ports) from the newest portscan.py results (NETWATCH_HOME/scans/ports-*.xml or .json)."""
    found = {}
    files = sorted(glob.glob(os.path.join(home, "scans", "ports-*.xml")) + glob.glob(os.path.join(home, "scans", "ports-*.json")),
                   key=os.path.getmtime)[-keep:]
    for p in files:
        if p.endswith(".json"):
            rows = load_json(p, [])
            for r in rows if isinstance(rows, list) else []:
                if isinstance(r, dict) and isinstance(r.get("port"), int) and _valid_ip(str(r.get("ip"))):
                    found.setdefault(r["ip"], set()).add(r["port"])
            continue
        try:
            root = ET.parse(p).getroot()
        except (ET.ParseError, OSError):
            continue
        for h in root.findall("host"):
            a = h.find("address[@addrtype='ipv4']")
            if a is None:
                continue
            for port in h.findall("ports/port"):
                st = port.find("state")
                if st is not None and st.get("state") == "open" and port.get("portid", "").isdigit():
                    found.setdefault(a.get("addr"), set()).add(int(port.get("portid")))
    return found


def from_inventory(scan_dir, nodes):
    inv = load_json(os.path.join(scan_dir, "inventory.json"), {}) if scan_dir else {}
    for key, h in (inv.get("hosts") or {}).items():
        if not isinstance(h, dict):
            continue
        ips = [ip for ip in h.get("ips") or [] if _valid_ip(ip)]
        nid = node_id(h.get("mac"), ips[0] if ips else "")
        if not nid:
            continue
        # fold an IP-only controller entry into a MAC entry seen by the scan
        merge(nodes, nid, mac=nw.normalize_mac(h.get("mac") or ""), ips=ips, vendor=clean(h.get("vendor"), 40),
              hostname=clean(h.get("hostname"), 60), label=clean(h.get("label") or h.get("hostname") or ""),
              sources=["scan"], randomized_mac=bool(h.get("randomized_mac")))


def build_graph(run_dir, scan_dir, home, gateway_ip="", traces=None, scope_nets=None):
    nodes, extra = {}, {"networks": [], "lldp": [], "notes": [], "traceroute": traces or {}}
    meta = load_json(os.path.join(run_dir, "collect.json"), {}) or {}
    src = meta.get("source", "none")
    if src == "unifi-classic":
        from_unifi_classic(run_dir, nodes, extra)
    elif src == "unifi-int":
        from_unifi_int(run_dir, nodes, extra)
    elif src == "omada":
        from_omada(run_dir, nodes, extra)
    from_inventory(scan_dir, nodes)
    # Fold ip:X nodes into MAC nodes that carry the same IP.
    by_ip = {ip: nid for nid, n in nodes.items() if not nid.startswith("ip:") for ip in n["ips"]}
    for nid in [k for k in nodes if k.startswith("ip:")]:
        ip = nid[3:]
        if ip in by_ip:
            target = nodes[by_ip[ip]]
            for k, v in nodes[nid].items():
                if k not in ("id",) and target.get(k) in (None, "", [], False) and v not in (None, "", [], False):
                    target[k] = v
            del nodes[nid]
    if scope_nets:
        for nid in list(nodes):
            n = nodes[nid]
            if n["ips"] and not any(nw.in_nets(ip, scope_nets) for ip in n["ips"]) and not n.get("managed"):
                del nodes[nid]
                extra["notes"].append("dropped an out-of-scope address")
    ports = open_ports(home)
    smart = load_smart_home(home)
    gw_id = ""
    for n in nodes.values():
        p = set()
        for ip in n["ips"]:
            p |= ports.get(ip, set())
        n["open_ports"] = sorted(p)
        n["kind"], n["observe_only"], n["reason"] = classify(n, p, smart, gateway_ip)
        if n["kind"] == "gateway" and not gw_id:
            gw_id = n["id"]
        if not n["label"]:
            n["label"] = n["hostname"] if n.get("hostname") else (n["mac"] or (n["ips"][0] if n["ips"] else n["id"]))
    if not gw_id:
        gw_id = "gateway"
        nodes[gw_id] = new_node(gw_id, label=f"Gateway {gateway_ip}".strip(), kind="gateway", ips=[gateway_ip] if gateway_ip else [],
                                sources=["route"], reason="default route (no controller data)")
    # Inferred unmanaged switches: several wired clients on one managed switch port that is not a link to managed gear.
    managed_by_port = {}
    for n in nodes.values():
        if n.get("managed") and n["parent"]:
            managed_by_port.setdefault((n["parent"], n.get("parent_port")), []).append(n["id"])
    groups = {}
    for n in nodes.values():
        if n["link"] == "wired" and n["parent"] and n.get("parent_port") is not None and not n.get("managed"):
            groups.setdefault((n["parent"], n["parent_port"]), []).append(n["id"])
    for (sw, port), members in groups.items():
        if len(members) > 1 and (sw, port) not in managed_by_port:
            hid = f"inferred:{sw}:{port}"
            nodes[hid] = new_node(hid, label=f"Unmanaged switch? ({len(members)} devices on port {port})", kind="switch",
                                  parent=sw, parent_port=port, link="wired", sources=["inferred"],
                                  reason="several MACs on one switch port", inferred=True)
            for m in members:
                nodes[m]["parent"] = hid
    # Attach orphans to the gateway, marked unknown attachment.
    for n in nodes.values():
        if n["id"] == gw_id:
            n["parent"] = ""
            continue
        if not n["parent"] or n["parent"] not in nodes or creates_cycle(nodes, n["id"]):
            n["parent"] = gw_id
            n["link"] = n["link"] if n["link"] else "unknown"
            n["attachment_unknown"] = True
    # Traceroute notes: an in-scope hop that is not the gateway means a router between the scan host and the target.
    gw_ips = set(nodes[gw_id]["ips"])
    for target, res in (traces or {}).items():
        hops = [h for h in res.get("hops", []) if h]
        mid = [h for h in hops[:-1] if h not in gw_ips and h != target]
        if mid:
            extra["notes"].append(f"traceroute to {target} passes through {', '.join(mid)} (another router or double NAT)")
    edges = [{"from": n["parent"], "to": n["id"], "link": n["link"], "port": n.get("parent_port")}
             for n in nodes.values() if n["parent"]]
    return {"generated_at": now().isoformat(), "source": src, "scan_dir": scan_dir, "gateway": gw_id,
            "nodes": sorted(nodes.values(), key=lambda x: (KINDS.index(x["kind"]), x["label"].lower())),
            "edges": edges, **extra, "collect_errors": meta.get("errors", [])}


def creates_cycle(nodes, nid):
    seen, cur = set(), nid
    while cur:
        if cur in seen:
            return True
        seen.add(cur)
        cur = nodes.get(cur, {}).get("parent", "")
    return False


# ---------------------------------------------------------------- diff
def diff(prev, cur):
    if not prev:
        return {"baseline": True, "new": [], "missing": [], "moved": [], "roamed": 0}
    p = {n["id"]: n for n in prev.get("nodes", []) if not n["id"].startswith("inferred:")}
    c = {n["id"]: n for n in cur.get("nodes", []) if not n["id"].startswith("inferred:")}
    out = {"baseline": False, "new": [], "missing": [], "moved": [], "roamed": 0}
    for nid in sorted(set(c) - set(p)):
        out["new"].append({"id": nid, "label": c[nid]["label"], "kind": c[nid]["kind"], "ips": c[nid]["ips"]})
    for nid in sorted(set(p) - set(c)):
        out["missing"].append({"id": nid, "label": p[nid]["label"], "kind": p[nid]["kind"]})
    for nid in sorted(set(p) & set(c)):
        a, b = p[nid], c[nid]
        if a.get("network") and b.get("network") and a["network"] != b["network"]:
            out["moved"].append({"id": nid, "label": b["label"], "what": f"network {a['network']} -> {b['network']}"})
        elif (a.get("parent"), a.get("parent_port")) != (b.get("parent"), b.get("parent_port")):
            if b["kind"] in INFRA or a.get("link") == "wired" or b.get("link") == "wired":
                out["moved"].append({"id": nid, "label": b["label"],
                                     "what": f"uplink {a.get('parent')}:{a.get('parent_port')} -> {b.get('parent')}:{b.get('parent_port')}"})
            else:
                out["roamed"] += 1  # Wi-Fi clients changing AP is normal
    return out


# ---------------------------------------------------------------- recommendations
SEV = {"high": 0, "medium": 1, "low": 2}


def recommend(g, d=None):
    nodes = {n["id"]: n for n in g["nodes"]}
    recs = []

    def add(sev, title, evidence, fix, who="owner (via netwatch-change-control)", skill=""):
        recs.append({"severity": sev, "title": title, "evidence": evidence, "fix": fix, "who": who, "skill": skill})

    kinds = {}
    for n in nodes.values():
        kinds.setdefault(n["kind"], []).append(n)
    iot_like = kinds.get("iot", []) + kinds.get("camera", []) + kinds.get("smart-home", [])
    trusted = kinds.get("workstation", []) + kinds.get("nas", []) + kinds.get("phone", [])
    lan_nets = [x for x in g.get("networks", []) if x.get("purpose") not in ("guest",)]
    vlans = [x for x in g.get("networks", []) if x.get("vlan")]
    if iot_like and len(lan_nets) <= 1 and not vlans:
        add("high", "Flat network: IoT, cameras, and computers share one LAN",
            f"{len(iot_like)} IoT/camera/smart-home devices and {len(trusted)} computers/phones/NAS on one network",
            "Create an IoT VLAN (and a camera VLAN if cameras record locally), move devices in stages, then block IoT to LAN",
            skill="netwatch-segmentation-review")
    else:
        main_nets = {n.get("network") for n in trusted if n.get("network")}
        mixed = [n for n in iot_like if n.get("network") and n["network"] in main_nets]
        if mixed:
            add("high", "IoT devices on the main LAN",
                f"{len(mixed)} devices, for example {', '.join(sorted(m['label'] for m in mixed)[:4])}",
                "Move them to the IoT network/SSID; smart-home devices are moved by the owner or the home-control bot",
                skill="netwatch-segmentation-review")
    if not any(x.get("purpose") == "guest" for x in g.get("networks", [])) and g.get("networks"):
        add("low", "No guest network", "controller lists no guest-purpose network",
            "Add a guest SSID with client isolation for visitors", skill="netwatch-wifi-audit")
    children = {}
    for n in nodes.values():
        if n["parent"]:
            children.setdefault(n["parent"], []).append(n["id"])

    def downstream(nid, seen=None):
        seen = seen or set()
        for ch in children.get(nid, []):
            if ch not in seen:
                seen.add(ch)
                downstream(ch, seen)
        return seen

    for n in nodes.values():
        if n["kind"] in ("switch", "ap") and n["id"] != g["gateway"]:
            dn = downstream(n["id"])
            infra_dn = [x for x in dn if nodes[x]["kind"] in INFRA]
            if len(dn) >= 10 or infra_dn:
                add("medium" if infra_dn else "low", f"Single point of failure: {n['label']}",
                    f"{len(dn)} devices ({len(infra_dn)} switches/APs) depend on it with one uplink",
                    "Keep a spare or add a second path for critical gear (NAS, APs); put it on UPS power", who="owner")
    inferred = [n for n in nodes.values() if n.get("inferred")]
    if inferred:
        add("medium", "Unmanaged switches inferred",
            "; ".join(f"{n['label']} behind {nodes.get(n['parent'], {}).get('label', n['parent'])}" for n in inferred[:4]),
            "Replace with a managed switch before VLANs, or keep only one VLAN on that run; unmanaged switches cannot enforce segmentation",
            who="owner")
    mesh = [n for n in nodes.values() if n["kind"] == "ap" and n["link"] == "wireless"]
    if mesh:
        add("medium", "Access points on wireless backhaul (mesh)", ", ".join(m["label"] for m in mesh[:4]),
            "Wire them (Ethernet or MoCA) for full speed and resilience", who="owner")
    aps = [n for n in nodes.values() if n["kind"] == "ap" and n.get("radios")]
    by_ch = {}
    for a in aps:
        for r in a["radios"]:
            ch = r.get("channel")
            if isinstance(ch, int) and ch > 0:
                rname = str(r.get("radio") or "").lower()
                if rname in ("6e", "6", "6.0"):
                    band = "6"
                elif rname in ("na", "5", "5.0"):
                    band = "5"
                elif rname in ("ng", "2.4", "2"):
                    band = "2.4"
                else:
                    band = "2.4" if ch <= 14 else "5"
                by_ch.setdefault((band, ch), []).append(a["label"])
                if band == "2.4" and ch not in (1, 6, 11):
                    add("medium", f"2.4 GHz on overlapping channel {ch}", f"{a['label']}",
                        "Use channel 1, 6, or 11 at 20 MHz width", skill="netwatch-wifi-audit")
                if isinstance(r.get("utilization"), (int, float)) and r["utilization"] >= 60:
                    add("medium", f"Busy radio on {a['label']} (channel {ch})", f"channel utilization {r['utilization']}%",
                        "Change channel, lower width, or add an AP closer to the clients", skill="netwatch-wifi-audit")
    for (band, ch), labels in by_ch.items():
        if len(labels) > 1:
            add("medium" if band == "2.4" else "low", f"APs share {band} GHz channel {ch}", ", ".join(labels[:4]),
                "Give neighboring APs different channels (auto channel or a manual plan)", skill="netwatch-wifi-audit")
    weak = {}
    for n in nodes.values():
        if n["link"] == "wireless" and isinstance(n.get("signal"), (int, float)) and n["signal"] <= -75:
            weak.setdefault(n["parent"], []).append(n["label"])
    for ap, labels in weak.items():
        if len(labels) >= 2:
            add("low", f"Weak Wi-Fi clients on {nodes.get(ap, {}).get('label', ap)}", f"{len(labels)} clients at -75 dBm or worse",
                "Consider AP placement or an extra AP near those devices", who="owner")
    models = {}
    for n in nodes.values():
        if n.get("managed") and n.get("model") and n.get("firmware"):
            models.setdefault(n["model"], set()).add(n["firmware"])
    drift = {m: v for m, v in models.items() if len(v) > 1}
    if drift:
        add("medium", "Firmware drift", "; ".join(f"{m}: {', '.join(sorted(v))}" for m, v in drift.items()),
            "Update all units of a model to the same current release, after a config backup", skill="netwatch-remediation")
    upg = [n["label"] for n in nodes.values() if n.get("upgradable")]
    if upg:
        add("medium", "Firmware updates available", ", ".join(upg[:6]),
            "Back up first, then update (one change at a time)", skill="netwatch-remediation")
    slow = [(n["label"], p["idx"], p["speed"]) for n in nodes.values() for p in n.get("ports", [])
            if p.get("up") and isinstance(p.get("speed"), int) and 0 < p["speed"] <= 100]
    halfd = [(n["label"], p["idx"]) for n in nodes.values() for p in n.get("ports", []) if p.get("up") and p.get("full_duplex") is False]
    if slow or halfd:
        add("low", "Links at 100 Mb/s or half duplex",
            "; ".join(f"{a} port {b} at {c} Mb/s" for a, b, c in slow[:4]) + ("; half duplex: " + ", ".join(f"{a} port {b}" for a, b in halfd[:3]) if halfd else ""),
            "Check the cable and the device; could be an old device or a damaged cable", who="owner")
    unknown = kinds.get("unknown", [])
    if unknown:
        add("medium" if len(unknown) > 3 else "low", "Unidentified devices", f"{len(unknown)} nodes, e.g. {', '.join(sorted(u['label'] for u in unknown)[:4])}",
            "Identify and label them (netwatch-asset-inventory label); unknown devices cannot be placed in the right segment",
            who="owner and Net Watch", skill="netwatch-asset-inventory")
    gw = nodes.get(g["gateway"], {})
    wan = gw.get("wan_ip", "")
    try:
        if wan and (ipaddress.ip_address(wan).is_private or ipaddress.ip_address(wan) in ipaddress.ip_network("100.64.0.0/10")):
            add("low", "Double NAT or CGNAT", f"gateway WAN address {wan}",
                "Put the ISP modem in bridge mode if possible; port forwards and some VPNs fail behind double NAT", who="owner")
    except ValueError:
        pass
    for note in g.get("notes", []):
        if "another router" in note:
            add("low", "Hidden router in the path", note, "Find the device and confirm it is intended (mesh in router mode, travel router)", who="owner")
    if d and not d.get("baseline"):
        if d.get("new"):
            add("medium", "New devices since the last map", ", ".join(x["label"] for x in d["new"][:6]),
                "Confirm each with the owner; unknown new devices go to netwatch-intrusion-detection", skill="netwatch-asset-inventory")
        moved_infra = [x for x in d.get("moved", [])]
        if moved_infra:
            add("medium", "Devices moved (uplink or network changed)", "; ".join(f"{x['label']}: {x['what']}" for x in moved_infra[:5]),
                "Confirm the change was intended (recabling, new switch); unexpected moves can mean a rogue device", who="owner")
    seen, uniq = set(), []
    for r in sorted(recs, key=lambda r: SEV[r["severity"]]):
        if r["title"] not in seen:
            seen.add(r["title"])
            uniq.append(r)
    for i, r in enumerate(uniq, 1):
        r["rank"] = i
    return uniq


# ---------------------------------------------------------------- render
COLORS = {"gateway": "#d9534f", "switch": "#5bc0de", "ap": "#5cb85c", "nas": "#8e44ad", "workstation": "#337ab7",
          "phone": "#f0ad4e", "iot": "#95a5a6", "camera": "#e67e22", "smart-home": "#16a085", "unknown": "#bdc3c7"}


def to_mermaid(g):
    nodes = {n["id"]: n for n in g["nodes"]}
    ids = {nid: f"n{i}" for i, nid in enumerate(nodes)}
    lines = ["graph TD"]
    children = {}
    for n in nodes.values():
        if n["parent"]:
            children.setdefault(n["parent"], []).append(n["id"])
    hidden = set()
    for parent, kids in children.items():
        leaves = [k for k in kids if not children.get(k) and nodes[k]["kind"] not in INFRA]
        if len(leaves) > CLIENT_GROUP:
            counts = {}
            for k in leaves:
                counts[nodes[k]["kind"]] = counts.get(nodes[k]["kind"], 0) + 1
                hidden.add(k)
            gid = ids[parent] + "g"
            lines.append(f'  {gid}["{len(leaves)} clients: {group_summary(counts)}"]')
            lines.append(f"  {ids[parent]} --- {gid}")
    for nid, n in nodes.items():
        if nid in hidden:
            continue
        tag = " observe only" if n["observe_only"] else ""
        lines.append(f'  {ids[nid]}["{mermaid_label(n["label"])} ({n["kind"]}{tag})"]:::{n["kind"].replace("-", "")}')
    for nid, n in nodes.items():
        if nid in hidden or not n["parent"] or n["parent"] not in ids:
            continue
        arrow = "-.-" if n["link"] in ("wireless", "unknown") else "---"
        lines.append(f"  {ids[n['parent']]} {arrow} {ids[nid]}")
    for k, c in COLORS.items():
        lines.append(f"  classDef {k.replace('-', '')} fill:{c},color:#000")
    return "\n".join(lines) + "\n"


def layout(g):
    nodes = {n["id"]: n for n in g["nodes"]}
    children = {}
    for n in nodes.values():
        if n["parent"] in nodes:
            children.setdefault(n["parent"], []).append(n["id"])
    for v in children.values():
        v.sort(key=lambda x: (KINDS.index(nodes[x]["kind"]), nodes[x]["label"].lower()))
    pos, counter = {}, [0]

    def place(nid, depth, seen):
        if nid in seen:
            return
        seen.add(nid)
        kids = [k for k in children.get(nid, []) if k not in seen]
        if not kids:
            pos[nid] = (counter[0], depth)
            counter[0] += 1
            return
        for k in kids:
            place(k, depth + 1, seen)
        xs = [pos[k][0] for k in kids if k in pos]
        pos[nid] = (sum(xs) / len(xs) if xs else counter[0], depth)

    seen = set()
    place(g["gateway"], 0, seen)
    for nid in nodes:
        if nid not in pos:
            pos[nid] = (counter[0], 0)
            counter[0] += 1
    return pos


def to_html(g, recs, d):
    e = html.escape
    nodes = {n["id"]: n for n in g["nodes"]}
    shown = list(nodes)[:HTML_MAX_NODES]
    pos = layout(g)
    W, H, BW, BH = 130, 110, 120, 44
    maxx = max((pos[n][0] for n in shown), default=0)
    maxy = max((pos[n][1] for n in shown), default=0)
    width, height = int((maxx + 1) * W + 40), int((maxy + 1) * H + 40)
    svg = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" font-family="sans-serif" font-size="10">']
    for nid in shown:
        n = nodes[nid]
        if n["parent"] in pos and n["parent"] in shown:
            x1, y1 = pos[n["parent"]]
            x2, y2 = pos[nid]
            dash = ' stroke-dasharray="4 3"' if n["link"] in ("wireless", "unknown") else ""
            svg.append(f'<line x1="{x1 * W + 20 + BW / 2:.0f}" y1="{y1 * H + 20 + BH:.0f}" x2="{x2 * W + 20 + BW / 2:.0f}" '
                       f'y2="{y2 * H + 20:.0f}" stroke="#666"{dash}/>')
    for nid in shown:
        n = nodes[nid]
        x, y = pos[nid]
        x, y = x * W + 20, y * H + 20
        stroke = ' stroke="#c0392b" stroke-width="3" stroke-dasharray="5 2"' if n["observe_only"] else ' stroke="#333"'
        title = e(f"{n['label']} | {n['kind']} | {', '.join(n['ips'])} | {n['mac']} | {n['vendor']} | {n['reason']}")
        svg.append(f'<g><title>{title}</title><rect x="{x:.0f}" y="{y:.0f}" rx="6" width="{BW}" height="{BH}" '
                   f'fill="{COLORS[n["kind"]]}"{stroke}/>'
                   f'<text x="{x + 6:.0f}" y="{y + 16:.0f}">{e(clean(n["label"], 20))}</text>'
                   f'<text x="{x + 6:.0f}" y="{y + 32:.0f}">{e(n["kind"])} {e(n["ips"][0] if n["ips"] else "")}</text></g>')
    svg.append("</svg>")
    legend = " ".join(f'<span style="background:{c};padding:2px 6px;margin:2px;display:inline-block">{e(k)}</span>' for k, c in COLORS.items())
    rows = "".join(f"<tr><td>{e(n['label'])}</td><td>{e(n['kind'])}{' (observe only)' if n['observe_only'] else ''}</td>"
                   f"<td>{e(', '.join(n['ips']))}</td><td>{e(n['mac'])}</td><td>{e(n['vendor'])}</td>"
                   f"<td>{e(nodes.get(n['parent'], {}).get('label', ''))}{(' port ' + e(str(n['parent_port']))) if n.get('parent_port') is not None else ''}</td>"
                   f"<td>{e(n['link'])}</td><td>{e(n['network'] or '')}</td><td>{e(n['reason'])}</td></tr>" for n in g["nodes"])
    recrows = "".join(f"<tr><td>{r['rank']}</td><td>{e(r['severity'])}</td><td>{e(r['title'])}</td><td>{e(r['evidence'])}</td>"
                      f"<td>{e(r['fix'])}</td><td>{e(r['who'])}</td></tr>" for r in recs)
    dtext = "first map (baseline)" if d.get("baseline") else (
        f"new {len(d['new'])}, missing {len(d['missing'])}, moved {len(d['moved'])}, Wi-Fi roams {d['roamed']}")
    more = f"<p>Map shows the first {HTML_MAX_NODES} nodes; the table lists all.</p>" if len(nodes) > HTML_MAX_NODES else ""
    return ("<!doctype html><html><head><meta charset='utf-8'>"
            "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; style-src 'unsafe-inline'\">"
            f"<title>Net Watch topology</title><style>body{{font-family:sans-serif;margin:16px}}table{{border-collapse:collapse;font-size:12px}}"
            "td,th{border:1px solid #ccc;padding:3px 6px;vertical-align:top}.map{overflow:auto;border:1px solid #ddd}</style></head><body>"
            f"<h1>Net Watch topology</h1><p>Generated {e(g['generated_at'])}; source {e(g['source'])}; {len(nodes)} nodes. "
            f"Changes: {e(dtext)}. Dashed lines are Wi-Fi or unknown attachment; red dashed outline means observe only.</p>"
            f"<p>{legend}</p>{more}<div class='map'>{''.join(svg)}</div>"
            f"<h2>Recommendations</h2><table><tr><th>#</th><th>Severity</th><th>Finding</th><th>Evidence</th><th>Fix</th><th>Who</th></tr>{recrows}</table>"
            f"<h2>Nodes</h2><table><tr><th>Name</th><th>Kind</th><th>IPs</th><th>MAC</th><th>Vendor</th><th>Upstream</th><th>Link</th>"
            f"<th>Network</th><th>Why this kind</th></tr>{rows}</table></body></html>")


def to_recs_md(recs, d, g):
    out = [f"# Topology recommendations ({g['generated_at']})", ""]
    if d.get("baseline"):
        out.append("First map: saved as the baseline for future diffs.")
    else:
        out.append(f"Since last map: new {len(d['new'])}, missing {len(d['missing'])}, moved {len(d['moved'])}, Wi-Fi roams {d['roamed']} (normal).")
    out += ["", "| # | Severity | Finding | Evidence | Fix | Who |", "|---|---|---|---|---|---|"]
    for r in recs:
        cells = [str(r["rank"]), r["severity"], r["title"], r["evidence"], r["fix"] + (f" ({r['skill']})" if r["skill"] else ""), r["who"]]
        out.append("| " + " | ".join(c.replace("|", "/") for c in cells) + " |")
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------- commands
def new_run_dir():
    d = os.path.join(topo_home(), now().strftime("%Y%m%d-%H%M%S"))
    os.makedirs(d, exist_ok=True)
    return d


def latest_run(require_built=False):
    runs = sorted(d for d in glob.glob(os.path.join(topo_home(), "2*")) if os.path.isdir(d))
    if require_built:
        runs = [r for r in runs if os.path.isfile(os.path.join(r, "graph.json"))]
    return runs[-1] if runs else ""


def summary(g, recs, d, run_dir):
    kinds = {}
    for n in g["nodes"]:
        kinds[n["kind"]] = kinds.get(n["kind"], 0) + 1
    print(f"run={run_dir}")
    print(f"nodes={len(g['nodes'])} " + " ".join(f"{k}={v}" for k, v in sorted(kinds.items())))
    print(f"observe_only={sum(1 for n in g['nodes'] if n['observe_only'])} source={g['source']} scan={g['scan_dir'] or 'none'}")
    if d.get("baseline"):
        print("diff=baseline (first map)")
    else:
        print(f"diff new={len(d['new'])} missing={len(d['missing'])} moved={len(d['moved'])} roamed={d['roamed']}")
    for err in g.get("collect_errors", []):
        print(f"COLLECT-WARN {err}")
    for r in recs[:10]:
        print(f"REC {r['rank']} [{r['severity']}] {r['title']}")
    print("files: graph.json topology.mmd topology.html diff.json recommendations.md")


def cmd_build(a):
    home = nw.netwatch_home()
    run_dir = a.run or latest_run()
    if not run_dir:
        run_dir = new_run_dir()
        collect("none", "default", run_dir)
    if not nw.inside(os.path.realpath(run_dir), os.path.realpath(topo_home())):
        print("REFUSED: --run must be inside NETWATCH_HOME/topology")
        return 3
    scan_dir = a.scan or latest_scan_dir(home)
    osf = nw.os_family()
    try:
        nets = nw.load_scope(home)
    except (FileNotFoundError, ValueError) as e:
        print(f"SCOPE-FAIL: {e}")
        return 1
    gw = nw.default_gateway(osf) or ""
    traces = {}
    if a.traceroute:
        targets = []
        for net in nets:
            if net.version == 4 and net.num_addresses > 2:
                first = str(next(net.hosts()))
                if first != gw:
                    targets.append(first)
        targets += [t for t in a.trace_to if t not in targets]
        traces = run_traceroutes(targets, nets, run_dir, osf)
    g = build_graph(run_dir, scan_dir, home, gw, traces, nets)
    prev_path = os.path.join(topo_home(), "latest", "graph.json")
    prev = load_json(prev_path) if os.path.isfile(prev_path) else None
    d = diff(prev, g)
    recs = recommend(g, d)
    nw.write_private(os.path.join(run_dir, "graph.json"), json.dumps(g, indent=1))
    nw.write_private(os.path.join(run_dir, "diff.json"), json.dumps(d, indent=1))
    nw.write_private(os.path.join(run_dir, "topology.mmd"), to_mermaid(g))
    nw.write_private(os.path.join(run_dir, "topology.html"), to_html(g, recs, d))
    nw.write_private(os.path.join(run_dir, "recommendations.md"), to_recs_md(recs, d, g))
    nw.write_private(os.path.join(run_dir, "recommendations.json"), json.dumps(recs, indent=1))
    if not a.no_accept:
        latest = os.path.join(topo_home(), "latest")
        os.makedirs(latest, exist_ok=True)
        for f in ("graph.json", "topology.mmd", "topology.html", "recommendations.md"):
            shutil.copyfile(os.path.join(run_dir, f), os.path.join(latest, f))
    summary(g, recs, d, run_dir)
    return 0


def cmd_collect(a):
    run_dir = new_run_dir()
    meta = collect(a.source, a.site, run_dir)
    print(f"run={run_dir} source={a.source} files={','.join(meta['files']) or 'none'}")
    for err in meta["errors"]:
        print(f"COLLECT-WARN {err}")
    return 0


def cmd_show(a):
    run_dir = a.run or latest_run(require_built=True)
    g = load_json(os.path.join(run_dir, "graph.json")) if run_dir else None
    if not g:
        print("NO-MAP: run 'topology.py run' first")
        return 1
    summary(g, load_json(os.path.join(run_dir, "recommendations.json"), []),
            load_json(os.path.join(run_dir, "diff.json"), {"baseline": True}), run_dir)
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("collect", "run"):
        p = sub.add_parser(name)
        p.add_argument("--source", default="unifi-classic", choices=["unifi-classic", "unifi-int", "omada", "none"])
        p.add_argument("--site", default="default")
    for name in ("build", "run"):
        p = sub.choices[name] if name in sub.choices else sub.add_parser(name)
        p.add_argument("--run", default="")
        p.add_argument("--scan", default="")
        p.add_argument("--traceroute", action="store_true")
        p.add_argument("--trace-to", action="append", default=[], metavar="IP")
        p.add_argument("--no-accept", action="store_true", help="do not make this map the new diff baseline")
    p = sub.add_parser("show")
    p.add_argument("--run", default="")
    a = ap.parse_args(argv)
    if a.cmd == "collect":
        return cmd_collect(a)
    if a.cmd == "build":
        return cmd_build(a)
    if a.cmd == "show":
        return cmd_show(a)
    run_dir = new_run_dir()
    meta = collect(a.source, a.site, run_dir)
    for err in meta["errors"]:
        print(f"COLLECT-WARN {err}")
    a.run = run_dir
    return cmd_build(a)


if __name__ == "__main__":
    sys.exit(main())
