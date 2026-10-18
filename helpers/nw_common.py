#!/usr/bin/env python3
"""Net Watch shared library (pure Python 3 standard library; Linux, macOS, Windows).

Imported by the other helpers from the same folder ($NETWATCH_HOME/bin). Never
prints secret values. Run directly for a quick self-description:
  nw_common.py [paths]   show OS family, NETWATCH_HOME, env file path, privilege
  nw_common.py init      create NETWATCH_HOME subfolders, private to the scan user
"""
import ctypes
import getpass
import ipaddress
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys

PROTECTED_ENV = re.compile(
    r"^(PATH|PATHEXT|HOME|USERPROFILE|APPDATA|LOCALAPPDATA|SYSTEMROOT|COMSPEC|IFS|ENV|BASH_ENV|SHELL|"
    r"LD_.*|DYLD_.*|PYTHON.*|NETWATCH_.*|NW_.*|CURL_.*|SSL_.*|REQUESTS_CA_BUNDLE|"
    r"HTTPS?_PROXY|ALL_PROXY|NO_PROXY)$", re.I)
# Redaction allowlist of real secret field names. The old broad patterns (^key$, _key$, session) also stripped
# harmless UniFi fields such as rest/setting "key": "mgmt"; those must survive so setting objects stay readable.
SECRET_NAMES = frozenset(n.lower() for n in (
    # generic credentials
    "password", "passwd", "pass", "pwd", "passphrase", "secret", "token", "api_key", "apikey", "api_token",
    "access_token", "refresh_token", "id_token", "auth_token", "bearer", "client_secret", "private_key", "privkey",
    "secret_key", "shared_secret", "shared_key", "pre_shared_key", "presharedkey", "psk", "wpa_psk", "wpa_key",
    "wep_key", "wpa_passphrase", "auth_key", "authkey", "mgmt_key", "community", "snmp_community",
    # HTTP session material
    "cookie", "cookies", "set-cookie", "csrf", "csrf_token", "x-csrf-token", "x_csrf_token", "authorization",
    "sid", "session", "sessionid", "session_id", "session_token", "session_cookie", "unifises",
    # RADIUS / VPN
    "radius_secret", "radius_key", "auth_secret", "acct_secret", "ipsec_key", "ipsec_psk", "wireguard_private_key",
    "openvpn_key", "tls_key", "ovpn_key",
    # UniFi Network x_ fields (wlanconf, setting/mgmt, radiusprofile, networkconf, device, account)
    "x_passphrase", "x_password", "x_secret", "x_shadow", "x_private_key", "x_iapp_key", "x_ssh_password",
    "x_ssh_keys", "x_ssh_key", "x_ssh_username", "x_authkey", "x_auth_key", "x_api_key", "x_mgmt_key",
    "x_ipsec_pre_shared_key", "x_wireguard_private_key", "x_openvpn_shared_secret_key", "x_ca_key",
    "x_server_key", "x_tls_key", "x_vwirekey", "x_vwire_key", "x_pppoe_password", "x_radius_secret",
    "x_mesh_psk", "x_wpa_psk", "x_wep_key", "x_sae_psk", "x_hotspot_password", "x_snmp_community",
    "wpa_psk_hex", "sae_psk", "private_preshared_keys",
))
# Name fragments that only ever mean a secret. "key" alone is deliberately NOT here.
SECRET_FRAGMENTS = ("password", "passphrase", "passwd", "secret", "token", "private_key", "preshared", "pre_shared",
                    "psk", "cookie", "csrf", "_shadow", "ssh_key")


class _SecretKey:
    """Drop-in for the old regex: .search(name) is truthy when name is a known secret field.
    UniFi x_ fields stay redacted by default (UniFi's convention for credential fields); x_ fields known to be
    harmless can be listed in X_SAFE."""
    X_SAFE = frozenset()

    def search(self, name):
        n = str(name).strip().lower()
        if n in SECRET_NAMES or any(f in n for f in SECRET_FRAGMENTS):
            return True
        if n.startswith("x_") and n not in self.X_SAFE:
            return True
        return False


SECRET_KEY = _SecretKey()
NW_VERSION = "v1.2.0"  # helper bundle version; build_bundle.py refuses a bundle whose VERSION differs
OWN_DEVICES_MARKER = "# netwatch: own-devices-only"  # scope.txt line for ISP or landlord routers: single addresses only
MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")


# ---------------------------------------------------------------- OS and paths
def os_family(system=None):
    s = (system or platform.system()).lower()
    if s.startswith(("win", "cygwin", "msys", "mingw")):
        return "windows"
    if s == "darwin":
        return "macos"
    return "linux"


def netwatch_home(env=None, script=None):
    """Parent of the bin folder this helper runs from; else NETWATCH_HOME; else ~/netwatch.

    Installed helpers live in NETWATCH_HOME/bin, so no environment variable is needed
    on any OS. The variable is used when helpers run from the skill folders (tests).
    """
    env = os.environ if env is None else env
    here = os.path.dirname(os.path.abspath(script or __file__))
    if os.path.basename(here).lower() == "bin":
        h = os.path.dirname(here)
    else:
        h = env.get("NETWATCH_HOME", "") or os.path.join(os.path.expanduser("~"), "netwatch")
    if not os.path.isabs(h):
        sys.exit(f"NETWATCH_HOME must be an absolute path (got '{h}')")
    return h


def env_file_path(osf=None, env=None, userhome=None, exists=os.path.isfile):
    """Owner-created secrets file. NETWATCH_ENV_FILE overrides (absolute path only)."""
    env = os.environ if env is None else env
    osf = osf or os_family()
    userhome = userhome or os.path.expanduser("~")
    override = env.get("NETWATCH_ENV_FILE", "")
    if override:
        if not os.path.isabs(override) and not re.match(r"^[A-Za-z]:[\\/]", override):
            sys.exit("NETWATCH_ENV_FILE must be an absolute path")
        return override
    if osf == "windows":
        appdata = env.get("APPDATA") or os.path.join(userhome, "AppData", "Roaming")
        return appdata.rstrip("\\/") + "\\netwatch\\env"
    xdg = os.path.join(env.get("XDG_CONFIG_HOME") or os.path.join(userhome, ".config"), "netwatch", "env")
    if osf == "macos":
        lib = os.path.join(userhome, "Library", "Application Support", "netwatch", "env")
        if exists(lib) or not exists(xdg):
            return lib
        return xdg
    return xdg


def is_wsl(release=None):
    """Linux running inside Windows Subsystem for Linux (WSL2 NAT hides the real LAN)."""
    rel = (release if release is not None else platform.uname().release).lower()
    return "microsoft" in rel or "wsl" in rel


def inside(child, parent):
    """True if child path is inside parent (False across Windows drives instead of raising)."""
    try:
        return os.path.commonpath([os.path.realpath(parent), os.path.realpath(child)]) == os.path.realpath(parent)
    except ValueError:
        return False


def python_cmd(osf=None):
    return "py -3" if (osf or os_family()) == "windows" else "python3"


# ---------------------------------------------------------------- privilege
def is_admin(osf=None):
    osf = osf or os_family()
    if osf == "windows":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        except Exception:
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0


def find_tool(name, osf=None):
    """shutil.which plus the default Windows install folders (nmap's installer skips PATH sometimes)."""
    osf = osf or os_family()
    p = shutil.which(name)
    if p or osf != "windows":
        return p
    for base in (os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
                 os.environ.get("ProgramFiles", r"C:\Program Files")):
        cand = os.path.join(base, "Nmap", name + ".exe")
        if os.path.isfile(cand):
            return cand
    return None


def linux_caps(path):
    getcap = shutil.which("getcap") or ("/usr/sbin/getcap" if os.path.exists("/usr/sbin/getcap") else None)
    if not getcap or not path:
        return ""
    rc, out = run([getcap, path], timeout=10)
    return out.strip() if rc == 0 else ""


def nmap_privilege(osf=None):
    """Return (flags, raw_ok, reason). raw_ok means raw-packet features (ARP ping, DHCP probe) work."""
    osf = osf or os_family()
    nmap = find_tool("nmap", osf)
    if not nmap:
        return [], False, "nmap not installed"
    if is_admin(osf):
        return [], True, "running as root/administrator"
    if osf == "linux":
        caps = linux_caps(os.path.realpath(nmap))
        if "cap_net_raw" in caps:
            return ["--privileged"], True, "nmap has cap_net_raw"
        return ["--unprivileged"], False, "nmap has no raw-socket capability (TCP connect discovery only)"
    if osf == "macos":
        return ["--unprivileged"], False, "macOS needs sudo for raw packets; the owner runs privileged checks"
    return ["--unprivileged"], False, "not an elevated (Administrator) session; Npcap raw features unavailable"


# ---------------------------------------------------------------- processes
def run(cmd, timeout=60, stdin_text=None, cwd=None):
    """Run a command list without a shell. Returns (returncode, stdout+stderr text)."""
    try:
        r = subprocess.run(cmd, input=stdin_text, capture_output=True, text=True,
                           timeout=timeout, errors="replace", cwd=cwd,
                           stdin=None if stdin_text is not None else subprocess.DEVNULL)
        return r.returncode, (r.stdout or "") + (r.stderr or "")
    except FileNotFoundError:
        return 127, f"not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return 124, f"timeout after {timeout}s: {cmd[0]}"


# ---------------------------------------------------------------- env file
def load_env(path, osf=None, check_perms=True):
    """Literal NAME=value parser (never executed). Returns (values, problems).

    problems never contain values, only line numbers and names.
    """
    problems = []
    if not os.path.isfile(path):
        return {}, [f"ENV-MISSING: {path} (owner must create it; see netwatch-setup)"]
    if check_perms:
        problems += env_perm_problems(path, osf)
        if problems:
            return {}, problems
    vals = {}
    with open(path, encoding="utf-8-sig", errors="replace") as fh:
        for n, line in enumerate(fh, 1):
            line = line.rstrip("\r\n")
            if re.match(r"^\s*(#|$)", line):
                continue
            if line.startswith("export "):
                line = line[7:]
            m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$", line)
            if not m:
                problems.append(f"ENV-SYNTAX: line {n} is not NAME=value (value not shown)")
                continue
            name, value = m.group(1), m.group(2)
            if PROTECTED_ENV.match(name):
                problems.append(f"ENV-REFUSED: line {n} sets protected variable {name}")
                continue
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
                value = value[1:-1]
            vals[name] = value
    return vals, problems


def env_perm_problems(path, osf=None):
    osf = osf or os_family()
    if osf == "windows":
        rc, out = run(["icacls", path], timeout=20)
        if rc != 0:
            return [f"ENV-PERMS: could not read ACL of {path} with icacls"]
        bad = icacls_broad_access(out, path, getpass.getuser())
        if bad:
            return [f"ENV-PERMS: {path} is readable by {', '.join(bad)}; fix with: "
                    f"icacls \"{path}\" /inheritance:r /grant:r \"${{env:USERNAME}}:F\""]
        return []
    st = os.stat(path)
    probs = []
    if st.st_mode & 0o077:
        probs.append(f"ENV-PERMS: {path} is mode {oct(st.st_mode & 0o777)[2:]}, expected 600 (chmod 600)")
    if hasattr(os, "geteuid") and st.st_uid != os.geteuid():
        probs.append(f"ENV-PERMS: {path} is not owned by the scan user")
    return probs


def icacls_broad_access(text, path, user):
    """Principals other than the current user, SYSTEM, or Administrators that hold any access."""
    allowed = {user.lower(), "nt authority\\system", "builtin\\administrators", "system", "administrators"}
    bad = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.lower().startswith("successfully processed"):
            continue
        if line.lower().startswith(path.lower()):
            line = line[len(path):].strip()
        if ":(" not in line:
            continue
        principal = line.split(":(", 1)[0].strip()
        short = principal.split("\\")[-1].lower()
        if principal.lower() in allowed or short == user.lower():
            continue
        bad.append(principal)
    return bad


def require(vals, *names):
    missing = [n for n in names if not vals.get(n)]
    if missing:
        sys.exit("ENV-MISSING-VARS: " + ", ".join(missing) + " (add them to the env file)")


def verify_tls(vals, prefix):
    return vals.get(f"{prefix}_VERIFY_SSL", "true").strip().lower() != "false"


# ---------------------------------------------------------------- redaction
def redact(obj):
    """Drop secret-looking keys anywhere in a JSON structure (Wi-Fi passphrases, VPN keys, tokens)."""
    if isinstance(obj, dict):
        return {k: redact(v) for k, v in obj.items() if not SECRET_KEY.search(str(k))}
    if isinstance(obj, list):
        return [redact(v) for v in obj]
    return obj


# ---------------------------------------------------------------- scope
def load_scope(home=None):
    path = os.path.join(home or netwatch_home(), "scope.txt")
    if not os.path.isfile(path):
        raise FileNotFoundError(path)
    nets = []
    own_only = False
    with open(path, encoding="utf-8-sig") as fh:
        for raw in fh:
            if raw.strip().lower() == OWN_DEVICES_MARKER:
                own_only = True
            line = raw.split("#", 1)[0].strip()
            if line:
                nets.append(ipaddress.ip_network(line, strict=False))
    if own_only:  # ISP or landlord router: the owner's own devices only, never a subnet sweep
        wide = [str(n) for n in nets if n.num_addresses > 1]
        if wide:
            raise ValueError("own-devices-only scope allows single addresses (/32 or /128) only, not " + ", ".join(wide))
    return nets


def scope_mode(home=None):
    """'own-devices-only' when scope.txt carries the marker line, else 'subnet'."""
    try:
        with open(os.path.join(home or netwatch_home(), "scope.txt"), encoding="utf-8-sig") as fh:
            return "own-devices-only" if any(l.strip().lower() == OWN_DEVICES_MARKER for l in fh) else "subnet"
    except OSError:
        return "subnet"


def scope_problems(targets, nets):
    bad = []
    if not nets:
        return ["scope file is empty"]
    for target in targets:
        try:
            tnet = ipaddress.ip_network(target, strict=False)
        except ValueError:
            bad.append(f"{target} (not an IP or CIDR; hostnames are refused)")
            continue
        if not tnet.is_private and not tnet.is_link_local:
            bad.append(f"{target} (public address; LAN scans only)")
            continue
        if not any(tnet.version == n.version and tnet.subnet_of(n) for n in nets):
            bad.append(f"{target} (outside scope.txt)")
    return bad


def require_scope(targets, home=None):
    try:
        nets = load_scope(home)
    except FileNotFoundError as exc:
        sys.exit(f"SCOPE-FAIL: no scope file at {exc}")
    except ValueError as exc:
        sys.exit(f"SCOPE-FAIL: bad line in scope file: {exc}")
    bad = scope_problems(targets, nets)
    if bad:
        print("SCOPE-FAIL: " + "; ".join(bad))
        sys.exit(1)
    return nets


def in_nets(ip, nets):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a.version == n.version and a in n for n in nets)


# ---------------------------------------------------------------- neighbors / routes
def normalize_mac(mac):
    """aa-bb-cc-dd-ee-ff, 0:1a:2b:3:4:5, AA:BB... -> aa:bb:cc:dd:ee:ff; '' if not a MAC."""
    parts = re.split(r"[:-]", (mac or "").strip().lower())
    if len(parts) != 6 or not all(re.fullmatch(r"[0-9a-f]{1,2}", p) for p in parts):
        return ""
    return ":".join(p.zfill(2) for p in parts)


def unicast_mac(mac):
    if not mac or mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
        return False
    return int(mac.split(":")[0], 16) & 0x01 == 0


def neighbor_command(osf):
    if osf == "linux":
        return ["ip", "-4", "neigh", "show"] if shutil.which("ip") else ["arp", "-an"]
    if osf == "macos":
        return ["arp", "-an"]
    return ["arp", "-a"]


def parse_neighbors(text, osf):
    """Return list of (ip, mac) for complete IPv4 unicast entries."""
    out = []
    for line in text.splitlines():
        ip = mac = ""
        if osf == "linux" and " lladdr " in f" {line} ":
            parts = line.split()
            if any(s in parts for s in ("FAILED", "INCOMPLETE")):
                continue
            ip, mac = parts[0], parts[parts.index("lladdr") + 1]
        else:
            m = re.search(r"\((\d{1,3}(?:\.\d{1,3}){3})\)\s+at\s+([0-9A-Fa-f:]+)", line)  # BSD/macOS, Linux arp -an
            if m:
                ip, mac = m.groups()
            else:
                m = re.match(r"^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){5})\s+\S+", line)  # Windows arp -a
                if m:
                    ip, mac = m.groups()
        mac = normalize_mac(mac)
        if ip and mac and unicast_mac(mac):
            try:
                if ipaddress.ip_address(ip).version == 4 and not ipaddress.ip_address(ip).is_multicast:
                    out.append((ip, mac))
            except ValueError:
                pass
    return out


def neighbors(osf=None):
    osf = osf or os_family()
    rc, out = run(neighbor_command(osf), timeout=30)
    if rc != 0:
        return [], out.strip()[:200]
    return parse_neighbors(out, osf), ""


def parse_proc_route(text):
    """Linux /proc/net/route -> (gateway, iface) of the default route."""
    for line in text.splitlines()[1:]:
        f = line.split()
        if len(f) >= 3 and f[1] == "00000000" and f[2] != "00000000":
            gw = ipaddress.IPv4Address(int(f[2], 16).to_bytes(4, "little"))
            return str(gw), f[0]
    return "", ""


def parse_macos_route(text):
    gw = iface = ""
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("gateway:"):
            gw = line.split(":", 1)[1].strip()
        elif line.startswith("interface:"):
            iface = line.split(":", 1)[1].strip()
    return gw, iface


def parse_windows_route(text):
    """`route print -4 0.0.0.0` -> (gateway, interface IP) with the lowest metric."""
    best = None
    for line in text.splitlines():
        f = line.split()
        if len(f) >= 5 and f[0] == "0.0.0.0" and f[1] == "0.0.0.0" and re.match(r"^\d+\.\d+\.\d+\.\d+$", f[2]):
            try:
                metric = int(f[4])
            except ValueError:
                continue
            if best is None or metric < best[0]:
                best = (metric, f[2], f[3])
    return (best[1], best[2]) if best else ("", "")


def default_gateway(osf=None):
    osf = osf or os_family()
    if osf == "linux":
        try:
            with open("/proc/net/route", encoding="ascii") as fh:
                return parse_proc_route(fh.read())
        except OSError:
            return "", ""
    if osf == "macos":
        rc, out = run(["route", "-n", "get", "default"], timeout=15)
        return parse_macos_route(out) if rc == 0 else ("", "")
    rc, out = run(["route", "print", "-4", "0.0.0.0"], timeout=15)
    return parse_windows_route(out) if rc == 0 else ("", "")


RFC1918 = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]  # generic-ranges
DOCKER_NET = ipaddress.ip_network("172.17.0.0/16")  # Docker default bridge
MASK_RE = re.compile(r"(?:0x[0-9a-fA-F]{8}|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")


def local_ip_for(gateway):
    """Address this host uses toward the gateway. UDP connect sends no packet."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((gateway or "192.0.2.1", 9))
        return s.getsockname()[0]
    except OSError:
        return ""
    finally:
        s.close()


def prefix_command(osf):
    if osf == "linux":
        return ["ip", "-4", "-o", "addr", "show"] if shutil.which("ip") else ["ifconfig"]
    if osf == "macos":
        return ["ifconfig"]
    return ["ipconfig"]


def _mask_prefix(tok, ip):
    try:
        if tok.lower().startswith("0x"):
            n = int(tok, 16)
        else:
            if tok == ip:
                return None
            n = int(ipaddress.IPv4Address(tok))
    except ValueError:
        return None
    bits = bin(n)[2:].zfill(32)
    if "01" in bits or n == 0:
        return None  # not a contiguous netmask
    return bits.count("1")


def parse_prefix(text, ip):
    """Prefix length for ip from `ip addr`, ifconfig, or ipconfig output (any language)."""
    if not ip:
        return None
    lines = text.splitlines()
    pat = re.compile(r"(?<![\d.])" + re.escape(ip) + r"(?![\d])(/(\d{1,2}))?")
    for i, line in enumerate(lines):
        m = pat.search(line)
        if not m:
            continue
        if m.group(2) and 0 < int(m.group(2)) <= 32:
            return int(m.group(2))
        rest = [line[m.end():]] + lines[i + 1:i + 4]
        for chunk in rest:
            for tok in MASK_RE.findall(chunk):
                pfx = _mask_prefix(tok, ip)
                if pfx:
                    return pfx
    return None


def suggest_scope(osf=None, gw_iface=None, ip=None, text=None, wsl=None, container=None):
    """Suggest the home LAN CIDR from this host's own address. Never scans."""
    osf = osf or os_family()
    gw, _ = gw_iface if gw_iface is not None else default_gateway(osf)
    ip = ip if ip is not None else local_ip_for(gw)
    out = {"gateway": gw or "", "local_ip": ip or "", "prefix": None, "suggest": "", "reason": ""}
    if wsl is None:
        wsl = osf == "linux" and is_wsl()
    if not ip:
        out["reason"] = "no IPv4 address toward the gateway"
        return out
    if text is None:
        rc, text = run(prefix_command(osf), timeout=15)
        text = text if rc == 0 else ""
    pfx = parse_prefix(text, ip)
    out["prefix"] = pfx
    addr = ipaddress.IPv4Address(ip)
    if not any(addr in n for n in RFC1918):  # is_private would also accept documentation and loopback ranges
        out["reason"] = "host address is not a private LAN address"
        return out
    if wsl:
        out["reason"] = "WSL NAT network, not the home LAN"
        return out
    if container is None:
        container = os.path.exists("/.dockerenv")
    if addr in DOCKER_NET or container:
        out["reason"] = "looks like a Docker or container network, not the home LAN"
        return out
    if pfx is None:
        pfx, note = 24, "netmask not found, assumed /24"
    elif pfx < 22:
        pfx, note = 24, f"interface is /{out['prefix']}, suggesting only the /24 around this host"
    else:
        note = "from this host's address and netmask"
    net = ipaddress.ip_network(f"{ip}/{pfx}", strict=False)
    if gw:
        try:
            if ipaddress.IPv4Address(gw) not in net:
                note += "; gateway is outside it, check the netmask"
        except ValueError:
            pass
    out["suggest"], out["reason"] = str(net), note
    return out


def ping_command(ip, osf):
    if osf == "windows":
        return ["ping", "-n", "1", "-w", "1000", ip]
    if osf == "macos":
        return ["ping", "-c", "1", "-W", "1000", ip]
    return ["ping", "-c", "1", "-W", "1", ip]


def ping_ok(rc, out, osf):
    # Windows ping exits 0 on "Destination host unreachable" replies from a router; require a TTL.
    if osf == "windows":
        return rc == 0 and "ttl=" in out.lower()
    return rc == 0


def write_private(path, data, mode="w"):
    """Create or replace a file readable only by the scan user (mode 600 on POSIX)."""
    tmp = path + ".tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0)
    fd = os.open(tmp, flags, 0o600)
    if "b" in mode:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
    else:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(data)
    os.replace(tmp, path)


def print_json(obj):
    print(json.dumps(obj, indent=2, ensure_ascii=False))


SUBDIRS = ("bin", "scans", "changes", "backups", "reports", "ai", "topology", "alerts")


def init_home(osf=None):
    osf = osf or os_family()
    home = netwatch_home()
    for d in SUBDIRS:
        os.makedirs(os.path.join(home, d), exist_ok=True)
    if osf == "windows":
        # Owner-only ACL on the folder Net Watch created (local and reversible).
        rc, out = run(["icacls", home, "/inheritance:r", "/grant:r", f"{getpass.getuser()}:(OI)(CI)F",
                       "/grant:r", "*S-1-5-18:(OI)(CI)F"], timeout=30)
        print(f"acl={'owner+SYSTEM only' if rc == 0 else 'NOT SET: ' + out.strip()[:160]}")
    else:
        os.chmod(home, 0o700)
        print("mode=700")
    print(f"initialized {home} ({', '.join(SUBDIRS)})")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "init":
        init_home()
        sys.exit(0)
    osf = os_family()
    flags, raw_ok, why = nmap_privilege(osf)
    print(f"os={osf} python={platform.python_version()} launcher='{python_cmd(osf)}'")
    print(f"NETWATCH_HOME={netwatch_home()}")
    print(f"env_file={env_file_path(osf)}")
    print(f"admin={is_admin(osf)} nmap_flags={' '.join(flags) or '(none)'} raw_packets={raw_ok} ({why})")
