#!/usr/bin/env python3
"""Net Watch scan host hardening check (Linux, macOS, Windows). Read-only, no sudo/UAC.

  hostcheck.py

The scan host holds network credentials, so it is a high-value target. Prints
auto-update, firewall, disk encryption (where readable without elevation),
remote access services, local users, raw-packet grants, and env file permissions.
"""
import glob
import os
import re
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [HERE, os.path.join(HERE, "..", "netwatch-setup")]
import nw_common as nw  # noqa: E402

MAC_CMDS = [
    ("disk encryption (FileVault)", ["fdesetup", "status"]),
    ("application firewall", ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"]),
    ("firewall stealth mode", ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getstealthmode"]),
    ("automatic update check", ["defaults", "read", "/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticCheckEnabled"]),
    ("automatic security updates", ["defaults", "read", "/Library/Preferences/com.apple.SoftwareUpdate", "CriticalUpdateInstall"]),
    ("Gatekeeper", ["spctl", "--status"]),
    ("listening TCP ports", ["netstat", "-an", "-p", "tcp"]),
    ("local users (uid >= 501)", ["dscl", ".", "list", "/Users", "UniqueID"]),
]
WIN_PS = [
    ("firewall profiles", "Get-NetFirewallProfile | ForEach-Object { '{0} enabled={1}' -f $_.Name, $_.Enabled }"),
    ("Defender", "try { $s = Get-MpComputerStatus -ErrorAction Stop; 'realtime={0} signatures={1}' -f $s.RealTimeProtectionEnabled, $s.AntivirusSignatureLastUpdated } catch { 'Defender status unavailable (third-party antivirus or no access)' }"),
    ("Windows Update service", "Get-Service wuauserv | ForEach-Object { '{0} start={1}' -f $_.Status, $_.StartType }"),
    ("remote access services", "Get-Service sshd,TermService -ErrorAction SilentlyContinue | ForEach-Object { '{0} {1} start={2}' -f $_.Name, $_.Status, $_.StartType }"),
    ("RDP allowed (fDenyTSConnections=0 means on)", "(Get-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server').fDenyTSConnections"),
    ("enabled local users", "Get-LocalUser | Where-Object Enabled | ForEach-Object Name"),
    ("local Administrators", "try { Get-LocalGroupMember -SID S-1-5-32-544 -ErrorAction Stop | ForEach-Object Name } catch { 'unavailable' }"),
    ("BitLocker", "'needs an elevated session; ask the owner to check Settings > Privacy & security > Device encryption'"),
]


def show(label, rc, out, limit=25):
    print(f"== {label}")
    lines = out.strip().splitlines() or ["(no output)"]
    for ln in lines[:limit]:
        print(ln)
    if len(lines) > limit:
        print(f"[{len(lines) - limit} more lines]")


def sshd_settings():
    files = ["/etc/ssh/sshd_config"]
    # sshd reads Include drop-ins (normally at the top), and the first value wins.
    files = sorted(glob.glob("/etc/ssh/sshd_config.d/*.conf")) + files
    seen = {}
    for f in files:
        try:
            with open(f, encoding="utf-8", errors="replace") as fh:
                for ln in fh:
                    m = re.match(r"^\s*(PasswordAuthentication|PermitRootLogin)\s+(\S+)", ln, re.I)
                    if m and m.group(1).lower() not in seen:
                        seen[m.group(1).lower()] = f"{m.group(2)} ({f})"
        except OSError:
            continue
    return seen


def linux():
    for unit in ("unattended-upgrades", "dnf-automatic.timer"):
        rc, out = nw.run(["systemctl", "is-enabled", unit], timeout=10)
        show(f"auto-updates {unit}", rc, out)
    for unit in ("ufw", "firewalld", "nftables"):
        rc, out = nw.run(["systemctl", "is-active", unit], timeout=10)
        show(f"firewall {unit}", rc, out)
    rc, out = nw.run(["systemctl", "is-active", "ssh", "sshd"], timeout=10)
    show("ssh service", rc, out)
    s = sshd_settings()
    show("sshd settings (first match wins; defaults apply when absent)", 0, "\n".join(f"{k}={v}" for k, v in s.items()))
    users = []
    try:
        with open("/etc/passwd", encoding="utf-8") as fh:
            for ln in fh:
                f = ln.split(":")
                if len(f) > 6 and f[2].isdigit() and 1000 <= int(f[2]) < 65534:
                    users.append(f[0])
    except OSError:
        pass
    show("local users (uid >= 1000)", 0, "\n".join(users))
    caps = [f"{t}: {nw.linux_caps(os.path.realpath(shutil.which(t))) or 'none'}" for t in ("nmap", "arp-scan") if shutil.which(t)]
    show("raw-packet grants", 0, "\n".join(caps))


def macos():
    for label, cmd in MAC_CMDS:
        rc, out = nw.run(cmd, timeout=20)
        if label.startswith("listening"):
            out = "\n".join(ln for ln in out.splitlines() if "LISTEN" in ln and re.search(r"\.(22|3283|5900|445|548)\s", ln)) or "no SSH/ARD/VNC/SMB/AFP listeners"
        if label.startswith("local users"):
            out = "\n".join(ln.split()[0] for ln in out.splitlines() if len(ln.split()) == 2 and ln.split()[1].isdigit() and int(ln.split()[1]) >= 501)
        show(label, rc, out)


def windows():
    ps = shutil.which("powershell") or shutil.which("pwsh")
    if not ps:
        print("powershell not found")
        return
    for label, script in WIN_PS:
        rc, out = nw.run([ps, "-NoProfile", "-NonInteractive", "-Command", script], timeout=60)
        show(label, rc, out)


def main():
    osf = nw.os_family()
    print(f"os={osf} admin_session={nw.is_admin(osf)}")
    {"linux": linux, "macos": macos, "windows": windows}[osf]()
    env = nw.env_file_path(osf)
    if os.path.isfile(env):
        probs = nw.env_perm_problems(env, osf)
        show("env file permissions", 0, "\n".join(probs) or f"ok ({env})")
    else:
        show("env file permissions", 0, f"missing ({env})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
