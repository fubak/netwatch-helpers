#!/usr/bin/env python3
"""Net Watch DNS check of the scan host (Linux, macOS, Windows). Read-only.

  dns_check.py

Shows the resolvers this host is configured to use (resolvectl or resolv.conf on
Linux, scutil --dns on macOS, Get-DnsClientServerAddress on Windows) and which
public resolver egress answers (whoami.akamai.net through the system resolver).
"""
import os
import re
import shutil
import socket
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [HERE, os.path.join(HERE, "..", "netwatch-setup")]
import nw_common as nw  # noqa: E402

WIN_PS = ("Get-DnsClientServerAddress -AddressFamily IPv4,IPv6 | Where-Object { $_.ServerAddresses } | "
          "ForEach-Object { '{0} {1} {2}' -f $_.InterfaceAlias, $_.AddressFamily, ($_.ServerAddresses -join ',') }")


def configured(osf):
    if osf == "linux":
        if shutil.which("resolvectl"):
            rc, out = nw.run(["resolvectl", "dns"], timeout=15)
            if rc == 0 and out.strip():
                return out.strip().splitlines()
        try:
            with open("/etc/resolv.conf", encoding="utf-8") as fh:
                return [ln.strip() for ln in fh if ln.startswith("nameserver")]
        except OSError:
            return []
    if osf == "macos":
        rc, out = nw.run(["scutil", "--dns"], timeout=15)
        return sorted(set(re.findall(r"nameserver\[\d+\]\s*:\s*(\S+)", out)))
    ps = shutil.which("powershell") or shutil.which("pwsh")
    if not ps:
        return ["powershell not found"]
    rc, out = nw.run([ps, "-NoProfile", "-NonInteractive", "-Command", WIN_PS], timeout=30)
    return out.strip().splitlines()


def main():
    osf = nw.os_family()
    print(f"== configured resolvers ({osf})")
    for line in configured(osf) or ["none found"]:
        print(line)
    print("== egress resolver (whoami.akamai.net)")
    try:
        ips = sorted({ai[4][0] for ai in socket.getaddrinfo("whoami.akamai.net", None, socket.AF_INET)})
        print("egress=" + ",".join(ips))
    except OSError as e:
        print(f"egress=unknown ({e.__class__.__name__})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
