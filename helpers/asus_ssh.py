#!/usr/bin/env python3
"""Net Watch Asus router reader over SSH (Linux, macOS, Windows OpenSSH client).

  asus_ssh.py firmware | leases | settings | portforwards | arp | firewall
  asus_ssh.py nvram NAME [NAME ...]

Runs only allowlisted read-only commands. nvram names that can hold secrets are
refused. Env: ASUS_SSH_HOST (router IP, must be in scope.txt), ASUS_SSH_USER,
optional ASUS_SSH_KEY (default ~/.ssh/netwatch_asus).
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [HERE, os.path.join(HERE, "..", "netwatch-setup")]
import nw_common as nw  # noqa: E402

FIXED = {
    "firmware": "nvram get firmver; nvram get buildno; nvram get extendno",
    "leases": "cat /var/lib/misc/dnsmasq.leases",
    "settings": "nvram get upnp_enable; nvram get misc_http_x; nvram get wps_enable; nvram get wan0_ipaddr; nvram get ipv6_service",
    "portforwards": "nvram get vts_rulelist",
    "arp": "arp -an",
    "firewall": "iptables -S",
}
NAME_OK = re.compile(r"^[a-z0-9_]{1,48}$")
SECRETISH = re.compile(r"(psk|pass|key|secret|crt|cert|token|pin|wpa|radius|ddns_user|auth|cred|pwd)", re.I)


def main(argv):
    if len(argv) < 2 or (argv[1] not in FIXED and argv[1] != "nvram"):
        print(__doc__)
        return 2
    if argv[1] == "nvram":
        names = argv[2:]
        if not names:
            print("usage: asus_ssh.py nvram NAME [NAME ...]")
            return 2
        bad = [n for n in names if not NAME_OK.match(n) or SECRETISH.search(n)]
        if bad:
            print("REFUSED: not allowed (may hold secrets or bad name): " + ", ".join(bad))
            return 3
        remote = "; ".join(f"nvram get {n}" for n in names)
    else:
        remote = FIXED[argv[1]]
    osf = nw.os_family()
    vals, probs = nw.load_env(nw.env_file_path(osf), osf)
    for p in probs:
        print(p, file=sys.stderr)
    nw.require(vals, "ASUS_SSH_HOST", "ASUS_SSH_USER")
    host = vals["ASUS_SSH_HOST"]
    nw.require_scope([host])
    key = os.path.expanduser(vals.get("ASUS_SSH_KEY") or os.path.join("~", ".ssh", "netwatch_asus"))
    ssh = nw.find_tool("ssh", osf)
    if not ssh:
        print("ssh client missing (Windows: Settings > Optional features > OpenSSH Client; ask the owner)")
        return 4
    rc, out = nw.run([ssh, "-i", key, "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
                      f"{vals['ASUS_SSH_USER']}@{host}", remote], timeout=60)
    print(out.rstrip())
    return 0 if rc == 0 else 4


if __name__ == "__main__":
    sys.exit(main(sys.argv))
