#!/usr/bin/env python3
"""Net Watch scope guard (Linux, macOS, Windows).

Exit 0 only when every target is an IP or CIDR fully inside a range listed in
NETWATCH_HOME/scope.txt (one CIDR per line, # comments allowed).
Hostnames are refused so DNS tricks cannot move a scan off the owned network.
  scope_guard.py TARGET [TARGET ...]
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [HERE, os.path.join(HERE, "..", "netwatch-setup")]
import nw_common as nw  # noqa: E402


def main(argv):
    if len(argv) < 2:
        print("usage: scope_guard.py TARGET [TARGET ...]")
        return 2
    home = nw.netwatch_home()
    try:
        nets = nw.load_scope(home)
    except FileNotFoundError:
        print(f"SCOPE-FAIL: no scope file at {os.path.join(home, 'scope.txt')}")
        return 2
    except ValueError as exc:
        print(f"SCOPE-FAIL: bad line in scope file: {exc}")
        return 2
    if not nets:
        print("SCOPE-FAIL: scope file is empty")
        return 2
    bad = nw.scope_problems(argv[1:], nets)
    if bad:
        print("SCOPE-FAIL: " + "; ".join(bad))
        return 1
    print("SCOPE-OK: " + " ".join(argv[1:]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
