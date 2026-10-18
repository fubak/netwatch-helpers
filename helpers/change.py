#!/usr/bin/env python3
"""Net Watch change ledger.

Every change to the network (block, firewall rule, port close, firmware update,
config edit) gets a record here BEFORE it runs, with a rollback step.

  change.py new --target T --action A --command C --rollback R --verify V
  change.py approve ID --quote "owner's exact words"
  change.py check ID          exit 0 only if approved, unapplied, and fresh
  change.py executed ID --result TEXT  (write helpers call this; approval is single-use)
  change.py applied ID --result TEXT
  change.py rolledback ID --result TEXT
  change.py failed ID --result TEXT
  change.py show ID
  change.py list
"""
import argparse
import datetime as dt
import json
import os
import secrets
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [HERE, os.path.join(HERE, "..", "netwatch-setup")]
import nw_common as nw  # noqa: E402

APPROVAL_TTL_MIN = 30


def ledger_dir():
    path = os.path.join(nw.netwatch_home(), "changes")
    os.makedirs(path, exist_ok=True)
    return path


def now():
    return dt.datetime.now().astimezone()


def path_for(cid):
    if not cid.replace("-", "").isalnum():
        sys.exit("bad change id")
    return os.path.join(ledger_dir(), f"{cid}.json")


def load(cid):
    p = path_for(cid)
    if not os.path.isfile(p):
        sys.exit(f"no change record {cid}")
    with open(p, encoding="utf-8") as fh:
        return json.load(fh)


def save(rec):
    p = path_for(rec["id"])
    tmp = p + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(rec, fh, indent=2)
    os.replace(tmp, p)


def cmd_new(a):
    for field in ("target", "action", "command", "rollback", "verify"):
        if not getattr(a, field).strip():
            sys.exit(f"refused: --{field} is required and must not be empty")
    cid = now().strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(2)
    rec = {
        "id": cid,
        "status": "proposed",
        "created": now().isoformat(),
        "target": a.target,
        "action": a.action,
        "command": a.command,
        "rollback": a.rollback,
        "verify": a.verify,
        "history": [],
    }
    save(rec)
    print(cid)


def stamp(rec, status, note):
    rec["status"] = status
    rec["history"].append({"at": now().isoformat(), "status": status, "note": note})
    save(rec)


def cmd_approve(a):
    rec = load(a.id)
    if rec["status"] != "proposed":
        sys.exit(f"refused: status is {rec['status']}, expected proposed")
    if not a.quote.strip():
        sys.exit("refused: --quote must hold the owner's exact approving words")
    rec["approved_at"] = now().isoformat()
    rec["approval_quote"] = a.quote
    stamp(rec, "approved", "owner approved")
    print(f"approved {a.id}")


def cmd_check(a):
    rec = load(a.id)
    if rec["status"] != "approved":
        print(f"NOT-APPROVED: status={rec['status']}")
        return 3
    age = now() - dt.datetime.fromisoformat(rec["approved_at"])
    if age > dt.timedelta(minutes=APPROVAL_TTL_MIN):
        print("APPROVAL-EXPIRED: ask the owner again")
        return 3
    print(f"OK {a.id}: {rec['action']} on {rec['target']}")
    return 0


ALLOWED_FROM = {
    "executed": {"approved", "executed"},
    "applied": {"approved", "executed"},
    "failed": {"approved", "executed", "applied"},
    "rolledback": {"approved", "executed", "applied", "failed"},
}


def cmd_result(a, status):
    rec = load(a.id)
    if rec["status"] not in ALLOWED_FROM[status]:
        sys.exit(f"refused: cannot mark {status} from status {rec['status']} (never approved?)")
    stamp(rec, status, a.result)
    print(f"{status} {a.id}")


def cmd_show(a):
    print(json.dumps(load(a.id), indent=2))


def cmd_list(_a):
    d = ledger_dir()
    for name in sorted(os.listdir(d)):
        if name.endswith(".json"):
            with open(os.path.join(d, name), encoding="utf-8") as fh:
                r = json.load(fh)
            print(f"{r['id']}\t{r['status']}\t{r['target']}\t{r['action']}")


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    n = sub.add_parser("new")
    for f in ("target", "action", "command", "rollback", "verify"):
        n.add_argument(f"--{f}", required=True)
    ap = sub.add_parser("approve")
    ap.add_argument("id")
    ap.add_argument("--quote", required=True)
    for name in ("check", "show"):
        sub.add_parser(name).add_argument("id")
    for name in ("executed", "applied", "rolledback", "failed"):
        s = sub.add_parser(name)
        s.add_argument("id")
        s.add_argument("--result", required=True)
    sub.add_parser("list")
    a = p.parse_args()
    if a.cmd == "new":
        cmd_new(a)
    elif a.cmd == "approve":
        cmd_approve(a)
    elif a.cmd == "check":
        return cmd_check(a)
    elif a.cmd in ("executed", "applied", "rolledback", "failed"):
        cmd_result(a, a.cmd)
    elif a.cmd == "show":
        cmd_show(a)
    else:
        cmd_list(a)
    return 0


if __name__ == "__main__":
    sys.exit(main())
