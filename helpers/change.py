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
  change.py declined ID --quote "owner's exact declining words"
  change.py expired ID [--result TEXT]   proposal never approved in time
  change.py superseded ID --by OTHER_ID_OR_REASON
  change.py expire            mark every proposal older than 30 minutes without approval as expired
  change.py list [--open]     --open: only proposed or approved-not-applied (runs expire first)

Closed statuses (declined, expired, superseded) are final: approve refuses them.
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
PROPOSAL_TTL_MIN = 30
CLOSED = {"declined", "expired", "superseded"}
OPEN = {"proposed", "approved", "executed"}


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
    if rec["status"] in CLOSED:
        sys.exit(f"refused: change is {rec['status']} and closed; propose a new change")
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


def cmd_declined(a):
    rec = load(a.id)
    if rec["status"] not in ("proposed", "approved"):
        sys.exit(f"refused: cannot decline from status {rec['status']}")
    if not a.quote.strip():
        sys.exit("refused: --quote must hold the owner's exact declining words")
    rec["declined_at"] = now().isoformat()
    rec["decline_quote"] = a.quote
    stamp(rec, "declined", "owner declined")
    print(f"declined {a.id}")


def cmd_expired(a):
    rec = load(a.id)
    if rec["status"] not in ("proposed", "approved"):
        sys.exit(f"refused: cannot expire from status {rec['status']}")
    stamp(rec, "expired", a.result or "expired by command")
    print(f"expired {a.id}")


def cmd_superseded(a):
    rec = load(a.id)
    if rec["status"] not in ("proposed", "approved"):
        sys.exit(f"refused: cannot supersede from status {rec['status']}")
    if not a.by.strip():
        sys.exit("refused: --by needs the replacing change id or a reason")
    rec["superseded_by"] = a.by
    stamp(rec, "superseded", f"superseded by {a.by}")
    print(f"superseded {a.id}")


def all_records():
    d = ledger_dir()
    out = []
    for name in sorted(os.listdir(d)):
        if name.endswith(".json"):
            try:
                with open(os.path.join(d, name), encoding="utf-8") as fh:
                    out.append(json.load(fh))
            except (OSError, ValueError):
                print(f"WARN unreadable record {name}", file=sys.stderr)
    return out


def auto_expire():
    n = 0
    for r in all_records():
        if r.get("status") != "proposed":
            continue
        try:
            age = now() - dt.datetime.fromisoformat(r["created"])
        except (KeyError, TypeError, ValueError):
            continue
        if age > dt.timedelta(minutes=PROPOSAL_TTL_MIN):
            r.setdefault("history", [])
            stamp(r, "expired", f"auto: no approval within {PROPOSAL_TTL_MIN} minutes")
            print(f"expired {r['id']}")
            n += 1
    return n


def cmd_show(a):
    print(json.dumps(load(a.id), indent=2))


def cmd_list(a):
    if getattr(a, "open", False):
        auto_expire()
    for r in all_records():
        if getattr(a, "open", False) and r.get("status") not in OPEN:
            continue
        print(f"{r['id']}\t{r['status']}\t{r.get('target', '')}\t{r.get('action', '')}")


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
    d = sub.add_parser("declined")
    d.add_argument("id")
    d.add_argument("--quote", required=True)
    e = sub.add_parser("expired")
    e.add_argument("id")
    e.add_argument("--result", default="")
    sp = sub.add_parser("superseded")
    sp.add_argument("id")
    sp.add_argument("--by", required=True)
    sub.add_parser("expire")
    ls = sub.add_parser("list")
    ls.add_argument("--open", action="store_true")
    a = p.parse_args()
    if a.cmd == "new":
        cmd_new(a)
    elif a.cmd == "approve":
        cmd_approve(a)
    elif a.cmd == "check":
        return cmd_check(a)
    elif a.cmd in ("executed", "applied", "rolledback", "failed"):
        cmd_result(a, a.cmd)
    elif a.cmd == "declined":
        cmd_declined(a)
    elif a.cmd == "expired":
        cmd_expired(a)
    elif a.cmd == "superseded":
        cmd_superseded(a)
    elif a.cmd == "expire":
        print(f"expired {auto_expire()} stale proposal(s)")
    elif a.cmd == "show":
        cmd_show(a)
    else:
        cmd_list(a)
    return 0


if __name__ == "__main__":
    sys.exit(main())
