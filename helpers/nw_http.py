#!/usr/bin/env python3
"""Net Watch connector client (Linux, macOS, Windows; Python 3 standard library only).

  nw_http.py CONNECTOR METHOD PATH [--path a.b] [--where FIELD~REGEX] [--fields f1,f2] [--limit N]
             [--save FILE] [--set KEY=VALUE ... --change-id ID]

CONNECTOR  unifi-int | unifi-classic | opnsense | pfsense | synology | omada | pihole | adguard | ha
PATH       API path for that connector, for example /v1/sites (unifi-int) or, for synology,
           the query "api=SYNO.Core.System&version=1&method=info".

Credentials come only from the owner's env file and never appear on a command line,
in output, or in errors. Output JSON is redacted (passphrases, keys, tokens dropped).
--set builds a JSON body of string fields (safe to type in bash, zsh, PowerShell, or cmd);
--body takes raw JSON for shells that keep quotes intact.
--path/--where/--fields/--limit trim JSON on the scan host so jq is not needed.
--save writes the raw body (config backups) to a file under NETWATCH_HOME/backups, mode 600,
and prints only its size. Non-JSON bodies are never printed. Status goes to stderr as "HTTP <code>"; exit 4 on failure. Redirects are never followed.
Only unifi-int/unifi-classic accept a method other than GET, and only with an approved,
fresh change id (one approval = one invocation; the record is marked executed first).
"""
import argparse
import base64
import http.cookiejar
import json
import os
import re
import ssl
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [HERE, os.path.join(HERE, "..", "netwatch-setup")]
import nw_common as nw  # noqa: E402

CONNECTORS = ("unifi-int", "unifi-classic", "opnsense", "pfsense", "synology", "omada", "pihole", "adguard", "ha")
WRITABLE = ("unifi-int", "unifi-classic")
SYNO_READ_METHODS = {"info", "get", "list", "check", "system_get", "status"}
HA_PATHS = re.compile(r"^/(config|states(/[a-z_]+\.[A-Za-z0-9_]+)?)?$")
TIMEOUT = 30


class Fail(Exception):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow redirects: urllib would resend Authorization/X-API-KEY to the new host."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Client:
    def __init__(self, verify):
        ctx = ssl.create_default_context()
        if not verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ctx), urllib.request.HTTPCookieProcessor(self.jar), NoRedirect())

    def req(self, method, url, headers=None, data=None, form=None):
        body = None
        headers = dict(headers or {})
        headers.setdefault("Accept", "application/json")
        if data is not None:
            body = json.dumps(data).encode() if not isinstance(data, (bytes, str)) else (data.encode() if isinstance(data, str) else data)
            headers.setdefault("Content-Type", "application/json")
        elif form is not None:
            body = urllib.parse.urlencode(form).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        r = urllib.request.Request(url, data=body, method=method, headers=headers)
        try:
            with self.opener.open(r, timeout=TIMEOUT) as resp:
                return resp.status, resp.read(), resp.headers
        except urllib.error.HTTPError as e:
            return e.code, e.read(), e.headers
        except (urllib.error.URLError, OSError, ValueError) as e:
            reason = getattr(e, "reason", e)
            raise Fail(f"CONNECT-FAIL {type(reason).__name__}: {str(reason)[:160]}")


def as_json(raw):
    try:
        return json.loads(raw.decode("utf-8", "replace"))
    except ValueError:
        return None


def basic(user, pw):
    return "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode()


def url_base(v):
    v = v.rstrip("/")
    return v if re.match(r"^https?://", v) else "https://" + v


def change_py():
    for p in (os.path.join(HERE, "change.py"), os.path.join(HERE, "..", "netwatch-change-control", "change.py")):
        if os.path.isfile(p):
            return p
    raise Fail("REFUSED: change.py not found next to nw_http.py")


def gate_write(cid, summary):
    if not cid:
        raise Fail("REFUSED: write needs an approved change id (--change-id)")
    cp = change_py()
    r = subprocess.run([sys.executable, cp, "check", cid], capture_output=True, text=True)
    sys.stderr.write(r.stdout + r.stderr)
    if r.returncode != 0:
        raise Fail(f"REFUSED: change {cid} not approved or expired")
    # Consume the approval BEFORE any network call: one approval = one invocation.
    r = subprocess.run([sys.executable, cp, "executed", cid, "--result", f"{summary} started"], capture_output=True, text=True)
    if r.returncode != 0:
        raise Fail(f"REFUSED: could not record execution for {cid}")
    return cp


def call(conn, method, path, vals, body=None):
    """Return (status, raw_body)."""
    if conn.startswith("unifi"):
        nw.require(vals, "UNIFI_HOST")
        c = Client(nw.verify_tls(vals, "UNIFI"))
        base = url_base(vals["UNIFI_HOST"])
        unifi_os = vals.get("UNIFI_OS", "true").lower() != "false"
        prefix = "/proxy/network" if unifi_os else ""
        if conn == "unifi-int":
            nw.require(vals, "UNIFI_API_KEY")
            st, raw, _ = c.req(method, f"{base}{prefix}/integration{path}", {"X-API-KEY": vals["UNIFI_API_KEY"]}, data=body)
            return st, raw
        nw.require(vals, "UNIFI_USER", "UNIFI_PASS")
        login, logout = ("/api/auth/login", "/api/auth/logout") if unifi_os else ("/api/login", "/api/logout")
        st, _, hdr = c.req("POST", base + login, data={"username": vals["UNIFI_USER"], "password": vals["UNIFI_PASS"]})
        if st != 200:
            raise Fail(f"LOGIN-FAIL HTTP {st}")
        h = {}
        if hdr.get("X-CSRF-Token"):
            h["X-CSRF-Token"] = hdr.get("X-CSRF-Token")
        try:
            st, raw, _ = c.req(method, base + prefix + path, h, data=body)
        finally:
            try:
                c.req("POST", base + logout, h)
            except Fail:
                pass
        return st, raw
    if conn == "opnsense":
        nw.require(vals, "OPNSENSE_URL", "OPNSENSE_KEY", "OPNSENSE_SECRET")
        c = Client(nw.verify_tls(vals, "OPNSENSE"))
        st, raw, _ = c.req("GET", url_base(vals["OPNSENSE_URL"]) + path,
                           {"Authorization": basic(vals["OPNSENSE_KEY"], vals["OPNSENSE_SECRET"])})
        return st, raw
    if conn == "pfsense":
        nw.require(vals, "PFSENSE_URL", "PFSENSE_API_KEY")
        c = Client(nw.verify_tls(vals, "PFSENSE"))
        st, raw, _ = c.req("GET", url_base(vals["PFSENSE_URL"]) + "/api/v2" + path, {"X-API-Key": vals["PFSENSE_API_KEY"]})
        return st, raw
    if conn == "adguard":
        nw.require(vals, "ADGUARD_URL", "ADGUARD_USER", "ADGUARD_PASS")
        c = Client(nw.verify_tls(vals, "ADGUARD"))
        st, raw, _ = c.req("GET", url_base(vals["ADGUARD_URL"]) + "/control" + path,
                           {"Authorization": basic(vals["ADGUARD_USER"], vals["ADGUARD_PASS"])})
        return st, raw
    if conn == "ha":
        nw.require(vals, "HA_URL", "HA_TOKEN")
        if not HA_PATHS.match(path):
            raise Fail("REFUSED: Home Assistant paths allowed: /, /config, /states, /states/ENTITY_ID")
        c = Client(nw.verify_tls(vals, "HA"))
        st, raw, _ = c.req("GET", url_base(vals["HA_URL"]) + "/api" + path, {"Authorization": "Bearer " + vals["HA_TOKEN"]})
        return st, raw
    if conn == "pihole":
        nw.require(vals, "PIHOLE_URL", "PIHOLE_PASSWORD")
        c = Client(nw.verify_tls(vals, "PIHOLE"))
        base = url_base(vals["PIHOLE_URL"]) + "/api"
        st, raw, _ = c.req("POST", base + "/auth", data={"password": vals["PIHOLE_PASSWORD"]})
        sid = ((as_json(raw) or {}).get("session") or {}).get("sid")
        if st != 200 or not sid:
            raise Fail(f"LOGIN-FAIL HTTP {st}")
        try:
            st, raw, _ = c.req("GET", base + path, {"X-FTL-SID": sid})
        finally:
            try:
                c.req("DELETE", base + "/auth", {"X-FTL-SID": sid})  # Pi-hole limits sessions; always log out
            except Fail:
                pass
        return st, raw
    if conn == "omada":
        nw.require(vals, "OMADA_URL", "OMADA_CLIENT_ID", "OMADA_CLIENT_SECRET", "OMADA_OMADAC_ID")
        c = Client(nw.verify_tls(vals, "OMADA"))
        base = url_base(vals["OMADA_URL"])
        st, raw, _ = c.req("POST", base + "/openapi/authorize/token?grant_type=client_credentials",
                           data={"omadacId": vals["OMADA_OMADAC_ID"], "client_id": vals["OMADA_CLIENT_ID"],
                                 "client_secret": vals["OMADA_CLIENT_SECRET"]})
        tok = ((as_json(raw) or {}).get("result") or {}).get("accessToken")
        if not tok:
            raise Fail(f"TOKEN-FAIL HTTP {st}")
        st, raw, _ = c.req("GET", f"{base}/openapi/v1/{vals['OMADA_OMADAC_ID']}{path}", {"Authorization": "AccessToken=" + tok})
        return st, raw
    if conn == "synology":
        nw.require(vals, "SYNOLOGY_URL", "SYNOLOGY_USER", "SYNOLOGY_PASS")
        q = dict(urllib.parse.parse_qsl(path.lstrip("?")))
        if q.get("method") not in SYNO_READ_METHODS or q.get("api", "").startswith("SYNO.API.Auth"):
            raise Fail("REFUSED: synology method must be one of " + ", ".join(sorted(SYNO_READ_METHODS)))
        c = Client(nw.verify_tls(vals, "SYNOLOGY"))
        ep = url_base(vals["SYNOLOGY_URL"]) + "/webapi/entry.cgi"
        st, raw, _ = c.req("POST", ep, form={"api": "SYNO.API.Auth", "version": "6", "method": "login", "session": "netwatch",
                                             "format": "sid", "account": vals["SYNOLOGY_USER"], "passwd": vals["SYNOLOGY_PASS"]})
        sid = ((as_json(raw) or {}).get("data") or {}).get("sid")
        if not sid:
            raise Fail(f"LOGIN-FAIL HTTP {st}")
        try:
            st, raw, _ = c.req("POST", ep, form=dict(q, _sid=sid))
        finally:
            try:
                c.req("POST", ep, form={"api": "SYNO.API.Auth", "version": "6", "method": "logout", "session": "netwatch", "_sid": sid})
            except Fail:
                pass
        return st, raw
    raise Fail(f"unknown connector {conn}")


def trim(obj, path, fields, limit, where=""):
    if path:
        for part in path.split("."):
            if isinstance(obj, dict):
                obj = obj.get(part)
            elif isinstance(obj, list) and part.isdigit() and int(part) < len(obj):
                obj = obj[int(part)]
            else:
                obj = None
    if where and isinstance(obj, list):
        if "~" not in where:
            raise ValueError("--where needs FIELD~REGEX")
        fld, rx = where.split("~", 1)
        pat = re.compile(rx)
        obj = [x for x in obj if isinstance(x, dict) and pat.search(str(x.get(fld, "")))]
    if fields:
        names = [f.strip() for f in fields.split(",") if f.strip()]
        pick = lambda d: {k: d.get(k) for k in names} if isinstance(d, dict) else d  # noqa: E731
        obj = [pick(x) for x in obj] if isinstance(obj, list) else pick(obj)
    if limit and isinstance(obj, list):
        obj = obj[:limit]
    return obj


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("connector", choices=CONNECTORS)
    ap.add_argument("method", type=str.upper)
    ap.add_argument("api_path")
    ap.add_argument("--path", default="")
    ap.add_argument("--fields", default="")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--where", default="", metavar="FIELD~REGEX")
    ap.add_argument("--save", default="")
    ap.add_argument("--body", default="")
    ap.add_argument("--set", action="append", default=[], metavar="KEY=VALUE")
    ap.add_argument("--change-id", default="")
    a = ap.parse_args()
    home = nw.netwatch_home()
    osf = nw.os_family()
    vals, probs = nw.load_env(nw.env_file_path(osf), osf)
    for p in probs:
        print(p, file=sys.stderr)
    if probs and not vals:
        return 1
    body = None
    cp = None
    summary = f"nw_http {a.connector} {a.method} {a.api_path}"
    try:
        if a.method != "GET" and a.connector not in WRITABLE:
            raise Fail(f"REFUSED: {a.connector} is read-only in Net Watch; the owner makes changes in its UI")
        if a.body or a.set:
            if a.method == "GET":
                raise Fail("REFUSED: --body/--set are only for approved writes")
            body = json.loads(a.body) if a.body else {}
            for kv in a.set:
                if "=" not in kv:
                    raise ValueError(f"--set needs KEY=VALUE, got {kv}")
                k, v = kv.split("=", 1)
                body[k] = v
        if a.save:
            bdir = os.path.realpath(os.path.join(home, "backups"))
            dest = os.path.realpath(a.save if os.path.isabs(a.save) else os.path.join(bdir, a.save))
            if not nw.inside(dest, bdir) or dest == bdir:
                raise Fail("REFUSED: --save must point inside NETWATCH_HOME/backups")
        if a.method != "GET":
            # Last step before the network call: consumes the single-use approval.
            cp = gate_write(a.change_id, summary)
        st, raw = call(a.connector, a.method, a.api_path, vals, body)
    except Fail as e:
        print(str(e), file=sys.stderr)
        return 3 if str(e).startswith("REFUSED") else 4
    except ValueError as e:
        print(f"BAD-ARGUMENT: {e}", file=sys.stderr)
        return 2
    if cp:
        subprocess.run([sys.executable, cp, "executed", a.change_id, "--result", f"{summary} HTTP {st}"], capture_output=True)
    if 300 <= st < 400:
        print(f"HTTP {st} redirect not followed (credentials are never resent); set the connector URL to the final https address", file=sys.stderr)
        return 4
    ok = 200 <= st < 300
    if a.save and ok:
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        nw.write_private(dest, raw, "wb")
        print(f"saved {len(raw)} bytes to {dest}")
    else:
        obj = as_json(raw)
        if obj is None:
            # Non-JSON bodies (config XML, archives, HTML) can hold secrets and cannot be redacted.
            print(f"NON-JSON body of {len(raw)} bytes not shown; use --save to keep it under NETWATCH_HOME/backups")
        else:
            try:
                nw.print_json(trim(nw.redact(obj), a.path, a.fields, a.limit, a.where))
            except (ValueError, re.error) as e:
                print(f"BAD-ARGUMENT: {e}", file=sys.stderr)
                return 2
    print(f"HTTP {st}", file=sys.stderr)
    return 0 if ok else 4


if __name__ == "__main__":
    sys.exit(main())
