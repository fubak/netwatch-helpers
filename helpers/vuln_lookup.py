#!/usr/bin/env python3
"""Net Watch CVE lookup against NVD (API 2.0) and CISA KEV. Public data only.

  vuln_lookup.py nvd --keyword "UniFi Network Application" [--exact] [--days 120] [--limit 20]
  vuln_lookup.py nvd --cpe "cpe:2.3:a:ui:unifi_network_application:8.0.24:*:*:*:*:*:*:*"
  vuln_lookup.py kev --vendor ubiquiti [--product unifi]

Optional env NVD_API_KEY (free) raises the NVD rate limit. Without it, keep calls
at or under 5 per 30 seconds.
"""
import argparse
import datetime as dt
import json
import os
import sys
import time
import urllib.parse
import urllib.request

NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CACHE = os.path.join(os.environ.get("TMPDIR", "/tmp"), "netwatch-kev.json")
UA = {"User-Agent": "netwatch-vuln-lookup/1.0"}


def fetch(url, headers=None):
    req = urllib.request.Request(url, headers={**UA, **(headers or {})})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.load(resp)


def kev_data():
    if os.path.isfile(CACHE) and time.time() - os.path.getmtime(CACHE) < 6 * 3600:
        try:
            with open(CACHE, encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, ValueError):
            pass  # unreadable or partial cache: refetch below
    data = fetch(KEV)
    tmp = f"{CACHE}.{os.getpid()}.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh)
    os.replace(tmp, CACHE)  # atomic, so a concurrent reader never sees half a file
    return data


def kev_ids():
    return {v["cveID"]: v for v in kev_data().get("vulnerabilities", [])}


def score(cve):
    m = cve.get("metrics", {})
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if m.get(key):
            d = m[key][0]["cvssData"]
            return f"{d.get('baseScore')} {d.get('baseSeverity', m[key][0].get('baseSeverity', ''))}".strip()
    return "n/a"


def nvd_get(params, headers, exact):
    url = NVD + "?" + urllib.parse.urlencode(params)
    if exact:
        url += "&keywordExactMatch"
    return fetch(url, headers)


def cmd_nvd(a):
    params = {"resultsPerPage": str(a.limit)}
    if a.cpe:
        params["cpeName"] = a.cpe
    else:
        params["keywordSearch"] = a.keyword
    if a.days:
        if a.days > 120:
            print("note: NVD allows at most 120 days per query; using 120")
        end = dt.datetime.now(dt.timezone.utc)
        start = end - dt.timedelta(days=min(a.days, 120))
        params["pubStartDate"] = start.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        params["pubEndDate"] = end.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    headers = {}
    if os.environ.get("NVD_API_KEY"):
        headers["apiKey"] = os.environ["NVD_API_KEY"]
    exact = bool(a.exact and a.keyword)
    data = nvd_get(params, headers, exact)
    total = data.get("totalResults", 0)
    if total > a.limit:
        # NVD returns oldest first; fetch the newest page instead.
        time.sleep(1 if headers else 6)
        params["startIndex"] = str(total - a.limit)
        data = nvd_get(params, headers, exact)
    kev = kev_ids()
    print(f"total_results={total} showing newest {min(total, a.limit)}")
    items = sorted(data.get("vulnerabilities", []), key=lambda i: i["cve"].get("published", ""), reverse=True)
    for item in items:
        c = item["cve"]
        desc = next((d["value"] for d in c.get("descriptions", []) if d.get("lang") == "en"), "")
        flag = "KEV" if c["id"] in kev else "-"
        print(f"{c['id']}\t{score(c)}\t{flag}\t{c.get('published', '')[:10]}\t{desc[:160]}")
    return 0


def cmd_kev(a):
    hits = []
    for v in kev_data().get("vulnerabilities", []):
        if a.vendor.lower() in v.get("vendorProject", "").lower() and (
            not a.product or a.product.lower() in v.get("product", "").lower()
        ):
            hits.append(v)
    for v in sorted(hits, key=lambda x: x.get("dateAdded", ""), reverse=True):
        print(f"{v['cveID']}\t{v.get('dateAdded', '')}\t{v.get('vendorProject')}\t{v.get('product')}\t"
              f"ransomware={v.get('knownRansomwareCampaignUse', '?')}\t{v.get('vulnerabilityName', '')}")
    print(f"kev_matches={len(hits)}")
    return 0


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    n = sub.add_parser("nvd")
    g = n.add_mutually_exclusive_group(required=True)
    g.add_argument("--keyword")
    g.add_argument("--cpe")
    n.add_argument("--exact", action="store_true", help="keyword must match as a phrase")
    n.add_argument("--days", type=int, default=0, help="publication window, max 120 (NVD limit)")
    n.add_argument("--limit", type=int, default=20)
    k = sub.add_parser("kev")
    k.add_argument("--vendor", required=True)
    k.add_argument("--product", default="")
    a = p.parse_args()
    try:
        return cmd_nvd(a) if a.cmd == "nvd" else cmd_kev(a)
    except Exception as exc:  # network errors: report and exit nonzero, never crash silently
        print(f"LOOKUP-FAIL: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
