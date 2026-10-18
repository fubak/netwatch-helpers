<!-- Net Watch guide netwatch-reporting. Read from the verified helper folder; skills and hard rules win on any conflict. -->
When to use: Use to produce daily, weekly, monthly, or quarterly network security reports, or to set up Net Watch routines. Routines observe and report only; they never contain or change anything.

# Reporting cadence

## Routines (one yes card at setup end; create with the routines feature, reuse by name)

| Cadence | Checks | Skills |
|---|---|---|
| nw-daily (every day) | new/missing devices, IDS and firewall alerts, gateway MAC and rogue DHCP | netwatch-discovery-scan, netwatch-asset-inventory, netwatch-intrusion-detection, netwatch-lan-threats |
| nw-weekly (Sunday) | full-subnet port scan (portscan.py, top 200 TCP ports, -T3, smart-home devices light connect only), UPnP mappings, CISA KEV and NVD pass for every known model and version, DNS filter health, release check, health | netwatch-port-exposure (A, B), netwatch-vuln-lookup, netwatch-dns-hygiene |
| nw-monthly (first Sunday) | full audit: Wi-Fi, segmentation, hardening, firmware versions, config backups, external WAN probe, topology map with diff and recommendations | netwatch-wifi-audit, netwatch-segmentation-review, netwatch-hardening-audit, netwatch-config-backup, netwatch-port-exposure (C), netwatch-topology |
| nw-quarterly (first Sunday of Jan, Apr, Jul, Oct) | scope reconfirmation, credential and API key age review, propose stale baseline entries to forget (owner decides), review this bot's own access | netwatch-setup step 1, netwatch-hardening-audit |

The monthly WAN probe needs the WAN IP read from the router in the same run (UniFi, OPNsense/pfSense, Omada connectors, or `external_ip` from upnp_check.py when it reports `is_default_gateway=yes`). Without any of these, mark it not checked and ask the owner next time they chat.

If netwatch-live-alerts is set up, real-time alerts arrive through its own webhook routine, not these schedules. The daily run adds the relay's `status` counters (low-severity counts kept local, duplicates, refused posts, send failures) in one line, and flags a relay that has not been heard from.

Last-done tracking: every routine run ends with `nw preflight.py --mark-routine NAME` using its name above (the alert routine uses nw-alerts). `nw preflight.py --health` then shows an `overdue` line naming any routine that missed its window (daily 36 hours, weekly 8 days, monthly 35 days, quarterly 100 days). A routine that finds its own run overdue says so in one line.

Owner-suppressed events: the daily report runs `nw alertd.py owner stats --since 24h`. When `owner_suppressed_events` is not zero, include one line with the count even on an otherwise quiet day ("3 changes by your trusted admin account from your computer in the last 24 hours"). If the owner did not make them, that may be a stolen admin session: start the incident steps.

The full-subnet port scan and the KEV and NVD pass run in nw-weekly and whenever the owner asks; daily runs only look at new devices and events.

Daily runs should be quiet: send a message only when something is new or wrong; otherwise a one-line "all clear" at most weekly.

## Report format

1. Headline: all clear, or N findings (critical/high/medium/low).
2. New since last report, each with evidence and a suggested action.
3. Still open from before (age in days).
4. Fixed since last report (with change ids).
5. Not checked and why (connector untested, scan host offline).

Times in the owner's time zone with its label. No secrets, no full config dumps. Save a copy to the `reports` folder of NETWATCH_HOME on the scan host. Deliver through the channel the profile names; sending outside the chat (email, Slack) follows the platform's send-approval rules.

## Optional AI summary

If the owner uses a local AI CLI (netwatch-local-ai), a report draft may be summarized by it only with a yes for that run; routines never call an AI CLI on their own.

## If the scan host is offline

Say so in one line, run what works from the box (KEV/NVD lookups for known models, WAN probe if the WAN IP was confirmed this session), and mark the rest not checked.
