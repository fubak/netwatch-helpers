<!-- Net Watch guide netwatch-unifi-reference. Read from the verified helper folder; skills and hard rules win on any conflict. -->
When to use: Use when the owner has UniFi (Dream Machine, Cloud Gateway, Cloud Key, or self-hosted Network application): device and client inventory, firmware, Wi-Fi and VLAN config, port forwards, Threat Management (IDS/IPS) events, rogue APs, and approved client blocks.

# UniFi connector (local API from the scan host)

No official Ubiquiti MCP server exists; community MCP servers (for example owine/unifi-network-mcp, enuno/unifi-mcp-server) are optional and must stay in read-only mode if used. This skill calls the controller's local API through `nw_http.py` (Python standard library, same command on Linux, macOS, and Windows; `nw` as defined in netwatch-setup).

## Owner setup

1. Default: a local View Only admin for the classic API (map, events, IDS, rogue APs). Settings > Admins & Users > Create New Admin, Restrict to Local Access Only (no cloud SSO, no 2FA prompt), username `netwatch`, role Network View Only, other apps None. Blocks need Site Admin, so keep this account read-only and do blocks in the app.
2. Optional: an Integration API key (UniFi Network > Settings > Control Plane > Integrations > Create API Key). A View Only admin cannot open Integrations (the key request returns 401), so the key must be created from the owner's own admin account and inherits that full admin role. Offer it only when the owner wants it, and say so.
3. Add to the env file (path per OS in netwatch-setup): `UNIFI_HOST` (console IP, no scheme; for a self-hosted Network application add the port, for example IP:8443, and set `UNIFI_OS=false`), `UNIFI_USER` and `UNIFI_PASS` (the View Only login from item 1), optionally `UNIFI_API_KEY` (item 2), and `UNIFI_VERIFY_SSL=false` only if the console uses its default self-signed certificate.

## Test

Classic login (the default; lists the sites the View Only account can see):
```text
nw nw_http.py unifi-classic GET /api/self/sites --path data --fields name,desc
```
Only when `UNIFI_API_KEY` is set, also the Integration API:
```text
nw nw_http.py unifi-int GET /v1/info
nw nw_http.py unifi-int GET /v1/sites --path data --fields id,name
```

## Read recipes

Integration API (`unifi-int`, paths under /proxy/network/integration; check the version-specific docs in UniFi Network > Integrations):
- `/v1/sites` (get SITE_ID), `/v1/sites/SITE_ID/devices`, `/v1/sites/SITE_ID/clients`, `/v1/sites/SITE_ID/devices/DEVICE_ID/statistics/latest`.

Classic API (`unifi-classic`, site name usually `default`; the helper logs in, sends the CSRF token, and logs out):
- `/api/s/default/stat/device` (models, firmware `version`, `upgradable`, WAN IP on the gateway's `wan1` field)
- `/api/s/default/stat/sta` (active clients with SSID, VLAN, first seen)
- `/api/s/default/rest/wlanconf` (Wi-Fi security), `/api/s/default/rest/networkconf` (VLANs), `/api/s/default/rest/portforward`, `/api/s/default/rest/firewallrule` (older firewall; newer zone-based policies appear under /v2 paths, verify on your version)
- `/api/s/default/stat/rogueap` (neighboring and rogue APs)
- IDS/IPS and system events: endpoints moved across Network versions (`/api/s/default/stat/ips/event`, `/v2/api/site/default/system-log/...`). Probe with GET and report which works; if none, ask the owner to check Insights/Threat Management in the app.

Output is always redacted by the helper: keys such as `x_passphrase`, VPN keys, and tokens are dropped before printing, so Wi-Fi and VPN payloads are safe to summarize. Trim on the scan host instead of pulling whole payloads into chat (they list every household device):

```text
nw nw_http.py unifi-classic GET /api/s/default/rest/wlanconf --path data --fields name,security,wpa_mode,wpa3_support,pmf_mode,wps_enabled,hide_ssid,networkconf_id,l2_isolation
nw nw_http.py unifi-classic GET /api/s/default/stat/device --path data --fields name,model,version,upgradable,ip
```

## Writes (only through netwatch-change-control)

- Block client: `nw nw_http.py unifi-classic POST /api/s/default/cmd/stamgr --set cmd=block-sta --set mac=MAC --change-id CHANGE_ID`
- Rollback: same with `--set cmd=unblock-sta` and a new approved change id.
- The helper checks the change id is approved and fresh, marks it executed before sending (one approval = one call), and refuses writes without it.
- Port forward, firewall, Wi-Fi, VLAN, and firmware changes: prefer the owner doing them in the UniFi app with exact steps; the bot verifies afterwards.

## Pass/fail test

Run on the scan host (read-only):

```text
nw nw_http.py unifi-classic GET /api/self/sites --path data --fields name,desc
nw nw_http.py unifi-version
```

- PASS: `HTTP 200`, at least one site, and the UniFi OS and Network versions print.
- FAIL: `LOGIN-FAIL` (user or password, or the account is not local), `LOGIN-FAIL HTTP 429` or `RATE-LIMITED` (wait a few minutes, never loop), a TLS error (UNIFI_VERIFY_SSL), or exit 4. Give the owner one line, mark the connector untested, and continue setup.
