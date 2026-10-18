<!-- Net Watch guide netwatch-pfsense-opnsense. Read from the verified helper folder; skills and hard rules win on any conflict. -->
When to use: Use when the owner's firewall is OPNsense or pfSense: firmware status, interfaces and WAN IP, ARP/DHCP tables, firewall and NAT rules, IDS (Suricata) alerts, config backup, and approved block rules.

# OPNsense / pfSense connector

Community MCP servers exist (for example AIops-tools/Firewall-AIops for both, mcp-opnsense) but are previews; this guide uses the REST APIs read-only through `nw_http.py` from the scan host (any OS; `nw` as defined in netwatch-setup). The helper allows GET only for these connectors and redacts secrets from output. Endpoint names change between releases: confirm against the firewall's own API docs and report any 404 instead of guessing.

## OPNsense

Owner setup: System > Access > Users, create a dedicated user with only the needed privileges (read pages for diagnostics, firewall, IDS), generate an API key (downloads key and secret). Env: `OPNSENSE_URL` (https://IP), `OPNSENSE_KEY`, `OPNSENSE_SECRET`, optional `OPNSENSE_VERIFY_SSL=false`.

```text
nw nw_http.py opnsense GET /api/core/firmware/status --fields product_version,updates
```

Useful GETs (names vary: newer releases use snake_case such as `get_arp`, older camelCase such as `getArp`): `/api/diagnostics/interface/get_arp`, `/api/diagnostics/interface/get_interface_config`, `/api/firewall/filter/search_rule`, `/api/ids/service/query_alerts`. Config backup: see netwatch-config-backup (`--save`, never printed).

## pfSense

Needs the free community package pfSense-pkg-RESTAPI (v2); installing it is a change the owner approves and performs. Create a dedicated user and API key with read privileges. Env: `PFSENSE_URL`, `PFSENSE_API_KEY`, optional `PFSENSE_VERIFY_SSL=false`.

```text
nw nw_http.py pfsense GET /status/system --path data
```

Useful GETs (paths are under /api/v2, which the helper adds): `/status/interfaces`, `/diagnostics/arp_table`, `/firewall/rules`, `/firewall/nat/port_forwards`, `/status/logs/firewall`. Without the package: owner screenshots of Status > Dashboard, Firewall > NAT, and Status > System Logs.

## Writes

Block a host: add its IP to an alias used by an existing block rule, then apply. Record the alias contents before and the exact removal as rollback. All through netwatch-change-control, done by the owner in the UI (the helper is read-only for these brands).
