<!-- Net Watch guide netwatch-dns-filter. Read from the verified helper folder; skills and hard rules win on any conflict. -->
When to use: Use when the owner runs Pi-hole (v6) or AdGuard Home: status, version, client list, query log, blocked domains, filter health, DHCP status, and Teleporter/config backup. Feeds DNS hygiene and intrusion detection.

# Pi-hole and AdGuard Home connector

Community MCP servers exist (hexamatic/pihole-mcp in the official MCP registry; AdGuard Home MCPs on npm/PyPI), but they expose write tools; this guide uses read-only REST calls through `nw_http.py` from the scan host (any OS; `nw` as defined in netwatch-setup). The helper allows GET only here and redacts secrets.

## Pi-hole v6

Env: `PIHOLE_URL` (prefer https://IP; plain http sends the password unencrypted across the LAN), `PIHOLE_PASSWORD` (the web password or an app password from Settings > Web interface/API), optional `PIHOLE_VERIFY_SSL=false`. Paths are under /api (the helper adds it, logs in, and always logs out because Pi-hole limits concurrent sessions).

```text
nw nw_http.py pihole GET /info/version --path version
nw nw_http.py pihole GET /stats/summary --fields queries,clients
nw nw_http.py pihole GET /network/devices --path devices --fields hwaddr,ips,macVendor
nw nw_http.py pihole GET "/queries?length=200" --path queries --fields time,domain,client,status
```

Backup (Teleporter, contains settings and lists): see netwatch-config-backup (`--save`, never printed).

## AdGuard Home

Env: `ADGUARD_URL`, `ADGUARD_USER`, `ADGUARD_PASS`, optional `ADGUARD_VERIFY_SSL=false`. Paths are under /control.

```text
nw nw_http.py adguard GET /status --fields version,protection_enabled,dns_addresses
nw nw_http.py adguard GET /stats --fields num_dns_queries,num_blocked_filtering,top_clients
nw nw_http.py adguard GET /clients --fields clients,auto_clients
nw nw_http.py adguard GET "/querylog?limit=200" --path data --fields time,client,question,reason
nw nw_http.py adguard GET /filtering/status --fields enabled,filters
```

## Rules

Read-only here. Blocking domains or clients, toggling protection, or DHCP changes go through netwatch-change-control and are done by the owner in the filter's UI.
