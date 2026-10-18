<!-- Net Watch guide netwatch-omada. Read from the verified helper folder; skills and hard rules win on any conflict. -->
When to use: Use when the owner has TP-Link Omada (hardware or software controller): sites, gateways, switches and APs with firmware, clients, SSIDs, alerts and logs, and approved client blocks.

# TP-Link Omada connector (Open API)

No official TP-Link MCP server exists; community ones (gaspareduard/Omada-mcp capability-gated, thalisantunes/mcp-omada read-only) are optional. This skill calls the controller's Open API read-only through `nw_http.py` from the scan host (any OS; `nw` as defined in netwatch-setup). The helper fetches the access token itself.

## Owner setup

Controller > Settings > Platform Integration > Open API: add an app in **Client Credentials** mode with a viewer role. Note Client ID, Client Secret, and the Omada ID (omadacId). Env: `OMADA_URL` (https://IP:PORT), `OMADA_CLIENT_ID`, `OMADA_CLIENT_SECRET`, `OMADA_OMADAC_ID`, optional `OMADA_VERIFY_SSL=false`.

## Recipe

Paths are relative to /openapi/v1/OMADAC_ID (the helper adds that prefix):

```text
nw nw_http.py omada GET "/sites?page=1&pageSize=100" --path result.data --fields siteId,name
nw nw_http.py omada GET "/sites/SITE_ID/devices?page=1&pageSize=100" --path result.data
nw nw_http.py omada GET "/sites/SITE_ID/clients?page=1&pageSize=100" --path result.data
```

Keep the double quotes around paths with `&` (cmd and PowerShell treat a bare `&` as a command separator). Exact paths and methods differ between controller 5.x and 6.x; the controller serves its own API docs (Platform Integration page). Report 404s rather than guessing.

## Writes

Client block and SSID or ACL changes: only through netwatch-change-control; the Open API app would need an admin role for writes and the helper is read-only for Omada, so the owner acts in the Omada app with exact steps.

## Pass/fail test

Run on the scan host (read-only):

```text
nw nw_http.py omada GET "/sites?page=1&pageSize=100" --path result.data --fields siteId,name
```

- PASS: stderr shows `HTTP 200` and at least one site name prints.
- FAIL: `HTTP 401` or `HTTP 403` (check OMADA_CLIENT_ID, OMADA_CLIENT_SECRET, OMADA_OMADAC_ID and the app's site access), a timeout (OMADA_URL or port), or exit 4. Give the owner one line, mark the connector untested, and continue setup.
