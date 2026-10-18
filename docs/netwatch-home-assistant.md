<!-- Net Watch guide netwatch-home-assistant. Read from the verified helper folder; skills and hard rules win on any conflict. -->
When to use: Use only to read Home Assistant for network context: device trackers, router/UniFi/Omada integration sensors, HA version and update entities. Never calls services. Device control belongs to the home-control bot.

# Home Assistant (read-only context)

Home Assistant has an official MCP Server integration (`/api/mcp`), but it exposes control tools, and HA long-lived tokens are not scoped: any token can call services. Net Watch therefore does not add the HA MCP server and uses only REST GETs through `nw_http.py` from the scan host (any OS; `nw` as defined in netwatch-setup). The helper refuses every method but GET and every path but `/`, `/config`, `/states`, and `/states/ENTITY_ID`. If the owner's home-control bot already owns HA, prefer asking that bot or the owner for the data.

## Owner setup (optional)

Create a non-administrator HA user for Net Watch and a long-lived token for it (Profile > Security). Env: `HA_URL` (http://IP:8123, or https if HA has TLS; over plain http the token crosses the LAN unencrypted), `HA_TOKEN`, optional `HA_VERIFY_SSL=false`.

## Recipe (GET only)

```text
nw nw_http.py ha GET /config --fields version,location_name
nw nw_http.py ha GET /states --where "entity_id~^(device_tracker|update)[.]" --fields entity_id,state,attributes
```

Only `device_tracker.*` and `update.*` entities matter here; the `--where` filter drops the rest on the scan host.

## Rules

- Never call `/api/services`, never fire events, never change automations (the helper cannot).
- HA itself is a security-relevant host: check its version and update entities, and whether port 8123 is exposed to the WAN (netwatch-port-exposure).

## Pass/fail test

Run on the scan host (read-only):

```text
nw nw_http.py ha GET /config --fields version,location_name
```

- PASS: `HTTP 200` and a version prints.
- FAIL: `HTTP 401` (long-lived token missing or revoked) or a timeout (HA_URL). Give the owner one line, mark the connector untested, and continue setup.
