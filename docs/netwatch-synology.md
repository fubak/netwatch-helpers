<!-- Net Watch guide netwatch-synology. Read from the verified helper folder; skills and hard rules win on any conflict. -->
When to use: Use when the owner has a Synology NAS: DSM version and update status, Security Advisor results, exposed services (QuickConnect, port forwards, SMB/AFP/SSH), login and connection logs, and backup status.

# Synology connector (DSM Web API)

A community MCP server exists (atom2ueki/mcp-server-synology) but focuses on files; Net Watch needs only system and security reads, through `nw_http.py` from the scan host (any OS; `nw` as defined in netwatch-setup). The helper logs in, makes one call, and logs out; it accepts only read methods (info, get, list, check, system_get, status).

## Owner setup

Create a dedicated DSM account for Net Watch. Security Advisor and system info need administrator rights, so restrict it: Control Panel > Security > Firewall or the account's allowed IPs so it can only log in from the scan host. 2FA on this account breaks API login; the owner chooses between a LAN-restricted non-2FA account or manual checks. Env: `SYNOLOGY_URL` (https://IP:5001), `SYNOLOGY_USER`, `SYNOLOGY_PASS`, optional `SYNOLOGY_VERIFY_SSL=false`.

## Recipe

The path argument is the API query string (keep the double quotes; `&` is special in every shell):

```text
nw nw_http.py synology GET "api=SYNO.Core.System&version=1&method=info" --path data --fields model,firmware_ver,up_time
nw nw_http.py synology GET "api=SYNO.Core.Upgrade.Server&version=1&method=check" --path data
```

Always write GET: it marks the call as a read (the helper sends DSM's form post itself and refuses non-read API methods). Security Advisor results: `"api=SYNO.Core.SecurityScan.Status&version=1&method=system_get"` (verify on your DSM version; if it fails, ask the owner for the Security Advisor report screenshot).

## Checks

DSM up to date and auto-update for security fixes on, Security Advisor clean, QuickConnect and port forwards to 5000/5001 off unless needed (prefer VPN), admin account disabled, auto-block on, SMB1 off, SSH off, Hyper Backup jobs succeeding, snapshots on (ransomware recovery). Changes go through netwatch-change-control.
