<!-- Net Watch guide netwatch-firewalla. Read from the verified helper folder; skills and hard rules win on any conflict. -->
When to use: Use when the owner has a Firewalla box: alarms, devices, flows, rules. The Firewalla device has no local API; the Firewalla MSP API (paid) enables a community MCP server. Default is guided use of the Firewalla app.

# Firewalla

## Options

1. **Default (free):** the owner shares app screenshots or exports of Alarms, Devices, Rules, and Network settings. Net Watch interprets them and combines with its own scans.
2. **MSP API (paid subscription):** the community MCP server djuntgen/firewalla-mcp wraps it with read and write tools. Never sign up or recommend purchase without telling the owner it costs money and getting a yes. If enabled, restrict Net Watch to read tools (alarms, devices, flows, trends); rule create/pause/delete only through netwatch-change-control. Env names used by that server: `FIREWALLA_MSP_DOMAIN`, `FIREWALLA_TOKEN`.

## Checks

Firewalla box firmware current, alarms reviewed (abnormal upload, intel hits, new devices, open ports), "new device quarantine" setting, VPN server exposure, Family/ad blocking as DNS hygiene context, Firewalla app account 2FA.

## Containment

Owner blocks or quarantines a device in the app with exact steps. Record in netwatch-change-control.
