<!-- Net Watch guide netwatch-eero. Read from the verified helper folder; skills and hard rules win on any conflict. -->
When to use: Use when the owner's Wi-Fi is Eero. No public local or cloud API exists, so Net Watch combines its own LAN scans with owner-provided app screenshots or exports for settings, and guides changes in the Eero app.

# Eero (guided, no connector)

There is no official Eero API or MCP server. Unofficial libraries need the owner's account login via SMS code and are not used by default (they would give Net Watch full control of the network).

## What Net Watch does itself

- Discovery, inventory, port exposure, LAN threat checks from the scan host as usual.
- WAN exposure check from the box after the owner reads the WAN IP from the Eero app (Settings > Network settings or the ISP modem).

## What to ask the owner for (screenshots are fine; crop out passwords)

- Devices list (to label inventory), network settings: WPA3, UPnP, IPv6, DNS (or Eero Plus DNS filtering), port forwards and reservations, guest network on/off.
- Eero firmware version (Settings > Software updates) and whether automatic updates are on.
- Eero account 2FA and who else has admin access in the app.

## Containment and changes

Give exact app steps, for example pausing or blocking a device in the Devices list, turning off UPnP, removing a port forward. Record each in netwatch-change-control with the rollback steps and wait for the owner to report done. Note: Eero Plus is a paid subscription; do not recommend buying it without saying it is optional and paid.

## Pass/fail test

Run on the scan host (read-only):

```text
nw discover.py CIDR
```

- PASS: eero has no local API, so the test is that discovery finds the eero gateway IP; the owner then confirms one screenshot from the eero app.
- FAIL: the gateway IP is missing from discovery (wrong range or the scan host is on a guest network). Give the owner one line, mark the connector untested, and continue setup.
