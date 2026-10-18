<!-- Net Watch guide netwatch-containment. Read from the verified helper folder; skills and hard rules win on any conflict. -->
When to use: Use when the owner wants to isolate or block a suspicious device or stop exposure: block or quarantine a client, add a firewall rule, close a port forward, pause internet for a device. Always through change control, one confirmation per action.

# Containment

## Steps

1. Confirm the target precisely (MAC first, then IP, name, connection: SSID/port/VLAN). MACs can be spoofed and randomized; say how confident you are it is the right device.
2. Preserve evidence first: save current client details, recent events, and DNS logs to the `changes` folder in NETWATCH_HOME or a report.
3. Choose the least disruptive effective option:
   - Pause internet only (keep LAN visibility): controller "block internet" or a firewall rule.
   - Quarantine VLAN or guest network move.
   - Full block on the controller (UniFi block-sta, Omada block client, OPNsense/pfSense alias plus block rule).
   - Close a port forward or UPnP mapping.
   - Consumer gear without an API (Eero, Asus stock, Firewalla without MSP): give the owner exact app steps (pause device / block device).
   - Last resort: owner physically unplugs or powers off the device, or rotates the Wi-Fi password.
4. Run netwatch-change-control with the exact command and rollback, for example for UniFi:
   - command: `nw nw_http.py unifi-classic POST /api/s/default/cmd/stamgr --set cmd=block-sta --set mac=MAC --change-id CHANGE_ID`
   - rollback: same with `--set cmd=unblock-sta` and a new change id.
5. After the yes, apply, verify (device shows blocked, no traffic), and record.
6. Tell the owner what remains: the device may still be compromised; next steps are in netwatch-incident-runbook (reset, update, or replace).

## Never

- Never block or alter devices owned by another bot or by the owner's household without the owner's yes, and never the scan host, router, controller, or the owner's current device without explicit warning that access may be lost.
- Never use ARP poisoning, deauthentication, or any offensive technique.
