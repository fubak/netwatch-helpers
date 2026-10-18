<!-- Net Watch guide netwatch-smart-home-observe. Read from the verified helper folder; skills and hard rules win on any conflict. -->
When to use: Use whenever a scan, audit, or finding touches smart-home devices (irrigation, pool, plugs, lights, garage, alarm, cameras, voice assistants, hubs). Observe-only rules and gentle scanning, with hand-off to the home-control bot or owner.

# Smart-home devices: observe only

Another bot (home control) or the owner controls these devices. Net Watch may see them on the network and report on them, nothing more.

## Allowed

- Appear in discovery, inventory, and controller client lists (daily host-discovery pings from netwatch-discovery-scan are fine; they are not port scans).
- Light TCP connect scan of top ports at `-T3` or slower, once per weekly cycle at most.
- Look up firmware CVEs and end-of-life status.
- Report what they talk to (DNS filter logs, controller traffic stats).
- Recommend segmentation or updates, addressed to the owner.

## Not allowed

- No logins, API calls, or app-protocol commands to the device (even read-only local APIs belong to the home-control bot).
- No version probing (`-sV`), OS detection, NSE scripts, UDP sweeps, or fuzzing: pool controllers, irrigation controllers, and cheap plugs can hang or reboot.
- No containment, firmware, or settings changes. If a device looks compromised, tell the owner and suggest they or the home-control bot act; network-level isolation of the device (blocking it on the router) is a Net Watch change that still needs change control and a warning that the home-control bot will lose it.

## Known category notes

- Many local IoT protocols are unauthenticated by design (some pool controllers, smart plugs with local TCP control). The fix is segmentation, not device changes.
- Cloud-dependent devices (garage, alarm, cameras) need outbound internet; blocking it breaks them.
- Moving these devices to a new VLAN changes IPs used by the home-control bot; coordinate first.
