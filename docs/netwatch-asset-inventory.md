<!-- Net Watch guide netwatch-asset-inventory. Read from the verified helper folder; skills and hard rules win on any conflict. -->
When to use: Use to compare a scan against the known-device baseline, alert on new, missing, or moved devices, label devices, or accept a reviewed scan as the new baseline.

# Asset inventory and new-device alerts

## Steps

0. Quick picture of a scan (setup and reviews):
   ```text
   nw inventory.py summary "SCAN_DIR"
   ```
   Read-only. Prints counts (hosts, named, unnamed, randomized MACs, ARP duplicates, out-of-scope entries dropped, controller clients matched) and an unnamed-devices table (ip, mac, vendor, network/ssid, sources), joining UniFi classic client names, OUI vendor, network, and SSID by MAC (live GET `/stat/sta` when `UNIFI_USER` and `UNIFI_PASS` are set, else the newest topology collection). `--json` for JSON, `--no-controller` to skip the live call, `--site NAME` for a non-default site. Use it instead of ad hoc parsing: `inventory.json` keeps `hosts` as a dict keyed by MAC (or `ip:ADDRESS`) with an `ips` list.
1. Diff the latest scan (scan_dir from netwatch-discovery-scan):
   ```text
   nw inventory.py diff "SCAN_DIR"
   ```
2. For each NEW device, report IP, MAC, vendor guess, hostname, and the controller's view (SSID, VLAN, first seen, AP) if a connector exists. Flag `randomized-MAC` entries: these are often the owner's own phones or laptops using private Wi-Fi addresses, so ask before treating them as intruders.
3. Ask the owner to identify unknown devices. Never auto-block. If the owner says it is unknown and worrying, run netwatch-incident-runbook.
4. When the owner confirms the list, label known devices and accept:
   ```text
   nw inventory.py label "MAC" "Kitchen tablet"
   nw inventory.py accept "SCAN_DIR"
   ```
   Updating the local baseline is not a network change and needs no change record, but do it only after the owner reviewed the diff. Accept merges: devices missing from this scan stay in the baseline (with `last_seen` kept) so sleeping devices keep their labels. Remove a device only when the owner says it is gone:
   ```text
   nw inventory.py forget "MAC"
   ```
5. MISSING devices are informational (off, asleep, or moved VLAN) unless a security device (camera, alarm hub, router node) is missing; then mention it prominently.
6. IP-CHANGED for infrastructure (gateway, DNS, NAS, controller) is notable; suggest a DHCP reservation.

## Notes

- Keep labels generic in shared material; device names and IPs belong in the owner's baseline and profile, not in skills.
- `nw` is the per-OS helper launcher from netwatch-setup; inventory.py reads the normalized neighbor table, arp-scan, nmap, and ping-sweep results the same way on Linux, macOS, and Windows. MACs are stored lower-case with colons whatever the OS printed (Windows dashes, macOS unpadded octets).
- Devices seen only by nmap or ping on routed subnets (or from an unelevated Windows/macOS host) have no MAC and are keyed by IP, so an IP change shows as one NEW plus one MISSING; check the controller's client list before alarming.
- If arp_duplicates is non-empty in inventory.json, run netwatch-lan-threats.
