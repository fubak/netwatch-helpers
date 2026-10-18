<!-- Net Watch guide netwatch-discovery-scan. Read from the verified helper folder; skills and hard rules win on any conflict. -->
When to use: Use when the owner asks to scan the network, find what is connected, or when a routine needs a fresh device list. Polite host discovery on in-scope CIDRs from the scan host (Linux, macOS, or Windows); no port scan.

# Discovery scan

## Steps

1. Read the profile: scan host, OS, launcher, NETWATCH_HOME, in-scope CIDRs. Confirm scope consent is recorded (netwatch-setup step 1). If not, stop and offer onboarding Step 1 (netwatch-onboarding).
2. Run on the scan host (`nw` as defined in netwatch-setup):
   ```text
   nw discover.py CIDR [CIDR ...]
   ```
   The helper refuses anything outside scope.txt, then per OS:
   - reads the neighbor table passively (Linux `ip -4 neigh`, macOS `arp -an`, Windows `arp -a`);
   - runs arp-scan only on Linux when it has cap_net_raw (or root) and the CIDR is on-link;
   - runs `nmap -sn -T3` when nmap is installed (privileged on Linux with capabilities, otherwise `--unprivileged` TCP discovery; on Windows nmap may live in Program Files without being on PATH, the helper looks there);
   - without nmap, does a polite ping sweep (32 at a time, max /22 per CIDR; larger needs `--allow-large` after the owner agrees);
   - rereads the neighbor table to attach MACs, then builds `inventory.json` in the printed scan_dir.
3. Pull vendor/model enrichment from connectors when present (more accurate than OUI guesses): UniFi or Omada client lists, router DHCP leases, Pi-hole/AdGuard client lists.
4. Hand off to netwatch-asset-inventory for the diff against baseline.

## Notes

- Other VLANs are only visible if the scan host can route to them and the firewall allows it; otherwise use the controller's client list for those VLANs and say which segments were not scanned directly.
- ARP works only on the scan host's own subnet; remote subnets rely on nmap or ping and may miss quiet devices. Devices that ignore ping (Windows firewall default, many phones) are invisible to the ping sweep; say the result is partial when nmap is missing.
- Windows and macOS scan hosts without elevation get fewer MACs (only hosts they have talked to). Controller client lists fill the gap.
- Sleeping phones and battery IoT may not answer. One scan is a snapshot; combine with controller client history.
- Never run aggressive timing (-T4/-T5), OS detection, or NSE scripts in discovery.
