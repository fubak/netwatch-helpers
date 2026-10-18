<!-- Net Watch guide netwatch-dns-hygiene. Read from the verified helper folder; skills and hard rules win on any conflict. -->
When to use: Use to review DNS: which resolvers clients really use, DNS filtering (Pi-hole, AdGuard Home, router or Firewalla), devices bypassing DNS (hard-coded resolvers, DoH/DoT), DNS rebinding protection, and suspicious lookups.

# DNS hygiene

## Steps

1. Map the chain: DHCP-advertised DNS (router or controller), the filter (Pi-hole/AdGuard via netwatch-dns-filter), upstream resolvers, and whether IPv6 RA advertises a different DNS server (a common bypass).
2. From the scan host (any OS; `nw` as defined in netwatch-setup), confirm what answers:
   ```text
   nw dns_check.py
   ```
   It lists the configured resolvers with the OS's own tool (Linux `resolvectl dns` or resolv.conf, macOS `scutil --dns`, Windows `Get-DnsClientServerAddress`) and the public egress resolver seen by whoami.akamai.net. Egress belonging to the ISP or a public resolver while the profile says all DNS goes through the filter means the filter is bypassed or forwards there (check its upstream setting). A VPN client on the scan host (common on Windows and macOS laptops) changes both answers; note it.
3. Bypass: compare filter client lists with inventory. Devices in inventory but absent from the filter's clients are likely using hard-coded DNS (smart TVs, Chromecast/Google devices) or DoH. Recommendation options: firewall NAT redirect of port 53 to the filter, block known DoH endpoints, accept the bypass for vendor devices. Each is a change.
4. Rebinding protection: on in the filter or router (blocks public names resolving to private IPs).
5. Suspicious lookups: from the filter's query log, flag newly registered or random-looking domains, known malware/C2 categories the filter blocked repeatedly from one client, very high query rates from one IoT device. Treat as leads for netwatch-intrusion-detection, not proof.
6. Filter health: up to date, blocklists updated, admin UI password set, not reachable from WAN.
