<!-- Net Watch guide netwatch-lan-threats. Read from the verified helper folder; skills and hard rules win on any conflict. -->
When to use: Use to check for ARP spoofing (gateway MAC changes, one MAC on many IPs, duplicate ARP replies) and rogue DHCP servers, or when devices suddenly get wrong IPs, DNS, or gateway.

# LAN threats: ARP spoofing and rogue DHCP

## Steps

1. Run on the scan host (any OS; `nw` as defined in netwatch-setup):
   ```text
   nw lan_threats.py
   ```
   It reads the default gateway and neighbor table with the OS's own tools (Linux /proc/net/route and `ip -4 neigh`, macOS `route -n get default` and `arp -an`, Windows `route print` and `arp -a`).
2. Interpret:
   - `ALERT gateway-mac-changed`: possible ARP spoofing, or the router or its WAN-side was replaced. Ask the owner whether hardware changed today before escalating. If not, run netwatch-incident-runbook (severity high).
   - `WARN mac-on-multiple-ips`: normal for the router itself, mesh nodes, or a device with several addresses; suspicious when the MAC is a random client claiming the gateway's IP.
   - `WARN duplicate-arp-reply`: two devices answering for one IP. Often a static-IP conflict; can be spoofing.
   - `ALERT rogue-dhcp`: a DHCP server not in expected_dhcp.txt. Common innocent causes: a mesh node or ISP modem in router mode, a travel router, a Pi-hole/AdGuard with DHCP turned on. Identify it via inventory (MAC, vendor) before calling it hostile.
   - `SKIP rogue DHCP check` or `SKIP duplicate ARP check`: no raw-packet rights or tool. Linux: capabilities missing (setup gap, mention once). macOS and Windows: the bot never elevates; the SKIP line includes a command the owner may run themselves (Terminal with sudo, or an Administrator PowerShell with Npcap) and paste back. arp-scan does not exist on Windows; the duplicate ARP check is Linux-only, and the controller's ARP or IP-conflict events cover it elsewhere.
   - `WARN gateway MAC unknown`: the neighbor table had no entry for the gateway; rerun, and if it persists check the scan host's connectivity. Not evidence either way.
   - `INFO no DHCP offer captured` or `INFO no expected_dhcp.txt baseline`: the rogue DHCP check could not conclude; say so instead of reporting all clear.
3. Cross-check with the controller: UniFi and Omada can report rogue DHCP and ARP events; OPNsense/pfSense ARP tables and logs.
4. Recommend prevention where hardware supports it: DHCP snooping/guarding on managed switches (UniFi "DHCP Guarding", Omada "DHCP L2 Relay/Guard"), static ARP for the gateway on critical hosts is rarely worth it at home.

Containment of a spoofing host goes through netwatch-containment.
