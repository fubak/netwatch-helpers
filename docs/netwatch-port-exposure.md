<!-- Net Watch guide netwatch-port-exposure. Read from the verified helper folder; skills and hard rules win on any conflict. -->
When to use: Use to find open ports and services inside the LAN, what is exposed to the internet (port forwards, UPnP/NAT-PMP mappings, IPv6 inbound), and to run the external WAN check from outside the network.

# Port and exposure audit

## A. Internal open ports (scan host)

1. Run on the scan host (any OS; `nw` as defined in netwatch-setup):
   ```text
   nw portscan.py TARGET [TARGET ...] [--exclude IP,IP]
   ```
   It refuses targets outside scope.txt, then runs `nmap -sT -T3 --top-ports 200 --open` (a TCP connect scan, which needs no admin rights on Linux, macOS, or Windows) and saves XML under NETWATCH_HOME/scans. Without nmap it does a Python connect scan of about 40 common ports (max 256 addresses) and says so.
   Routine (weekly) runs target infrastructure hosts only (router, APs, NAS, PCs, the scan host). Full-subnet runs that include smart-home devices happen at most weekly; use `--exclude` with their IPs from the profile when the owner prefers to skip them entirely.
2. Service versions: add `--version-light` (nmap `-sV --version-light`), accepted only for a single host the owner confirmed is general-purpose (NAS, PC, router). Never version-probe or run NSE scripts against smart-home devices (see netwatch-smart-home-observe); many crash or reboot.
3. Flag: telnet (23), FTP (21), SMB (445) on anything but the NAS, RDP (3389), VNC (5900), MQTT without TLS (1883), UPnP/SSDP (1900) on non-media devices, admin web UIs on HTTP only, databases (3306, 5432, 6379, 27017), Docker API (2375).

## B. What the router exposes

1. Port forwards and firewall WAN rules from the connector (UniFi, OPNsense/pfSense, Omada, Asus) or ask the owner for a screenshot (Eero, Firewalla).
2. UPnP mappings created by devices (game consoles, cameras, Plex), from the scan host (any OS, no miniupnpc needed):
   ```text
   nw upnp_check.py
   ```
   It sends one SSDP search, ignores answers from outside scope.txt, and lists every mapping (protocol, external port, internal client and port, lease, description) read-only. `UPNP-ENABLED` with mappings: recommend disabling UPnP or limiting it to named devices. `is_default_gateway=no` means some other LAN device claims to be a UPnP gateway (a second router, or something hostile); investigate. NAT-PMP/PCP is not queried; check the router UI for it. Windows Firewall can drop SSDP replies on networks marked Public: "no UPnP gateway answered" there is inconclusive, so confirm in the router UI.
3. IPv6: NAT does not hide IPv6 devices. Check the router's IPv6 inbound firewall default is deny and that no "allow all inbound IPv6" rule exists. Whether the LAN has global IPv6, from the scan host: Linux `ip -6 addr show scope global`; macOS `ifconfig | grep inet6`; Windows `Get-NetIPAddress -AddressFamily IPv6 -PrefixOrigin RouterAdvertisement`.
4. Remote admin: router/controller web UI or SSH reachable from WAN, cloud remote access (vendor accounts) and whether that account has 2FA.

## C. External check (from the box, outside the LAN)

1. Get the WAN IP from the router connector this session (UniFi gateway WAN status, OPNsense/pfSense interface status, the `external_ip` from upnp_check.py when `is_default_gateway=yes`, or the owner reading it from the router app). Do not use a cached or guessed IP: dynamic IPs get reassigned to strangers.
2. If the router's WAN IP is private or in 100.64.0.0/10, the ISP uses CGNAT or there is double NAT; report that inbound exposure cannot be tested from outside and check the ISP modem instead.
3. Run on the box (no machineId; if the file is missing, run the netwatch-setup helper bootstrap first; a download needs the owner's yes):
   ```bash
   python3 /workspace/nw-helpers/wan_probe.py --ip WAN_IP --confirmed-by-router
   ```
   It does plain TCP connects to about 20 common ports, no payloads or logins. IPv6 hosts can only be probed if the box has IPv6 egress (it usually does not); otherwise rely on the router's IPv6 rule review in B3.
4. Every open port must map to a port forward the owner knows about; anything else is a finding. tcp/7547 open means the ISP's TR-069 management is exposed; tell the owner to raise it with the ISP.

## Output

Table: port, service, internal host, why it matters, recommendation. Fixes (close forward, disable UPnP) go through netwatch-change-control.
