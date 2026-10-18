<!-- Net Watch guide netwatch-response-by-brand. Read from the verified helper folder; skills and hard rules win on any conflict. -->
When to use: when a finding needs a response (block, close a port, isolate, update) and the owner's gear is not only UniFi, or the owner asks what Net Watch can do with their router. Say the brand's row plainly before proposing anything.

# What Net Watch can do, by brand

Every change still goes through netwatch-change-control: current state and exact rollback first, then the owner's own yes for that one change. "With consent" means Net Watch runs it after that yes. "Owner only" means Net Watch gives exact steps and verifies afterward, read-only.

| Gear | Can detect | Can propose | Can do with consent | Owner only |
|---|---|---|---|---|
| UniFi | clients, devices, firmware, port forwards, Wi-Fi and VLAN config, IDS/IPS and admin events, rogue APs, live alerts | block or isolate a client, close a forward, firmware, Wi-Fi and VLAN fixes | block and unblock a client (stamgr with a change id) | firewall, forwards, Wi-Fi, VLANs, firmware in the app |
| pfSense / OPNsense | interfaces, DHCP leases, rules, NAT and forwards, firmware, logs (read-only API user) | rules, forward removal, alias block lists, updates | none by default (read-only key) | every rule, NAT, alias, and update in the web UI |
| Omada | clients, devices, firmware, Wi-Fi and network config, topology | block a client, Wi-Fi and VLAN fixes, firmware | none by default | all controller changes |
| ASUS | clients, firmware, forwards, UPnP, remote admin and Wi-Fi settings (read-only SSH, asus_ssh.py) | close forwards, disable UPnP or remote admin, firmware | none (read-only) | all changes in the router UI or app |
| eero | what discovery and UPnP show; no local API | block or pause a device, turn off UPnP, updates | none | all changes in the eero app |
| Firewalla | what discovery shows plus anything the owner shares from its app | block or quarantine a device, rules | none | all changes in the Firewalla app |
| Synology | DSM version, open services, users, security advisor results (read-only) | updates, disable services, 2FA, firewall | none | all changes in DSM |
| Pi-hole / AdGuard Home | query stats, clients, blocklist health, bypass leads (dns_check.py) | add a block or allow entry, fix upstream resolvers | none by default | list and resolver changes in its UI |
| ISP router | what discovery shows of the owner's own devices; in own-devices-only scope no WAN probe and no login page fetch | ask the ISP about open ports, enable bridge mode, add an owner router | none | everything; the router belongs to the ISP or landlord |

Containment without a write API: Net Watch proposes the least disruptive step the owner can take in that brand's app (pause, block, guest network), gives exact steps, and verifies by scanning afterward. Smart-home devices are never blocked by Net Watch on any brand; the owner or the home-control bot decides.
