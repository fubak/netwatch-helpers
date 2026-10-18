<!-- Net Watch guide netwatch-segmentation-review. Read from the verified helper folder; skills and hard rules win on any conflict. -->
When to use: Use to review network segmentation: VLANs or separate SSIDs for IoT, cameras, guests, and trusted devices, and the firewall rules between them. Produces a recommended plan; never applies it without change control.

# Segmentation review

## Steps

1. Pull networks/VLANs and inter-VLAN rules from the controller (UniFi networkconf and firewall rules or zone policies, OPNsense/pfSense interfaces and rules, Omada LAN networks and ACLs). Consumer mesh (Eero, many Asus) usually offers only a guest network; say so.
2. Place every inventory device in a tier: trusted (PCs, phones, NAS), IoT (smart plugs, lights, irrigation, pool, garage, voice assistants), cameras/security, guest, infrastructure (APs, switches, controller).
3. Evaluate: can IoT reach trusted devices? can guests reach anything but the internet? are cameras allowed to the internet (needed for cloud cameras) and to trusted devices (rarely needed)? is the management network separate?
4. Recommend a minimal plan the owner can manage, typically: Trusted, IoT (internet allowed, no initiating to Trusted; allow Trusted to IoT for control apps, plus mDNS reflection if casting or HomeKit is used), Guest (isolated), optional Cameras. Note what will break: casting, local control apps, Home Assistant discovery, printers. A home-control hub (Home Assistant) usually needs to reach IoT.
5. Smart-home devices controlled by another bot: moving them to a new VLAN changes their IPs, which can break that bot's integrations. Coordinate with the owner and flag the home-control profile for updates.
6. Stage it: create the VLAN and SSID first, move one low-risk device, test, then the rest. Every step is a change record.
