<!-- Net Watch guide netwatch-unifi-verified-steps. Read from the verified helper folder; skills and hard rules win on any conflict. -->
When to use: Use when the owner makes a UniFi change in the app (zone firewall policy, IPS mode, port forward, Remote Access) and needs version-aware, verified steps.

# UniFi owner steps: verified menu paths (Network app 9.x, zone-based firewall)

Use this when the owner makes a change in the UniFi UI. Rules:

1. Read the version first: `nw nw_http.py unifi-version` (prints `network_app_version`, `console_version`, read-only). Say the version in the instructions.
2. Give detailed numbered steps with the exact field values to enter (names, IPs, ports, protocol, action, order).
3. Only name a menu path listed below for that version. For any other version, or a label not listed, say "the label may differ on your version" and describe what to look for (for example "the firewall policy list where you can add a policy between two zones").
4. Offer to confirm the result afterward by reading the config (read-only GETs listed per task), and record the change in netwatch-change-control.

Status key: VERIFIED = the path and field names appear in the cited Ubiquiti help article; UNVERIFIED = not confirmed on help.ui.com, describe it instead of naming it as fact. Ubiquiti's own articles differ between versions and sometimes between articles, so quote the version with every path.

## Sources (Ubiquiti Help Center, read 2026-10-18)

- Zone-Based Firewalls in UniFi: https://help.ui.com/hc/en-us/articles/115003173168-Zone-Based-Firewalls-in-UniFi
- UniFi Gateway - Port Forwarding: https://help.ui.com/hc/en-us/articles/235723207-UniFi-Gateway-Port-Forwarding
- UniFi Gateway - Intrusion Detection and Prevention (IDS/IPS): https://help.ui.com/hc/en-us/articles/360006893234
- Enabling UniFi Remote Management: https://help.ui.com/hc/en-us/articles/115012240067-Enabling-UniFi-Remote-Management
- Traffic & Policy Management in UniFi: https://help.ui.com/hc/en-us/articles/5546542486551-Traffic-Policy-Management-in-UniFi
- Release notes, UniFi Network Application 10.5.54: https://community.ui.com/releases/UniFi-Network-Application-10-5-54/fdfe1b15-091c-410b-9cb9-3de3acfc1255
- Release notes, UniFi Network Application 10.6.97: https://community.ui.com/releases/UniFi-Network-Application-10-6-97/ef8cd545-b479-4fac-bdc5-cabdd91692de
- Release notes, 10.6.106 (page did not render for reading; nothing taken from it): https://community.ui.com/releases/UniFi-Network-Application-10-6-106/f206c01d-3f73-471b-b4a5-2da48f157ea6

## 1. Zone policy: allow specific IPs from the VPN zone to Internal, block the rest below it

Built-in zones (VERIFIED): External, Internal, Gateway, VPN, Hotspot, DMZ. VPN to Internal is "Allow All" by default (VERIFIED, zone matrix in the article), so a block is needed for the rest.

Menu path (VERIFIED, article text):
- Network 9.4: Settings > Zones > Create Policy, or Settings > Policy Table > Create New Policy
- Network 9.3: Settings > Policy Engine > Zones > Create Policy
- Other versions: UNVERIFIED; say the label may differ and look for the zone matrix or the firewall policy list.

Steps for the allow policy:
1. Open the path above for the owner's version and choose to create a policy.
2. Name: `Allow VPN admin IPs to Internal` (any clear name).
3. Source zone: VPN. Narrow the source with "IP or MAC" (VERIFIED option) and enter the exact allowed VPN client IPs.
4. Destination zone: Internal (optionally narrow to the target device, network, or IP).
5. Action: Allow. "Auto Allow Return Traffic" (VERIFIED option) is only needed if return traffic is not already allowed.
6. Optional restrictions (VERIFIED): IP version, protocol, connection state, syslog logging, schedule.
7. Save.

Steps for the block policy (below the allow):
1. Create another policy: Name `Block VPN to Internal`, Source zone VPN (Any), Destination zone Internal (Any), Action Block (silently drops; Reject also notifies the sender, VERIFIED).
2. Save.

Order (VERIFIED): a new custom policy goes above built-in policies but after other custom policies. Use "Reorder" so the allow policy sits above the block policy. The article itself advises creating the allow first, then the block.

Confirm afterward (read-only): ask the bot to list firewall policies (the API path for zone policies differs by version; probe and report which works), then test from a VPN client: an allowed IP reaches the target, another IP does not.

## 2. Switch IPS to detect and block

Menu path (VERIFIED for current articles): Settings > CyberSecure > Protection, toggle Intrusion Prevention, select networks, set Detection Mode to "Notify and Block (IPS)" instead of "Notify (IDS)". The same article still mentions Settings > Security > Intrusion Prevention for suppression and allow lists, so older versions may use that label; say the label may differ.

Steps:
1. Open Settings > CyberSecure > Protection (or, on older versions, the Security settings page with Intrusion Prevention).
2. Make sure Intrusion Prevention is on.
3. Select every network to protect (at least the main LAN and IoT networks).
4. Detection Mode: Notify and Block (IPS).
5. Save. IPS blocks last 5 minutes unless the owner blocks the source permanently from the detection (stated in the Traditional Chinese edition of the same Ubiquiti article, help.tw.ui.com/articles/360006893234; treat as UNVERIFIED for the English edition).

Confirm afterward (read-only): `nw nw_http.py unifi-classic GET /api/s/default/rest/setting --path data --where key~^ips$` and report the mode field (field names vary by version; report what is present). The relay then shows inbound threats as blocked.

## 3. Port forward

Menu path (VERIFIED, article text):
- Network 9.4: Settings > Policy Engine > Port Forwarding
- Network 9.3: Settings > Policy Table > Create New Policy > Port Forwarding
Note: the zone firewall article names the 9.4 policy area differently ("Policy Table"); if the owner does not see the label, say it may differ and look for Port Forwarding in the policy area.

Steps (field names VERIFIED):
1. Name: what the forward is for.
2. WAN Interface: the one WAN, or all WANs.
3. Incoming traffic: the external port; From: all incoming traffic, or only specified source IPs (prefer restricting the source when possible).
4. Forward IP address and port: the internal device and its port.
5. Protocol: TCP, UDP, or Both.
6. Optional: syslog logging.
7. Save.
Removing a forward: open the same list and delete the rule (the delete control's label is UNVERIFIED).

Confirm afterward (read-only): `nw nw_http.py unifi-classic GET /api/s/default/rest/portforward --path data --fields name,enabled,dst_port,fwd,fwd_port,proto,src`. If the WAN IP is private or 100.64.0.0/10, the gateway is behind double NAT or CGNAT (VERIFIED) and the forward will not work from the internet alone.

## 4. Remote Access toggle

Menu path: the Remote Management article (VERIFIED text) says Settings > Control Plane > Console and "Check Remote Management". On UniFi OS consoles the control is commonly shown as a Remote Access toggle, but that label is UNVERIFIED on help.ui.com; say the label may differ. Only the console Owner account sees it, and the owner must be signed in locally (UNVERIFIED on help.ui.com; describe as "if you do not see it, sign in locally as the Owner").

Steps:
1. Connect locally to the console (not through unifi.ui.com).
2. Open Settings > Control Plane > Console.
3. Turn Remote Management / Remote Access on or off as agreed.
4. Save if prompted.

Confirm afterward: the bot cannot read this toggle through the Network API reliably (UNVERIFIED endpoint). Ask the owner to confirm the console disappears from (or appears in) unifi.ui.com, and note it in the change record.

## Network 10.x (researched 2026-10-18 for Network 10.6.106 on UniFi OS 5.1)

No help.ui.com article read on 2026-10-18 states a Network 10.x menu path for these tasks; the help articles still list 9.3 and 9.4 paths only. Official 10.x release notes confirm that some features and labels exist, but not where they sit in the menu. So every 10.x menu path below is UNVERIFIED: tell the owner "on 10.x the label may differ" and describe what to look for. Third-party guides (not official, not used as proof) report that Network 10 groups the firewall, zones and port forwards under Settings > Policy Engine > Policy Table.

What IS verified for 10.x (official release notes):
- Policy Table with Firewall Policies exists, and has a Duplicate action plus Firewall Hit and Last Hit columns (10.5.54). Use the hit columns to confirm an allow or block policy is matching.
- Test & Confirm: changes roll back automatically if device connectivity is lost, for Internet and Network settings (10.5.54, requires UniFi OS 5.1.12 or newer), expanded to VPN and Management networks (10.6.97). If a change seems to vanish, it was probably not confirmed: tell the owner to confirm when prompted.
- CyberSecure settings still exist (10.5.54 mentions a manual Suricata 8 upgrade option there; the Suricata 6 to 8 migration can take up to 1 hour after updating and requires UniFi OS 5.1.20 or newer).
- A Port Forwarding table exists (10.6.97 "Improved the Port Forwarding table user experience").
- The Policy Engine groups the zone-based firewall and NAT/port forwarding (Traffic & Policy Management article; not version-tagged, so its location in the 10.x menu stays UNVERIFIED).

### 10.x zone policy (allow VPN IPs to Internal, block the rest)
1. UNVERIFIED path: look in Settings for the Policy Engine and its policy table or zone matrix; on 10.x the label may differ. Choose to create a policy.
2. Fields (VERIFIED for 9.x in the zone firewall article; assumed unchanged on 10.x, UNVERIFIED): Name, Source zone VPN narrowed by IP or MAC to the allowed client IPs, Destination zone Internal, Action Allow.
3. Second policy: Source VPN (Any), Destination Internal (Any), Action Block.
4. Order the allow above the block (the "Reorder" control is VERIFIED for 9.x only; on 10.x look for a way to reorder or drag policies in the table).
5. Confirm if Test & Confirm prompts (VERIFIED behavior on 10.5 and later for Network and VPN settings).
6. Read back: check the Firewall Hit and Last Hit columns (VERIFIED on 10.5.54) after a test from an allowed and a non-allowed VPN client.

### 10.x IPS mode
UNVERIFIED path on 10.x: look for CyberSecure in Settings (CyberSecure settings exist on 10.5.54, VERIFIED), then the Intrusion Prevention section; set the mode that both notifies and blocks ("Notify and Block (IPS)" in the help article, label UNVERIFIED on 10.x) for every protected network. Read back with `nw nw_http.py unifi-classic GET /api/s/default/rest/setting --path data --where key~^ips$`.

### 10.x port forward
UNVERIFIED path: look for Port Forwarding in the Policy Engine or its policy table (a Port Forwarding table exists on 10.6.97, VERIFIED). Fields as in section 3 (VERIFIED for 9.x, assumed unchanged, UNVERIFIED on 10.x). Saving a forward also creates an automatic allow policy (third-party report, UNVERIFIED). Read back with the portforward GET in section 3.

### 10.x Remote Access
Nothing official for Network 10.x or UniFi OS 5.1 was found. Use section 4 (the help article path Settings > Control Plane > Console) and say the label may differ on UniFi OS 5.1; this is a console (UniFi OS) setting, not a Network app setting.
