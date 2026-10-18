<!-- Net Watch guide netwatch-incident-runbook. Read from the verified helper folder; skills and hard rules win on any conflict. -->
When to use: Use when there is a likely compromise or serious security event: unknown device the owner cannot identify, IDS alert for malware or C2, gateway MAC change, rogue DHCP, admin login the owner did not make, ransomware signs, or unexpected internet exposure.

# Incident runbook

## 1. Triage (minutes)

- Severity: **critical** (active exfiltration, ransomware, router/controller admin compromise), **high** (C2 signature, ARP spoofing, rogue DHCP, unknown admin login), **medium** (unknown device, unexpected open port), **low** (policy hygiene).
- Tell the owner immediately for high and critical, in plain words: what, which device, evidence, what you suggest first.

## 2. Preserve evidence (before containment)

Save controller events, IDS alerts, DNS logs, inventory, and lan_threats output with timestamps into a folder `incident-YYYYMMDD-HHMM` under the `reports` folder of NETWATCH_HOME on the scan host (any OS).

## 3. Contain (with consent)

Use netwatch-containment. Prefer isolating the device over shutting down the whole network. If the router or controller itself may be compromised, recommend the owner disconnect the WAN cable and work from the console locally.

## 4. Eradicate and recover (owner-led)

- Compromised PC/phone: offline malware scan or reinstall, change passwords from a clean device, enable 2FA.
- Compromised IoT: factory reset, update firmware, re-pair on the IoT network; replace if end-of-life.
- Router/NAS/controller: update firmware, rotate admin credentials and API keys (update the env file), review port forwards, users, VPN peers, SSH keys; restore from a known-good backup if config was altered.
- Rotate Wi-Fi passphrase if a device on the main SSID was compromised.
- Rotate the Net Watch credentials in the env file (path per OS in netwatch-setup) if the scan host is suspect, and remove Net Watch's raw-packet grants (Linux capabilities) until it is clean.

## 5. Follow-up

Write a short incident note: timeline (owner's time zone), cause if known, actions with change ids, what to watch. Offer to run the daily checks more often for 7 days (the owner decides).

## Escalate outside the bot

Suggest professional help or the ISP for: ransomware, financial account takeover, router compromise the owner cannot reset, anything involving threats or extortion (also local police/IC3). Never hack back or contact the attacker.

## Short form (from netwatch-change-control)

1. Severity: critical (exfiltration, ransomware, router or controller admin compromise), high (C2 signature, ARP spoofing, rogue DHCP, unknown admin login), medium (unknown device, unexpected port), low (hygiene). Tell the owner at once for high and critical, in plain words.
2. Preserve evidence before containment: controller events, IDS alerts, DNS logs, inventory, lan_threats output, into NETWATCH_HOME/reports/incident-YYYYMMDD-HHMM.
3. Contain with the least disruptive option, each as a change above: pause internet, quarantine VLAN, block on the controller (netwatch-unifi, or the brand's guide), close a forward or UPnP mapping, app steps for gear without an API, or the owner unplugging it. Confirm the target by MAC first and say how sure you are.
4. Recovery is owner-led: reset or reinstall, update firmware, rotate passwords from a clean device, rotate Net Watch credentials if the scan host is suspect. Then a short incident note with change ids.
5. Escalate to professionals, the ISP, or police for ransomware, account takeover, or extortion. Never hack back or contact the attacker.
