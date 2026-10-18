<!-- Net Watch guide netwatch-hardening-audit. Read from the verified helper folder; skills and hard rules win on any conflict. -->
When to use: Use for a security posture review: default or weak admin credentials, admin interfaces and remote management, vendor cloud account 2FA, router settings (WPS, UPnP, remote access), and hardening of the scan host itself.

# Hardening audit

## Default credentials (careful)

1. From inventory and port results, list devices with admin UIs (routers, NAS, printers, cameras, IoT hubs).
2. Look up whether each model ships with a default or printed password (vendor docs). Ask the owner whether it was changed. That answer is usually enough.
3. Only if the owner explicitly asks to test a specific device: one login attempt with the single documented default for that model, made by the owner in the device UI or as one single request, logged in the report as device, time, and result (never the password value). No password lists, no brute force, no testing devices owned by another bot or by anyone else. Lockouts are possible; warn first.

## Router and controller settings

Check via connector or owner screenshots: firmware auto-update policy, WPS off, UPnP off or limited, remote WAN admin off, SSH off or key-only, admin account not "admin"/"ubnt", 2FA on the vendor cloud account (Ubiquiti, TP-Link, Synology, Eero, Asus, Google, and smart-home vendor apps), unused port forwards, guest network isolation, DNS settings (see netwatch-dns-hygiene), syslog/remote logging, NTP correct (log timestamps).

## Scan host hardening

The scan host holds network credentials, so it is now a high-value target. Read-only checks that need no sudo, Administrator session, or UAC, per OS automatically (`nw` as defined in netwatch-setup):

```text
nw hostcheck.py
```

- Linux: unattended-upgrades or dnf-automatic, ufw/firewalld/nftables active, SSH service and `PasswordAuthentication`/`PermitRootLogin` (drop-ins in sshd_config.d are read first; the first value wins, absent means the default), local users, nmap/arp-scan capabilities.
- macOS: FileVault, application firewall and stealth mode, automatic update settings, Gatekeeper, listeners for SSH (Remote Login), Screen Sharing/ARD, SMB, AFP, local users.
- Windows: firewall profiles, Defender real-time protection and signature age, Windows Update service, sshd and RDP state, enabled local users and Administrators members. BitLocker needs elevation: ask the owner to read Settings > Privacy & security > Device encryption.
- All: env file permissions (mode 600 on Linux/macOS; on Windows no access for Everyone, Users, or other accounts per icacls).

Look for: updates automatic, firewall on, disk encryption on (laptops especially), remote access off or key-only, no unexpected local users or admins, raw-packet grants understood (Linux capabilities, Npcap on Windows), env file private. Fixes are owner actions on their own machine with exact steps; record them in netwatch-change-control.

## Output

Findings as: item, current state, risk, fix, effort. Fixes go through netwatch-change-control; password changes are done by the owner.
