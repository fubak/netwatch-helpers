<!-- Net Watch guide netwatch-asus. Read from the verified helper folder; skills and hard rules win on any conflict. -->
When to use: Use when the owner's router is Asus (stock firmware or Asuswrt-Merlin, including AiMesh): DHCP leases, UPnP and port forwards, firmware, remote access settings, via read-only SSH on Merlin/stock with SSH enabled, otherwise owner screenshots.

# Asus router connector

No official API or MCP server. Asus SSH logins are always the router admin, so the safeguard is `asus_ssh.py`, which runs only allowlisted read-only commands (any OS with an OpenSSH client: built into Linux, macOS, and Windows 10/11 as an optional feature; `nw` as defined in netwatch-setup).

## Owner setup (optional)

Administration > System: enable SSH on **LAN only**, key authentication only, paste the scan host's public key. The owner generates a dedicated key on the scan host. Linux and macOS: `ssh-keygen -t ed25519 -f ~/.ssh/netwatch_asus`. Windows PowerShell (Windows does not expand `~` for native tools, and the folder may not exist yet): `New-Item -ItemType Directory -Force "$env:USERPROFILE\.ssh" | Out-Null; ssh-keygen -t ed25519 -f "$env:USERPROFILE\.ssh\netwatch_asus"`. An empty passphrase is needed for unattended use; the key file stays on the scan host. Env: `ASUS_SSH_HOST` (router IP, must be in scope.txt), `ASUS_SSH_USER`, optional `ASUS_SSH_KEY` (full path if not the default). The owner connects once by hand (`ssh -i KEYPATH USER@ROUTER_IP exit`) and verifies the host key fingerprint against the router UI, because BatchMode refuses unknown host keys.

## Read-only commands

```text
nw asus_ssh.py firmware
nw asus_ssh.py leases
nw asus_ssh.py settings
nw asus_ssh.py portforwards
nw asus_ssh.py arp
nw asus_ssh.py firewall
nw asus_ssh.py nvram NAME [NAME ...]
```

`settings` returns upnp_enable, misc_http_x, wps_enable, wan0_ipaddr, ipv6_service. `nvram` reads other single variables and refuses names that can hold secrets (anything with psk, pass, key, secret, cert, token, pin, wpa, radius, auth, and similar) and never dumps all of nvram. Never run anything else over this SSH key by hand. `misc_http_x=1` means web admin is reachable from WAN: high finding.

Without SSH: ask for screenshots of Network Map clients, WAN > Virtual Server / Port Forwarding, WAN > NAT Passthrough/UPnP, Administration > System (remote access), and Firmware Upgrade.

## Changes

Owner applies in the Asus web UI or app with exact steps; record each in netwatch-change-control.

## Pass/fail test

Run on the scan host (read-only):

```text
nw asus_ssh.py firmware
```

- PASS: a firmware version line prints.
- FAIL: an SSH error (SSH not enabled on the router, wrong ASUS_SSH_HOST or user, host key not yet accepted by the owner) or a non-zero exit. Give the owner one line, mark the connector untested, and continue setup.
