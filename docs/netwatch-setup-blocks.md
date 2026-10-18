<!-- Net Watch guide netwatch-setup-blocks. Read from the verified helper folder; skills and hard rules win on any conflict. -->
When to use: the owner setup list of onboarding Step 3 (blocks A to G, shown only where they apply, one at a time) and block H in Step 5.

# Owner setup list blocks (onboarding Step 3)

Title "Your setup list". Show one block per message, only blocks that apply, each with its letter, a title, a time label, one line on why, and detailed numbered steps; the next block follows the owner's done. Fill in detected values (SCAN_HOST, SCAN_HOST_LAN_IP, GATEWAY_IP, paths); secrets stay placeholders. The bot never runs sudo and never sees the env file.

Install rule for every block that installs something: name the exact command, its source (package manager and repository, or vendor URL), what it does for Net Watch, and that it needs sudo, Administrator, or UAC. The owner running it is the yes; the bot never elevates.

Block A. (about 5 minutes) nmap with raw-packet access (only when `--detect` shows it missing or without `cap_net_raw`). Linux, from the Ubuntu or Debian package repository, needs sudo. The capabilities let any local user of this computer send raw packets: leave out the setcap part on shared machines.
```bash
sudo apt install -y nmap && sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip "$(command -v nmap)" && getcap "$(command -v nmap)"
```
Fedora: `dnf`; macOS and Windows: the lines in netwatch-setup. arp-scan is optional and not offered (nmap covers discovery).

Block B. (about 5 minutes) UniFi read-only login for Net Watch (the default UniFi path; verify on your version):
1. Open https://GATEWAY_IP in a browser on the home network and sign in with your own admin account.
2. Go to Settings (gear) > Admins & Users > Create New Admin (or Add Admin).
3. Turn on Restrict to Local Access Only (no cloud account, no 2FA prompt).
4. Username `netwatch`, a long unique password saved in your password manager.
5. Role: Network View Only. Other apps (Protect, Access, Talk): None.
6. Save. Keep this account View Only; Net Watch never needs more.
Why: the map, IDS events, and rogue AP data come from the classic API, which uses this login. An Integration API key would carry the full admin rights of the account that creates it, so block B2 is offered only if the owner asks.

Block B2 (optional). Integration API key from the owner's own admin account:
1. Signed in as yourself, open UniFi Network > Settings > Control Plane > Integrations (or Integrations in the left menu).
2. Create API Key, name it `netwatch`, copy it once.
3. Put it in the env file as `UNIFI_API_KEY` (block C). Never paste it in chat.
4. It has your admin role; delete it on the same screen if you stop using Net Watch.

Block C. (about 5 minutes) One env file with every key. The block below is for Linux. Get the template from `nw preflight.py --env-template` (add `--no-alerts` when alerts were not picked; `--gear unifi` or `--gear none` overrides the guess). It prints placeholders only, prefills `UNIFI_HOST` and `ALERT_SOURCES` with the detected gateway, never opens the env file, and writes nothing. Put its output between the `EOF` lines below. When `--detect` shows the env file exists, do not use this block: show only the MISSING names and the open command.
```bash
mkdir -p ~/.config/netwatch && chmod 700 ~/.config/netwatch
[ -e ~/.config/netwatch/env ] || ( umask 077; cat > ~/.config/netwatch/env <<'EOF'
PASTE THE --env-template OUTPUT HERE
EOF
)
grep -q '^ALERT_INBOUND_TOKEN=PUT_GENERATED_TOKEN_HERE' ~/.config/netwatch/env && sed -i "s|^ALERT_INBOUND_TOKEN=.*|ALERT_INBOUND_TOKEN=$(python3 -c 'import secrets;print(secrets.token_urlsafe(32))')|" ~/.config/netwatch/env
chmod 600 ~/.config/netwatch/env && nano ~/.config/netwatch/env
```
Then: 1. Replace `PUT_NETWATCH_PASSWORD_HERE` with the block B password. 2. Leave `ROUTINE_WEBHOOK_URL` and `ROUTINE_WEBHOOK_KEY` as placeholders for now; block H fills them after the first test alert. 3. Leave `ALERT_INBOUND_TOKEN` as filled (the line above wrote it without showing it); you copy it into UniFi in block E. 4. Delete the `UNIFI_VERIFY_SSL` line if your console has a trusted certificate. 5. Save and close (Ctrl+O, Enter, Ctrl+X). macOS: same block with the folder `~/Library/Application Support/netwatch` (quote the path) and `sed -i ''` instead of `sed -i`. Windows: create the file with the PowerShell line in netwatch-setup step 7 (opens Notepad), paste the template, and generate the token with the command it prints.

Block D. (about 5 minutes) Start the alert relay (only with alerts). Run `nw alertd.py service --bind SCAN_HOST_LAN_IP` and show its output; the firewall lines already carry the console IP from `ALERT_SOURCES` (or the default gateway). Items 2 to 4 are for Linux; on macOS (LaunchAgent) and Windows (Task Scheduler and the commented firewall lines) follow the printed text.
1. Paste the printed lines into a terminal on SCAN_HOST; they create and start the user service `netwatch-alertd`.
2. Only if `--detect` showed `linger=no`: `sudo loginctl enable-linger $USER` (keeps it running when you log out).
3. Only if `--detect` showed `ufw=active`: run the printed `sudo ufw allow` line.
4. Check: `systemctl --user status netwatch-alertd --no-pager` shows active (running).

Block E. (about 10 minutes) UniFi alert settings (only with alerts; verify on your version):
1. UniFi Network > Alarm Manager > Create Alarm, name it Net Watch.
2. Triggers: threat detected (IDS/IPS), honeypot triggered, admin access or failed login, device offline, internet disconnected or WAN failover, rogue DHCP or IP conflict if listed. Scope: all.
3. Action: Webhook > Custom Webhook. URL `http://SCAN_HOST_LAN_IP:8787/unifi`, method POST.
4. Advanced: Bearer authentication. In your own terminal on SCAN_HOST run the line below (Net Watch writes out the full `nw` path for you); it puts `ALERT_INBOUND_TOKEN` on your clipboard without showing it. Paste it into the token field. Turn on Ignore Repeated Actions. Save.
```bash
nw alertd.py token copy
```
5. Press the alarm's Test button if your version has one; Net Watch watches for `leg_webhook=proven`.
6. Settings > CyberSecure > Traffic Logging > Activity Logging (Syslog) > SIEM Server: address SCAN_HOST_LAN_IP, port 5514. Contents: Security Detections, Admin Activity, Critical, Triggers. Debug Logs and Devices off. Save.
7. Settings > CyberSecure > Protection: Intrusion Prevention (IDS/IPS) on.

Block F. (about 2 minutes) Let Net Watch run commands on SCAN_HOST without a prompt each time (needed for routines):
1. On the next command approval card for SCAN_HOST, pick the option that always allows Net Watch there (wording varies by app version).
2. Missed it: open Grok Bot's settings for Net Watch's machine access and allow SCAN_HOST.
3. Net Watch confirms with one harmless command that should not prompt.

Block G. (about 3 minutes) Keep SCAN_HOST awake (only when `--detect` shows `battery=yes` or `sleep_on_ac` other than never). Ubuntu: Settings > Power > Automatic Suspend: Off (at least when plugged in); Screen Blank may stay on. Or the owner may run: `sudo systemctl mask sleep.target suspend.target hibernate.target hybrid-sleep.target`. macOS: System Settings > Energy (or Battery > Options) > prevent automatic sleeping when the display is off. Windows: Settings > System > Power (and battery) > Screen and sleep: put the device to sleep Never when plugged in.

Block H. (about 5 minutes, onboarding Step 5, only after `create_routine=ready`). Connect the alert routine:
1. Open the routine panel for "Net Watch: UDM live alerts" and copy its webhook URL and sender key into `ROUTINE_WEBHOOK_URL` and `ROUTINE_WEBHOOK_KEY` in the env file (block C path). Never in chat.
2. Restart the relay so it reads them (Linux):
```bash
systemctl --user restart netwatch-alertd
```
macOS and Windows: stop and start the task the block D text created.
3. Net Watch checks `nw alertd.py status` for the routine values (names only) and then asks about one test alert.
