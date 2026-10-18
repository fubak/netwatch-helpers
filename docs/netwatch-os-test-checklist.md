<!-- Net Watch guide netwatch-os-test-checklist. Read from the verified helper folder; skills and hard rules win on any conflict. -->
When to use: before calling Windows or macOS support anything other than beta, or when an owner on Windows or macOS reports a setup problem. Linux is the tested scan host; Windows and macOS are beta.

# Windows and macOS scan host test checklist

Run each item on a real machine, note PASS or FAIL with the OS version, and fix or document every FAIL before removing the beta label. Nothing here needs a secret in chat.

## Both

1. `python3 --version` (macOS) or `py -3 --version` (Windows) is 3.8 or newer; on Windows a Microsoft Store stub that opens the Store does not count.
2. The helper bootstrap prints `BOOTSTRAP OK`, and `--rollback --out FOLDER` restores the previous copy.
3. `nw preflight.py` and `nw preflight.py --detect` finish without a traceback and print the interface, range, and gateway.
4. `nw preflight.py --health` prints one line per check and no RED except for things not yet set up.
5. Unprivileged nmap: `nw discover.py CIDR` without elevation finds devices (nmap falls back to a TCP ping, so results may be partial; the report must say so). Without nmap the ping sweep runs.
6. arp-scan absence: with arp-scan not installed, discovery and `nw lan_threats.py` print SKIP or INFO lines for it, never an error, and reports say "not checked".
7. `nw portscan.py TARGET` against one infrastructure IP finishes in TCP connect mode.

## Windows

1. Env file privacy: after the owner runs the block C commands, `icacls "%APPDATA%\netwatch\env"` lists only the owner and SYSTEM (and Administrators if the owner chose that). `nw preflight.py --detect` reports no permission problem.
2. NETWATCH_HOME folders: `icacls` on `NETWATCH_HOME` shows inheritance removed and owner-only access after `nw nw_common.py init`.
3. Task Scheduler: `nw alertd.py service` prints PowerShell `Register-ScheduledTask` lines (task `NetWatch alertd`, runs at logon with pythonw.exe, no elevation); after the owner runs them, `Get-ScheduledTask -TaskName 'NetWatch alertd'` shows Ready or Running, again after a sign-out and sign-in, and `nw alertd.py status` answers.
4. Windows Defender Firewall: the printed `New-NetFirewallRule` lines (Administrator, owner decides) allow only the console IP to the relay ports on the Private profile; check the scan host's network is set to Private.
5. Paths with spaces in the user name work in both PowerShell and cmd lines from the skills.

## macOS

1. Env file privacy: `ls -l "$HOME/Library/Application Support/netwatch/env"` shows `-rw-------`.
2. Local Network prompt: the first LAN scan from the Grok Bot desktop app (or Terminal) triggers the macOS Local Network permission prompt; with it denied, discovery finds nothing and Net Watch must say "Local Network access is off for this app" instead of "no devices". Recheck in System Settings > Privacy & Security > Local Network.
3. LaunchAgent: `nw alertd.py service` prints the `com.netwatch.alertd` plist and a `launchctl bootstrap gui/UID` line; after the owner runs them, `launchctl print gui/$(id -u)/com.netwatch.alertd` shows it running, and it survives a logout and login.
4. Unprivileged nmap from Homebrew runs without sudo; raw-packet checks report SKIP with the line the owner may run.
5. The application firewall, if on, allows incoming connections for the Python used by the relay.

## Record

Save results (no secrets) as `NETWATCH_HOME/reports/os-test-YYYYMMDD.md` and send the summary to the maintainers through a GitHub issue on the release repo, if the owner agrees.
