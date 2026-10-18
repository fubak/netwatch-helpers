<!-- Net Watch guide netwatch-config-backup. Read from the verified helper folder; skills and hard rules win on any conflict. -->
When to use: Use to back up network device configurations (gateway/controller, firewall, NAS, DNS filter) before changes and on a monthly cadence, and to check backups exist and are recent.

# Config backups

Backups contain secrets (Wi-Fi passphrases, VPN keys, password hashes). Keep them on the scan host in the `backups` folder of NETWATCH_HOME (private to the scan user: mode 700 on Linux/macOS, owner-only ACL on Windows, set by `nw nw_common.py init`). Never copy them to the box, chat, email, or cloud without the owner's explicit request naming the destination.

## Per platform (download is read-only; restore is a change)

- **UniFi**: built-in autobackup (Settings > System > Backups) is on by default on UniFi OS consoles; confirm it is on and recent, and that a cloud or off-device copy exists. Manual `.unf` download is a UI action by the owner.
- **OPNsense**: `nw nw_http.py opnsense GET /api/core/backup/download/this --save opnsense-YYYY-MM-DD.xml` on recent versions (verify on your version; the helper writes into the backups folder with private permissions and prints only the size), or System > Configuration > Backups in the UI.
- **pfSense**: Diagnostics > Backup & Restore in the UI (the REST API package may also expose config history; verify before relying on it).
- **Pi-hole v6**: `nw nw_http.py pihole GET /teleporter --save pihole-YYYY-MM-DD.zip` (the helper logs in and out around the call).
- **AdGuard Home**: copy `AdGuardHome.yaml` from its host (owner or SSH read).
- **Synology**: Control Panel > Update & Restore > Configuration Backup (owner), plus Hyper Backup for data.
- **Omada**: controller Settings > Maintenance > Backup (owner); controller autobackup schedule.
- **Eero, Asus stock, Firewalla**: settings live in the vendor cloud or app; record key settings in a short markdown note in backups instead.

## Steps

1. For each platform in the profile, check last backup date and location. Report anything older than 30 days or missing.
2. Before any change record that touches config, take or confirm a backup and put its path in the change record.
3. Keep at least the last 6 monthly backups. Deleting older backup files on the scan host needs the owner's yes for that specific cleanup (list the files first); never delete automatically.
