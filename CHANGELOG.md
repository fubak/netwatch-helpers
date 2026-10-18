# Changelog

Every release is a new tag with its own release file and SHA-256. Tags and files are never reused or replaced.

## v1.3.0

Release file `netwatch-helpers-v1.3.0.tar.gz`, SHA-256 `edf13a4dff2d63dd68b9576174851ce6b2b172f4f1aa4e0b4c844e0493d152e0`.

- `preflight.py --detect` adds a host and network checks section: scan host fitness (`scan_host_ok`: the only connected desktop is picked without asking only when every safety check ran and passed; a check that could not run means the owner is asked), private gateway, VPN route, company-managed computer, WSL, admin rights, battery and sleep on mains power, Windows Store Python stub, host firewall, Windows network profile, IPv6, and the router brand with its source. Any check that fails prints `not checked`, never a pass.
- `preflight.py --detect --probe` (after consent, private gateway only): the gateway's UPnP description and reported external address (CGNAT and double NAT shown as `wan_type`), its login page title, and the macOS Local Network permission check. Read-only.
- `upnp_check.py` saves `upnp/latest.json`; `wan_probe.py --upnp-file` probes only when that record is from the default gateway, under an hour old, and names the same address.
- `inventory.py accept --provisional` keeps a first baseline open for 24 hours and marks unnamed devices unreviewed; `inventory.py status` shows the window; a plain accept makes it final.
- `alertd.py status` names why UniFi posts were refused (missing, scheme, mismatch) and says when the alert routine can be created (`create_routine=ready` after `leg_webhook` is proven). New `alertd.py token copy` puts the inbound token on the clipboard in the owner's own terminal without printing it.
- Onboarding: plainer consent wording with guest networks left out, one setup block at a time with time labels, the download card only when the helpers are missing, the routine created after the first real test alert, and one quiet daily check card instead of two report cards. Template smaller.

## v1.2.0

Release file `netwatch-helpers-v1.2.0.tar.gz`, SHA-256 `2a312190a976a763b7021d5e4b8500d429e10a4bcba41d13dabe7de5425e3b80`.

- Consent is now two plain statements (I own or administer this network; people in my household know it is being monitored), plus an "ISP or landlord router" choice that limits scope to the owner's own devices. Scope files marked `# netwatch: own-devices-only` refuse any range wider than one address.
- Onboarding: a Quick look path (one scan, results in about 5 minutes), a no-controller track, and fewer cards that say what each option does.
- Every vendor guide has a pass/fail test. New guide netwatch-os-test-checklist; Windows and macOS are labeled beta.
- `preflight.py --health` (GREEN, YELLOW, RED per check), `--mark-routine`, and a read-only `--release-check` that never trusts a fingerprint from the API.
- Alert relay: change-controlled "Ignore this signature" and "Always page me" lists (`alertd.py feedback`); ignore never hides critical, honeypot, or unblocked inbound events. Relay leg health, severity floor for unblocked inbound threats, owner identity folding, and refused-token alerts.
- UniFi: cached sessions with a lock and 429 backoff, `nw_http.py unifi-version`, and version-aware owner instructions.
- Change records: declined, expired, superseded, and `list --open`.
- Bootstrap keeps the previous copy and supports `--rollback`. Builds exclude `__pycache__`. New `tools/check_export.py`.
- Redaction keeps harmless fields (allowlist) while still dropping secrets.

## v1.1.0

Release file `netwatch-helpers-v1.1.0.tar.gz`, SHA-256 `3c1ac9a3f90a3a643def5794b52e34614c171dc89b0151029ae9aab97390e6d6`.

- Adds the guides (vendor connectors, local AI CLIs, audits, references) to the bundle under `docs/`. Helpers unchanged from v1.0.0.

## v1.0.0

Release file `netwatch-helpers-v1.0.0.tar.gz`, SHA-256 `5db7c8abc78532bf7a1586829ef2e511c2a86e8ec61874ba040bd6a3a8e73390`.

- First release: 18 standard-library helpers.
