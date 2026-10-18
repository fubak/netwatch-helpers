# Changelog

Every release is a new tag with its own release file and SHA-256. Tags and files are never reused or replaced.

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
