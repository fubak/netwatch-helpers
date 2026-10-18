# Security policy

## Reporting a problem

Please report security issues privately through GitHub's "Report a vulnerability" button on this repository (Security tab, private vulnerability reporting). Do not open a public issue for something that could put a household network at risk. Include the release version, the helper or guide involved, and steps to reproduce. Never include real passwords, tokens, IP addresses, or MAC addresses from your own network; use obvious placeholders.

We aim to acknowledge reports within 7 days and to publish a fixed release, with a new tag and a new SHA-256, as soon as a fix is verified. Published tags and release files are never replaced; a fix is always a new version.

## What is in scope

- The helper scripts in `helpers/` and the guides in `docs/`.
- The bootstrap and its checks (bundle SHA-256, per-file SHA256SUMS, file name rules).
- Anything that lets a helper scan outside scope.txt, read a secret it should not, change a device without an approved change id, or send data off the scan host other than to the owner's own routine.

## Design rules the project keeps

- Standard library only, no pip packages.
- Scope guard on every scan; own-devices-only mode refuses any range wider than one address.
- Secrets live only in the owner-created env file and are never printed.
- Writes need a fresh, single-use, owner-approved change id.
- Release files are reproducible, pinned by SHA-256 in the skill, and verified before install.
