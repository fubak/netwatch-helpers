# netwatch-helpers

Helper scripts and guides for Net Watch, a Grok Bot agent that observes and secures a home network the owner owns or administers. Template copies of the agent carry only short skill text, so the helpers and the longer guides ship here as one pinned release file. The agent downloads it only after the owner says yes, checks the bundle SHA-256 written in its netwatch-setup skill, then checks every file against the SHA256SUMS inside the bundle (covered by that same hash), and refuses on any mismatch.

## Quick start (for a new owner)

1. Add the Net Watch template to your Grok Bot and say hello. It asks two plain questions first: do you own or administer this network, and does your household know it is being monitored. If your router belongs to your ISP or landlord, pick that option: Net Watch then checks only your own devices and never sweeps the subnet.
2. Pick **Quick look** for one scan with results in about 5 minutes, or **Full setup** (5 steps, about 30 minutes).
3. Connect one always-on computer as the scan host (Linux is tested; Windows and macOS are beta).
4. When asked, say yes to download this release file. The agent verifies it before installing anything.

## Verify the release file yourself

Current release: `netwatch-helpers-v1.3.0.tar.gz`, SHA-256 `edf13a4dff2d63dd68b9576174851ce6b2b172f4f1aa4e0b4c844e0493d152e0`.

Linux:

```bash
sha256sum netwatch-helpers-v1.3.0.tar.gz
```

macOS:

```bash
shasum -a 256 netwatch-helpers-v1.3.0.tar.gz
```

Windows (PowerShell):

```powershell
Get-FileHash -Algorithm SHA256 .\netwatch-helpers-v1.3.0.tar.gz
```

The output must equal the hash above and the `BUNDLE_SHA256` line in the netwatch-setup skill. To check that an exported or shared template still pins this file, run `python3 tools/check_export.py EXPORTED_TEMPLATE --expect-sha256 edf13a4dff2d63dd68b9576174851ce6b2b172f4f1aa4e0b4c844e0493d152e0`.

## Contents

- `helpers/`: 18 Python 3.8+ scripts, standard library only. 16 run on the owner's scan host (Linux, macOS beta, Windows beta); `vuln_lookup.py` and `wan_probe.py` run on the agent's box.
- `docs/`: 33 guides (vendor connectors with pass/fail tests, local AI CLIs, audits, full references, the Windows and macOS test checklist). In the bundle they sit under `docs/`. Skills and the agent's hard rules win over a guide on any conflict.
- `build_bundle.py`: reproducible build (sorted, USTAR, mode 0644, uid and gid 0, fixed mtime, gzip mtime 0, level 9). It refuses unexpected file names, `__pycache__`, and files with non-generic IP literals.
- `tools/check_export.py`: extracts the bootstrap from exported template text and checks its pins.
- `SHA256SUMS`: per-file SHA-256 of every bundled file, plus the release file.
- `dist/*.tar.gz.b64`: every published release file, base64 encoded, so each asset can be recreated byte for byte. Tags are never reused.

Recreate and check the current file:

```bash
base64 -d dist/netwatch-helpers-v1.3.0.tar.gz.b64 > netwatch-helpers-v1.3.0.tar.gz
sha256sum -c SHA256SUMS --ignore-missing
python3 build_bundle.py --out /tmp/rebuild && cmp /tmp/rebuild/netwatch-helpers-v1.3.0.tar.gz netwatch-helpers-v1.3.0.tar.gz
```

The rebuild matches when the local zlib produces the same deflate stream (zlib 1.3.1 was used); the base64 copy is exact regardless.

## Updates and rollback

The agent runs a weekly read-only release check and asks the owner before any update. A new fingerprint arrives only with an updated netwatch-setup skill or template, never from the releases API. Each install keeps the previous copy, and `--rollback` restores it.

## Releases

See CHANGELOG.md. Earlier files: v1.2.0 SHA-256 `2a312190a976a763b7021d5e4b8500d429e10a4bcba41d13dabe7de5425e3b80`, v1.1.0 SHA-256 `3c1ac9a3f90a3a643def5794b52e34614c171dc89b0151029ae9aab97390e6d6`, v1.0.0 SHA-256 `5db7c8abc78532bf7a1586829ef2e511c2a86e8ec61874ba040bd6a3a8e73390`.

## Safety

Read-only by default, scans only what the owner lists in scope.txt, reads secrets only from the owner's own env file, and changes the network only through the agent's change-control flow after the owner's explicit yes. Report security issues as described in SECURITY.md.

## License

MIT, see LICENSE.
