# netwatch-helpers

Helper scripts and guides for Net Watch, a Grok Bot agent that observes and secures a home network the owner owns. Template copies of the agent carry only short skill text, so the helpers and the longer guides ship here as one pinned release file. The agent downloads it only after the owner says yes, checks the bundle SHA-256 written in its netwatch-setup skill, then checks every file against the SHA256SUMS inside the bundle (covered by that same hash), and refuses on any mismatch.

## Contents

- `helpers/`: 18 Python 3.8+ scripts, standard library only. 16 run on the owner's scan host (Linux, macOS, or Windows); `vuln_lookup.py` and `wan_probe.py` run on the agent's box.
- `docs/`: 31 guides (vendor connectors such as Omada, pfSense and OPNsense, Synology, Asus, Eero, Firewalla, DNS filters, Home Assistant; local AI CLIs; audits; full references). In the bundle they sit under `docs/` and install to the helper folder's `docs` subfolder. Skills and the agent's hard rules win over a guide on any conflict.
- `build_bundle.py`: reproducible build of the release file (sorted, USTAR, mode 0644, uid and gid 0, fixed mtime, gzip mtime 0, level 9). It refuses unexpected file names and files with non-generic IP literals.
- `SHA256SUMS`: per-file SHA-256 of every bundled file, plus the release file.
- `dist/netwatch-helpers-v1.1.0.tar.gz.b64` (and the older v1.0.0 copy): the exact release file, base64 encoded, so the asset can be recreated byte for byte.

## v1.1.0 (current)

Release file: `netwatch-helpers-v1.1.0.tar.gz`, SHA-256 `3c1ac9a3f90a3a643def5794b52e34614c171dc89b0151029ae9aab97390e6d6`. Helpers are unchanged from v1.0.0; v1.1.0 adds the guides.

Recreate and check it:

```bash
base64 -d dist/netwatch-helpers-v1.1.0.tar.gz.b64 > netwatch-helpers-v1.1.0.tar.gz
sha256sum -c SHA256SUMS --ignore-missing
python3 build_bundle.py --out /tmp/rebuild && cmp /tmp/rebuild/netwatch-helpers-v1.1.0.tar.gz netwatch-helpers-v1.1.0.tar.gz
```

The rebuild matches when the local zlib produces the same deflate stream (zlib 1.3.1 was used); the base64 copy is exact regardless.

## v1.0.0

Helpers only, SHA-256 `5db7c8abc78532bf7a1586829ef2e511c2a86e8ec61874ba040bd6a3a8e73390`.

## Safety

The helpers are read-only by default, scan only ranges the owner lists in scope.txt, never read secrets except from the owner's own env file, and make network changes only through the agent's change-control flow after the owner's explicit yes. The guides follow the same rules.

## License

MIT, see LICENSE.
