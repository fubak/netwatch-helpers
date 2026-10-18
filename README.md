# netwatch-helpers

Helper scripts for Net Watch, a Grok Bot agent that observes and secures a home network the owner owns. Template copies of the agent carry only skill text, so the helpers ship here as one pinned release file. The agent downloads it only after the owner says yes, checks the bundle SHA-256 and every file's SHA-256 against values written in its netwatch-setup skill, and refuses on any mismatch.

## Contents

- `helpers/`: 18 Python 3.8+ scripts, standard library only. 16 run on the owner's scan host (Linux, macOS, or Windows); `vuln_lookup.py` and `wan_probe.py` run on the agent's box.
- `build_bundle.py`: reproducible build of the release file (flat, sorted, USTAR, mode 0644, uid and gid 0, fixed mtime, gzip mtime 0, level 9). It refuses to bundle files with personal markers or non-generic IP literals.
- `SHA256SUMS`: per-file SHA-256 of every helper, plus the release file.
- `dist/netwatch-helpers-v1.0.0.tar.gz.b64`: the exact v1.0.0 release file, base64 encoded, so the release asset can be recreated byte for byte.

## v1.0.0

Release file: `netwatch-helpers-v1.0.0.tar.gz`, SHA-256 `5db7c8abc78532bf7a1586829ef2e511c2a86e8ec61874ba040bd6a3a8e73390`.

Recreate and check it:

```bash
base64 -d dist/netwatch-helpers-v1.0.0.tar.gz.b64 > netwatch-helpers-v1.0.0.tar.gz
sha256sum -c SHA256SUMS --ignore-missing
python3 build_bundle.py --src helpers --out /tmp/rebuild && cmp /tmp/rebuild/netwatch-helpers-v1.0.0.tar.gz netwatch-helpers-v1.0.0.tar.gz
```

The rebuild matches when the local zlib produces the same deflate stream (zlib 1.3.1 was used); the base64 copy is exact regardless.

## Safety

The helpers are read-only by default, scan only ranges the owner lists in scope.txt, never read secrets except from the owner's own env file, and make network changes only through the agent's change-control flow after the owner's explicit yes.

## License

MIT, see LICENSE.
