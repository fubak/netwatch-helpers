# Net Watch helpers v1.2.0

Release file: `netwatch-helpers-v1.2.0.tar.gz`
SHA-256: `2a312190a976a763b7021d5e4b8500d429e10a4bcba41d13dabe7de5425e3b80`

Verify after download:

- Linux: `sha256sum netwatch-helpers-v1.2.0.tar.gz`
- macOS: `shasum -a 256 netwatch-helpers-v1.2.0.tar.gz`
- Windows PowerShell: `Get-FileHash -Algorithm SHA256 .\netwatch-helpers-v1.2.0.tar.gz`

The result must match the SHA-256 above and the `BUNDLE_SHA256` line in the netwatch-setup skill of the template you use.

## Highlights

- Clearer consent, with an own-devices-only mode for ISP or landlord routers (no subnet scans).
- Quick look onboarding: one scan, results in about 5 minutes. No-controller track.
- Pass/fail connector tests in every vendor guide; Windows and macOS marked beta with a test checklist.
- `preflight.py --health` and a weekly read-only release check; installs keep a previous copy with `--rollback`.
- Change-controlled "Ignore this signature" and "Always page me" alert feedback.

Full list: CHANGELOG.md. v1.1.0 and v1.0.0 stay published unchanged.
