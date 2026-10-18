# Net Watch helpers v1.3.1

Release file: `netwatch-helpers-v1.3.1.tar.gz`
SHA-256: `af27bc332de56c8a9704964575bc0a4a5b88f57480520a7d399a90e7713f31f1`

Verify after download:

- Linux: `sha256sum netwatch-helpers-v1.3.1.tar.gz`
- macOS: `shasum -a 256 netwatch-helpers-v1.3.1.tar.gz`
- Windows PowerShell: `Get-FileHash -Algorithm SHA256 .\netwatch-helpers-v1.3.1.tar.gz`

The result must match the SHA-256 above and the `BUNDLE_SHA256` line in the netwatch-setup skill of the template you use.

## Highlights

- ISP or landlord routers stay untouched: in own-devices-only scope the WAN probe refuses and setup no longer opens the router's login page.
- Routines record each run, and `preflight.py --health` names any that are overdue. Daily, weekly, monthly, and quarterly checks are offered together on one card at the end of setup.
- The daily report counts changes made by your trusted admin account, so a stolen session cannot hide behind the "this was me" list.
- A new guide says, per router brand, what Net Watch can detect, propose, do with your yes, and what only you can do.
- Setup starts with a Quick look, offers full setup once, and gives you the command to run yourself if you decline an approval.

Full list: CHANGELOG.md. v1.3.0, v1.2.0, v1.1.0, and v1.0.0 stay published unchanged.
