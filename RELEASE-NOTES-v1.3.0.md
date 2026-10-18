# Net Watch helpers v1.3.0

Release file: `netwatch-helpers-v1.3.0.tar.gz`
SHA-256: `edf13a4dff2d63dd68b9576174851ce6b2b172f4f1aa4e0b4c844e0493d152e0`

Verify after download:

- Linux: `sha256sum netwatch-helpers-v1.3.0.tar.gz`
- macOS: `shasum -a 256 netwatch-helpers-v1.3.0.tar.gz`
- Windows PowerShell: `Get-FileHash -Algorithm SHA256 .\netwatch-helpers-v1.3.0.tar.gz`

The result must match the SHA-256 above and the `BUNDLE_SHA256` line in the netwatch-setup skill of the template you use.

## Highlights

- Setup detects more and asks less: scan host fitness, VPN, company-managed computers, battery and sleep, admin rights, host firewall, IPv6, CGNAT or double NAT, and the router brand. Anything it could not check says `not checked`.
- The only connected desktop is picked without a question only when every safety check ran and passed (anything not checked means you are asked); the download question appears only when the helpers are missing.
- A 24 hour provisional baseline so devices that were asleep during the first scan are not reported as new.
- The live alert routine is created only after the first real alert reaches the relay; `alertd.py token copy` avoids retyping the token.
- WAN probes based on UPnP require a fresh record from the default gateway.

Full list: CHANGELOG.md. v1.2.0, v1.1.0, and v1.0.0 stay published unchanged.
