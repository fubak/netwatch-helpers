<!-- Net Watch guide netwatch-vuln-lookup. Read from the verified helper folder; skills and hard rules win on any conflict. -->
When to use: Use to check device firmware or software versions against known vulnerabilities (NVD) and actively exploited ones (CISA KEV), to flag end-of-life devices, or when the owner asks if a device is vulnerable or needs an update.

# Firmware and CVE lookup

## Steps

1. Collect versions from connectors (UniFi device list `version`/`upgradable`, OPNsense/pfSense firmware status, Synology DSM info, Omada device firmware, Pi-hole version, Home Assistant version) or from the owner. Note the exact model.
2. Check actively exploited first (box, no machineId; if the file is missing, run the netwatch-setup helper bootstrap first; a download needs the owner's yes). KEV matches by substring on CISA's spelling of the vendor (for example `TP-Link`, `ASUS`, `Ubiquiti`, `Synology`); try a shorter or alternative spelling before concluding there are no hits:
   ```bash
   python3 /workspace/nw-helpers/vuln_lookup.py kev --vendor "VENDOR" --product "PRODUCT"
   ```
3. Then NVD by keyword (or exact CPE when known):
   ```bash
   python3 /workspace/nw-helpers/vuln_lookup.py nvd --keyword "VENDOR PRODUCT" --exact --limit 20
   ```
   `--exact` matches the phrase (plain keyword search matches the words anywhere and returns unrelated vendors). Results are the newest N. Without an NVD API key keep to 5 calls per 30 seconds. A free NVD key, if the owner wants one, is set by the owner as the box environment secret `NVD_API_KEY`, never written into a skill or chat. `--days N` limits to CVEs published in the last N days (max 120).
4. Decide relevance by reading the affected version ranges on the CVE page (https://nvd.nist.gov/vuln/detail/CVE-ID) and the vendor advisory. Keyword hits are candidates, not proof. Say "possibly affected, verify" when unsure.
5. Check the vendor's current firmware and end-of-life status (vendor release notes or support page via WebSearch/WebFetch). End-of-life devices with KEV entries are top priority to replace or isolate.
6. Rank: KEV and internet-exposed first, then critical/high CVSS on exposed services, then internal-only.

## Output

Per device: model, current version, latest version, KEV hits, notable CVEs (id, score, one line), EOL status, recommendation. Firmware updates go through netwatch-remediation and netwatch-change-control.
