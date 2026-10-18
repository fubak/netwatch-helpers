<!-- Net Watch guide netwatch-wifi-audit. Read from the verified helper folder; skills and hard rules win on any conflict. -->
When to use: Use to review Wi-Fi security: SSIDs, encryption (WPA3/WPA2), PMF, WPS, guest and IoT SSIDs, client isolation, password age, and rogue or evil-twin access points seen nearby.

# Wi-Fi audit

## Steps

1. Pull SSID config from the controller (UniFi wlanconf through `nw_http.py` as shown in netwatch-unifi; the helper strips passphrases before printing; or the Integration API WiFi endpoints; Omada SSID list; Asus/Eero/Firewalla via owner screenshots).
2. Check per SSID: security mode (WPA3-Personal or WPA2/WPA3 transitional preferred; flag WPA/TKIP, WEP, open), PMF (optional or required), WPS off, hidden SSID (not a security control), VLAN assignment, client isolation on guest/IoT, band steering irrelevant to security.
3. Password: ask the owner when it was last changed and whether ex-guests, contractors, or old devices still know it. Never ask for the password itself. Recommend a separate IoT SSID with its own passphrase so the main one can be rotated without re-pairing every gadget.
4. Rogue/evil-twin: controllers list neighboring APs (UniFi `stat/rogueap`). Without a controller, a Wi-Fi scan host can list nearby networks and its own link security (read-only):
   ```bash
   nmcli -f SSID,BSSID,SECURITY,SIGNAL dev wifi list
   ```
   (Linux with NetworkManager.) macOS: `system_profiler SPAirPortDataType` (current network security and nearby networks; the old `airport` tool is gone on recent macOS and `wdutil` needs sudo). Windows:
   ```powershell
   netsh wlan show interfaces; netsh wlan show networks mode=bssid
   ```
   Recent Windows and macOS versions may hide SSIDs or BSSIDs unless location access is allowed for the terminal app; if names are blank, say so instead of reporting none. Flag any AP broadcasting the owner's SSID name from an unknown BSSID (compare with the controller's or router's AP list). Neighbors' networks are normal and out of scope: observe only, never connect to, deauthenticate, or interfere with them.
5. Note WPA3 compatibility risk: some older IoT cannot join WPA3-only SSIDs; suggest transitional mode on the IoT SSID.

Changes go through netwatch-change-control. Changing an SSID password disconnects every device on it; say so.
