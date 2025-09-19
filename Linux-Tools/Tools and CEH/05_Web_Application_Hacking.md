# 05 - Web Application Hacking (Web Servers / Web Apps / SQL Injection)

**Purpose:** Enumerate and exploit web servers and applications.

**Tools mapped from your list:**
- `curl` — interact with web servers, send crafted requests, test headers and payloads.  
  Example: `curl -I -s https://target` or `curl -X POST -d "user=1' OR '1'='1" http://target/login`
- `gobuster`, `ffuf`, `wfuzz` — directory & parameter fuzzing (discover hidden endpoints).  
  Example: `ffuf -u https://target/FUZZ -w /usr/share/wordlists/common.txt`
- `nikto` — web server scanner for known misconfigurations and default files.  
  Example: `nikto -h https://target`
- `sqlmap` — automated SQL injection discovery and exploitation.  
  Example: `sqlmap -u "http://target/vuln.php?id=1" --batch --dbs`
- `wpscan` — WordPress enumeration and plugin vulnerability checks.
- `curl` + `netcat` — useful for uploading shells, verifying endpoints, and interacting with web shells

**Added recommended web tools:**
- `Burp Suite` (Proxy + Scanner + Intruder) — essential for CEH web tasks
- `ZAP` (OWASP ZAP) — alternative proxy/scanner
- `ffuf`, `feroxbuster`, `dirb` — directory brute-force alternatives

**Examples & quick tips:**
```bash
# quick header check and follow redirects
curl -I -L https://target
# run nikto
nikto -h http://target -p 80
# run sqlmap
sqlmap -u "http://target/page?id=1" --risk=3 --level=5 --batch
```