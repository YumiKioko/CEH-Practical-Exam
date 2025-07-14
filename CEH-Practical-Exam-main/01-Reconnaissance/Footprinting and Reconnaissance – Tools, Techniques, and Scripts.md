
## 🧭 Phases of Reconnaissance

- **Passive Reconnaissance**: No direct interaction with the target (e.g., Whois, Google dorking).
    
- **Active Reconnaissance**: Direct interaction with the target (e.g., port scanning, service enumeration).
    

---

## ⚙️ Best Tools for Reconnaissance

### ✅ Passive Reconnaissance Tools

|Tool|Purpose|Script Example|
|---|---|---|
|`whois`|Domain registration info|`whois example.com`|
|`nslookup` / `dig`|DNS information|`dig example.com any`|
|`theHarvester`|Emails, subdomains, hosts, etc.|`theHarvester -d example.com -b google`|
|`Shodan`|Public device search|`shodan search apache`|
|`Google Dorks`|Advanced search queries|`site:example.com filetype:pdf`|
|`Maltego`|Graph-based OSINT|GUI-based, Python transforms|
|`Recon-ng`|Modular recon framework|See below for script|

---

### ✅ Active Reconnaissance Tools

|Tool|Purpose|Script Example|
|---|---|---|
|`nmap`|Port scan, service, OS detection|`nmap -sV -O example.com`|
|`Netcat (nc)`|Banner grabbing|`nc -v example.com 80`|
|`WhatWeb`|Web fingerprinting|`whatweb example.com`|
|`Wappalyzer`|Tech stack discovery|`wappalyzer https://example.com`|
|`Nikto`|Web vulnerability scan|`nikto -h http://example.com`|
|`Burp Suite`|Manual testing proxy|GUI tool|
|`httprobe`|Live hosts discovery|`cat subdomains.txt \| httprobe`|
|`Amass`|Subdomain enumeration|`amass enum -d example.com`|

---

## 🧑‍💻 Recon-ng Example Script

```bash
# Install Recon-ng
git clone https://github.com/lanmaster53/recon-ng.git
cd recon-ng
./recon-ng

# Inside recon-ng console
> marketplace install all
> workspaces create example
> add domains example.com
> modules load recon/domains-hosts/bing_domain_web
> run
> show hosts
```

---

## 🧑‍💻 Nmap Recon Script

```bash
nmap -sS -sV -O -A -T4 -p- example.com -oN fullscan.txt
```

Options explained:

- `-sS`: Stealth scan
    
- `-sV`: Version detection
    
- `-O`: OS detection
    
- `-A`: Aggressive scan
    
- `-p-`: Scan all 65535 ports
    
- `-T4`: Faster execution
    
- `-oN`: Output to file
    

---

## 🧑‍💻 theHarvester Script

```bash
theHarvester -d example.com -b all -l 200 -f results.html
```

- `-d`: Domain to search
    
- `-b`: Data sources (e.g., google, bing, linkedin)
    
- `-l`: Limit of results
    
- `-f`: Output file
    

---

## 🧑‍💻 Amass Subdomain Enumeration

```bash
amass enum -passive -d example.com -o subdomains.txt
```

---

## 🧑‍💻 Google Dork Examples

```bash
# Find public PDFs
site:example.com filetype:pdf

# Discover admin panels
intitle:"admin login" site:example.com

# Look for sensitive directories
inurl:wp-content/uploads site:example.com
```

---

## 🧑‍💻 Automated Bash Recon Script

```bash
#!/bin/bash
domain=$1

echo "[+] Running whois..."
whois $domain > whois.txt

echo "[+] Running dig..."
dig any $domain > dns.txt

echo "[+] Subdomain enum with amass..."
amass enum -passive -d $domain -o subdomains.txt

echo "[+] Nmap full scan..."
nmap -sS -sV -O -T4 -p- $domain -oN nmap.txt

echo "[+] Checking web tech with whatweb..."
whatweb $domain > whatweb.txt

echo "[+] Completed recon on $domain"
```

Save the script as `recon.sh` and run it with:

```bash
bash recon.sh example.com
```
