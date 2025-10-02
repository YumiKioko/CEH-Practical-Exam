# DNS Brute Force with DNSMap — Cheat Sheet

## Table of Contents
- [DNSMap Overview](#dnsmap-overview)
- [Basic Usage](#basic-usage)
- [Advanced Options](#advanced-options)
- [Wordlist Management](#wordlist-management)
- [Output Formats](#output-formats)
- [Practical Examples](#practical-examples)
- [Alternative Tools](#alternative-tools)
- [Important Notes](#important-notes)

---

## DNSMap Overview

DNSMap is a tool for DNS subdomain brute-forcing that helps discover hidden subdomains of a target domain.

### Installation

```bash
# Kali Linux (often pre-installed)
apt update && apt install dnsmap

# Ubuntu/Debian
sudo apt install dnsmap

# From source
git clone https://github.com/makefu/dnsmap.git
cd dnsmap
./configure
make
sudo make install
```

---

## Basic Usage

### Simple Scan

```bash
# Basic subdomain discovery (uses built-in wordlist)
dnsmap example.com

# Use a specific built-in wordlist
dnsmap example.com -w /usr/share/dnsmap/wordlist_TLAs.txt
```

### Specify a Custom Wordlist

```bash
# Custom wordlist
dnsmap example.com -w /path/to/wordlist.txt

# Common locations
dnsmap example.com -w /usr/share/dnsmap/wordlist_TLAs.txt
dnsmap example.com -w /usr/share/wordlists/dnsmap.txt
```

---

## Advanced Options

### Output Results

```bash
# Save results to file
dnsmap example.com -r /tmp/dnsmap_results.txt

# Verbose mode
dnsmap example.com -v

# Combined
dnsmap example.com -w custom_wordlist.txt -r results.txt -v
```

### Delay and Performance

```bash
# Add delay between requests (milliseconds)
dnsmap example.com -d 3000

# Use specific DNS server (resolver)
dnsmap example.com -s 8.8.8.8

# Combine delay and custom DNS
dnsmap example.com -d 2000 -s 1.1.1.1
```

### Comprehensive Scan Example

```bash
dnsmap target-domain.com -w /usr/share/dnsmap/wordlist_TLAs.txt \
  -r /root/scan_results.txt -d 1000 -v
```

---

## Wordlist Management

### Built-in Wordlists

```bash
# List available dnsmap wordlists
ls /usr/share/dnsmap/
```

Common built-in files:
- `/usr/share/dnsmap/wordlist_TLAs.txt`
- `/usr/share/dnsmap/wordlist_extra.txt`

### Create Custom Wordlists

```bash
# Simple wordlist creation
echo -e "www\nftp\nmail\nadmin\ntest\ndev\napi" > custom_wordlist.txt

# Generate sequential subdomains
for i in {1..100}; do echo "server$i"; done > sequential_wordlist.txt
```

Example `common_subdomains.txt`:

```
www
ftp
mail
admin
test
dev
staging
api
blog
shop
secure
portal
cpanel
webmail
```

### Popular Wordlist Sources

```bash
# SecLists
git clone https://github.com/danielmiessler/SecLists.git
dnsmap example.com -w /path/to/SecLists/Discovery/DNS/subdomains-top1million-5000.txt

# Local repo example
dnsmap example.com -w /usr/share/wordlists/dnsmap.txt
```

---

## Output Formats

### Typical dnsmap Output (example)

```
dnsmap version 0.30 [IP address 127.0.1.1]

[+] searching (sub)domains for example.com using wordlist file: built-in wordlist ...
[+] using maximum random delay of 10 millisecond(s) between requests

address: 93.184.216.34    hostname: www.example.com
address: 93.184.216.34    hostname: example.com
address: 203.0.113.100    hostname: api.example.com
address: 198.51.100.42    hostname: admin.example.com

[+] 4 (sub)domains and 3 IP address(es) found
[+] completion time: 12 second(s)
[+] results written to: dnsmap_example.com_hl2.txt
```

### Parsing Results

```bash
# Extract only subdomains
grep "hostname:" results.txt | awk '{print $3}'

# Extract IP addresses
grep "address:" results.txt | awk '{print $2}' | sort -u

# Create a clean subdomain list
grep "hostname:" results.txt | cut -d' ' -f3 > subdomains.txt
```

---

## Practical Examples

### Basic Corporate Scan

```bash
dnsmap target-company.com -w /usr/share/dnsmap/wordlist_TLAs.txt -r scan_results.txt
```

### Stealthy Scan (slow)

```bash
# Slow scan with delay to avoid detection
dnsmap example.com -d 5000 -w custom_small_wordlist.txt
```

### Multiple Domains Script

```bash
#!/bin/bash
DOMAINS=("example.com" "test.org" "demo.net")

for domain in "${DOMAINS[@]}"; do
    echo "Scanning: $domain"
    dnsmap $domain -w /usr/share/dnsmap/wordlist_TLAs.txt -r "dnsmap_${domain}_results.txt"
    echo "Results saved to: dnsmap_${domain}_results.txt"
    echo "----------------------------------------"
done
```

### Integration with Other Tools

```bash
# Use dnsmap output for further scanning with nmap
dnsmap example.com -r subdomains.txt
grep "hostname:" subdomains.txt | awk '{print $3}' | while read subdomain; do
    echo "Scanning $subdomain"
    nmap -sS -p 80,443,22,21 $subdomain
done
```

---

## Alternative Tools

- **DNSRecon**
  ```bash
  dnsrecon -d example.com -D /usr/share/wordlists/dnsmap.txt -t brt
  dnsrecon -d example.com -t std,axfr,brt
  ```

- **Sublist3r**
  ```bash
  sublist3r -d example.com
  sublist3r -d example.com -e google,bing,yahoo
  ```

- **MassDNS**
  ```bash
  massdns -r /path/to/resolvers.txt -t A -o S -w massdns_results.txt subdomains.txt
  ```

- **Amass**
  ```bash
  amass enum -d example.com -brute -w /usr/share/wordlists/dnsmap.txt
  amass enum -d example.com -passive
  ```

- **Fierce**
  ```bash
  fierce --domain example.com --wordlist /usr/share/wordlists/dnsmap.txt
  ```

---

## Important Notes

### Legal & Ethical
- **Authorization:** Always obtain explicit permission before scanning domains you don't own.
- **Rate Limiting:** Respect DNS rate limits and avoid disrupting services.
- **Public Domains:** Only scan domains you are authorized to test.
- **Detection:** DNS brute force is often logged and detectable.

### Performance Tips
```bash
# Use delays to avoid rate limiting
dnsmap example.com -d 2000

# Start with small wordlists
dnsmap example.com -w small_wordlist.txt

# Use reliable DNS resolvers
dnsmap example.com -s 8.8.8.8
```

### Common Issues & Fixes
```bash
# Command not found
sudo apt update && sudo apt install dnsmap

# Wordlist not found — use full path
dnsmap example.com -w /usr/share/dnsmap/wordlist_TLAs.txt

# For large targets, start with a small wordlist
dnsmap large-domain.com -w top_100_subdomains.txt
```

### Useful One-liners
```bash
# Quick subdomain check
echo "www ftp mail admin api" | tr ' ' '\n' | while read sub; do host $sub.example.com; done

# dnsmap with resolver and delay
dnsmap target.com -s 8.8.8.8 -d 3000 -w custom_list.txt -r results.txt

# Multiple TLDs
for tld in com net org io; do dnsmap example.$tld -w top_100.txt -r ${tld}_results.txt; done
```

---

## Post-Processing Results

```bash
# Extract clean subdomain list
grep "hostname:" dnsmap_results.txt | awk '{print $3}' | sort -u > subdomains_clean.txt

# Check for live hosts
cat subdomains_clean.txt | while read sub; do ping -c 1 $sub && echo "$sub is live"; done

# Port scan discovered subdomains
cat subdomains_clean.txt | while read sub; do nmap -p 80,443,22 $sub; done
```

---

### Final notes I noticed (summary)
- Emphasize legal compliance (only test with permission).
- Use delays (-d) to reduce detection and rate-limit issues.
- Start with smaller wordlists to limit noise.
- Changing DNS resolvers can give different results.
- Always validate discovered hosts (DNS entries can be stale).
