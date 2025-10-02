# DNS Brute Force with DNSMap Cheat Sheet

## Table of Contents
- [DNSMap Overview](#dnsmap-overview)
- [Basic Usage](#basic-usage)
- [Advanced Options](#advanced-options)
- [Wordlist Management](#wordlist-management)
- [Output Formats](#output-formats)
- [Practical Examples](#practical-examples)
- [Alternative Tools](#alternative-tools)
- [Important Notes](#important-notes)

## DNSMap Overview

DNSMap is a tool for DNS subdomain brute-forcing that helps discover hidden subdomains of a target domain.

### Installation

```bash
# Kali Linux (pre-installed)
apt update && apt install dnsmap

# Ubuntu/Debian
sudo apt install dnsmap

# From source
git clone https://github.com/makefu/dnsmap.git
cd dnsmap
./configure
make
sudo make install
Basic Usage
Simple Scan
bash
# Basic subdomain discovery
dnsmap example.com

# Using built-in wordlist
dnsmap example.com -w /usr/share/dnsmap/wordlist_TLAs.txt
Specify Wordlist
bash
# Custom wordlist
dnsmap example.com -w /path/to/wordlist.txt

# Common wordlist locations
dnsmap example.com -w /usr/share/dnsmap/wordlist_TLAs.txt
dnsmap example.com -w /usr/share/wordlists/dnsmap.txt
Advanced Options
Output Results
bash
# Save results to file
dnsmap example.com -r /tmp/dnsmap_results.txt

# Run in verbose mode
dnsmap example.com -v

# Combine options
dnsmap example.com -w custom_wordlist.txt -r results.txt -v
Delay and Performance
bash
# Add delay between requests (milliseconds)
dnsmap example.com -d 3000

# Use specific DNS server
dnsmap example.com -s 8.8.8.8

# Combine delay and custom DNS
dnsmap example.com -d 2000 -s 1.1.1.1
Comprehensive Scan
bash
# Full featured scan
dnsmap target-domain.com -w /usr/share/dnsmap/wordlist_TLAs.txt -r /root/scan_results.txt -d 1000 -v
Wordlist Management
Built-in Wordlists
bash
# Check available wordlists
ls /usr/share/dnsmap/

# Common built-in wordlists
/usr/share/dnsmap/wordlist_TLAs.txt
/usr/share/dnsmap/wordlist_extra.txt
Create Custom Wordlists
bash
# Simple wordlist creation
echo -e "www\nftp\nmail\nadmin\ntest\ndev\napi" > custom_wordlist.txt

# Generate sequential subdomains
for i in {1..100}; do echo "server$i"; done > sequential_wordlist.txt

# Common subdomains wordlist
cat > common_subdomains.txt << EOF
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
EOF
Popular Wordlist Sources
bash
# SecLists collection
git clone https://github.com/danielmiessler/SecLists.git
dnsmap example.com -w /path/to/SecLists/Discovery/DNS/subdomains-top1million-5000.txt

# DNS recon wordlist
dnsmap example.com -w /usr/share/wordlists/dnsmap.txt
Output Formats
Basic Output
text
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
Parse Results
bash
# Extract only subdomains
cat results.txt | grep "hostname:" | awk '{print $3}'

# Extract IP addresses
cat results.txt | grep "address:" | awk '{print $2}' | sort -u

# Create a clean subdomain list
dnsmap example.com -r results.txt
grep "hostname:" results.txt | cut -d' ' -f3 > subdomains.txt
Practical Examples
Basic Corporate Scan
bash
dnsmap target-company.com -w /usr/share/dnsmap/wordlist_TLAs.txt -r scan_results.txt
Stealthy Scan
bash
# Slow scan with delay to avoid detection
dnsmap example.com -d 5000 -w custom_small_wordlist.txt
Multiple Domains Script
bash
#!/bin/bash
DOMAINS=("example.com" "test.org" "demo.net")

for domain in "${DOMAINS[@]}"; do
    echo "Scanning: $domain"
    dnsmap $domain -w /usr/share/dnsmap/wordlist_TLAs.txt -r "dnsmap_${domain}_results.txt"
    echo "Results saved to: dnsmap_${domain}_results.txt"
    echo "----------------------------------------"
done
Integration with Other Tools
bash
# Use dnsmap output for further scanning
dnsmap example.com -r subdomains.txt
cat subdomains.txt | grep "hostname:" | awk '{print $3}' | while read subdomain; do
    echo "Scanning $subdomain"
    nmap -sS -p 80,443,22,21 $subdomain
done
Alternative Tools
DNSRecon
bash
# Standard subdomain brute force
dnsrecon -d example.com -D /usr/share/wordlists/dnsmap.txt -t brt

# Comprehensive DNS enumeration
dnsrecon -d example.com -t std,axfr,brt
Sublist3r
bash
# Passive subdomain enumeration
sublist3r -d example.com

# With specific engines
sublist3r -d example.com -e google,bing,yahoo
MassDNS
bash
# High-speed DNS brute force
massdns -r /path/to/resolvers.txt -t A -o S -w massdns_results.txt subdomains.txt
Amass
bash
# Comprehensive attack
amass enum -d example.com -brute -w /usr/share/wordlists/dnsmap.txt

# Passive mode only
amass enum -d example.com -passive
Fierce
bash
# DNS reconnaissance
fierce --domain example.com --wordlist /usr/share/wordlists/dnsmap.txt
Important Notes
Legal and Ethical Considerations
Authorization: Always obtain proper authorization before scanning

Rate Limiting: Respect DNS rate limits to avoid disrupting services

Public Domains: Only scan domains you own or have permission to test

Detection: DNS brute force activities are often logged and detectable

Performance Tips
bash
# Use delays to avoid rate limiting
dnsmap example.com -d 2000

# Start with small wordlists
dnsmap example.com -w small_wordlist.txt

# Use reliable DNS resolvers
dnsmap example.com -s 8.8.8.8
Common Issues and Solutions
bash
# If you get "command not found"
sudo apt update && sudo apt install dnsmap

# If wordlist not found, specify full path
dnsmap example.com -w /usr/share/dnsmap/wordlist_TLAs.txt

# For large domains, use smaller wordlists first
dnsmap large-domain.com -w top_100_subdomains.txt
Useful One-Liners
bash
# Quick subdomain check
echo "www ftp mail admin api" | tr ' ' '\n' | while read sub; do host $sub.example.com; done

# DNSMap with custom resolver and delay
dnsmap target.com -s 8.8.8.8 -d 3000 -w custom_list.txt -r results.txt

# Multiple TLDs check
for tld in com net org io; do dnsmap example.$tld -w top_100.txt -r ${tld}_results.txt; done
Post-Processing Results
bash
# Extract clean subdomain list
grep "hostname:" dnsmap_results.txt | awk '{print $3}' | sort -u > subdomains_clean.txt

# Check for live hosts
cat subdomains_clean.txt | while read sub; do ping -c 1 $sub && echo "$sub is live"; done

# Port scan discovered subdomains
cat subdomains_clean.txt | while read sub; do nmap -p 80,443,22 $sub; done
Important Considerations I Noticed:

Legal Compliance: Emphasize that this should only be used on domains you own or have explicit permission to test

Stealth Operations: The delay option (-d) is crucial for avoiding detection in monitored environments

Wordlist Selection: Start with smaller wordlists to avoid unnecessary noise

DNS Server Choice: Using different DNS resolvers can yield different results

Result Validation: Always verify discovered subdomains as DNS records can contain outdated information