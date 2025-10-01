# DNS Enumeration Cheat Sheet

## Overview
DNS enumeration is the process of gathering information about DNS records, subdomains, and related infrastructure of a target domain. This is a critical reconnaissance phase in penetration testing and security assessments.

---

## Basic DNS Queries

### Using `dig`
```bash
# Basic A record lookup
dig example.com

# Specific record types
dig example.com A          # IPv4 address
dig example.com AAAA       # IPv6 address
dig example.com MX         # Mail servers
dig example.com NS         # Name servers
dig example.com TXT        # Text records
dig example.com SOA        # Start of Authority
dig example.com CNAME      # Canonical name
dig example.com PTR        # Pointer record (reverse lookup)

# Short answer format
dig example.com +short

# Query specific DNS server
dig @8.8.8.8 example.com

# Reverse DNS lookup
dig -x 192.168.1.1
```

### Using `nslookup`
```bash
# Basic lookup
nslookup example.com

# Specific record type
nslookup -type=MX example.com
nslookup -type=NS example.com
nslookup -type=TXT example.com

# Query specific DNS server
nslookup example.com 8.8.8.8
```

### Using `host`
```bash
# Basic lookup
host example.com

# Specific record types
host -t MX example.com
host -t NS example.com
host -t TXT example.com

# Verbose output
host -v example.com
```

---

## Zone Transfer (AXFR)

Zone transfers can reveal all DNS records if misconfigured.

```bash
# Using dig
dig axfr @ns1.example.com example.com

# Using host
host -l example.com ns1.example.com

# Using nslookup
nslookup
> server ns1.example.com
> set type=any
> ls -d example.com
```

---

## Subdomain Enumeration

### Brute Force with Tools

#### DNSRecon
```bash
# Standard enumeration
dnsrecon -d example.com

# Zone transfer attempt
dnsrecon -d example.com -a

# Brute force subdomains
dnsrecon -d example.com -D subdomains.txt -t brt

# Google enumeration
dnsrecon -d example.com -g
```

#### Sublist3r
```bash
# Basic enumeration
sublist3r -d example.com

# With brute force
sublist3r -d example.com -b

# Specify threads and output
sublist3r -d example.com -t 100 -o output.txt
```

#### Amass
```bash
# Basic passive enumeration
amass enum -d example.com

# Active enumeration (includes brute force)
amass enum -d example.com -active

# With specific data sources
amass enum -d example.com -src

# Output to file
amass enum -d example.com -o results.txt
```

#### Gobuster DNS Mode
```bash
# Basic DNS brute force
gobuster dns -d example.com -w wordlist.txt

# With custom resolvers
gobuster dns -d example.com -w wordlist.txt -r 8.8.8.8

# Show CNAMEs
gobuster dns -d example.com -w wordlist.txt -c
```

#### FFuF for DNS
```bash
# Subdomain fuzzing
ffuf -w wordlist.txt -u https://FUZZ.example.com -v
```

### Manual Brute Force
```bash
# Simple bash loop with dig
for sub in $(cat subdomains.txt); do
  dig $sub.example.com +short | grep -v "^$" && echo "[+] $sub.example.com"
done
```

---

## DNS Reconnaissance Tools

### Fierce
```bash
# Basic scan
fierce --domain example.com

# With specific wordlist
fierce --domain example.com --subdomain-file wordlist.txt

# Wide scan (multiple IPs)
fierce --domain example.com --wide
```

### DNSEnum
```bash
# Basic enumeration
dnsenum example.com

# With specific options
dnsenum --enum example.com -f subdomains.txt --threads 10
```

### Knock
```bash
# Basic scan
knockpy example.com

# With custom wordlist
knockpy example.com -w wordlist.txt
```

---

## Certificate Transparency Logs

Search CT logs for subdomains:

```bash
# Using crt.sh
curl -s "https://crt.sh/?q=%25.example.com&output=json" | jq -r '.[].name_value' | sort -u

# Using certspotter (tool)
certspotter example.com

# Online resources
# - https://crt.sh
# - https://censys.io
# - https://transparencyreport.google.com/https/certificates
```

---

## Reverse DNS Lookup

### For IP ranges
```bash
# Using dnsrecon
dnsrecon -r 192.168.1.0/24

# Manual with dig
for ip in 192.168.1.{1..254}; do
  dig -x $ip +short
done

# Using host
host -l 1.168.192.in-addr.arpa
```

---

## DNS Cache Snooping

Check if specific domains are cached:

```bash
# Non-recursive query to check cache
dig @dns-server.com example.com +norecurse
```

---

## DNS Fingerprinting

### Identify DNS Server Software
```bash
# Version query (often disabled)
dig version.bind chaos txt @dns-server.com

# Or using nmap
nmap -sU -p 53 --script dns-nsid dns-server.com
```

---

## DNSSEC Validation

```bash
# Check DNSSEC records
dig example.com +dnssec

# Verify DNSSEC chain
delv example.com @8.8.8.8
```

---

## Useful Wordlists

Common subdomain wordlists:
- **SecLists**: `/usr/share/seclists/Discovery/DNS/`
- **fierce**: Built-in wordlist
- **dnscan**: `subdomains-10000.txt`
- **Assetnote**: `best-dns-wordlist.txt`

Popular wordlists:
```
/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
/usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt
```

---

## Nmap DNS Scripts

```bash
# DNS brute force
nmap --script dns-brute example.com

# DNS zone transfer
nmap --script dns-zone-transfer --script-args dns-zone-transfer.domain=example.com -p 53 ns1.example.com

# DNS service discovery
nmap --script dns-service-discovery example.com

# Multiple DNS scripts
nmap --script "dns-*" example.com
```

---

## Online DNS Tools

- **DNSDumpster**: https://dnsdumpster.com
- **SecurityTrails**: https://securitytrails.com
- **VirusTotal**: https://www.virustotal.com
- **Shodan**: https://www.shodan.io
- **Censys**: https://censys.io
- **RapidDNS**: https://rapiddns.io
- **DNS.coffee**: https://dns.coffee
- **MXToolbox**: https://mxtoolbox.com

---

## Common DNS Record Types

| Record | Purpose |
|--------|---------|
| A | IPv4 address |
| AAAA | IPv6 address |
| CNAME | Canonical name (alias) |
| MX | Mail exchange servers |
| NS | Name servers |
| TXT | Text records (SPF, DKIM, verification) |
| SOA | Start of Authority |
| PTR | Pointer (reverse DNS) |
| SRV | Service location |
| CAA | Certificate Authority Authorization |

---

## Automation Scripts

### Quick Bash Script for Multiple Checks
```bash
#!/bin/bash
DOMAIN=$1

echo "[*] Checking DNS records for $DOMAIN"
echo ""

echo "[+] A Records:"
dig $DOMAIN A +short

echo ""
echo "[+] MX Records:"
dig $DOMAIN MX +short

echo ""
echo "[+] NS Records:"
dig $DOMAIN NS +short

echo ""
echo "[+] TXT Records:"
dig $DOMAIN TXT +short

echo ""
echo "[+] Attempting Zone Transfer:"
for ns in $(dig $DOMAIN NS +short); do
  echo "    Trying $ns"
  dig axfr @$ns $DOMAIN
done
```

---

## Best Practices

1. **Always get authorization** before performing DNS enumeration on targets you don't own
2. **Rate limit** your queries to avoid detection and being blocked
3. **Use multiple DNS resolvers** to avoid rate limiting and get complete results
4. **Combine techniques** - passive (CT logs) and active (brute force) for comprehensive results
5. **Document findings** systematically for reporting
6. **Respect scope** - stay within authorized testing boundaries

---

## Detection Avoidance

```bash
# Randomize query timing
sleep $((RANDOM % 5))

# Use different DNS resolvers
resolvers=(8.8.8.8 1.1.1.1 9.9.9.9)

# Rotate user agents and tools
# Spread queries over time
```

---

## Quick Reference Commands

```bash
# Fast subdomain discovery
subfinder -d example.com | httpx -silent

# DNS enumeration pipeline
amass enum -d example.com -passive | dnsx -resp

# Certificate transparency lookup
curl -s "https://crt.sh/?q=%25.example.com&output=json" | jq -r '.[].name_value' | sort -u

# Check all record types
for type in A AAAA CNAME MX NS TXT SOA; do
  echo "[$type]"; dig example.com $type +short
done
```