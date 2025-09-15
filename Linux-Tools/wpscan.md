# WPScan Ultimate Cheat Sheet

## Overview
WPScan is a black box WordPress vulnerability scanner designed to find security issues in WordPress websites.

## Basic Syntax
```bash
wpscan [options] --url <target-url>
```

## Installation & Update
```bash
# Install on Kali Linux
sudo apt install wpscan

# Install on Parrot OS
sudo apt install wpscan

# Update the database (crucial before scanning)
wpscan --update

# Docker version
docker pull wpscanteam/wpscan
docker run -it --rm wpscanteam/wpscan --url https://target.com
```

## Core Scan Types

### Basic Scan
```bash
# Basic vulnerability scan
wpscan --url https://target.com

# Scan with random user agent
wpscan --url https://target.com --random-user-agent

# Scan through proxy
wpscan --url https://target.com --proxy http://127.0.0.1:8080
```

### Enumeration Scans
```bash
# Enumerate users
wpscan --url https://target.com --enumerate u

# Enumerate plugins
wpscan --url https://target.com --enumerate p

# Enumerate themes
wpscan --url https://target.com --enumerate t

# Enumerate timthumbs
wpscan --url https://target.com --enumerate tt

# Enumerate all (comprehensive but noisy)
wpscan --url https://target.com --enumerate u,p,t,tt

# Enumerate vulnerable plugins only
wpscan --url https://target.com --enumerate vp

# Enumerate vulnerable themes only
wpscan --url https://target.com --enumerate vt

# Enumerate usernames from specific range
wpscan --url https://target.com --enumerate u1-100
```

### Aggressive Scans
```bash
# Aggressive plugin enumeration
wpscan --url https://target.com --enumerate ap

# Aggressive theme enumeration
wpscan --url https://target.com --enumerate at

# Full aggressive scan
wpscan --url https://target.com --enumerate u,ap,at,t,tt,vp,vt
```

## Authentication & Brute Force
```bash
# Password attack against specific user
wpscan --url https://target.com --usernames admin --passwords /usr/share/wordlists/rockyou.txt

# Password attack with discovered users
wpscan --url https://target.com --passwords /usr/share/wordlists/rockyou.txt

# Specify username and password lists
wpscan --url https://target.com --usernames users.txt --passwords passwords.txt

# Brute force with XMLRPC
wpscan --url https://target.com --passwords /usr/share/wordlists/rockyou.txt --brute-force

# Threaded brute force attack
wpscan --url https://target.com --usernames admin --passwords /usr/share/wordlists/rockyou.txt --threads 10
```

## Advanced Options

### Output Formats
```bash
# Save results to file
wpscan --url https://target.com -o results.txt
wpscan --url https://target.com -o results.json --format json

# Multiple output formats
wpscan --url https://target.com -o - --format cli-no-color | tee results.txt

# Output formats available: cli-no-color, json, cli
```

### Performance Tuning
```bash
# Set number of threads
wpscan --url https://target.com --threads 20

# Request timeout
wpscan --url https://target.com --request-timeout 15

# Throttle requests
wpscan --url https://target.com --throttle 1000

# Maximum requests per second
wpscan --url https://target.com --max-rate 10
```

### Stealth & Evasion
```bash
# Use random user agents
wpscan --url https://target.com --random-user-agent

# Specific user agent
wpscan --url https://target.com --user-agent "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

# Disable SSL verification
wpscan --url https://target.com --disable-tls-checks

# Use custom headers
wpscan --url https://target.com --headers "X-Forwarded-For: 127.0.0.1"
```

## Vulnerability Detection
```bash
# Check for vulnerabilities only
wpscan --url https://target.com --vulnerable

# Check specific component vulnerabilities
wpscan --url https://target.com --plugins vulnerable --themes vulnerable

# Exclude certain components from scan
wpscan --url https://target.com --exclude-content-based "thank you for creating with wordpress"
```

## API Token Usage
```bash
# Use WPVulnDB API token for enhanced vulnerability data
wpscan --url https://target.com --api-token YOUR_API_TOKEN

# Get your free API token from: https://wpscan.com/api
```

## Practical Examples

### Comprehensive Assessment
```bash
# Full assessment with API token
wpscan --url https://target.com \
  --api-token YOUR_TOKEN \
  --enumerate u,ap,at,t,tt,vp,vt \
  --plugins-version-detection mixed \
  --random-user-agent \
  -o wpscan_results.txt
```

### Quick Reconnaissance
```bash
# Quick scan for basic info
wpscan --url https://target.com --detection-mode mixed

# Check WordPress version only
wpscan --url https://target.com --enumerate v
```

### Targeted Plugin Scan
```bash
# Scan specific plugins
wpscan --url https://target.com --plugins hello-dolly,akismet

# Scan plugins with version detection
wpscan --url https://target.com --plugins all --plugins-version-detection aggressive
```

### User Enumeration Techniques
```bash
# Enumerate users from author pages
wpscan --url https://target.com --enumerate u

# Enumerate users from RSS feed
wpscan --url https://target.com --enumerate u --rss

# Enumerate users with specific range
wpscan --url https://target.com --enumerate u1-50
```

## Integration with Other Tools

### Combine with Nuclei
```bash
# First run WPScan, then Nuclei for specific vulnerabilities
wpscan --url https://target.com --enumerate p -o plugins.txt
cat plugins.txt | grep -oP '(?<=Plugin: )[\w-]+' | nuclei -t /path/to/wordpress-templates/
```

### Use with Custom Wordlists
```bash
# Custom password list for specific target
wpscan --url https://target.com --usernames admin --passwords custom_passwords.txt

# Combine with CeWL for targeted wordlists
cewl https://target.com -w target_words.txt
wpscan --url https://target.com --passwords target_words.txt
```

## Common Detection Methods
```bash
# Passive detection (stealthier)
wpscan --url https://target.com --detection-mode passive

# Aggressive detection
wpscan --url https://target.com --detection-mode aggressive

# Mixed detection (recommended)
wpscan --url https://target.com --detection-mode mixed
```

## Error Handling & Debugging
```bash
# Show errors and debug info
wpscan --url https://target.com --verbose

# Debug mode with maximum output
wpscan --url https://target.com --debug

# Skip common error checks
wpscan --url https://target.com --ignore-main-redirect
```

## Useful Scripts & Automation

### Batch Scanning
```bash
# Scan multiple sites from file
for site in $(cat targets.txt); do
    wpscan --url $site -o scan_${site//\//_}.txt
done
```

### Scheduled Scanning
```bash
# Daily scan with email alerts
wpscan --url https://target.com --api-token YOUR_TOKEN -o /var/log/wpscan_$(date +%Y%m%d).json
```

## Important Directories & Files
```bash
# Default wordlists location
/usr/share/wordlists/
/usr/share/wpscan/wordlists/

# Configuration files
~/.wpscan/
~/.wpscan/db/
```

## Tips & Best Practices

1. **Always update** before scanning: `wpscan --update`
2. **Use API token** for complete vulnerability database
3. **Start with passive** detection to avoid detection
4. **Use random user agents** to avoid fingerprinting
5. **Throttle requests** when scanning production sites
6. **Save results** for later analysis and reporting
7. **Combine with other tools** for comprehensive assessment
8. **Respect robots.txt** and terms of service
9. **Get proper authorization** before scanning
10. **Use proxies** for anonymity when needed

## Common Findings & What to Look For

- **Outdated WordPress core**
- **Vulnerable plugins/themes**
- **User enumeration possibilities**
- **Weak passwords**
- **XMLRPC enabled**
- **Directory listing enabled**
- **Debug information exposed**
