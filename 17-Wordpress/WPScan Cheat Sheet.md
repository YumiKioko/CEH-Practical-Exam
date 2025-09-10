# WPScan Cheat Sheet

**Disclaimer:** Only use on WordPress sites you own or have explicit, written permission to test.

## Installation & Update

```bash
# Install on Kali
sudo apt install wpscan

# Update the vulnerability database
wpscan --update

# Install via Ruby Gem
gem install wpscan

```markdown
# WPScan Cheat Sheet

**Disclaimer:** Only use on WordPress sites you own or have explicit, written permission to test.

## Installation & Update

```bash
# Install on Kali
sudo apt install wpscan

# Update the vulnerability database
wpscan --update

# Install via Ruby Gem
gem install wpscan
```

## Basic Syntax

```bash
wpscan --url <target-url> [options]
```

---

## 1. Reconnaissance & Enumeration

### Basic Scan (Passive)
```bash
wpscan --url https://target.com
```

### Enumerate Everything (Aggressive)
```bash
wpscan --url https://target.com --enumerate u,p,t,tt,cb,dbe
# u = Users, p = Plugins, t = Themes
# tt = Timthumbs, cb = Config Backups, dbe = DB Exports
```

### Enumerate Specific Components
```bash
# Enumerate Users only
wpscan --url https://target.com --enumerate u

# Enumerate Plugins only (can be noisy)
wpscan --url https://target.com --enumerate p

# Enumerate Themes only
wpscan --url https://target.com --enumerate t

# Enumerate vulnerable Plugins only
wpscan --url https://target.com --enumerate vp

# Enumerate vulnerable Themes only
wpscan --url https://target.com --enumerate vt
```

### Advanced Enumeration
```bash
# Enumerate usernames from 1 to 10
wpscan --url https://target.com --enumerate u1-10

# Enumerate with API token for full vuln data (register at wpscan.com)
wpscan --url https://target.com --enumerate u,p,t --api-token YOUR_TOKEN_HERE

# Force enumerate even if detection is blocked
wpscan --url https://target.com --enumerate u --force
```

---

## 2. Vulnerability Scanning

### Check for Vulnerabilities (Requires API Token)
```bash
# Check everything for vulnerabilities
wpscan --url https://target.com --api-token YOUR_TOKEN_HERE

# Check only plugins for vulnerabilities
wpscan --url https://target.com --plugins-detection mixed --api-token YOUR_TOKEN_HERE

# Check a specific plugin
wpscan --url https://target.com --plugin hello-dolly --api-token YOUR_TOKEN_HERE
```

### Plugin & Theme Detection Modes
```bash
# Passive detection (stealthier)
wpscan --url https://target.com --plugins-detection passive

# Aggressive detection (more thorough)
wpscan --url https://target.com --plugins-detection aggressive

# Mixed mode (default)
wpscan --url https://target.com --plugins-detection mixed
```

---

## 3. Password Attacks

### Basic Password Attack
```bash
# Attack a specific user with a wordlist
wpscan --url https://target.com --usernames admin --passwords /usr/share/wordlists/rockyou.txt

# Attack multiple users
wpscan --url https://target.com --usernames admin,editor,author --passwords /usr/share/wordlists/rockyou.txt

# Attack users found during enumeration
wpscan --url https://target.com --passwords /usr/share/wordlists/rockyou.txt
```

### Advanced Brute-Force Options
```bash
# Specify login URI (if not wp-login.php)
wpscan --url https://target.com --wp-content-dir custom-wp-content --usernames admin --passwords rockyou.txt

# Set throttle/delay between requests (milliseconds)
wpscan --url https://target.com --usernames admin --passwords rockyou.txt --throttle 1000

# Max password attempts per user
wpscan --url https://target.com --usernames admin --passwords rockyou.txt --max-threads 10

# Use XML-RPC for multicall attack (more efficient)
wpscan --url https://target.com --usernames admin --passwords rockyou.txt --password-attack xmlrpc
```

---

## 4. Advanced Options

### Stealth & Evasion
```bash
# Random user agent
wpscan --url https://target.com --random-user-agent

# Specify custom user agent
wpscan --url https://target.com --user-agent "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

# Use proxy
wpscan --url https://target.com --proxy http://127.0.0.1:8080
wpscan --url https://target.com --proxy http://user:pass@127.0.0.1:8080

# Disable TLS verification
wpscan --url https://target.com --disable-tls-checks
```

### Output & Reporting
```bash
# Output to file (formatted)
wpscan --url https://target.com --output wpscan_results.txt

# Output to file (JSON)
wpscan --url https://target.com --format json --output wpscan_results.json

# Output to file (cli format for later use)
wpscan --url https://target.com --format cli-no-colour --output wpscan_results.txt
```

### Miscellaneous
```bash
# Scan from a file (for multiple targets)
wpscan --url-list targets.txt

# Specify custom WordPress content directory
wpscan --url https://target.com --wp-content-dir custom-content

# Ignore SSL certificate verification
wpscan --url https://target.com --disable-tls-checks
```

---

## 5. Useful Combinations & Examples

### Comprehensive Scan
```bash
wpscan --url https://target.com --enumerate u,p,t,vp,vt,tt,cb,dbe --api-token YOUR_TOKEN --plugins-detection aggressive --output scan_results.txt
```

### Stealthy User Enumeration
```bash
wpscan --url https://target.com --enumerate u --random-user-agent --throttle 2000
```

### Targeted Plugin Vulnerability Check
```bash
wpscan --url https://target.com --plugin woocommerce,elementor --api-token YOUR_TOKEN
```

### Efficient Password Spraying
```bash
wpscan --url https://target.com --usernames admin,administrator --passwords /top-passwords.txt --password-attack xmlrpc --throttle 500
```

---

## 6. Common Wordlists Location (Kali Linux)

```bash
# RockYou (most common)
/usr/share/wordlists/rockyou.txt

# SecLists collection
/usr/share/wordlists/SecLists/Passwords/Common-Credentials/
/usr/share/wordlists/SecLists/Passwords/Leaked-Databases/

# Dirbuster wordlists (for content discovery)
/usr/share/wordlists/dirbuster/
```

---

## Important Notes

1.  **API Token:** Get a free API token from [https://wpscan.com/](https://wpscan.com/) for full vulnerability data.
2.  **Noise Level:** Aggressive scans (`--enumerate p`, `--plugins-detection aggressive`) are very noisy and will likely trigger alarms.
3.  **Legal Use:** Always have proper authorization before scanning.
4.  **Rate Limiting:** Use `--throttle` to avoid overwhelming the target server or getting blocked.

**Example Legal Command:**
```bash
wpscan --url https://my-own-site.com --enumerate u,p,t --api-token YOUR_TOKEN --output scan_report.txt
```