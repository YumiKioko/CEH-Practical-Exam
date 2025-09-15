# cURL Complete Walkthrough for Linux

> A comprehensive guide to mastering cURL on Linux systems

## Table of Contents

- [Introduction](#introduction)
- [Installation](#installation)
- [Basic Usage](#basic-usage)
- [HTTP Methods](#http-methods)
- [Headers & Authentication](#headers--authentication)
- [Data Handling](#data-handling)
- [Advanced Features](#advanced-features)
- [Troubleshooting](#troubleshooting)

---

## Introduction

**cURL** (Client URL) is a command-line tool for transferring data to/from servers using URL syntax. It's an essential tool for Linux system administrators, developers, and DevOps professionals.

### Key Features

- **Multi-protocol support**: HTTP/HTTPS, FTP, SFTP, SCP, LDAP
- **Native Linux integration**: Works seamlessly with shell scripts and Unix tools
- **Scriptable and automation-friendly**: Perfect for CI/CD pipelines
- **SSL/TLS support**: Built-in encryption and certificate handling
- **Proxy support**: Enterprise-ready with corporate proxy integration

### Why cURL on Linux?

cURL integrates perfectly with the Linux ecosystem, allowing you to pipe outputs, combine with other tools, and create powerful automation scripts.

---

## Installation

### Ubuntu/Debian

```bash
sudo apt update
sudo apt install curl
```

### CentOS/RHEL 7/8

```bash
sudo yum install curl
```

### RHEL 9/Fedora

```bash
sudo dnf install curl
```

### Arch Linux

```bash
sudo pacman -S curl
```

### Alpine Linux

```bash
apk add curl
```

### openSUSE

```bash
sudo zypper install curl
```

### Verify Installation

```bash
curl --version
which curl
```

Expected output:
```
curl 7.81.0 (x86_64-pc-linux-gnu) libcurl/7.81.0
Release-Date: 2022-01-05
Protocols: dict file ftp ftps gopher gophers http https imap imaps ldap ldaps mqtt pop3 pop3s rtsp smb smbs smtp smtps telnet tftp 
Features: alt-svc AsynchDNS brotli GSS-API H2 HSTS HTTP2 HTTPS-proxy IDN IPv6 Kerberos Largefile libz NTLM NTLM_WB PSL SPNEGO SSL TLS-SRP UnixSockets zstd
```

---

## Basic Usage

### Syntax

```bash
curl [options] [URL]
```

### Simple GET Request

```bash
# Basic request
curl https://httpbin.org/get

# With user agent
curl -A "Mozilla/5.0" https://httpbin.org/get
```

### Save Output to File

```bash
# Specify output filename
curl -o response.json https://api.github.com/users/torvalds

# Use remote filename
curl -O https://example.com/file.tar.gz

# Multiple files
curl -O https://example.com/file1.txt -O https://example.com/file2.txt
```

### Follow Redirects

```bash
# Follow all redirects
curl -L https://git.io/shortened-url

# Limit redirects
curl -L --max-redirs 5 https://example.com
```

### Show Headers

```bash
# Include headers in output
curl -i https://httpbin.org/get

# Headers only
curl -I https://httpbin.org/get

# Verbose output (shows full conversation)
curl -v https://httpbin.org/get
```

### Silent Mode

```bash
# Hide progress bar
curl -s https://httpbin.org/get

# Show only errors
curl -sS https://httpbin.org/get

# Completely silent
curl -s -o /dev/null https://httpbin.org/get
```

### Progress Options

```bash
# Progress bar instead of meter
curl -# https://example.com/largefile.zip

# No progress at all
curl -s https://httpbin.org/get
```

**Shell Integration Tip**: Use `curl -s url | jq` to pipe JSON responses directly to jq for formatting.

---

## HTTP Methods

### GET (Default)

```bash
# Implicit GET
curl https://httpbin.org/get

# Explicit GET
curl -X GET https://httpbin.org/get

# GET with query parameters
curl "https://httpbin.org/get?param1=value1&param2=value2"

# GET with URL-encoded parameters
curl -G -d "param1=value1" -d "param2=value2" https://httpbin.org/get
```

### POST Requests

#### POST with JSON

```bash
# Inline JSON
curl -X POST \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"secret"}' \
  https://httpbin.org/post

# JSON from variable
JSON_DATA='{"name":"John","email":"john@example.com"}'
curl -X POST \
  -H "Content-Type: application/json" \
  -d "$JSON_DATA" \
  https://httpbin.org/post
```

#### POST with Form Data

```bash
# URL-encoded form data
curl -X POST \
  -d "username=admin" \
  -d "password=secret" \
  https://httpbin.org/post

# Form data with special characters
curl -X POST \
  --data-urlencode "message=Hello World & Special Characters!" \
  https://httpbin.org/post
```

#### POST from File

```bash
# From JSON file
curl -X POST \
  -H "Content-Type: application/json" \
  -d @payload.json \
  https://httpbin.org/post

# From text file
curl -X POST \
  -H "Content-Type: text/markdownplain" \
  -d @message.txt \
  https://httpbin.org/post
```

### PUT Request

```bash
curl -X PUT \
  -H "Content-Type: application/json" \
  -d '{"status":"updated","timestamp":"'$(date -Iseconds)'"}' \
  https://httpbin.org/put
```

### PATCH Request

```bash
curl -X PATCH \
  -H "Content-Type: application/json" \
  -d '{"field":"new_value"}' \
  https://httpbin.org/patch
```

### DELETE Request

```bash
# Simple delete
curl -X DELETE https://httpbin.org/delete

# Delete with confirmation
curl -X DELETE \
  -H "Content-Type: application/json" \
  -d '{"confirm":true}' \
  https://httpbin.org/delete
```

### HEAD Request

```bash
# Get only headers
curl -X HEAD https://httpbin.org/get

# Same as -I flag
curl -I https://httpbin.org/get
```

---

## Headers & Authentication

### Custom Headers

```bash
# Single header
curl -H "Accept: application/json" https://httpbin.org/get

# Multiple headers
curl -H "Accept: application/json" \
     -H "User-Agent: Linux-Script/1.0" \
     -H "X-Request-ID: $(uuidgen)" \
     https://httpbin.org/get

# Remove default headers
curl -H "User-Agent:" https://httpbin.org/get
```

### Bearer Token Authentication

```bash
# Using environment variable (recommended)
export TOKEN="your_token_here"
curl -H "Authorization: Bearer $TOKEN" \
  https://api.github.com/user

# Direct token (not recommended for production)
curl -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  https://api.example.com/protected
```

### Basic Authentication

```bash
# Interactive password prompt
curl -u username https://httpbin.org/basic-auth/username/password

# With password (visible in history)
curl -u username:password https://httpbin.org/basic-auth/username/password

# From environment variables (recommended)
export AUTH_USER="admin"
export AUTH_PASS="secret"
curl -u "$AUTH_USER:$AUTH_PASS" https://httpbin.org/basic-auth/admin/secret

# Using .netrc file (most secure)
# Create ~/.netrc with: machine api.example.com login username password secret
curl -n https://api.example.com/protected
```

### API Key Authentication

```bash
# Header-based API key
export API_KEY="your-api-key-here"
curl -H "X-API-Key: $API_KEY" https://api.example.com/data

# Query parameter API key
curl "https://api.example.com/data?api_key=$API_KEY"

# Custom header name
curl -H "X-RapidAPI-Key: $API_KEY" https://rapidapi.example.com/endpoint
```

### Cookie Management

```bash
# Save cookies to file
curl -c cookies.txt https://httpbin.org/cookies/set/session/abc123

# Use cookies from file
curl -b cookies.txt https://httpbin.org/cookies

# One-liner cookie session
curl -c /tmp/cookies -b /tmp/cookies https://example.com/login

# Set cookies manually
curl -b "session=abc123; user=john" https://httpbin.org/cookies
```

### Advanced Authentication

```bash
# Digest authentication
curl --digest -u username:password https://httpbin.org/digest-auth/auth/username/password

# NTLM authentication
curl --ntlm -u domain\\username:password https://ntlm.example.com

# Negotiate/SPNEGO authentication
curl --negotiate -u : https://kerberos.example.com
```

**Security Best Practice**: Always use environment variables or configuration files for credentials. Never hardcode them in scripts.

---

## Data Handling

### File Upload

```bash
# Simple file upload (multipart form)
curl -F "file=@/path/to/document.pdf" \
  https://httpbin.org/post

# File upload with additional fields
curl -F "file=@/path/to/image.jpg" \
  -F "description=Profile picture" \
  -F "category=avatar" \
  https://httpbin.org/post

# Multiple files
curl -F "file1=@/path/to/doc1.pdf" \
  -F "file2=@/path/to/doc2.pdf" \
  https://httpbin.org/post

# Binary file upload (raw)
curl -T /path/to/backup.tar.gz \
  ftp://backup.example.com/

# Upload with custom content type
curl -F "data=@data.xml;type=application/xml" \
  https://httpbin.org/post
```

### Download Files

```bash
# Download with progress bar
curl -# -O https://releases.ubuntu.com/22.04/ubuntu-22.04-desktop-amd64.iso

# Resume interrupted download
curl -C - -O https://example.com/largefile.tar.gz

# Download to specific directory
curl -o /tmp/downloaded_file.zip https://example.com/file.zip

# Download multiple files with pattern
curl -O "https://example.com/file[001-010].txt"

# Download with bandwidth limiting
curl --limit-rate 500k -O https://example.com/largefile.zip
```

### Batch Operations

```bash
# Download files from list
while IFS= read -r url; do
    curl -O "$url"
    sleep 1  # Rate limiting
done < urls.txt

# Multiple URLs with brace expansion
curl -O "https://api.example.com/data/{users,posts,comments}.json"

# Sequential numbering
curl -O "https://example.com/image[001-100:2].jpg"  # Every 2nd image

# Parallel downloads (using xargs)
cat urls.txt | xargs -n 1 -P 4 curl -O  # 4 parallel downloads
```

### Data Processing with Pipes

```bash
# Direct JSON processing
curl -s https://api.github.com/users/torvalds | jq '.name'

# Save and process simultaneously
curl -s https://httpbin.org/json | tee response.json | jq '.slideshow.title'

# Stream processing
curl -s https://httpbin.org/stream/10 | while IFS= read -r line; do
    echo "$(date): $line" >> stream.log
done

# Extract specific data
curl -s https://api.github.com/repos/torvalds/linux | \
  jq -r '.clone_url, .stargazers_count, .language'

# CSV processing
curl -s https://example.com/data.csv | \
  awk -F',' '{print $1, $3}' | \
  head -10
```

### Compression Handling

```bash
# Request compressed response
curl -H "Accept-Encoding: gzip,deflate,br" https://httpbin.org/gzip

# Auto-decompress response
curl --compressed https://httpbin.org/gzip

# Upload compressed data
gzip -c data.json | curl -X POST \
  -H "Content-Type: application/json" \
  -H "Content-Encoding: gzip" \
  --data-binary @- \
  https://httpbin.org/post
```

---

## Advanced Features

### Timeouts and Retries

```bash
# Connection timeout (time to establish connection)
curl --connect-timeout 10 https://example.com

# Total timeout (entire operation)
curl --max-time 30 https://example.com

# DNS resolution timeout
curl --dns-timeout 5 https://example.com

# Retry on failure
curl --retry 3 --retry-delay 2 --retry-max-time 60 https://flaky-api.com

# Retry only on specific HTTP codes
curl --retry 3 --retry-connrefused https://example.com
```

### Proxy Configuration

```bash
# HTTP proxy
curl --proxy http://proxy.company.com:8080 https://example.com

# SOCKS5 proxy
curl --socks5-hostname 127.0.0.1:1080 https://example.com

# Proxy with authentication
curl --proxy-user username:password \
  --proxy http://proxy.company.com:8080 \
  https://example.com

# Environment-based proxy (respects http_proxy/https_proxy)
export https_proxy=http://proxy:8080
export no_proxy=localhost,127.0.0.1,.local
curl https://example.com

# Different proxy for different protocols
export http_proxy=http://proxy:8080
export https_proxy=https://secure-proxy:8443
export ftp_proxy=http://ftp-proxy:8080
```

### SSL/TLS Configuration

```bash
# Custom CA certificate bundle
curl --cacert /etc/ssl/certs/ca-certificates.crt https://internal.company.com

# Client certificate authentication
curl --cert /path/to/client.pem \
  --key /path/to/client.key \
  https://secure.api.com

# Specific TLS version
curl --tlsv1.2 https://example.com
curl --tls-max 1.2 https://example.com

# Skip certificate verification (dangerous - use only for testing)
curl -k https://self-signed.example.com

# Certificate information
curl -vI https://example.com 2>&1 | grep -A5 -B5 "certificate"
```

### Rate Limiting and Throttling

```bash
# Bandwidth limiting (500 KB/s)
curl --limit-rate 500k https://example.com/largefile.zip

# Request rate limiting in loops
for i in {1..10}; do
    curl -s "https://api.example.com/data/$i" > "data_$i.json"
    sleep 0.5  # 500ms delay between requests
done

# Advanced rate limiting with timestamps
rate_limit() {
    local last_request_file="/tmp/last_curl_request"
    local min_interval=1  # seconds
    
    if [[ -f "$last_request_file" ]]; then
        local last_request=$(cat "$last_request_file")
        local current_time=$(date +%s)
        local time_diff=$((current_time - last_request))
        
        if [[ $time_diff -lt $min_interval ]]; then
            sleep $((min_interval - time_diff))
        fi
    fi
    
    date +%s > "$last_request_file"
}

# Usage
rate_limit && curl https://api.example.com/endpoint1
rate_limit && curl https://api.example.com/endpoint2
```

### Configuration Files

```bash
# Global configuration: ~/.curlrc
user-agent = "Linux-Automation/1.0"
connect-timeout = 10
max-time = 30
location = true
show-error = true
compressed = true
cookie-jar = ~/.curl-cookies

# Project-specific configuration
curl -K project.curlrc https://api.project.com

# Example project.curlrc:
header = "Authorization: Bearer $PROJECT_TOKEN"
header = "Accept: application/json"
output = /tmp/project-response.json
silent = true
```

### Advanced Output Formatting

```bash
# Custom write-out format
curl -w "Response Code: %{http_code}\nTotal Time: %{time_total}s\nDownload Speed: %{speed_download} bytes/sec\n" \
  -o /dev/null -s https://example.com

# Create custom format file (curl-format.txt):
     time_namelookup:  %{time_namelookup}s\n
        time_connect:  %{time_connect}s\n
     time_appconnect:  %{time_appconnect}s\n
    time_pretransfer:  %{time_pretransfer}s\n
       time_redirect:  %{time_redirect}s\n
  time_starttransfer:  %{time_starttransfer}s\n
                     ----------\n
          time_total:  %{time_total}s\n
           http_code:  %{http_code}\n
        size_download:  %{size_download} bytes\n
         size_upload:  %{size_upload} bytes\n

# Use custom format
curl -w "@curl-format.txt" -o /dev/null -s https://httpbin.org/get

# JSON timing with processing
curl -w "@curl-format.txt" -s https://httpbin.org/json | \
  jq '.' && echo -e "\n--- Timing Information ---"
```

### Network Interface Selection

```bash
# Bind to specific network interface
curl --interface eth0 https://example.com

# Use specific source IP
curl --interface 192.168.1.100 https://example.com

# IPv4 only
curl -4 https://example.com

# IPv6 only  
curl -6 https://example.com

# Resolve hostname to specific IP
curl --resolve example.com:443:93.184.216.34 https://example.com
```

---

## Troubleshooting

### Debugging and Diagnostics

```bash
# Verbose output (shows complete conversation)
curl -v https://httpbin.org/get

# Trace all data
curl --trace-ascii /tmp/curl-trace.log https://example.com
cat /tmp/curl-trace.log

# Trace binary data
curl --trace /tmp/curl-binary-trace.log https://example.com

# Show only timing information
curl -w "Time: %{time_total}s\n" -o /dev/null -s https://example.com

# DNS resolution debugging
curl -v https://example.com 2>&1 | grep -i "trying\|connected\|host"
```

### Common Error Diagnosis

#### SSL Certificate Issues

```bash
# Check certificate details
openssl s_client -connect example.com:443 -servername example.com

# Update CA certificates
sudo apt update && sudo apt install ca-certificates  # Ubuntu/Debian
sudo yum update ca-certificates                      # CentOS/RHEL

# Test with different TLS versions
curl --tlsv1.2 https://example.com
curl --tls-max 1.3 https://example.com

# Bypass certificate verification (testing only)
curl -k https://self-signed.example.com
```

#### Connection Problems

```bash
# Test basic connectivity
curl -I --connect-timeout 5 https://example.com

# Check DNS resolution
nslookup example.com
dig example.com A
dig example.com AAAA

# Test with different protocols
curl -4 https://example.com  # IPv4 only
curl -6 https://example.com  # IPv6 only

# Test specific port
curl -v telnet://example.com:80
nc -zv example.com 443
```

#### Network Diagnostics

```bash
# Trace network path
traceroute example.com
mtr example.com

# Check firewall/iptables
sudo iptables -L -n
sudo ufw status

# Monitor network traffic
sudo tcpdump -i any host example.com
sudo netstat -tuln | grep :443
```

#### Performance Analysis

```bash
# Detailed timing breakdown
curl -w "
    time_namelookup:   %{time_namelookup}s
    time_connect:      %{time_connect}s
    time_appconnect:   %{time_appconnect}s  
    time_pretransfer:  %{time_pretransfer}s
    time_redirect:     %{time_redirect}s
    time_starttransfer: %{time_starttransfer}s
    time_total:        %{time_total}s
    speed_download:    %{speed_download} bytes/sec
    size_download:     %{size_download} bytes
" -o /dev/null -s https://example.com

# Multiple requests for average timing
for i in {1..5}; do
    curl -w "%{time_total}\n" -o /dev/null -s https://example.com
done | awk '{sum+=$1; count++} END {print "Average:", sum/count "s"}'
```

### Production Scripting Best Practices

```bash
#!/bin/bash
# Robust cURL script template

set -euo pipefail  # Exit on error, undefined vars, pipe failures

# Configuration
readonly API_BASE="${API_BASE:-https://api.example.com}"
readonly API_TOKEN="${API_TOKEN:-}"
readonly TIMEOUT="${TIMEOUT:-30}"
readonly MAX_RETRIES="${MAX_RETRIES:-3}"
readonly LOG_FILE="${LOG_FILE:-/var/log/api-client.log}"

# Logging function
log() {
    echo "[$(date -Iseconds)] $*" | tee -a "$LOG_FILE"
}

# Error handling
handle_error() {
    local exit_code=$?
    log "ERROR: Script failed with exit code $exit_code on line $1"
    exit $exit_code
}
trap 'handle_error $LINENO' ERR

# Validate environment
if [[ -z "$API_TOKEN" ]]; then
    log "ERROR: API_TOKEN environment variable not set"
    exit 1
fi

# Function to make API calls
api_call() {
    local endpoint="$1"
    local method="${2:-GET}"
    local data="${3:-}"
    
    local curl_opts=(
        --silent
        --show-error
        --fail
        --location
        --connect-timeout 10
        --max-time "$TIMEOUT"
        --retry "$MAX_RETRIES"
        --retry-delay 2
        --header "Authorization: Bearer $API_TOKEN"
        --header "Accept: application/json"
        --header "User-Agent: Production-Script/1.0"
        --write-out "%{http_code}|%{time_total}"
    )
    
    if [[ "$method" != "GET" && -n "$data" ]]; then
        curl_opts+=(
            --request "$method"
            --header "Content-Type: application/json"
            --data "$data"
        )
    fi
    
    local response
    response=$(curl "${curl_opts[@]}" "$API_BASE$endpoint" 2>/dev/null) || {
        log "ERROR: API call failed for $method $endpoint"
        return 1
    }
    
    local http_code="${response##*|}"
    local time_total="${response%|*}"
    time_total="${time_total%|*}"
    local body="${response%|*|*}"
    
    log "INFO: $method $endpoint completed in ${time_total}s with HTTP $http_code"
    
    if [[ "$http_code" -ge 200 && "$http_code" -lt 300 ]]; then
        echo "$body"
        return 0
    else
        log "ERROR: API returned HTTP $http_code for $method $endpoint"
        echo "$body" >&2
        return 1
    fi
}

# Example usage
main() {
    log "INFO: Starting API operations"
    
    # Get user data
    if user_data=$(api_call "/users/me"); then
        log "INFO: Successfully retrieved user data"
        echo "$user_data" | jq '.'
    else
        log "ERROR: Failed to retrieve user data"
        exit 1
    fi
    
    # Create new resource
    new_resource='{"name":"test","description":"Created by script"}'
    if resource_response=$(api_call "/resources" "POST" "$new_resource"); then
        log "INFO: Successfully created new resource"
        resource_id=$(echo "$resource_response" | jq -r '.id')
        log "INFO: Created resource with ID: $resource_id"
    else
        log "ERROR: Failed to create new resource"
        exit 1
    fi
    
    log "INFO: All operations completed successfully"
}

# Run main function
main "$@"
```

### Monitoring and Alerting

```bash
# Health check script
#!/bin/bash
check_endpoint() {
    local url="$1"
    local expected_code="${2:-200}"
    local timeout="${3:-10}"
    
    local response
    response=$(curl --write-out "%{http_code}|%{time_total}" \
                   --output /dev/null \
                   --silent \
                   --connect-timeout "$timeout" \
                   --max-time $((timeout * 2)) \
                   "$url")
    
    local http_code="${response%|*}"
    local time_total="${response#*|}"
    
    if [[ "$http_code" == "$expected_code" ]]; then
        echo "OK: $url responded with $http_code in ${time_total}s"
        return 0
    else
        echo "CRITICAL: $url responded with $http_code (expected $expected_code) in ${time_total}s"
        return 1
    fi
}

# Check multiple endpoints
endpoints=(
    "https://api.example.com/health"
    "https://api.example.com/status"
    "https://web.example.com"
)

failed=0
for endpoint in "${endpoints[@]}"; do
    if ! check_endpoint "$endpoint"; then
        ((failed++))
    fi
done

if [[ $failed -gt 0 ]]; then
    echo "ALERT: $failed endpoint(s) failed health check"
    exit 1
else
    echo "All endpoints healthy"
    exit 0
fi
```

This comprehensive guide covers all essential aspects of using cURL on Linux systems. Remember to always test your scripts in a safe environment before deploying to production, and follow security best practices when handling sensitive data and credentials.