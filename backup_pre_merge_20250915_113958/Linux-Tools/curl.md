# cURL Ultimate Cheat Sheet

## Overview
cURL (Client URL) is a command-line tool for transferring data with URLs. It supports various protocols including HTTP, HTTPS, FTP, FTPS, SCP, SFTP, and more.

## Basic Syntax
```bash
curl [options] [URL]
```

## Essential Options

### HTTP Methods
```bash
# GET request (default)
curl http://example.com

# POST request with data
curl -X POST http://example.com
curl -d "name=value" http://example.com

# PUT request
curl -X PUT http://example.com

# DELETE request
curl -X DELETE http://example.com

# HEAD request (headers only)
curl -I http://example.com
```

### Headers & Authentication
```bash
# Add custom header
curl -H "Content-Type: application/json" http://example.com
curl -H "Authorization: Bearer token123" http://example.com

# Basic authentication
curl -u username:password http://example.com
curl -u username http://example.com # (will prompt for password)

# User agent spoofing
curl -A "Mozilla/5.0" http://example.com
```

### Data Handling
```bash
# POST form data
curl -d "param1=value1&param2=value2" http://example.com
curl -d @data.txt http://example.com # from file

# POST JSON data
curl -H "Content-Type: application/json" -d '{"key":"value"}' http://example.com

# URL-encoded data
curl --data-urlencode "name=value" http://example.com

# Multipart form data (file upload)
curl -F "file=@file.txt" http://example.com
curl -F "name=value" -F "file=@file.txt" http://example.com
```

### Output Control
```bash
# Save output to file
curl -o output.txt http://example.com
curl -O http://example.com/file.txt # saves with remote filename

# Show response headers only
curl -I http://example.com

# Show both headers and body
curl -i http://example.com

# Silent mode (no progress meter)
curl -s http://example.com

# Verbose mode (see request/response details)
curl -v http://example.com
curl --trace-ascii debug.txt http://example.com # detailed trace
```

### File Transfer
```bash
# Download file
curl -O http://example.com/file.zip
curl -o customname.zip http://example.com/file.zip

# Upload file
curl -T file.txt http://example.com/upload
curl -T file.txt -u user:pass ftp://example.com/

# Resume interrupted download
curl -C - -O http://example.com/largefile.zip

# Limit download speed (bytes per second)
curl --limit-rate 100K -O http://example.com/largefile.zip
```

### SSL/TLS Options
```bash
# Ignore SSL certificate verification (for testing)
curl -k https://example.com

# Specify client certificate
curl --cert client.pem https://example.com

# Specify private key
curl --key key.pem https://example.com

# Specify CA bundle
curl --cacert ca-bundle.pem https://example.com

# SSL version specification
curl --ssl-reqd --tlsv1.2 https://example.com
```

### Proxy Support
```bash
# HTTP proxy
curl -x http://proxy:port http://example.com

# SOCKS proxy
curl --socks5 proxy:port http://example.com

# Proxy with authentication
curl -x http://user:pass@proxy:port http://example.com
```

### Advanced Features
```bash
# Follow redirects
curl -L http://example.com

# Maximum redirects
curl -L --max-redirs 5 http://example.com

# Set connection timeout
curl --connect-timeout 30 http://example.com

# Set maximum time for operation
curl --max-time 60 http://example.com

# Keepalive requests
curl --keepalive-time 60 http://example.com

# Custom request method
curl -X PURGE http://example.com/cache
```

### Cookie Management
```bash
# Send cookies
curl -b "name=value" http://example.com
curl -b cookies.txt http://example.com

# Save cookies
curl -c cookies.txt http://example.com

# Send and save cookies
curl -b cookies.txt -c cookies.txt http://example.com
```

### Debugging & Testing
```bash
# Show timing information
curl -w "@curl-format.txt" http://example.com

# Custom output format
curl -w "Time: %{time_total}\nCode: %{http_code}\n" http://example.com

# Test if site is reachable
curl -s -o /dev/null -w "%{http_code}" http://example.com

# Measure response time
curl -s -o /dev/null -w "Connect: %{time_connect} TTFB: %{time_starttransfer} Total: %{time_total}\n" http://example.com
```

## Practical Examples

### API Interaction
```bash
# GET request to API
curl -H "Accept: application/json" https://api.example.com/users

# POST JSON to API
curl -X POST -H "Content-Type: application/json" -d '{"name":"John"}' https://api.example.com/users

# PUT with authentication
curl -X PUT -H "Authorization: Bearer token123" -d '{"status":"active"}' https://api.example.com/users/1

# DELETE resource
curl -X DELETE -u admin:password https://api.example.com/users/1
```

### Web Scraping
```bash
# Download webpage
curl -o page.html https://example.com

# Follow links and download
curl -L -O https://example.com/sitemap.xml

# With custom user agent
curl -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" https://example.com
```

### File Operations
```bash
# Upload to FTP
curl -T file.txt -u user:pass ftp://ftp.example.com/

# Download from FTP
curl -u user:pass -O ftp://ftp.example.com/file.txt

# Secure file copy (SCP)
curl -u user -T file.txt scp://example.com/path/
```

### Testing & Monitoring
```bash
# Check HTTP status
curl -s -o /dev/null -w "%{http_code}" https://example.com

# Monitor response time
while true; do curl -s -o /dev/null -w "HTTP: %{http_code} Time: %{time_total}s\n" https://example.com; sleep 5; done

# Test load balancer
for i in {1..10}; do curl -s https://example.com | grep "Server"; done
```

### Authentication Examples
```bash
# OAuth2 Bearer token
curl -H "Authorization: Bearer YOUR_TOKEN" https://api.example.com

# API key in header
curl -H "X-API-Key: YOUR_API_KEY" https://api.example.com

# Digest authentication
curl --digest -u user:pass https://example.com

# NTLM authentication
curl --ntlm -u user:pass https://example.com
```

## Custom Format Strings

Create a `curl-format.txt` file:
```
    time_namelookup:  %{time_namelookup}s\n
       time_connect:  %{time_connect}s\n
    time_appconnect:  %{time_appconnect}s\n
   time_pretransfer:  %{time_pretransfer}s\n
      time_redirect:  %{time_redirect}s\n
 time_starttransfer:  %{time_starttransfer}s\n
                    ----------\n
         time_total:  %{time_total}s\n
```

Use it with:
```bash
curl -w "@curl-format.txt" -o /dev/null -s https://example.com
```

## Common Protocols

```bash
# HTTP/HTTPS
curl http://example.com
curl https://example.com

# FTP/FTPS
curl ftp://ftp.example.com/
curl ftps://ftp.example.com/

# SCP/SFTP
curl scp://user@example.com/path/
curl sftp://user@example.com/path/

# SMTP (send email)
curl smtp://smtp.example.com --mail-from from@example.com --mail-rcpt to@example.com --upload-file email.txt
```

## Tips & Best Practices

1. **Always use `-s`** for scripts to suppress progress output
2. **Use `-L`** to follow redirects when needed
3. **Always quote URLs** to avoid shell interpretation
4. **Use `--data-urlencode`** for proper URL encoding
5. **Test with `-v`** first to see what's being sent/received
6. **Use `-k` sparingly** - only for testing, not production
7. **Save cookies** for maintaining sessions across requests
8. **Use rate limiting** when scraping or testing production systems

## Error Handling

```bash
# Continue on error (for scripts)
curl -f --retry 3 http://example.com || true

# Retry failed attempts
curl --retry 3 http://example.com

# Retry with delay
curl --retry 3 --retry-delay 5 http://example.com

# Fail on HTTP errors
curl -f http://example.com
```

This cheat sheet covers the most essential cURL commands and options for web development, API testing, and system administration tasks.
