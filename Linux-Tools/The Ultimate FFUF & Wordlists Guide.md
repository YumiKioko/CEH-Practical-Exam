<<<<<<< HEAD
# The Ultimate FFUF & Wordlists Guide

## Overview

`ffuf` (Fuzz Faster U Fool) is a blazing-fast web fuzzer written in Go. When combined with the right wordlists, it becomes an incredibly powerful tool for discovering content, vulnerabilities, and hidden endpoints. This guide covers essential `ffuf` techniques and wordlist selection strategies.

## Basic FFUF Syntax

```bash
# Basic structure
ffuf -u <TARGET_URL> -w <WORDLIST> -mc <STATUS_CODES> -fs <FILTER_SIZE>

# Practical example
ffuf -u http://example.com/FUZZ -w /usr/share/wordlists/common.txt -mc 200,301,302 -fs 0
```

## Essential FFUF Flags

### Core Flags
| Flag | Description | Example |
|------|-------------|---------|
| `-u` | Target URL with FUZZ keyword | `-u http://site.com/FUZZ` |
| `-w` | Wordlist path | `-w wordlist.txt` |
| `-H` | Add header | `-H "Cookie: session=abc"` |
| `-X` | HTTP method | `-X POST` |
| `-d` | POST data | `-d 'user=FUZZ&pass=FUZZ'` |
| `-c` | Colorize output | `-c` |
| `-t` | Threads (default: 40) | `-t 100` |

### Filtering & Matching Flags
| Flag | Description | Use Case |
|------|-------------|----------|
| `--fc` | Filter HTTP status codes | `--fc 404,403` |
| `--fs` | Filter response size | `--fs 1024` |
| `--fw` | Filter by word count | `--fw 100` |
| `--mc` | Match HTTP status codes | `--mc 200,301` |
| `--ms` | Match response size | `--ms 5000` |
| `--ml` | Match lines in response | `--ml 50` |

### Advanced Flags
| Flag | Description | Example |
|------|-------------|---------|
| `-recursion` | Recursive fuzzing | `-recursion` |
| `-recursion-depth` | Max recursion depth | `-recursion-depth 2` |
| `-rate` | Requests per second | `-rate 20` |
| `-p` | Delay between requests (ms) | `-p 1.5` |
| `-o` | Output to file | `-o results.json` |
| `-of` | Output format | `-of json` |

## Critical Wordlist Guide

### Directory/Path Discovery
```bash
# Common directories/files
ffuf -u http://target/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt -mc 200,301,302 -fs 0

# Comprehensive discovery
ffuf -u http://target/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-directories.txt -recursion -mc 200,301,302
```

**Best Wordlists:**
- `seclists/Discovery/Web-Content/common.txt`
- `seclists/Discovery/Web-Content/raft-large-*`
- `seclists/Discovery/Web-Content/dirbuster/*`

### Subdomain Enumeration
```bash
# Basic subdomain fuzzing
ffuf -u https://FUZZ.target.com -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -mc 200,301,302 -fs 0

# With Host header (for VHosts)
ffuf -u http://target.com -H "Host: FUZZ.target.com" -w subdomains.txt -mc 200,301,302
```

**Best Wordlists:**
- `seclists/Discovery/DNS/subdomains-top1million-5000.txt`
- `seclists/Discovery/DNS/subdomains-top1million-20000.txt`
- `jhaddix/all.txt` (for bug bounties)

### Parameter Discovery
```bash
# GET parameter fuzzing
ffuf -u http://target.com/endpoint?FUZZ=test -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt -mc 200 -fs 0

# POST parameter fuzzing
ffuf -u http://target.com/login -X POST -d 'username=admin&FUZZ=test' -w parameters.txt -mc 200
```

**Best Wordlists:**
- `seclists/Discovery/Web-Content/burp-parameter-names.txt`
- `seclists/Discovery/Web-Content/raft-large-parameters.txt`

### Local File Inclusion (LFI)
```bash
# Linux LFI testing
ffuf -u http://target.com/page?file=FUZZ -w /usr/share/wordlists/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt -mc 200 -fs 0

# Windows LFI testing
ffuf -u http://target.com/page?file=FUZZ -w /usr/share/wordlists/seclists/Fuzzing/LFI/LFI-windows.txt -mc 200 -fs 0
```

**Best Wordlists:**
- `seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt`
- `seclists/Fuzzing/LFI/LFI-windows.txt`
- `seclists/Fuzzing/LFI/LFI-*` (all LFI wordlists)

### API Endpoint Discovery
```bash
# API path fuzzing
ffuf -u http://target.com/api/v1/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/api/ common-api-endpoints.txt -mc 200 -fs 0

# API parameter fuzzing
ffuf -u http://target.com/api/user?FUZZ=test -w api-parameters.txt -mc 200
```

**Best Wordlists:**
- `seclists/Discovery/Web-Content/api/` (directory)
- Custom API wordlists

## Advanced FFUF Techniques

### Recursive Fuzzing
```bash
# Discover directories then fuzz each found directory
ffuf -u http://target.com/FUZZ -w directories.txt -recursion -recursion-depth 2 -mc 200,301,302
```

### Header Fuzzing
```bash
# Fuzz headers for bypasses
ffuf -u http://target.com/admin -H "X-Forwarded-For: FUZZ" -w ips.txt -mc 200

# Fuzz User-Agent
ffuf -u http://target.com -H "User-Agent: FUZZ" -w user-agents.txt -mc 200
```

### Multi-position Fuzzing
```bash
# Fuzz multiple positions simultaneously
ffuf -u http://target.com/FUZZ/FUZ2Z -w first-wordlist.txt:FUZZ -w second-wordlist.txt:FUZ2Z -mc 200
```

### Rate Limiting & Stealth
```bash
# Slow, stealthy fuzzing
ffuf -u http://target.com/FUZZ -w wordlist.txt -rate 10 -p 0.5 -t 20

# With random user-agent
ffuf -u http://target.com/FUZZ -w wordlist.txt -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" -rate 15
```

## Wordlist Management Tips

1. **Start Small**: Begin with common wordlists before moving to larger ones
2. **Context Matters**: Use OS-specific wordlists (Windows vs Linux)
3. **Custom Wordlists**: Generate targeted wordlists with:
   ```bash
   # Generate from target website
   cewl http://target.com -d 2 -m 5 -w target-words.txt
   
   # Combine wordlists
   cat wordlist1.txt wordlist2.txt | sort -u > combined.txt
   ```
4. **Wordlist Maintenance**: Regularly update and curate your wordlists

## Example Commands Cheat Sheet

```bash
# Quick directory discovery
ffuf -u http://target/FUZZ -w common.txt -mc 200,301,302 -fs 0 -c

# Comprehensive subdomain enumeration
ffuf -u https://FUZZ.target.com -w subdomains-top20000.txt -mc 200,301,302 -fs 0 -c

# LFI testing with bypasses
ffuf -u http://target/page?file=FUZZ -w LFI-gracefulsecurity-linux.txt -mc 200 -fs 0 -c -r

# API endpoint discovery
ffuf -u http://target/api/v1/FUZZ -w api-endpoints.txt -mc 200 -fs 0 -c

# Parameter discovery with filtering
ffuf -u http://target/endpoint?FUZZ=test -w parameters.txt -mc 200 --fs 1024 -c
```

## Output & Analysis

```bash
# Save results for later analysis
ffuf -u http://target/FUZZ -w wordlist.txt -o results.json -of json
ffuf -u http://target/FUZZ -w wordlist.txt -o results.html -of html

# Verbose output for debugging
ffuf -u http://target/FUZZ -w wordlist.txt -v
```

=======
# The Ultimate FFUF & Wordlists Guide

## Overview

`ffuf` (Fuzz Faster U Fool) is a blazing-fast web fuzzer written in Go. When combined with the right wordlists, it becomes an incredibly powerful tool for discovering content, vulnerabilities, and hidden endpoints. This guide covers essential `ffuf` techniques and wordlist selection strategies.

## Basic FFUF Syntax

```bash
# Basic structure
ffuf -u <TARGET_URL> -w <WORDLIST> -mc <STATUS_CODES> -fs <FILTER_SIZE>

# Practical example
ffuf -u http://example.com/FUZZ -w /usr/share/wordlists/common.txt -mc 200,301,302 -fs 0
```

## Essential FFUF Flags

### Core Flags
| Flag | Description | Example |
|------|-------------|---------|
| `-u` | Target URL with FUZZ keyword | `-u http://site.com/FUZZ` |
| `-w` | Wordlist path | `-w wordlist.txt` |
| `-H` | Add header | `-H "Cookie: session=abc"` |
| `-X` | HTTP method | `-X POST` |
| `-d` | POST data | `-d 'user=FUZZ&pass=FUZZ'` |
| `-c` | Colorize output | `-c` |
| `-t` | Threads (default: 40) | `-t 100` |

### Filtering & Matching Flags
| Flag | Description | Use Case |
|------|-------------|----------|
| `--fc` | Filter HTTP status codes | `--fc 404,403` |
| `--fs` | Filter response size | `--fs 1024` |
| `--fw` | Filter by word count | `--fw 100` |
| `--mc` | Match HTTP status codes | `--mc 200,301` |
| `--ms` | Match response size | `--ms 5000` |
| `--ml` | Match lines in response | `--ml 50` |

### Advanced Flags
| Flag | Description | Example |
|------|-------------|---------|
| `-recursion` | Recursive fuzzing | `-recursion` |
| `-recursion-depth` | Max recursion depth | `-recursion-depth 2` |
| `-rate` | Requests per second | `-rate 20` |
| `-p` | Delay between requests (ms) | `-p 1.5` |
| `-o` | Output to file | `-o results.json` |
| `-of` | Output format | `-of json` |

## Critical Wordlist Guide

### Directory/Path Discovery
```bash
# Common directories/files
ffuf -u http://target/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt -mc 200,301,302 -fs 0

# Comprehensive discovery
ffuf -u http://target/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-directories.txt -recursion -mc 200,301,302
```

**Best Wordlists:**
- `seclists/Discovery/Web-Content/common.txt`
- `seclists/Discovery/Web-Content/raft-large-*`
- `seclists/Discovery/Web-Content/dirbuster/*`

### Subdomain Enumeration
```bash
# Basic subdomain fuzzing
ffuf -u https://FUZZ.target.com -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -mc 200,301,302 -fs 0

# With Host header (for VHosts)
ffuf -u http://target.com -H "Host: FUZZ.target.com" -w subdomains.txt -mc 200,301,302
```

**Best Wordlists:**
- `seclists/Discovery/DNS/subdomains-top1million-5000.txt`
- `seclists/Discovery/DNS/subdomains-top1million-20000.txt`
- `jhaddix/all.txt` (for bug bounties)

### Parameter Discovery
```bash
# GET parameter fuzzing
ffuf -u http://target.com/endpoint?FUZZ=test -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt -mc 200 -fs 0

# POST parameter fuzzing
ffuf -u http://target.com/login -X POST -d 'username=admin&FUZZ=test' -w parameters.txt -mc 200
```

**Best Wordlists:**
- `seclists/Discovery/Web-Content/burp-parameter-names.txt`
- `seclists/Discovery/Web-Content/raft-large-parameters.txt`

### Local File Inclusion (LFI)
```bash
# Linux LFI testing
ffuf -u http://target.com/page?file=FUZZ -w /usr/share/wordlists/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt -mc 200 -fs 0

# Windows LFI testing
ffuf -u http://target.com/page?file=FUZZ -w /usr/share/wordlists/seclists/Fuzzing/LFI/LFI-windows.txt -mc 200 -fs 0
```

**Best Wordlists:**
- `seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt`
- `seclists/Fuzzing/LFI/LFI-windows.txt`
- `seclists/Fuzzing/LFI/LFI-*` (all LFI wordlists)

### API Endpoint Discovery
```bash
# API path fuzzing
ffuf -u http://target.com/api/v1/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/api/ common-api-endpoints.txt -mc 200 -fs 0

# API parameter fuzzing
ffuf -u http://target.com/api/user?FUZZ=test -w api-parameters.txt -mc 200
```

**Best Wordlists:**
- `seclists/Discovery/Web-Content/api/` (directory)
- Custom API wordlists

## Advanced FFUF Techniques

### Recursive Fuzzing
```bash
# Discover directories then fuzz each found directory
ffuf -u http://target.com/FUZZ -w directories.txt -recursion -recursion-depth 2 -mc 200,301,302
```

### Header Fuzzing
```bash
# Fuzz headers for bypasses
ffuf -u http://target.com/admin -H "X-Forwarded-For: FUZZ" -w ips.txt -mc 200

# Fuzz User-Agent
ffuf -u http://target.com -H "User-Agent: FUZZ" -w user-agents.txt -mc 200
```

### Multi-position Fuzzing
```bash
# Fuzz multiple positions simultaneously
ffuf -u http://target.com/FUZZ/FUZ2Z -w first-wordlist.txt:FUZZ -w second-wordlist.txt:FUZ2Z -mc 200
```

### Rate Limiting & Stealth
```bash
# Slow, stealthy fuzzing
ffuf -u http://target.com/FUZZ -w wordlist.txt -rate 10 -p 0.5 -t 20

# With random user-agent
ffuf -u http://target.com/FUZZ -w wordlist.txt -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" -rate 15
```

## Wordlist Management Tips

1. **Start Small**: Begin with common wordlists before moving to larger ones
2. **Context Matters**: Use OS-specific wordlists (Windows vs Linux)
3. **Custom Wordlists**: Generate targeted wordlists with:
   ```bash
   # Generate from target website
   cewl http://target.com -d 2 -m 5 -w target-words.txt
   
   # Combine wordlists
   cat wordlist1.txt wordlist2.txt | sort -u > combined.txt
   ```
4. **Wordlist Maintenance**: Regularly update and curate your wordlists

## Example Commands Cheat Sheet

```bash
# Quick directory discovery
ffuf -u http://target/FUZZ -w common.txt -mc 200,301,302 -fs 0 -c

# Comprehensive subdomain enumeration
ffuf -u https://FUZZ.target.com -w subdomains-top20000.txt -mc 200,301,302 -fs 0 -c

# LFI testing with bypasses
ffuf -u http://target/page?file=FUZZ -w LFI-gracefulsecurity-linux.txt -mc 200 -fs 0 -c -r

# API endpoint discovery
ffuf -u http://target/api/v1/FUZZ -w api-endpoints.txt -mc 200 -fs 0 -c

# Parameter discovery with filtering
ffuf -u http://target/endpoint?FUZZ=test -w parameters.txt -mc 200 --fs 1024 -c
```

## Output & Analysis

```bash
# Save results for later analysis
ffuf -u http://target/FUZZ -w wordlist.txt -o results.json -of json
ffuf -u http://target/FUZZ -w wordlist.txt -o results.html -of html

# Verbose output for debugging
ffuf -u http://target/FUZZ -w wordlist.txt -v
```

>>>>>>> 7c13458 (Resolve merge conflicts)
Remember: **The right wordlist is more important than the fastest fuzzer.** Always choose your wordlist based on the specific target and attack vector for maximum effectiveness.