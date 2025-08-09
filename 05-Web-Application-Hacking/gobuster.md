### 🔧 Basic Syntax

```
gobuster [mode] -u <URL> -w <wordlist> [options]
```

## 🔍 Modes

| Mode    | Description                      |
| ------- | -------------------------------- |
| `dir`   | Directory and file brute-forcing |
| `dns`   | Subdomain enumeration            |
| `vhost` | Virtual host discovery           |
| `s3`    | S3 bucket fuzzing                |
| `fuzz`  | General-purpose fuzzing          |
### 📁 Directory Bruteforce
```
gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt
```

### Common Options

| Option           | Description                    |                                          |
| ---------------- | ------------------------------ | ---------------------------------------- |
| `-x .php,.html`  | File extensions to try         |                                          |
| `-t 50`          | Threads (default: 10)          |                                          |
| `-o results.txt` | Output file                    |                                          |
| `-k`             | Skip SSL verification          |                                          |
| `-b 403,404`     | Hide status codes              |                                          |
| `-e`             | Expanded mode (show full URLs) | #### Example with extensions and output: |
Example with extensions and output:

```
gobuster dir -u https://site.com -w common.txt -x php,txt -o gobuster_results.txt -t 50
```

### 🌐 DNS Subdomain Enumeration

```
gobuster dns -d target.com -w /usr/share/wordlists/dns/subdomains-top1million-5000.txt
```
### Extra Options

- `-i`: Show IPs
- `-r`: Do not randomize subdomain case

### 🧾 VHOST Bruteforcing

```
gobuster vhost -u http://target.com -w /usr/share/wordlists/SecLists/Discovery/DNS/namelist.txt
```
⚠️ Requires a **proper Host header** setup.

### 🎯 FUZZ Mode

```
gobuster fuzz -u http://site.com/FUZZ -w wordlist.txt
```

### Custom Headers

```
-H "X-Forwarded-For: 127.0.0.1"
-H "Authorization: Bearer <token>"
```

## 🛡️ Useful Tips

- Filter out 403s with `-b 403`
- Combine with tools like `ffuf` or `feroxbuster` for deeper fuzzing
- Use `-s` to filter status codes (e.g., `-s 200,204`)
- Use `--wildcard` to detect wildcard DNS when scanning subdomains

## 📚 Wordlist Recommendations

- `/usr/share/wordlists/dirb/`
- `/usr/share/wordlists/dirbuster/`
- [SecLists GitHub](https://github.com/danielmiessler/SecLists)
- 
## 🧪 Sample Usage Scenarios

### Common web scan

```
gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt -t 30 -x php,html -o found.txt
```

### Subdomain brute-force

```
gobuster dns -d internal.example.com -w subdomains.txt -t 20
```
