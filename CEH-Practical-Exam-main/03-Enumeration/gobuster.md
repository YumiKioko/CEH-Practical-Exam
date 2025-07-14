
## Description

Gobuster is a fast and flexible directory, DNS, and virtual host brute-forcer written in Go. Often used for discovering hidden directories, files, or subdomains.

## Modes

- `dir`: Directory/file brute-forcing

- `dns`: Subdomain brute-forcing

- `vhost`: Virtual host brute-forcing

- `s3`: Amazon S3 bucket enumeration

- `fuzz`: General fuzzing mode

  
---

## Directory and File Discovery

```
gobuster dir -u http://target.com -w /path/to/wordlist.txt
```