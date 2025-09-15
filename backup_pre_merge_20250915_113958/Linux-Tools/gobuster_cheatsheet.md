# Gobuster Cheat Sheet — Quick Reference

**Purpose:** Fast lookup for common Gobuster commands, flags, and quick workflows.

---

## Quick mode syntax
- `dir` (directories/files): `gobuster dir -u <URL> -w <WORDLIST>`
- `dns` (subdomains): `gobuster dns -d <DOMAIN> -w <WORDLIST>`
- `vhost` (virtual hosts): `gobuster vhost -u <URL> -w <WORDLIST>`

---

## Most useful global flags
- `-t <num>` / `--threads` — concurrent threads (default 10). Example: `-t 64`.
- `-o <file>` / `--output` — write results to file.
- `-v` / `--verbose` — verbose output.
- `-z` / `--no-progress` — hide progress bar.
- `-q` / `--quiet` — minimal noise.

---

## `dir` mode essentials
- `-u` — target URL (must include `http://` or `https://`).
- `-w` — wordlist path.
- `-x .php,.html,.txt` — search specific file extensions (comma separated).
- `-k` — skip TLS verification (useful for self‑signed certs in labs).
- `-H 'Header: val'` — add custom header(s).
- `-c 'cookie=val'` — send cookies.
- `-s 200,301,302,401` — only show these status codes.
- `-b 404,400` — blacklist (hide) these codes.

**Example**:
```
gobuster dir -u https://target.thm -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x .php,.txt -k -t 64 -o dir.txt
```

---

## `dns` mode essentials
- `-d` — target domain.
- `-w` — wordlist path (subdomain list).
- `-i` / `--show-ips` — display discovered IPs.
- `-c` / `--show-cname` — show CNAMEs.
- `-r <resolver>` — use custom DNS resolver.

**Example**:
```
gobuster dns -d example.thm -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -i
```

---

## `vhost` mode essentials
- `-u` — target URL (Host header will be fuzzed).
- `-w` — wordlist (subdomain/vhost names).
- Works well with `-k`, `-t`, `-o`, `-H`.

**Example**:
```
gobuster vhost -u http://10.10.10.10 -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -t 64 -o vhosts.txt
```

---

## Quick status code guide
- `200` — OK (found resource)
- `301/302` — Redirect (check `Location`)
- `401/403` — Auth required / Forbidden (interesting)
- `404` — Not found (usually noise)

Use `-s`/`-b` to filter.

---

## Common wordlists (Kali & SecLists)
- `/usr/share/wordlists/dirbuster/directory-list-2.3-*.txt`
- `/usr/share/wordlists/dirb/common.txt`
- `/usr/share/wordlists/dirb/big.txt`
- `/usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt`

Install SecLists: `sudo apt install seclists`

---

## Quick workflows / recipes
- **Fast discovery:** small wordlist → find quick hits → expand with larger lists.
- **Find files in discovered dir:** run `dir` with `-x` for `.php,.conf,.bak,.txt`.
- **CTF HTTPS labs:** add `-k` to dir/vhost scans.
- **Subdomain to host mapping:** `dns -d` to find subdomains → `host`/`dig` or `-i` to get IPs.

---

## Safety & etiquette
- Always confirm scope and permission before scanning real targets.
- Reduce `-t` on production targets to avoid DoS.

---

## Quick copy/paste commands
```
# Basic dir
gobuster dir -u http://target -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 64 -o results.txt

# Dir with extensions and TLS skip
gobuster dir -u https://target -w wordlist -x .php,.html,.txt -k -t 64

# DNS subdomain scan
gobuster dns -d target.thm -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -i

# VHost scan
gobuster vhost -u http://target -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -t 64
```

---

*End of cheat sheet.*
