# Gobuster Cheat Sheet — Quick Reference (CTF‑focused)

**Purpose:** Fast lookup for common Gobuster commands, flags, and CTF recipes with practical examples you can copy‑paste.

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

## `dir` mode essentials + CTF tricks
- `-u` — target URL (must include `http://` or `https://`).
- `-w` — wordlist path.
- `-x .php,.html,.txt` — search specific file extensions (comma separated).
- `-k` — skip TLS verification (useful for self‑signed certs in labs).
- `-H 'Header: val'` — add custom header(s).
- `-c 'cookie=val'` — send cookies (useful when you have authentication token).
- `-s 200,301,302,401,403` — show only these status codes (tweak for CTFs).
- `-b 404` — blacklist (hide) these codes.

**Why these matter in CTFs**
- Many CTFs hide admin panels (`/admin`, `/admins`), backup files (`.bak`, `.old`), or configuration files (`.env`, `.config`) — use `-x` to search for them quickly.
- Wordlists can be smaller to get quick wins then escalate.

**CTF example 1 — fast WP reconnaissance**

```bash
# Quick WP dir scan for common WP paths (fast list)
gobuster dir -u http://10.10.10.10 -w /usr/share/wordlists/dirb/common.txt -t 50 -o wp-fast.txt

# Search for php files in discovered dirs
gobuster dir -u http://10.10.10.10 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x .php -t 64 -o wp-php.txt
```

**CTF example 2 — find exposed backup/config files**

```bash
# Search for common backup extensions and env files in the root
gobuster dir -u http://target.ctf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x .env,.bak,.old,.backup,.zip -t 64 -o backups-and-envs.txt
```

**CTF example 3 — authenticated enumeration**

```bash
# If you have a session cookie (after logging in via browser), pass it to Gobuster
gobuster dir -u http://target.ctf -w wordlist.txt -c 'PHPSESSID=abcd1234; other=val' -t 40 -o auth-dir.txt
```

**CTF example 4 — filter interesting status codes**

```bash
# Only display 200, 301, 302, 401, 403 which are usually interesting
gobuster dir -u http://target -w wordlist.txt -s 200,301,302,401,403 -t 64 -o interesting.txt
```

**CTF example 5 — hunt for exposed backups inside a discovered folder**

1. Discover directories quickly.
2. For each directory found, run Gobuster with `-x` to look for backups.

```bash
# Step 1: find directories
gobuster dir -u http://target -w small.txt -t 50 -o dirs.txt

# Step 2: scan one directory for backups
gobuster dir -u http://target/uploads -w /usr/share/wordlists/dirb/big.txt -x .zip,.bak,.tar.gz,.tar -t 40 -o uploads-backups.txt
```

---

## `dns` mode essentials + CTF tricks
- `-d` — target domain.
- `-w` — wordlist path (subdomain list).
- `-i` / `--show-ips` — display discovered IPs.
- `-c` / `--show-cname` — show CNAMEs.
- `-r <resolver>` — use custom DNS resolver (e.g., `8.8.8.8` or internal lab resolver).

**CTF example 6 — subdomain bruteforce (fast then deep)**

```bash
# Fast: top small list, show IPs
gobuster dns -d target.ctf -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -i -t 50 -o dns-fast.txt

# Deep: larger list for stubborn targets
gobuster dns -d target.ctf -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -i -t 100 -o dns-deep.txt
```

**CTF example 7 — use resolver to bypass internal DNS or speed resolution**

```bash
gobuster dns -d target.ctf -w subdomains.txt -r 8.8.8.8 -i -t 40
```

---

## `vhost` mode essentials + CTF tricks
- `-u` — target URL (Host header will be fuzzed).
- `-w` — wordlist (subdomain/vhost names).
- Useful for finding completely different sites hosted on same IP (common CTF trick).

**CTF example 8 — find hidden vhosts**

```bash
gobuster vhost -u http://10.10.10.10 -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -t 80 -o vhost-results.txt
```

If the target returns different content based on `Host` header, you may find alternate sites (look for 200 responses or unique HTML titles).

---

## Combining results & quick analysis tips
- Save outputs (`-o`) and then grep or jq (if JSON) to triage.
- Example: extract 200 responses from a Gobuster output file:

```bash
# Gobuster output is plain text; filter lines containing '200'
grep '200' gobuster-output.txt
```

- Use `xargs` to feed discovered directories into other tools (e.g., wget, curl) to fetch content.

**Example: fetch a discovered path**

```bash
# Suppose gobuster found /backup.zip
curl -sI http://target/backup.zip
# Or download it
curl -sO http://target/backup.zip
```

---

## Common wordlists (Kali & SecLists)
- `/usr/share/wordlists/dirbuster/directory-list-2.3-*.txt`
- `/usr/share/wordlists/dirb/common.txt`
- `/usr/share/wordlists/dirb/big.txt`
- `/usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt`

Install SecLists: `sudo apt install seclists`

**CTF tip:** keep a hybrid list: `small.txt` for speed and `big.txt` for depth — combine them if needed.

---

## Quick status code guide
- `200` — OK (found resource)
- `301/302` — Redirect (check `Location`)
- `401/403` — Auth required / Forbidden (interesting)
- `404` — Not found (usually noise)

Use `-s`/`-b` to filter and focus on the interesting codes.

---

## Safety & etiquette
- Always confirm scope and permission before scanning real targets.
- Reduce `-t` on production targets to avoid DoS.

---

## Quick copy/paste CTF command summary
```
# Fast WP dir scan
gobuster dir -u http://10.10.10.10 -w /usr/share/wordlists/dirb/common.txt -t 50 -o wp-fast.txt

# Search for backups and env files
gobuster dir -u http://target.ctf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x .env,.bak,.old,.zip -t 64 -o secrets.txt

# Authenticated scan with cookies
gobuster dir -u http://target.ctf -w wordlist.txt -c 'session=abcd1234' -t 40 -o auth-results.txt

# DNS fast then deep
gobuster dns -d target.ctf -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -i -t 50 -o dns-fast.txt

# VHost discovery
gobuster vhost -u http://10.10.10.10 -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -t 80 -o vhost-results.txt
```

---

*End of CTF‑focused cheat sheet.*
