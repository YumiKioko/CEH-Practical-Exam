# Gobuster — Beginner's E‑Paper

**Author:** Generated for you
**Audience:** Beginners to enumeration and penetration testing
**Purpose:** Quick-start, reference, and practice guide for Gobuster on Kali Linux

---

## Abstract
This e‑paper walks a beginner through installing and using **Gobuster**, a fast directory/subdomain/virtual‑host brute‑forcer written in Go. You'll learn how to use Gobuster's three most useful modes (`dir`, `dns`, `vhost`), the flags you will most commonly need, how to tune scans, and which wordlists to use. At the end you'll find practical tips and a suggested practice lab (TryHackMe "Blog" room) to apply what you've learned.

---

## Table of contents
1. Introduction
2. What is Gobuster?
3. Installing Gobuster on Kali Linux
4. Modes and usage
   - `dir` mode (directory and file discovery)
   - `dns` mode (subdomain brute force)
   - `vhost` mode (virtual host brute force)
5. Important flags and examples
6. Useful global flags
7. Useful wordlists
8. Practical tips, TLS (-k) and extensions (-x)
9. Where to go for help & further reading
10. Suggested practice lab

---

## 1. Introduction
Welcome to the Gobuster portion of this room! This guide is aimed at complete beginners to enumeration and penetration testing. By the time you finish this e‑paper you will know:

- How to install Gobuster on Kali Linux.
- How to use `dir` mode to enumerate directories (and common options).
- How to use `dns` mode to enumerate subdomains (and common options).
- How to use `vhost` mode to brute‑force virtual hosts.
- Where to go for help and practice.

At the end of this section you'll have the opportunity to practice using Gobuster on another room (TryHackMe: **Blog**), which uses WordPress — a CMS with a predictable directory layout that makes it ideal for directory enumeration.

---

## 2. What is Gobuster?
**Gobuster** is a fast CLI tool written in Go for brute‑forcing URIs (directories/files), DNS subdomains, and virtual hosts on web servers. It is commonly used during penetration tests and Capture The Flag (CTF) events to discover hidden or unlinked content.

Gobuster is powerful because:
- It returns HTTP status codes alongside discovered paths so you can quickly triage results.
- It can search for files by specifying extensions.
- It supports multiple modes (`dir`, `dns`, `vhost`) tailored to different enumeration tasks.

> Gobuster is written in Go — an open‑source language developed by Google. If you want to learn more about Go, visit the official Go website.

---

## 3. Installing Gobuster on Kali Linux
Installation on Kali is simple and requires no manual Go build process:

```bash
sudo apt update
sudo apt install gobuster
```

That's it — Gobuster will be installed and ready to use.

---

## 4. Modes and usage

### `dir` Mode (directory and file discovery)
`dir` mode enumerates directories (and files) on a web server using a wordlist. This is useful to map a site's directory structure and find hidden pages or files that may contain sensitive information.

**Basic syntax**:

```bash
gobuster dir -u <URL> -w <WORDLIST>
```

**Example**:

```bash
gobuster dir -u http://10.10.10.10 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

**Notes**:
- `-u` sets the URL (base path) Gobuster starts from — e.g. `http://example.com/` or `http://10.10.10.10/products` to target a subpath.
- Always include the protocol (`http://` or `https://`).

**Searching for specific file extensions**
The `-x` or `--extensions` flag lets you search for files of certain types in directories you discover. For example, to look for `.html`, `.css`, and `.js` files inside `/myfolder`:

```bash
gobuster dir -u http://10.10.252.123/myfolder   -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt   -x .html,.css,.js
```

This is handy when you want to find configuration files (`.conf`), text files (`.txt`), or specific web pages (`.php`, `.html`).

**Important `dir` flags (selected)**

| Flag | Long flag | Description |
|---|---:|---|
| `-c` | `--cookies` | Cookies to use for requests |
| `-x` | `--extensions` | File extension(s) to search for |
| `-H` | `--headers` | Specify HTTP headers, e.g. `-H 'Header1: val1'` |
| `-k` | `--no-tls-validation` | Skip TLS certificate verification (bypass invalid certs) |
| `-n` | `--no-status` | Don't print status codes |
| `-P` | `--password` | Password for Basic Auth |
| `-s` | `--status-codes` | Positive status codes (only show these) |
| `-b` | `--status-codes-blacklist` | Negative status codes (hide these) |
| `-U` | `--username` | Username for Basic Auth |

> See the full docs for the complete flag list. These are the common options you'll use often.


### TLS & the `-k` flag
When a target is running HTTPS with a self‑signed or invalid certificate (common in CTF labs), Gobuster may error out when it tries to validate TLS. Use the `-k` flag to skip TLS verification and continue scanning:

```bash
gobuster dir -u https://target.thm -w wordlist -k
```

This prevents Gobuster from failing due to certificate errors. The `-k` flag works in `dir` and `vhost` modes.


### `dns` Mode (subdomain brute force)
`dns` mode brute‑forces subdomains for a domain. Subdomains often host different applications and can be overlooked — they may contain unique vulnerabilities.

**Basic syntax**:

```bash
gobuster dns -d <domain> -w <WORDLIST>
```

**Example**:

```bash
gobuster dns -d mydomain.thm -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
```

If Gobuster finds subdomains, it will list them in the terminal.

**Useful `dns` flags (selected)**

| Flag | Long flag | Description |
|---|---:|---|
| `-c` | `--show-cname` | Show CNAME records (cannot be used with `-i`) |
| `-i` | `--show-ips` | Show IP addresses for found hosts |
| `-r` | `--resolver` | Use custom DNS server (format `server.com` or `server.com:port`) |

`-d` (domain) and `-w` (wordlist) are the main flags you'll need for `dns` mode.


### `vhost` Mode (virtual host brute force)
`vhost` mode brute‑forces virtual hosts — different websites hosted on the same IP (via HTTP `Host:` header). Virtual hosts can hide entirely different content than the main site and are worth checking.

**Basic syntax**:

```bash
gobuster vhost -u <URL> -w <WORDLIST>
```

**Example**:

```bash
gobuster vhost -u http://example.com -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
```

Many of the same `dir` flags apply here (e.g. headers, cookies, TLS skipping).

---

## 5. Important flags and examples (quick reference)

**Directory scan (simple)**

```bash
gobuster dir -u http://10.10.10.10 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

**Directory scan with extensions and TLS skip**

```bash
gobuster dir -u https://target.thm -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt   -x .php,.html,.txt -k
```

**DNS scan**

```bash
gobuster dns -d target.thm -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
```

**VHost scan**

```bash
gobuster vhost -u http://example.com -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
```

---

## 6. Useful global flags
These flags apply across Gobuster modes.

| Flag | Long flag | Description |
|---|---:|---|
| `-t` | `--threads` | Number of concurrent threads (default 10) |
| `-v` | `--verbose` | Verbose output |
| `-z` | `--no-progress` | Don't display progress |
| `-q` | `--quiet` | Don't print the banner and other noise |
| `-o` | `--output` | Output file to write results to |

**Tip:** I typically change threads to `64` on powerful hosts to speed scans up:

```bash
gobuster dir -u http://target -w wordlist -t 64
```

Be mindful of noise and potential rate limits when increasing concurrency.

---

## 7. Useful wordlists
Good wordlists are key to effective enumeration. Kali ships with some default lists; SecLists adds many more.

**Kali default lists (examples)**

```
/usr/share/wordlists/dirbuster/directory-list-2.3-*.txt
/usr/share/wordlists/dirbuster/directory-list-1.0.txt
/usr/share/wordlists/dirb/big.txt
/usr/share/wordlists/dirb/common.txt
/usr/share/wordlists/dirb/small.txt
/usr/share/wordlists/dirb/extensions_common.txt  # useful when fuzzing for files
```

**SecLists**
Daniel Miessler's SecLists project compiles many lists used for discovery. On Kali you can install it with:

```bash
sudo apt install seclists
```

A popular subdomain list included with SecLists is:

```
/usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
```

Between Kali defaults and SecLists you'll have plenty of options for CTFs and tests.

---

## 8. Practical tips & best practices
- **Always include the protocol** (`http://` or `https://`) in `-u`.
- **Use `-k`** when targeting CTF labs or hosts with self‑signed certificates.
- **Start with smaller wordlists** for quick wins; then escalate to larger lists if needed.
- **Filter by status codes**: use `-s` to show only interesting statuses (e.g. `200,301,302,401`) and `-b` to blacklist uninteresting ones (e.g. `404`).
- **Try different wordlists across modes**: directory lists can sometimes reveal subdomain names and vice versa.
- **Be considerate**: on real engagements, confirm scope and throttle threads to avoid DoS.
- **Use output files** (`-o`) to save results for later analysis.

---

## 9. Where to go for help & further reading
- Gobuster official documentation (project README / docs)
- SecLists (Daniel Miessler) — for curated wordlists
- TryHackMe / HackTheBox labs for hands‑on practice
- Community writeups, blog posts and YouTube tutorials on web enumeration

---

## 10. Suggested practice lab — TryHackMe: Blog (WordPress)
The "Blog" room on TryHackMe uses WordPress, which has a large, predictable directory structure that makes it ideal for directory enumeration. Practical steps:

1. Run a quick Gobuster `dir` scan against the target root with a moderate wordlist.
2. If HTTPS is enabled and certs are invalid, add `-k`.
3. Use `-x` to look for `.php` pages and `.txt` files that may reveal sensitive info.
4. Try `dns` mode on the target domain to find subdomains.
5. Optionally, run `vhost` mode to find virtual hosts that may host other applications.

---

## Appendix — Full example commands (copy/paste)

```bash
# Basic dir
gobuster dir -u http://10.10.10.10 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

# Dir with extensions and TLS skip
gobuster dir -u https://target.thm -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x .php,.html,.txt -k -t 64 -o gobuster-dir-results.txt

# DNS scan (subdomain brute force)
gobuster dns -d target.thm -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -i

# VHost scan
gobuster vhost -u http://example.com -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -t 64
```

---

## Closing thoughts
Gobuster is a compact, fast and highly useful tool for web enumeration. With the commands and flags covered here, you'll be able to discover directories, files, subdomains, and virtual hosts — the foundational steps for further manual inspection and exploitation. Pair Gobuster with thoughtful wordlist selection and conservative thread settings when targeting live infrastructure.

Happy enumerating — and good luck on the Blog room!

---

*End of e‑paper.*
