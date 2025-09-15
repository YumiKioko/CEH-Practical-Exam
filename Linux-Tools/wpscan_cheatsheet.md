# WPScan Cheat Sheet — quick, CTF-focused reference

**Purpose:** concise reference for enumerating WordPress sites with WPScan — what it finds, how it finds it, useful flags, example commands, and CTF tips.

---

## Quick summary of what WPScan can discover
- **Themes** — active/default themes (by checking known locations, assets, CSS/JS references).  
- **Plugins** — installed plugins (by probing `/wp-content/plugins/<name>/`, reading `readme.txt`, and looking for embedded assets).  
- **Users** — usernames (by enumerating author pages / REST endpoints / author archive links).  
- **Vulnerabilities** — cross-reference discovered plugins/themes with WPVulnDB (requires API token).  
- **Auth checks / password attacks** — brute-force login with a provided username list and password list.  
- WPScan also shows *how* it determined a finding (e.g., Known Locations, Readme, Generator tag, assets).

---

## Installation (quick)
On Kali / Debian:
```bash
sudo apt update
sudo apt install wpscan
```
(Or use gem/bundler if you prefer the upstream release.)

---

## Basic scan syntax
```bash
wpscan --url http://target.site
```

---

## Enumerate themes / plugins / users / vulnerabilities
- Enumerate themes:
```bash
wpscan --url http://target.site --enumerate t
```
- Enumerate plugins:
```bash
wpscan --url http://target.site --enumerate p
```
- Enumerate users:
```bash
wpscan --url http://target.site --enumerate u
```
- Enumerate plugins *and* check them against WPVulnDB (requires API token):
```bash
wpscan --url http://target.site --enumerate vp --api-token YOUR_WPVULNDB_TOKEN
```
- Enumerate users & plugins at once:
```bash
wpscan --url http://target.site --enumerate u,p
```

**Notes:** WPScan will often tell you the technique used (Known Locations, Readme, Embedded Asset, etc.).

---

## How WPScan detects things (brief)
- **Themes:** checks typical theme directories and looks at loaded assets referenced by the site (e.g., `/wp-content/themes/<theme>/assets/...`) and known location patterns.
- **Plugins:** probes known plugin folder paths, checks for `readme.txt` and other fingerprintable files, and looks for JS/CSS/assets loaded by pages.
- **Users:** enumerates author archive URLs or WP REST endpoints and parses responses for usernames.
- **Versions/Vulns:** WPScan maps discovered names + version (from readmes / asset headers / meta) against WPVulnDB.

---

## Password / login bruteforce
- Bruteforce a single user using `rockyou.txt`:
```bash
wpscan --url http://target.site --usernames alice --passwords /path/to/rockyou.txt
```
- Bruteforce multiple usernames and passwords:
```bash
wpscan --url http://target.site --usernames users.txt --passwords passwords.txt
```
**CTF tip:** capture a valid session cookie in your browser and use it (or test authenticated-only areas) instead of brute forcing if possible.

---

## Aggressiveness / detection profiles (to avoid/induce noise)
- WPScan defaults to being cautious (low noise). To be more aggressive for CTFs:
```bash
wpscan --url http://target.site --plugins-detection aggressive --enumerate p
```
- Aggressive detection will do more probing and may trigger WAFs — on real targets, always have permission.

---

## Useful options (practical)
- `--enumerate <ARG>` — `p,t,u,vt,vtp,vp` etc. (p=plugins, t=themes, u=users, v=use with other args for vulnerability checks).  
- `--api-token <TOKEN>` — set your WPVulnDB API token to enable vulnerability cross-checks.  
- `--plugins-detection <passive|aggressive>` — change detection mode for plugins.  
- `--random-agent` — rotate user agents (helpful to avoid simple blocks).  
- `--disable-tls-checks` — skip TLS certificate validation for self-signed HTTPS (CTF labs).  
- `--cookie 'NAME=VAL'` — scan with a session cookie (authenticated scanning).  
- `--proxy http://127.0.0.1:8080` — route through Burp/Proxy for manual inspection.  
- `-o / --output <file>` — save results to file.  
- `--plugins-version-all` — try to enumerate version info for plugins (may increase requests).

> Exact option names/availability may vary slightly between WPScan versions — check `wpscan --help` for your installed version.

---

## Example workflows & commands (CTF-oriented)

### 1) Quick reconnaissance (light)
```bash
wpscan --url http://10.10.10.10 --enumerate t,p,u -o wpscan_quick.txt
```

### 2) Aggressive plugin detection + save output
```bash
wpscan --url http://target.ctf --enumerate p --plugins-detection aggressive -o wpscan_plugins.txt
```

### 3) Check discovered plugins for known vulns (requires API token)
```bash
wpscan --url http://target.ctf --enumerate vp --api-token YOUR_WPVULNDB_TOKEN -o wpscan_vulns.txt
```

### 4) Brute force a specific user with rockyou
```bash
wpscan --url http://target.ctf --usernames admin --passwords /usr/share/wordlists/rockyou.txt
```

### 5) Authenticated scan using a session cookie (e.g., after login)
```bash
wpscan --url http://target.ctf --cookie 'wordpress_logged_in=abcd1234' --enumerate p,t -o wpscan_auth.txt
```

### 6) Throttle / stealth (reduce requests)
```bash
wpscan --url http://target.ctf --enumerate p --throttle 0.5
```
*(Note: `--throttle` or equivalent may exist depending on version — check help.)*

---

## Tips to improve accuracy and reduce false positives
- **Use `--plugins-detection aggressive`** in CTFs to find more than passive detection would.  
- **Combine WPScan with manual inspection:** look at browser DevTools → Network / Page Source for theme/plugin asset paths (fast manual confirmation).  
- **If you see a plugin name but no version, try fetching `/wp-content/plugins/<plugin>/readme.txt`** or check asset file headers to locate version strings.  
- **Use `--api-token`** (WPVulnDB) to avoid manual CVE lookups — WPScan will match versions to known vulns.  
- **Filter output** saved with `-o` and `grep` for `Found` / `Vulnerable` to quickly identify targets.

---

## How WPScan reports findings (what to look for)
- It annotates each finding with the *method* (e.g., `Detected By: Known Locations`, `Confirmed via Readme`, `Found via Embedded Asset`) — use this to validate the result.
- Pay attention to version numbers — they determine whether an item is *vulnerable* according to WPVulnDB.

---

## Where WPScan can miss things
- If a site blocks probing (WAF) or uses non-standard plugin directories, WPScan may miss components.  
- If plugin/theme assets are obfuscated or loaded from CDN, detection can be harder. In these cases, use aggressive detection and manual inspection.

---

## Ethics & Good Practice
- **Always have explicit permission** before scanning a live/production site. WPScan can be noisy and trigger defenses.  
- In CTF/lab environments, increase aggressiveness and threads freely; on real targets lower noise and confirm scope.

---

## Quick reference table

| Task | Flag / Command |
|---|---|
| Enumerate plugins | `--enumerate p` |
| Enumerate themes | `--enumerate t` |
| Enumerate users | `--enumerate u` |
| Check plugin vulns (WPVulnDB) | `--enumerate vp` + `--api-token TOKEN` |
| Aggressive plugin detection | `--plugins-detection aggressive` |
| Brute force password | `--usernames <file|name> --passwords <file>` |
| Authenticated scan | `--cookie 'NAME=VAL'` |

---

If you want I can:
- convert this to a downloadable `wpscan_cheatsheet.md`,  
- produce a one-page printable PDF, or  
- generate a small workflow script that: enumerates plugins/themes/users → queries WPVulnDB (if token provided) → runs a password attack (if you supply username/password lists).  

Which would you like?
