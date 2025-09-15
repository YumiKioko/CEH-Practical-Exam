<<<<<<< HEAD
# Nikto Cheat Sheet — Plugins, Verbosity, Tuning, and Saving Findings

**Purpose:** Practical, copy‑paste cheat sheet for using **Nikto** to scan web servers. Focuses on plugin usage, verbosity/display controls, tuning scans for vulnerability searching, and saving/reporting results (CTF and lab focused).

**Sources:** Nikto official repo & docs (usage & flags). citeturn1view0turn1view1

---

## Quick install (Kali/Debian) & run
```bash
# Debian/Ubuntu/Kali (package may be available)
sudo apt update && sudo apt install nikto

# Or run from GitHub repo (Perl script)
git clone https://github.com/sullo/nikto.git
cd nikto/program
perl nikto.pl -h http://example.com
```

(Official repo and how-to run are on GitHub). citeturn1view0

---

## Basic usage (core flags)
```bash
nikto -h http://target.example.com
# or perl nikto.pl -h http://target.example.com
```
Key flags you'll use often (canonical names shown in Nikto docs): `-h` (host), `-port`, `-ssl`/`-nossl`, `-timeout`, `-maxtime`, `-no404`. citeturn1view0

---

## Plugins — listing, selecting, and updating
- **List available plugins** (no tests run):
```bash
nikto -list-plugins
# or perl nikto.pl -list-plugins
```
- **Run only specific plugins** (comma separated or a single name):
```bash
nikto -h http://target -Plugins pluginname,anotherplugin
```
- **Default behaviour**: `-Plugins ALL` runs all built-in plugins (this is default). You can restrict to reduce noise or speed up scans. citeturn1view0

- **Updating plugin DB**: Nikto keeps plugin databases; update with:
```bash
nikto -update
```
(Updates databases and plugins from CIRT.net). citeturn1view0

**Why use plugins:** plugins allow targeted checks (e.g., checks for specific server software, default credentials, or vendor‑specific issues). Use `-list-plugins` to discover what checks are available and then run only the ones you need to reduce false positives and time.

---

## Verbosity & display controls (`-Display`)
Nikto has a flexible `-Display` option to control what output you see in real time. Combine letters / numbers for different output types:

Common `-Display` values (from docs): citeturn1view0
- `1` — show redirects.  
- `2` — show cookies received.  
- `3` — show all 200/OK responses.  
- `4` — show URLs which require authentication.  
- `D` — debug output (very noisy).  
- `E` — display all HTTP errors.  
- `P` — print progress to STDOUT.  
- `S` — scrub output of IPs and hostnames (useful for sharing).  
- `V` — verbose output (more details).

**Examples**:
```bash
# verbose + progress + show 200s
nikto -h http://target -Display PV3
# debug mode (very verbose, troubleshooting)
nikto -h http://target -Display D
```

Tip: For development and manual verification use `V` or `D`. For concise scans in CTFs, `P` (progress) plus `3` or `E` can be helpful to see interesting responses quickly.

---

## Tuning scans (`-Tuning`) — focus your checks
Nikto's `-Tuning` option lets you choose categories of tests to run. This is extremely useful to focus on likely issues and avoid irrelevant noise. The tuning options map to categories (run multiple by concatenating digits/letters):

From the Nikto docs: citeturn1view0
- `1` — Interesting File / Seen in logs  
- `2` — Misconfiguration / Default File  
- `3` — Information Disclosure  
- `4` — Injection (XSS/Script/HTML)  
- `5` — Remote File Retrieval - Inside Web Root  
- `6` — Denial of Service  
- `7` — Remote File Retrieval - Server Wide  
- `8` — Command Execution / Remote Shell  
- `9` — SQL Injection  
- `0` — File Upload  
- `a` — Authentication Bypass  
- `b` — Software Identification  
- `c` — Remote Source Inclusion  
- `x` — Reverse tuning (include all except specified)

**Examples**:
```bash
# Run only misconfiguration/default file checks + info disclosure
nikto -h http://target -Tuning 23

# Run everything except DoS/Command Execution/SQL (safer)
nikto -h http://target -Tuning x6789

# Focus only on injection & RFI
nikto -h http://target -Tuning 49
```

**CTF tip:** start with `-Tuning 23` (misconfigurations + info disclosure) to find low-hanging fruits quickly, then expand to `4,5,7,9` for deeper checks if permitted.

---

## Tuning + plugins example for vulnerability searching
Combine `-Tuning` with `-Plugins` to run high‑value checks quickly:

```bash
# Run only plugin 'headers' and 'xss' while limiting tests to misconfigs/info disclosure
nikto -h http://target -Plugins headers,xss -Tuning 23 -Display PV
```
This reduces scan time and noise while focusing on likely exploitable items. (Choose plugins from `-list-plugins` output). citeturn1view0

---

## Saving findings — output formats & options (`-o`, `-Format`, `-Save`)
Nikto supports multiple output formats and options to save results:

- **Output file** (`-output` or `-o`) + **Format** (`-Format`):
  - Supported formats: `txt`, `csv`, `htm`, `xml`, `nbe` (Nessus), `msf` (Metasploit), etc. If you provide `-o file.ext` Nikto will infer format from the extension unless `-Format` is set. citeturn1view0
```bash
# Save HTML report
nikto -h http://target -o nikto_report.html -Format htm

# Save machine-readable XML
nikto -h http://target -o nikto_report.xml -Format xml

# Save CSV for quick parsing
nikto -h http://target -o nikto_report.csv -Format csv
```

- **Save positive responses** to a directory (`-Save`):
```bash
nikto -h http://target -Save ./nikto_hits
```
This writes copies of requests/responses that were positive (useful for manual verification).

- **Metasploit integration**:
```bash
nikto -h http://target -o nikto_msf.log -Format msf
```
This writes output in Metasploit importable format. citeturn1view0

---

## Controlling speed, time, and retries
- `-Pause` — pause (seconds) between tests (float allowed) to reduce speed/noise.  
- `-timeout` — set per-request timeout (default 10s).  
- `-maxtime` — maximum total time per host (helps bound long scans).  
- `-mutate` — attempt guessed or mutated filenames (can increase discovery but adds noise). citeturn1view0

**Example (slower, stealthier scan)**:
```bash
nikto -h http://target -Tuning 23 -Pause 0.5 -timeout 8 -Display P -o nikto_slow.txt
=======
# 🛡️ Nikto Cheat Sheet

## 🔹 Basic Usage
```bash
nikto -h <target>
```
- `<target>` = IP, domain, or URL  

---

## 🔹 Target & Ports
```bash
nikto -h example.com       # Scan domain
nikto -h 192.168.1.10      # Scan IP
nikto -h example.com -p 8080  # Custom port
>>>>>>> 840c5fad46bf0825b692909b9e0ffba727f8b83a
```

---

<<<<<<< HEAD
## Examples — practical workflows

### 1) Fast reconnaissance (CTF)
```bash
nikto -h http://10.10.10.10 -Tuning 23 -Display PV -o nikto_quick.txt
```

### 2) Focused plugin checks + save hits
```bash
nikto -h http://target -Plugins headers,cgi,userdir -Tuning 23 -Save ./positive_hits -o nikto_plugins.html -Format htm
```

### 3) Stealthy scan (production with permission)
```bash
nikto -h http://target -Tuning 23 -Pause 1 -timeout 12 -Display P -o nikto_prod.xml -Format xml
```

### 4) Full scan with Metasploit export
```bash
nikto -h http://target -o nikto_msf.nbe -Format nbe
=======
## 🔹 Output Options
```bash
nikto -h example.com -o results.txt          # Save results
nikto -h example.com -o report.xml -Format xml   # Save as XML
nikto -h example.com -o report.json -Format json # Save as JSON
>>>>>>> 840c5fad46bf0825b692909b9e0ffba727f8b83a
```

---

<<<<<<< HEAD
## Post‑processing & triage
- Grep/filter CSV or XML for severity keywords: `grep -i 'OSVDB' nikto_report.csv` or `grep -i 'XSS' nikto_report.txt`.  
- Import `msf`/`nbe` results into Metasploit / Nessus compatible workflows if desired.  
- Use saved positive responses (`-Save`) to replay or verify findings with Burp/Wireshark.

---

## Plugin development & database details
- Nikto plugins live in the `plugins` directory of the repo; see the GitHub wiki for plugin data structures and writing custom checks. citeturn1view1

---

## Ethical & practical notes
- Nikto is noisy; use it only with permission on production. In CTFs and labs crank up checks and tuning freely.  
- Use `-Display S` to scrub IPs/hostnames before sharing reports publicly. citeturn1view0

---

## Quick reference command summary
```bash
# Basic scan
nikto -h http://target

# List plugins
nikto -list-plugins

# Run specific plugins
nikto -h http://target -Plugins headers,xss

# Tuning to misconfig/info disclosure
nikto -h http://target -Tuning 23

# Save HTML report
nikto -h http://target -o report.html -Format htm

# Save positives to directory
nikto -h http://target -Save ./nikto_hits

# Stealthy scan
nikto -h http://target -Tuning 23 -Pause 1 -timeout 12 -Display P -o nikto_prod.xml -Format xml
=======
## 🔹 Scan Tuning
```bash
nikto -h example.com -Tuning 123
```
Categories:  
- `1` = Interesting files  
- `2` = Misconfigurations  
- `3` = Default files  
- `4` = Information Disclosure  
- `5` = Injection vulnerabilities  
- `6` = Server-related issues  
- `7` = XSS vulnerabilities  

---

## 🔹 SSL / Protocols
```bash
nikto -h example.com -ssl      # Force SSL
nikto -h https://example.com   # Auto-detect SSL
nikto -h example.com -nossl    # Disable SSL
>>>>>>> 840c5fad46bf0825b692909b9e0ffba727f8b83a
```

---

<<<<<<< HEAD
*End of Nikto cheat sheet.*
=======
## 🔹 Evading Detection
```bash
nikto -h example.com -useragent "Mozilla/5.0"   # Custom User-Agent
nikto -h example.com -useproxy                  # Use proxy
```

---

## 🔹 Miscellaneous
```bash
nikto -list-plugins    # Show all available plugins
nikto -D VHOST         # Virtual host scanning
nikto -timeout 10      # Set timeout in seconds
```

---

## 🔹 Example Scans
```bash
nikto -h http://example.com                 # Standard scan
nikto -h 192.168.1.15 -p 8081               # Non-standard port
nikto -h example.com -Tuning 45             # Focused tuning scan
nikto -h example.com -o scan.json -Format json   # JSON output
```

---

⚡ **Tip**: Nikto is best used with other tools (Nmap, Burp Suite, Metasploit) for deeper analysis.  
>>>>>>> 840c5fad46bf0825b692909b9e0ffba727f8b83a
