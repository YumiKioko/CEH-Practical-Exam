# IMAP Version / Fingerprint Scan — Practical Guide + Ready-to-run Script

> **Warning:** Only run this guide against hosts/networks you are authorized to test. These methods detect what the server advertises (banner, CAPABILITY tokens, or service fingerprints). Many IMAP servers intentionally hide precise version info.

---

## Overview
This document provides a short methodology and a ready-to-run Bash script (`imap-version-scan.sh`) you can use on Parrot OS (or other Debian-like distributions) to detect IMAP servers and attempt to identify their software and advertised versions from a list of IPs. The script aggregates findings into a CSV (`imap-results.csv`).

## Quick approach (summary)
1. Port scan for IMAP ports (TCP **143** and **993**).
2. Use `nmap` service/version detection and the `imap-capabilities` NSE script.
3. If a port is open, connect and request `CAPABILITY`:
   - For implicit TLS (port 993): use `openssl s_client`.
   - For plain IMAP or STARTTLS (port 143): use `openssl -starttls imap` and fall back to plaintext if needed.
4. Parse returned greeting banner / `CAPABILITY` tokens for server product (Dovecot, Cyrus, Exchange/IMAP, Courier, Zimbra, etc.) and any version strings.
5. Aggregate results into a CSV or table for review.

## Tools used (available on Parrot OS)
- `nmap` (with `-sV` and NSE scripts)
- `openssl s_client` (for TLS / STARTTLS IMAP conversations)
- `nc`, `timeout`, `printf`, `grep`, `awk`, `jq` (for parsing / scripting)

---

## Manual commands (examples)
```bash
# Quick port/service scan
nmap -Pn -sV -p 143,993 <IP>

# NSE script to request IMAP capabilities
nmap -Pn -p 143,993 --script=imap-capabilities <IP>

# Connect to implicit-TLS IMAP (port 993) and ask CAPABILITY
printf "A001 CAPABILITY\r\nA002 LOGOUT\r\n" | openssl s_client -crlf -connect <IP>:993 -quiet

# Connect to plain IMAP and attempt STARTTLS (port 143)
printf "A001 CAPABILITY\r\nA002 LOGOUT\r\n" | openssl s_client -crlf -starttls imap -connect <IP>:143 -quiet

# Connect without TLS (if allowed/open) using netcat
( printf "A001 CAPABILITY\r\nA002 LOGOUT\r\n"; sleep 1 ) | nc <IP> 143
```

Look for responses such as:
- `* OK [CAPABILITY ...] Dovecot ready.`
- `Cyrus IMAP v2.4.17` or similar.
- Capability tokens: `IMAP4rev1`, `SASL-IR`, `AUTH=PLAIN`, `ID`, `UIDPLUS`, `NAMESPACE`, etc.

---

## Ready-to-run script
Save the script below as `imap-version-scan.sh`, make it executable (`chmod +x imap-version-scan.sh`), and run `./imap-version-scan.sh ips.txt` where `ips.txt` contains one IP per line. The script writes `imap-results.csv` in the current directory.

```bash
#!/usr/bin/env bash
# imap-version-scan.sh
# Usage: ./imap-version-scan.sh ips.txt
# Requires: nmap, openssl, nc, awk, grep, timeout

set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <ip-list-file>"
  exit 2
fi

IPFILE="$1"
OUTCSV="imap-results.csv"

echo "ip,port,open,probe_method,banner_or_capabilities" > "$OUTCSV"

while IFS= read -r ip; do
  ip=$(echo "$ip" | tr -d '\r\n' | awk '{print $1}')
  [[ -z "$ip" ]] && continue
  echo "==> Scanning $ip"

  # 1) quick nmap to find which ports are open (143/993)
  nm=$(nmap -Pn -p 143,993 --open -oG - "$ip" 2>/dev/null)

  # parse open ports
  if ! echo "$nm" | grep -q "Ports:"; then
    echo "$ip,NA,none,nmap,none" >> "$OUTCSV"
    continue
  fi

  # Check port 993 first (implicit TLS) then 143
  for port in 993 143; do
    if echo "$nm" | grep -q "${port}/open"; then
      echo " port $port open on $ip"

      # run nmap service/version + imap-capabilities script (fast)
      nout=$(nmap -Pn -sV -p "$port" --script=imap-capabilities --script-timeout 10s "$ip" -oG - 2>/dev/null || true)

      # capture verbose nmap output as well
      nmap_full=$(nmap -Pn -sV -p "$port" --script=imap-capabilities --script-timeout 10s "$ip" 2>/dev/null || true)

      # attempt direct connection to fetch IMAP greeting/capabilities
      if [[ "$port" -eq 993 ]]; then
        cap=$(timeout 6 bash -c "printf 'A001 CAPABILITY\r\nA002 LOGOUT\r\n' | openssl s_client -crlf -connect ${ip}:993 -quiet 2>/dev/null" || true)
      else
        cap=$(timeout 6 bash -c "printf 'A001 CAPABILITY\r\nA002 LOGOUT\r\n' | openssl s_client -crlf -starttls imap -connect ${ip}:143 -quiet 2>/dev/null" || true)

        # if no TLS response, try plaintext with nc
        if [[ -z "${cap}" ]]; then
          cap=$(timeout 4 bash -c "( printf 'A001 CAPABILITY\r\nA002 LOGOUT\r\n'; sleep 1 ) | nc ${ip} 143 2>/dev/null" || true)
        fi
      fi

      # Normalize output (single line, strip commas)
      combined=$(printf "%s\n%s\n%s\n" "$nout" "$nmap_full" "$cap" | tr '\n' ' ' | tr -s ' ' | sed 's/,/;/g' | sed 's/\"/'"'"'/g')

      # heuristics to find recognizable server names/versions
      server_hint=$(echo "$combined" | grep -Eoi 'dovecot(/[0-9\.]+|[[:space:]]+[0-9\.]+)?|cyrus imap(v| )[0-9\.]+|cyrus-imapd|courier-imap(/[0-9\.]+)?|exchange|microsoft|uw-imap|uwimap|imapd|gmail|google|zimbra(/[0-9\.]+)?' | head -n1 || true)

      capability_hint=$(echo "$combined" | grep -Eoi 'IMAP4rev1|SASL-IR|ID|ACL|QUOTA|NAMESPACE|THREAD|UIDPLUS|LITERAL+' | tr '\n' ' ' | sed 's/ */ /g' || true)

      probe_method="openssl/nmap"

      if [[ -n "$server_hint" ]]; then
        info="$server_hint ${capability_hint}"
      elif [[ -n "$capability_hint" ]]; then
        info="$capability_hint"
      elif [[ -n "$combined" ]]; then
        info=$(echo "$combined" | cut -c1-200)
      else
        info="no-info"
      fi

      open_str="open"
      echo "$ip,$port,$open_str,$probe_method,\"$info\"" >> "$OUTCSV"
    fi
  done

done < "$IPFILE"

echo "Done. Results saved to $OUTCSV"
```

---

## CSV output format (template)
```
ip,port,open,probe_method,banner_or_capabilities
# example:
# 192.0.2.1,993,open,openssl/nmap,"Dovecot ready; UIDPLUS NAMESPACE IMAP4rev1"
```

---

## How it works (short)
- `nmap` finds open IMAP ports (143/993).
- For each open port, the script runs `nmap --script=imap-capabilities` and connects using `openssl s_client` (implicit TLS or STARTTLS) to request `CAPABILITY` and record the server greeting.
- The script parses banners and `CAPABILITY` responses for known server signatures (Dovecot, Cyrus, Courier, UW IMAP, Zimbra, Microsoft Exchange, etc.) and common capability tokens.

## What to expect in findings
- **Dovecot** often includes `Dovecot` in the greeting or a `Dovecot ready.` message.
- **Cyrus** may show `Cyrus IMAP` or `imapd` and sometimes a version.
- **Microsoft Exchange** IMAP responses are often terse; cross-correlation with LDAP/SMB/HTTP may reveal more.
- **Zimbra**, hosted providers, and other MTA stacks may return product/version tokens.
- **Many providers will not publish explicit versions.** In those cases, capability tokens like `UIDPLUS`, `NAMESPACE`, `ID`, SASL mechanisms, and other extensions are useful for fingerprinting.

---

## Next steps / deeper fingerprinting
- Use `nmap -sV --version-all --version-trace` for more verbose fingerprinting.
- Combine IMAP findings with other service banners (SMB, LDAP, HTTP) to improve confidence for Exchange/Domains.
- Create a fingerprint database (regexes) for known server greeting patterns and capability sets.

---

## Offer
If you want, I can:
- Generate a ready-to-download script file (`imap-version-scan.sh`) and the CSV template now, or
- Modify the script to also try LDAP/SMB cross-correlation (useful for Exchange/DC detection), or
- Provide a concise one-liner to run interactively against a single IP.

Tell me which you'd like and I will produce it.

