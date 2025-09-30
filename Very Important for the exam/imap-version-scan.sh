#!/usr/bin/env bash
# imap-version-scan.sh
# Usage: ./imap-version-scan.sh ips.txt
# Requires: nmap, openssl, nc, awk, grep, timeout
#
# Scans a list of IPs for IMAP (ports 143 and 993), attempts to grab banners/CAPABILITIES,
# and writes results to imap-results.csv
#
# IMPORTANT: Only run this against hosts/networks you are authorized to test.

set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <ip-list-file>"
  exit 2
fi

IPFILE="$1"
OUTCSV="imap-results.csv"

echo "ip,port,open,probe_method,banner_or_capabilities" > "$OUTCSV"

while IFS= read -r ip || [[ -n "$ip" ]]; do
  ip=$(echo "$ip" | tr -d '\r\n' | awk '{print $1}')
  [[ -z "$ip" ]] && continue

  echo "==> Scanning $ip"

  # quick nmap to find which of 143/993 are open
  nm=$(nmap -Pn -p 143,993 --open -oG - "$ip" 2>/dev/null || true)

  # if no Ports line found, record and continue
  if ! echo "$nm" | grep -q "Ports:"; then
    echo "$ip,NA,none,nmap,none" >> "$OUTCSV"
    continue
  fi

  # Check each relevant port
  for port in 993 143; do
    if echo "$nm" | grep -q "${port}/open"; then
      echo "  port $port open on $ip"

      # Run nmap service/version detection with imap-capabilities script (capture both grepable and normal)
      nmap_grep=$(nmap -Pn -sV -p "$port" --script=imap-capabilities --script-timeout 10s "$ip" -oG - 2>/dev/null || true)
      nmap_full=$(nmap -Pn -sV -p "$port" --script=imap-capabilities --script-timeout 10s "$ip" 2>/dev/null || true)

      # Try direct interaction to fetch greeting/capabilities
      cap=""
      if [[ "$port" -eq 993 ]]; then
        cap=$(timeout 8 bash -c "printf 'A001 CAPABILITY\r\nA002 LOGOUT\r\n' | openssl s_client -crlf -connect ${ip}:993 -quiet 2>/dev/null" || true)
      else
        # Try STARTTLS via openssl
        cap=$(timeout 8 bash -c "printf 'A001 CAPABILITY\r\nA002 LOGOUT\r\n' | openssl s_client -crlf -starttls imap -connect ${ip}:143 -quiet 2>/dev/null" || true)
        # If nothing returned, try plaintext
        if [[ -z "$cap" ]]; then
          cap=$(timeout 5 bash -c "( printf 'A001 CAPABILITY\r\nA002 LOGOUT\r\n'; sleep 1 ) | nc ${ip} 143 2>/dev/null" || true)
        fi
      fi

      # Combine outputs for parsing
      combined=$(printf "%s\n%s\n%s\n" "$nmap_grep" "$nmap_full" "$cap" | tr '\n' ' ' | tr -s ' ' | sed 's/,/;/g' | sed 's/"/'"'"'/g')

      # Heuristics to extract server product/version hints
      server_hint=$(echo "$combined" | grep -Eoi 'dovecot(/[0-9\.]+|[[:space:]]+[0-9\.]+)?|cyrus imap(v| )[0-9\.]+|cyrus-imapd|courier-imap(/[0-9\.]+)?|exchange|microsoft|uw-imap|uwimap|imapd|zimbra(/[0-9\.]+)?|uw-imapd' | head -n1 || true)
      capability_hint=$(echo "$combined" | grep -Eoi 'IMAP4rev1|SASL-IR|ID|ACL|QUOTA|NAMESPACE|THREAD|UIDPLUS|LITERAL\+|CONDSTORE|CATENATE' | tr '\n' ' ' | sed 's/  */ /g' || true)

      probe_method="openssl/nmap"
      if [[ -n "$server_hint" ]]; then
        info="$server_hint ${capability_hint}"
      elif [[ -n "$capability_hint" ]]; then
        info="$capability_hint"
      elif [[ -n "$combined" ]]; then
        info=$(echo "$combined" | cut -c1-240)
      else
        info="no-info"
      fi

      open_str="open"
      echo "$ip,$port,$open_str,$probe_method,\"$info\"" >> "$OUTCSV"
    fi
  done

done < "$IPFILE"

echo "Done. Results saved to $OUTCSV"
