#!/bin/bash
set -euo pipefail

if [ $# -ne 1 ]; then
  echo "Usage: $0 <target_ip_or_hostname>"
  exit 1
fi

TARGET=$1
OUTDIR=~/ceh-tools/results/$TARGET
mkdir -p "$OUTDIR"

echo "[*] Starting quick recon for $TARGET..."

# Quick Nmap scan - top 1000 ports + service/version detection + OS detection
echo "[*] Running Nmap scan..."
nmap -sC -sV -O -oN "$OUTDIR/nmap_quick.txt" "$TARGET"

# Basic enum: SMB enum if port 445 is open
if grep -q '445/tcp open' "$OUTDIR/nmap_quick.txt"; then
  echo "[*] SMB detected on $TARGET, running enum4linux..."
  enum4linux "$TARGET" > "$OUTDIR/enum4linux.txt"
fi

# Check for HTTP ports and run nikto + gobuster
HTTP_PORTS=$(grep -E '(^| )[0-9]{1,5}/tcp open' "$OUTDIR/nmap_quick.txt" | grep -E '80|443|8080|8000' | awk '{print $1}' | cut -d/ -f1)

if [ -n "$HTTP_PORTS" ]; then
  for port in $HTTP_PORTS; do
    echo "[*] HTTP service on port $port detected. Running Nikto and Gobuster..."
    nikto -h "$TARGET" -p "$port" -output "$OUTDIR/nikto_port_${port}.txt"
    gobuster dir -u "http://$TARGET:$port/" -w ~/ceh-tools/wordlists/common.txt -o "$OUTDIR/gobuster_port_${port}.txt"
  done
else
  echo "[*] No HTTP services detected."
fi

echo "[*] Recon complete. Results saved in $OUTDIR"
