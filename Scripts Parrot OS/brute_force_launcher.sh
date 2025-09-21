#!/bin/bash
set -euo pipefail

if [ $# -lt 3 ] || [ $# -gt 4 ]; then
  echo "Usage: $0 <service> <target> <user> [wordlist]"
  echo "Services: ssh, ftp, smb"
  echo "If wordlist is not provided, defaults to ~/ceh-tools/wordlists/rockyou.txt"
  exit 1
fi

SERVICE=$1
TARGET=$2
USER=$3
WORDLIST=${4:-~/ceh-tools/wordlists/rockyou.txt}

if [ ! -f "$WORDLIST" ]; then
  echo "[!] Wordlist file not found: $WORDLIST"
  exit 1
fi

OUTDIR=~/ceh-tools/results/$TARGET
mkdir -p "$OUTDIR"

case "$SERVICE" in
  ssh)
    hydra -L <(echo "$USER") -P "$WORDLIST" -t 4 ssh://"$TARGET" -o "$OUTDIR/hydra_ssh.txt"
    ;;
  ftp)
    hydra -L <(echo "$USER") -P "$WORDLIST" -t 4 ftp://"$TARGET" -o "$OUTDIR/hydra_ftp.txt"
    ;;
  smb)
    hydra -L <(echo "$USER") -P "$WORDLIST" -t 4 smb://"$TARGET" -o "$OUTDIR/hydra_smb.txt"
    ;;
  *)
    echo "[!] Unknown service: $SERVICE"
    exit 1
    ;;
esac

echo "[*] Brute force on $SERVICE finished for target $TARGET user $USER."
echo "[*] Results saved in $OUTDIR"
