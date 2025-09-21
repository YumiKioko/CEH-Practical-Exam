#!/bin/bash
set -euo pipefail

if [ $# -lt 1 ]; then
  echo "Usage: nmap_quick.sh <target> [ports]"
  exit 1
fi

TARGET=$1
PORTS=${2:-"1-65535"}
nmap -sC -sV -T4 -Pn -p"$PORTS" -oN nmap_quick_${TARGET}.txt "$TARGET"
