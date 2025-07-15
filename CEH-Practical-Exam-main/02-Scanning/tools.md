Scanning Tools

# Port Scanning

Nmap (Essencial)

# Vulnerability Scanning

 Nikto
- Scanner de vulnerabilidades web

# Scripts Úteis

Scan completo com nmap

nmap -sS -sV -sC -O -A -p- -oA complete_scan target

Scan UDP top ports

nmap -sU --top-ports 1000 target

Scan com scripts vulnerabilidades

nmap --script vuln target





