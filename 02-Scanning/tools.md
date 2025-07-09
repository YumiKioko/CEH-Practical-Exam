Scanning Tools

# Port Scanning

Nmap (Essencial)
- Stealth Scan: `nmap -sS target`
- Service Version: `nmap -sV target`
- OS Detection: `nmap -O target`
- Script Scan: `nmap -sC target`
- UDP Scan: `nmap -sU target`

# Vulnerability Scanning

 Nikto
- Scanner de vulnerabilidades web
- `nikto -h target`

# Scripts Úteis

Scan completo com nmap

nmap -sS -sV -sC -O -A -p- -oA complete_scan target

Scan UDP top ports

nmap -sU --top-ports 1000 target

Scan com scripts vulnerabilidades

nmap --script vuln target

Masscan para descoberta rápida

masscan -p1-65535 target --rate=1000 -oG masscan.txt

Rustscan com output para nmap

rustscan -a target -- -sV -sC

Nuclei
Fast and modern vulnerability scanner using templates

Scan using CVE templates:
nuclei -u http://target -t cves/

All templates:
nuclei -u http://target -t templates/

Update templates:
nuclei -update-templates

