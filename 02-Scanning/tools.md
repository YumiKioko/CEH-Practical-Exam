Scanning Tools

<<<<<<< HEAD
# Port Scanning

Nmap (Essencial)

# Vulnerability Scanning

 Nikto
- Scanner de vulnerabilidades web

# Scripts Úteis
=======
Port Scanning

Nmap (Essencial)
- Stealth Scan: `nmap -sS target`
- Service Version: `nmap -sV target`
- OS Detection: `nmap -O target`
- Script Scan: `nmap -sC target`
- UDP Scan: `nmap -sU target`

 Masscan
- Fast Scan: `masscan -p1-65535 target --rate=1000`

 Rustscan
- Quick Scan: `rustscan -a target`

 Vulnerability Scanning

 OpenVAS
- Scanner de vulnerabilidades completo
- Interface web para gestão

 Nikto
- Scanner de vulnerabilidades web
- `nikto -h target`

 Nuclei
- Scanner moderno baseado em templates
- `nuclei -u target -t cves/`

Scripts Úteis
>>>>>>> c1b4712547a17da4c827bb6759b6cfb87d5bc851

Scan completo com nmap

nmap -sS -sV -sC -O -A -p- -oA complete_scan target

Scan UDP top ports

nmap -sU --top-ports 1000 target

Scan com scripts vulnerabilidades

nmap --script vuln target

<<<<<<< HEAD



=======
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
>>>>>>> c1b4712547a17da4c827bb6759b6cfb87d5bc851

