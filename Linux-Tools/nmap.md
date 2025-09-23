# Nmap

**Description:**  
Nmap is a powerful network scanner for host discovery, port scanning and service/OS detection.

**Basic Syntax:**
```bash
nmap [options] target
```

**Common Options & Scans:**
- `-sS` — TCP SYN scan (stealth)  
- `-sV` — Service/version detection  
- `-O` — OS detection (requires root)  
- `-p` — Specify ports (e.g. `-p 1-65535` or `-p 80,443`)  
- `-A` — Aggressive scan (`-sV -O --script=default`)  
- `-Pn` — No ping (assume hosts are up)  
- `-T4` — Timing template (faster)

**Use Cases:**
- Discover live hosts and open ports  
- Identify services and versions for vulnerability research  
- Map network topology

**Examples:**
```bash
nmap -sS -sV -p 1-1000 10.10.10.10
nmap -A --script=vuln target.com
nmap -Pn -p 80,443 192.168.1.0/24
```