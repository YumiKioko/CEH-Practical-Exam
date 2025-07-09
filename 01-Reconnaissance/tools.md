# Reconnaissance Tools

## Passive Reconnaissance

### OSINT
- **theHarvester**: Coleta emails, subdomínios, IPs

```
theHarvester -d target.com -l 500 -b all
```

- **Recon-ng**: Framework de reconhecimento

### DNS Enumeration
- **dnsrecon**: Enumeração DNS completa


- **sublist3r**: Enumeração de subdomínios

##  Subdomain Enumeration

```
sublist3r -d target.com -o subdomains.txt
```

## Active Reconnaissance
- **nmap**: Scanner de rede essencial

## Basic Network Discovery

```bash
nmap -sn <IP>/24
```

## Scan completo de portas

```
nmap -sS -sCV -O -A -p- <IP>
```

Scan without DNS resolution

```
nmap -Pn -n -T4 -sCV <IP>
```