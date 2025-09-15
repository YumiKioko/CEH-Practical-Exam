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
```
dnsrecon -d example.com
```
- **sublist3r**: Enumeração de subdomínios
	
```
sublist3r -d target.com -o subdomains.txt

```
## Active Reconnaissance
- **nmap**: Scan de rede básico
```
namp -sn target
```
- **nmap**: Scan completo de portas
```
nmap -sS -sV -sC -O -A -p- target
```
- **nmap**: Scan sem resolução de DNS
```
nmap -Pn -n -T4 -sCV target
```


