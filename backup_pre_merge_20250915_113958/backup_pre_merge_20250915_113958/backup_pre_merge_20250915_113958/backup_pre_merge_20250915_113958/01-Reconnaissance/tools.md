# Reconnaissance Tools

## Passive Reconnaissance

### OSINT
- **theHarvester**: Coleta emails, subdomínios, IPs
<<<<<<< HEAD

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

**netcratf**
Go to: https://sitereport.netcraft.com/
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
=======
- **Shodan CLI**: Pesquisa em dispositivos conectados
- **Maltego**: Análise de links e relacionamentos
- **Recon-ng**: Framework de reconhecimento
- **SpiderFoot**: Automação de OSINT

### DNS Enumeration
- **dnsrecon**: Enumeração DNS completa
- **fierce**: Descoberta de subdomínios
- **sublist3r**: Enumeração de subdomínios
- **amass**: Mapeamento de superfície de ataque

## Active Reconnaissance

### Network Discovery
- **nmap**: Scanner de rede essencial
- **masscan**: Scanner de portas rápido
- **rustscan**: Scanner moderno e rápido
- **zmap**: Scanner de internet

### Scripts Úteis
```bash
# Descoberta básica de rede
nmap -sn 192.168.1.0/24

# Scan completo de portas
nmap -sS -sV -sC -O -A -p- target

# Enumeração de subdomínios
sublist3r -d target.com -o subdomains.txt

# TheHarvester
theHarvester -d target.com -l 500 -b all
>>>>>>> c1b4712547a17da4c827bb6759b6cfb87d5bc851
