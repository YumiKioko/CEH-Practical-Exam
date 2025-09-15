<<<<<<< HEAD
Enumeration Tools

# Service Enumeration
=======
 Enumeration Tools

 SMB/NetBIOS
- enum4linux: Enumeração completa SMB/NetBIOS
- smbclient: Cliente SMB
- smbmap: Mapeamento de shares SMB
<<<<<<< HEAD

 FTP
- ftp: Cliente FTP nativo

 SSH
- ssh: Cliente SSH

 HTTP/HTTPS
- gobuster: Directory/file brute force
=======
- rpcclient: Cliente RPC

 FTP
- ftp: Cliente FTP nativo
- ncftp: Cliente FTP avançado

 SSH
- ssh: Cliente SSH
- ssh-audit: Auditoria SSH

 HTTP/HTTPS
- gobuster: Directory/file brute force
- dirb: Directory brute force
- wfuzz: Web fuzzer
>>>>>>> c1b4712547a17da4c827bb6759b6cfb87d5bc851
- ffuf: Fast web fuzzer

 DNS
- dig: DNS lookup
- nslookup: DNS query
<<<<<<< HEAD
=======
- host: DNS lookup simples
>>>>>>> c1b4712547a17da4c827bb6759b6cfb87d5bc851

 SNMP
- snmpwalk: SNMP enumeration
- snmp-check: SNMP scanner

<<<<<<< HEAD
# Database Enumeration

MySQL
- mysql: Cliente MySQL
- mysqldump: Backup MySQL

SQLMAP
- sqlmap

# Scripts Úteis
=======
 Database Enumeration

 MySQL
- mysql: Cliente MySQL
- mysqldump: Backup MySQL

 PostgreSQL
- psql: Cliente PostgreSQL
- pg_dump: Backup PostgreSQL

 MSSQL
- sqlcmd: Cliente MSSQL
- mssql-cli: Cliente moderno MSSQL


Scripts Úteis
>>>>>>> c1b4712547a17da4c827bb6759b6cfb87d5bc851

SMB Enumeration

Full enumeration: shares, users, OS info, etc
enum4linux -a target

List shares (anonymous or with creds)
smbclient -L //target

Share access and permissions
smbmap -H target

Direct interaction with RPC for enumeration
rpcclient -U "" target
rpcclient -U "" target -c enumdomusers



Web Directory Enumeration

gobuster dir -u http://target -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
dirb http://target /usr/share/wordlists/dirb/common.txt

DNS Enumeration

dig @target domain.com any
nslookup target
host target

Brute-force subdomains (with dnsenum or dnsrecon):
dnsenum domain.com
dnsrecon -d domain.com -D subdomains.txt -t brt

SNMP Enumeration

Full SNMP enumeration
snmpwalk -c public -v1 target

Scanner for SNMP vulnerabilities/info
snmp-check target

FTP Enumeration

ftp target
ncftp target

Check for anonymous login:
ftp target
Name: anonymous
Password: anonymous@

🗃️ Database Enumeration
MySQL
mysql -h target -u root -p
↳ Connect to MySQL

mysqldump -h target -u root -p --all-databases
↳ Dump all databases

PostgreSQL
psql -h target -U postgres -W
↳ PostgreSQL CLI client

pg_dump -h target -U postgres -W -F c dbname > db.dump
↳ Backup specific database
