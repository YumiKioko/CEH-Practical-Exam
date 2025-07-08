 Enumeration Tools

 Service Enumeration

 SMB/NetBIOS
- enum4linux: Enumeração completa SMB/NetBIOS
- smbclient: Cliente SMB
- smbmap: Mapeamento de shares SMB
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
- ffuf: Fast web fuzzer

 DNS
- dig: DNS lookup
- nslookup: DNS query
- host: DNS lookup simples

 SNMP
- snmpwalk: SNMP enumeration
- snmp-check: SNMP scanner

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

bash
 SMB Enumeration
enum4linux -a target
smbclient -L //target
smbmap -H target

 Web Directory Enumeration
gobuster dir -u http://target -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
dirb http://target /usr/share/wordlists/dirb/common.txt

 DNS Enumeration
dig @target domain.com any
nslookup target
host target

 SNMP Enumeration
snmpwalk -c public -v1 target
snmp-check target

 FTP Enumeration
ftp target
ncftp target