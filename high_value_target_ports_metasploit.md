---
title: "High-Value Target Ports & Metasploit Modules — CEH v12 (Updated)"
tags: [security, pentest, metasploit, ceh, reference]
description: "Reference guide for penetration testers and CEH v12 practical — ports, services and Metasploit modules (updated for Sep 27, 2025 exam)."
---

# High-Value Target Ports & Metasploit Modules
_A reference guide for penetration testers and CEH v12 practical_

> [!warning] **Legal / Ethical**
> This information is for educational purposes and authorized security testing **only**. Unauthorized access to computer systems is illegal.

---

**Exam reminder:** This guide is tuned for your CEH v12 practical due **September 27, 2025**. Use it as a checklist during lab time.

---

## Controls
`Show All Ports` — quick list: 21 · 22 · 23 · 25/465/587 · 53 · 80/443/8080/8000/8443/8888 · 110/995 · 139/445 · 143/993 · 1433/1434 · 1521 · 27017/27018 · 3306 · 3389 · 4848 · 5432 · 5985/5986 · 5984 · 5900+ · 6379 · 8009 · 8282 · 8383 · 9000/9001 · 9200 · 10000 · 161/162 (SNMP) · 69 (TFTP) · 123 (NTP) · 5060 (SIP) · 11211 (Memcached) · 2375/2376 (Docker) · 6443 (Kubernetes) · 1883 (MQTT)

---

## How to use this note in the exam
- Run a fast discovery scan first (`nmap -sS -sU -T4 -p-`) then targeted scans (`-sV -sC --script vuln`).
- Prioritise quick wins (SMB, RDP, web, DBs, SNMP, VNC, LDAP).
- Don’t skip UDP ports — many labs hide easy info there.
- Timebox exploitation attempts: enumerate → identify → exploit (when authorized by the lab environment).

---

## Port reference (expanded)

> Each entry shows common Metasploit modules and purpose. Module commands are presented as Metasploit `use` lines for quick copy/paste.

### Port 21 — FTP
**Service:** FTP

**Auxiliary (Brute Force)**
```
use auxiliary/scanner/ftp/ftp_login
```
Purpose: Bruteforce credentials.

**Exploit (vsftpd Backdoor)**
```
use exploit/unix/ftp/vsftpd_234_backdoor
```
Purpose: Exploits vsftpd 2.3.4 backdoor.

---

### Port 22 — SSH
**Service:** SSH

**Auxiliary (Brute Force)**
```
use auxiliary/scanner/ssh/ssh_login
```

**Auxiliary (User Enum)**
```
use auxiliary/scanner/ssh/ssh_enumusers
```

---

### Port 23 — Telnet
**Service:** Telnet

**Auxiliary (Brute Force)**
```
use auxiliary/scanner/telnet/telnet_login
```

**Exploit (Encryption option vuln)**
```
use exploit/linux/telnet/telnet_encrypt_keyid
```

---

### Port 25 / 465 / 587 — SMTP
**Service:** SMTP

**Auxiliary (User Enumeration)**
```
use auxiliary/scanner/smtp/smtp_enum
```

**Exploit (Exim variants / RCE/priv esc)**
```
use exploit/linux/smtp/exim4_deliver_message_priv_esc
```

---

### Port 53 — DNS
**Service:** DNS (TCP/UDP)

**Auxiliary (Version / Info)**
```
use auxiliary/gather/dns_info
```

**Auxiliary (Zone Transfer)**
```
use auxiliary/gather/dns_axfr
```

---

### Port 69 (UDP) — TFTP  *(add)*
**Service:** TFTP

**Notes:** Useful to check for readable or writable configs/firmware. Use `tftp` or `atftp` and targeted `nmap --script tftp-enum`.

---

### Port 80 / 443 / 8080 / 8000 / 8443 / 8888 — HTTP / HTTPS  *(expanded)*
**Service:** Web apps, APIs, dashboards

**Auxiliary (Service ID)**
```
use auxiliary/scanner/http/http_version
```

**Exploits (example Tomcat/Jenkins)**
```
use exploit/multi/http/tomcat_mgr_upload
use exploit/multi/http/jenkins_script_console
```

---

### Port 110 / 995 — POP3
**Auxiliary (Brute Force)**
```
use auxiliary/scanner/pop3/pop3_login
```

---

### Port 139 / 445 — SMB
**Recon & Shares**
```
use auxiliary/scanner/smb/smb_version
use auxiliary/scanner/smb/smb_enumshares
```

**Exploit (EternalBlue)**
```
use exploit/windows/smb/ms17_010_eternalblue
```

---

### Port 143 / 993 — IMAP
**Brute Force / Version**
```
use auxiliary/scanner/imap/imap_login
use auxiliary/scanner/imap/imap_version
```

---

### Port 1433 / 1434 — MSSQL
**Brute Force**
```
use auxiliary/scanner/mssql/mssql_login
```

**Exploit (xp_cmdshell payload)**
```
use exploit/windows/mssql/mssql_payload
```

---

### Port 1521 — Oracle TNS
**SID discovery & login**
```
use auxiliary/scanner/oracle/sid_brute
use auxiliary/admin/oracle/oracle_login
```

**Sniffer (requires MITM)**
```
use auxiliary/sniffer/oracle
```

---

### Port 3306 — MySQL  *(add)*
**Service:** MySQL / MariaDB

**Auxiliary (Brute Force)**
```
use auxiliary/scanner/mysql/mysql_login
```

**Notes:** Also practice `mysql` CLI, `sqlmap` for injection and `msf` modules for post-exploitation where applicable.

---

### Port 27017 / 27018 — MongoDB
**Auxiliary (Enumeration / Brute Force)**
```
use auxiliary/scanner/mongodb/mongodb_enum
use auxiliary/scanner/mongodb/mongodb_login
```

---

### Port 3389 — RDP
**Brute Force**
```
use auxiliary/scanner/rdp/rdp_login
```

**BlueKeep check**
```
use auxiliary/scanner/rdp/cve_2019_0708_bluekeep
```

---

### Port 5900+ — VNC  *(add)*
**Service:** VNC (remote display)

**Auxiliary (Brute Force)**
```
use auxiliary/scanner/vnc/vnc_login
```

**Notes:** Exposed VNC often lacks passwords in labs — check multiple display numbers (5900,5901...).

---

### Port 4848 — GlassFish
**Admin brute / traversal**
```
use auxiliary/scanner/http/glassfish_login
use auxiliary/scanner/http/glassfish_traversal
```

---

### Port 5432 — PostgreSQL
**Brute Force**
```
use auxiliary/scanner/postgres/postgres_login
```

**Exploit (COPY FROM PROGRAM)**
```
use exploit/linux/postgres/postgres_copy_from_program_cmd_exec
```

---

### Port 5985 / 5986 — WinRM
**Brute Force / Script Exec**
```
use auxiliary/scanner/winrm/winrm_login
use exploit/windows/winrm/winrm_script_exec
```

---

### Port 5984 — CouchDB
```
use auxiliary/scanner/couchdb/couchdb_enum
use exploit/linux/http/apache_couchdb_cmd_exec
```

---

### Port 6379 — Redis
```
use auxiliary/scanner/redis/redis_server
use exploit/linux/redis/redis_unauthorized_exec
```

---

### Port 8009 — AJP (Tomcat) — Ghostcat
```
use auxiliary/admin/http/tomcat_ghostcat
use exploit/linux/http/tomcat_ghostcat
```

---

### Port 8282 / 8383 — API Management / Management Consoles
```
use auxiliary/scanner/http/http_version
use exploit/multi/http/wso2_uploader_rce
use exploit/multi/http/vmware_vcenter_analytics_upload_ova
```

---

### Port 9000 / 9001 — Web Apps / Jenkins
```
use auxiliary/scanner/http/http_version
use auxiliary/scanner/http/jenkins_enum
use exploit/multi/http/jenkins_script_console
```

---

### Port 9200 — Elasticsearch
```
use auxiliary/scanner/elasticsearch/indices_enum
use exploit/multi/elasticsearch/script_mvel_rce
```

---

### Port 10000 — Webmin
```
use auxiliary/scanner/webmin/webmin_login
use exploit/linux/http/webmin_backdoor
```

---

### UDP / Other services to add (high exam value)
- **SNMP 161/162**: `auxiliary/scanner/snmp/snmp_enum`, `snmp_login` — check for `public`/`private` communities and `snmpwalk`.
- **NTP 123**: check `monlist` and time-based attacks; `nmap --script ntp-*`.
- **SSDP 1900, SSDP/SSDP discovery**: useful for discovery.
- **CLDAP (389 UDP)**: lightweight LDAP enumeration.
- **NetBIOS 137/138**: `enum4linux`, `smbclient`.
- **CharGen (19) / QOTD (17)**: legacy UDP services sometimes present for amplification or lab tasks.
- **SIP 5060**: VoIP enumeration/brute force.
- **Memcached 11211**: check unauthenticated instances for data leakage/amplification.

---

## Useful tools & quick commands
- **Nmap**: `nmap -sS -sU -T4 -p- --min-rate 1000 -oA discovery` then `nmap -sV -sC -p <ports> -oA target-services`.
- **Enumeration**: `enum4linux`, `snmpwalk`, `ldapsearch`, `nikto`, `gobuster/dirb`.
- **Brute force**: `hydra`, `medusa`, Metasploit scanner modules.
- **DBs & web**: `sqlmap`, `mongo` shell, `psql`, `mysql` client.
- **Containers / Cloud**: `curl` to Docker API (2375), `kubectl` checks for kube API (6443) if lab allows.

---

## One-page quick checklist for the exam (pin this)
1. Discovery: full TCP+UDP scan (nmap).  
2. Identify top 10 open services.  
3. Enumerate each service (version, banner, directories, shares).  
4. Try quick creds: default credentials, `admin:admin`, common lists.  
5. Check SNMP, TFTP, VNC (fast wins).  
6. Check DBs for unauthenticated access (MongoDB, Redis, Elasticsearch).  
7. Check web consoles (Jenkins, Tomcat, GlassFish, vCenter).  
8. If exploit found, verify safe exploit in lab (no destructive flags).  
9. Document everything: commands, outputs, screenshots.

---

## Additional resources
- Metasploit docs — https://docs.metasploit.com/
- Nmap docs — https://nmap.org/
- OffSec Metasploit Unleashed — https://www.offsec.com/metasploit-unleashed/
- MITRE CVE — https://cve.mitre.org/

---

*Disclaimer:* This guide is a study aid for authorized testing only.

