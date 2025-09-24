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

---

## CEH Practical — Attack Playbook (Actionable)
This section converts the port/module reference into **repeatable attack flows** you can execute under exam conditions. Timebox each step (see "Exam day strategy"). Treat these as recipes — enumerate first, exploit second, document continuously.

### 1) Attack methodology (the canonical flow)
1. **Recon / Discovery (5–15m):** `nmap -sS -sU -p- -T4 -oA scans/full <target>` then `nmap -sV -sC -p <top_ports> -oA scans/services <target>`.
2. **Service enumeration (10–30m):** For each open port: banners, versions, directories, shares, users. Use service-specific tools (see per-service flows below).
3. **Credential checks (5–20m per service):** Try default creds, common creds lists, quick Hydra/Metasploit scanners.
4. **Exploit (10–60m):** Only after confirming versions & safe exploitability in the lab. Prefer non-destructive options that provide shells or credentials.
5. **Post-exploitation (10–40m):** Lateral movement, credential harvesting, persistence (only within lab).
6. **Documentation:** Record commands, outputs, screenshots and timeline — critical for CEH reports.

### 2) Per-service quick workflows (copy/paste ready)
- **HTTP (80/443/8080/9000/8000/8443/8888)**
  1. `nmap -sV --script=http-enum,http-headers -p <port>`
  2. `gobuster dir -u http://<ip>:<port> -w /usr/share/wordlists/dirb/common.txt -x php,asp,aspx,html`.
  3. `nikto -h http://<ip>:<port>`.
  4. If admin console found (Jenkins/Tomcat/vCenter): attempt enum creds then Metasploit exploit listed in main doc.
  5. Test for SQLi with `sqlmap -u 'http://<ip>:<port>/vuln.php?id=1' --batch --level=3 --risk=2` (only in authorized lab).

- **SMB (139/445)**
  1. `nmap --script smb-os-discovery,smb-enum-shares -p 139,445 <ip>`
  2. `enum4linux -a <ip>`
  3. `smbclient -L //<ip> -N` (anonymous)
  4. If writable share: upload a reverse shell or scheduled task payload; if MS17-010 present use the module shown in the doc.

- **RDP (3389)**
  1. `nmap -sV --script rdp-enum-encryption -p 3389 <ip>`
  2. Try `rdp_check` or `xfreerdp` with common creds.
  3. Use Metasploit `auxiliary/scanner/rdp/rdp_login` for quick brute force if allowed.

- **Databases (MySQL 3306, PostgreSQL 5432, MSSQL 1433, MongoDB 27017)**
  1. `nmap -sV --script=mysql-info -p 3306 <ip>` (example for MySQL)
  2. `msf` scanner modules (listed in main doc) or `hydra` brute for creds.
  3. If unauthenticated DB: dump data, search for credentials, connection strings.

- **SNMP (161/162)**
  1. `snmpwalk -v2c -c public <ip>`
  2. `nmap --script snmp-info --script-args snmpcommunity=public -p 161 <ip>`
  3. Look for `sysLocation`, device lists, ARP tables and plaintext credentials.

- **VNC (5900+)**
  1. `nmap -sV -p 5900-5910 --script vnc-info <ip>`
  2. `msf auxiliary/scanner/vnc/vnc_login` or try `vncviewer` with blank password.

- **Redis / Elasticsearch / CouchDB / Memcached**
  1. Check if unauthenticated. These often expose data (keys, indices). Use the scanner modules in the doc.

- **Docker (2375)**
  1. `curl http://<ip>:2375/containers/json` — if accessible, you can create containers or mount host volumes (lab-dependent; be safe).

### 3) Privilege escalation cheatsheet (quick)
#### Linux (common checks)
- Enumerate kernel & distro: `uname -a; cat /etc/os-release`.
- Check sudo rights: `sudo -l`.
- Search for SUID binaries: `find / -perm -4000 -type f 2>/dev/null`.
- Look for credentials in files: `grep -R "password\|passwd\|secret" /etc /var /home 2>/dev/null`.
- Check cron jobs: `cat /etc/crontab`, `ls -la /etc/cron.*`.
- Check running services: `ps aux --forest` & `ss -tulpen`.
- Kernel exploits (only in lab): check kernel version and search local exploit repo; prefer post-exploit enumeration first.

#### Windows (common checks)
- Enumerate domain & local info: `whoami /priv`, `systeminfo`, `net user`, `net localgroup administrators`.
- Check for weak service permissions: `accesschk.exe -accepteula -uwcqv *` (Sysinternals). If not available, enumerate services with PowerShell.
- Check scheduled tasks: `schtasks /query /fo LIST /v`.
- Dump creds: `mimikatz` (lab only) — document and justify use.
- Look for stored credentials in files, scripts or configuration XMLs (IIS, SQL connection strings).

### 4) Post-exploitation checklist
- Enumerate credentials and tokens, pivot vectors (RDP/SMB/WinRM), and data of interest.
- Set up a reversible persistence only if required by lab (e.g., create a user with documented password in a safe directory). Avoid destructive changes.
- Capture screenshots, command output, and proof-of-concept in a non-destructive way.

### 5) Reporting template (short)
- **Target:** IP/hostname
- **Scope/Authorization:** Lab name, CEH practical environment (prove authorized)
- **Findings:** ordered by severity (open ports, vulnerabilities, evidence)
- **Exploit steps:** commands run (copy/paste), timestamps, outputs
- **Impact:** what access or data was obtained
- **Remediation:** quick fixes (patch, disable service, restrict network)

### 6) Exam day strategy & timeboxing
- **0–15m:** Full discovery scan (TCP+UDP). Export results.
- **15–45m:** Rapid enumeration & quick wins (SMB, VNC, SNMP, any unauth DB).
- **45–120m:** Deeper exploitation & privilege escalation attempts.
- **120–150m:** Post-exploitation evidence gathering & documentation.
- **Final 15–30m:** Clean up (if required by lab) & finalize report. Screenshot every major step.

### 7) One-page printable quick reference (for exam)
- Top nmap commands, quick Metasploit scanner commands, default creds list location, critical port list.
- I added a condensed one-page under the new "One-page quick checklist" heading in the doc for you to pin.

---

## How I can help next (live prep)
- I can generate **mock lab scenarios** and walk you through the steps; you narrate commands and I give feedback and expected outputs.
- I can convert this document into separate `.md` files (one per port) and ZIP them for download.
- I can produce a dataview-friendly format for Obsidian so you can quickly query ports/modules.

---

*Good luck on Sep 27, 2025 — you got this.*


