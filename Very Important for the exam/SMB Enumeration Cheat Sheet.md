# SMB Enumeration Cheat Sheet

## Table of Contents
- [Basic Discovery](#basic-discovery)
- [Advanced Enumeration](#advanced-enumeration)
- [Tool-Specific Commands](#tool-specific-commands)
- [Password Attacks](#password-attacks)
- [Useful Commands](#useful-commands)
- [Common Shares](#common-shares)
- [Important Notes](#important-notes)

## Basic Discovery

### Network Scanning

```bash
# NetBIOS name resolution
nbtscan <target_ip>
nmblookup -A <target_ip>

# SMB service discovery
nmap -p 445 <target_ip>/24
nmap -sU -sS --script smb-os-discovery <target_ip>
Basic SMB Connection
bash
# List shares (anonymous/null session)
smbclient -L //<target_ip> -N
smbclient -L //<target_ip> -U ""

# Connect to specific share
smbclient //<target_ip>/<share> -N
smbclient //<target_ip>/<share> -U <username>

# Interactive session
smbclient //<target_ip>/<share> -U <username>%<password>
Advanced Enumeration
Nmap SMB Scripts
bash
# All SMB scripts
nmap -p 445 --script smb-* <target_ip>

# Common useful scripts
nmap -p 445 --script smb-os-discovery <target_ip>
nmap -p 445 --script smb-security-mode <target_ip>
nmap -p 445 --script smb-enum-shares <target_ip>
nmap -p 445 --script smb-enum-users <target_ip>
nmap -p 445 --script smb-enum-groups <target_ip>
nmap -p 445 --script smb-enum-sessions <target_ip>
nmap -p 445 --script smb-enum-domains <target_ip>
nmap -p 445 --script smb-brute <target_ip>
nmap -p 445 --script smb-vuln-* <target_ip>

# Specific vulnerability checks
nmap -p 445 --script smb-vuln-ms17-010 <target_ip>
nmap -p 445 --script smb-vuln-ms08-067 <target_ip>
Enum4linux
bash
# Comprehensive enumeration
enum4linux -a <target_ip>

# Specific enumeration types
enum4linux -U <target_ip>          # User enumeration
enum4linux -S <target_ip>          # Share enumeration
enum4linux -P <target_ip>          # Password policy
enum4linux -G <target_ip>          # Group enumeration
enum4linux -M <target_ip>          # Machine enumeration
enum4linux -o <target_ip>          # OS information
enum4linux -A <target_ip>          # All simple enumeration

# With credentials
enum4linux -u <username> -p <password> -a <target_ip>
RPC Client
bash
rpcclient -U "" -N <target_ip>
rpcclient -U <username>%<password> <target_ip>

# Inside rpcclient:
srvinfo                  # Server info
enumdomusers            # Enumerate domain users
enumdomgroups           # Enumerate domain groups
querydominfo            # Domain info
getdompwinfo            # Password policy
netshareenum            # Share enumeration
netshareenumall         # All shares
queryuser <rid>         # User info
querygroup <rid>        # Group info
querygroupmem <rid>     # Group members
lookupnames <username>  # User SID
lookupsids <SID>        # SID to name
Tool-Specific Commands
SMBMap
bash
# List shares with permissions
smbmap -H <target_ip>
smbmap -H <target_ip> -u <username> -p <password>
smbmap -H <target_ip> -u <username> -p <password> -r <share>  # Recursive listing

# Anonymous access
smbmap -H <target_ip> -u "" -p ""

# Download files
smbmap -H <target_ip> -u <user> -p <pass> -r <share> -A <filename> -q

# Upload files
smbmap -H <target_ip> -u <user> -p <pass> --upload <local_file> <remote_path>
CrackMapExec
bash
# Basic enumeration
crackmapexec smb <target_ip>
crackmapexec smb <target_ip> -u <user> -p <password> --shares
crackmapexec smb <target_ip> -u <user> -p <password> --sessions
crackmapexec smb <target_ip> -u <user> -p <password> --loggedon-users
crackmapexec smb <target_ip> -u <user> -p <password> --users
crackmapexec smb <target_ip> -u <user> -p <password> --groups
crackmapexec smb <target_ip> -u <user> -p <password> --local-groups

# Password spraying
crackmapexec smb <target_ip> -u users.txt -p passwords.txt
crackmapexec smb <target_ip> -u users.txt -p 'Password123' --continue-on-success

# Hash authentication
crackmapexec smb <target_ip> -u <user> -H <ntlm_hash>
Impacket Tools
smbclient.py
bash
smbclient.py <domain>/<user>:<password>@<target_ip>
smbclient.py -hashes <lmhash>:<nthash> <domain>/<user>@<target_ip>
lookupsid.py
bash
# SID enumeration
lookupsid.py <domain>/<user>:<password>@<target_ip>
lookupsid.py <domain>/<user>@<target_ip> -hashes <lmhash>:<nthash>
samrdump.py
bash
# SAM database dumping
samrdump.py <domain>/<user>:<password>@<target_ip>
samrdump.py <domain>/<user>@<target_ip> -hashes <lmhash>:<nthash>
GetADUsers.py
bash
# Enumerate AD users
GetADUsers.py <domain>/<user>:<password> -dc-ip <target_ip>
GetADUsers.py <domain>/<user> -hashes <lmhash>:<nthash> -dc-ip <target_ip>
Password Attacks
Hydra
bash
# SMB password brute force
hydra -L <userlist> -P <passlist> <target_ip> smb
hydra -L <userlist> -P <passlist> -s 445 <target_ip> smb
hydra -L <userlist> -P <passlist> -M targets.txt smb
Nmap Brute Force
bash
nmap -p 445 --script smb-brute <target_ip>
nmap -p 445 --script smb-brute --script-args userdb=<userlist>,passdb=<passlist> <target_ip>
Medusa
bash
medusa -h <target_ip> -U <userlist> -P <passlist> -M smbnt
Useful Commands
Check SMB Signing
bash
nmap --script smb-security-mode -p 445 <target_ip>
nmap --script smb2-security-mode -p 445 <target_ip>
Check SMB Version
bash
nmap --script smb-protocols -p 445 <target_ip>
Mount SMB Shares
bash
# Linux mount
mount -t cifs //<target_ip>/<share> /mnt/<mountpoint> -o username=<user>,password=<pass>

# List files in share
smbclient //<target_ip>/<share> -U <user>%<pass> -c "ls"

# Download file
smbclient //<target_ip>/<share> -U <user>%<pass> -c "get file.txt"

# Upload file
smbclient //<target_ip>/<share> -U <user>%<pass> -c "put file.txt"
Net Command (Windows)
cmd
net view \\<target_ip>
net use \\<target_ip>\<share>
net user /domain
net group /domain
Common Shares
Share Name	Purpose
ADMIN$	Administrative share
C$	Default drive share
IPC$	Inter-process communication
NETLOGON	Domain logon scripts
SYSVOL	Domain system volume
PRINT$	Printer drivers
FAX$	Fax services
Data shares	Custom named shares
Important Notes
Authorization: Always ensure you have proper authorization before testing

Privileges: Some commands require specific privileges to work

Modern Systems: Null sessions may be restricted on modern Windows systems

SMB Signing: Watch for SMB signing requirements which can affect relay attacks

Firewalls: Consider network segmentation and firewall rules

Detection: Many of these techniques generate significant logs and may trigger alerts

Legal Compliance: Ensure all testing complies with relevant laws and regulations

Documentation: Keep detailed notes of all commands used and results obtained

Common Error Messages
NT_STATUS_ACCESS_DENIED - Permission issues

NT_STATUS_LOGON_FAILURE - Authentication failure

NT_STATUS_BAD_NETWORK_NAME - Share doesn't exist

NT_STATUS_CONNECTION_REFUSED - Service not running/blocked

Useful One-Liners
bash
# Quick SMB scan and enumeration
nmap -p 445 --script smb-os-discovery,smb-enum-shares,smb-enum-users <target_ip>

# Comprehensive SMB audit
enum4linux -a <target_ip> | tee enum4linux_output.txt

# Quick share listing with smbmap
smbmap -H <target_ip> -u "" -p "" | grep -v "Working"
Remember to always practice ethical hacking and obtain proper permissions before conducting any security assessments.

text

Now here's the command to create the file with the corrected links:

```bash
cat > smb-enumeration-cheatsheet.md << 'EOF'
# SMB Enumeration Cheat Sheet

## Table of Contents
- [Basic Discovery](#basic-discovery)
- [Advanced Enumeration](#advanced-enumeration)
- [Tool-Specific Commands](#tool-specific-commands)
- [Password Attacks](#password-attacks)
- [Useful Commands](#useful-commands)
- [Common Shares](#common-shares)
- [Important Notes](#important-notes)

## Basic Discovery

### Network Scanning

```bash
# NetBIOS name resolution
nbtscan <target_ip>
nmblookup -A <target_ip>

# SMB service discovery
nmap -p 445 <target_ip>/24
nmap -sU -sS --script smb-os-discovery <target_ip>
Basic SMB Connection
bash
# List shares (anonymous/null session)
smbclient -L //<target_ip> -N
smbclient -L //<target_ip> -U ""

# Connect to specific share
smbclient //<target_ip>/<share> -N
smbclient //<target_ip>/<share> -U <username>

# Interactive session
smbclient //<target_ip>/<share> -U <username>%<password>
Advanced Enumeration
Nmap SMB Scripts
bash
# All SMB scripts
nmap -p 445 --script smb-* <target_ip>

# Common useful scripts
nmap -p 445 --script smb-os-discovery <target_ip>
nmap -p 445 --script smb-security-mode <target_ip>
nmap -p 445 --script smb-enum-shares <target_ip>
nmap -p 445 --script smb-enum-users <target_ip>
nmap -p 445 --script smb-enum-groups <target_ip>
nmap -p 445 --script smb-enum-sessions <target_ip>
nmap -p 445 --script smb-enum-domains <target_ip>
nmap -p 445 --script smb-brute <target_ip>
nmap -p 445 --script smb-vuln-* <target_ip>

# Specific vulnerability checks
nmap -p 445 --script smb-vuln-ms17-010 <target_ip>
nmap -p 445 --script smb-vuln-ms08-067 <target_ip>
Enum4linux
bash
# Comprehensive enumeration
enum4linux -a <target_ip>

# Specific enumeration types
enum4linux -U <target_ip>          # User enumeration
enum4linux -S <target_ip>          # Share enumeration
enum4linux -P <target_ip>          # Password policy
enum4linux -G <target_ip>          # Group enumeration
enum4linux -M <target_ip>          # Machine enumeration
enum4linux -o <target_ip>          # OS information
enum4linux -A <target_ip>          # All simple enumeration

# With credentials
enum4linux -u <username> -p <password> -a <target_ip>
RPC Client
bash
rpcclient -U "" -N <target_ip>
rpcclient -U <username>%<password> <target_ip>

# Inside rpcclient:
srvinfo                  # Server info
enumdomusers            # Enumerate domain users
enumdomgroups           # Enumerate domain groups
querydominfo            # Domain info
getdompwinfo            # Password policy
netshareenum            # Share enumeration
netshareenumall         # All shares
queryuser <rid>         # User info
querygroup <rid>        # Group info
querygroupmem <rid>     # Group members
lookupnames <username>  # User SID
lookupsids <SID>        # SID to name
Tool-Specific Commands
SMBMap
bash
# List shares with permissions
smbmap -H <target_ip>
smbmap -H <target_ip> -u <username> -p <password>
smbmap -H <target_ip> -u <username> -p <password> -r <share>  # Recursive listing

# Anonymous access
smbmap -H <target_ip> -u "" -p ""

# Download files
smbmap -H <target_ip> -u <user> -p <pass> -r <share> -A <filename> -q

# Upload files
smbmap -H <target_ip> -u <user> -p <pass> --upload <local_file> <remote_path>
CrackMapExec
bash
# Basic enumeration
crackmapexec smb <target_ip>
crackmapexec smb <target_ip> -u <user> -p <password> --shares
crackmapexec smb <target_ip> -u <user> -p <password> --sessions
crackmapexec smb <target_ip> -u <user> -p <password> --loggedon-users
crackmapexec smb <target_ip> -u <user> -p <password> --users
crackmapexec smb <target_ip> -u <user> -p <password> --groups
crackmapexec smb <target_ip> -u <user> -p <password> --local-groups

# Password spraying
crackmapexec smb <target_ip> -u users.txt -p passwords.txt
crackmapexec smb <target_ip> -u users.txt -p 'Password123' --continue-on-success

# Hash authentication
crackmapexec smb <target_ip> -u <user> -H <ntlm_hash>
Impacket Tools
smbclient.py
bash
smbclient.py <domain>/<user>:<password>@<target_ip>
smbclient.py -hashes <lmhash>:<nthash> <domain>/<user>@<target_ip>
lookupsid.py
bash
# SID enumeration
lookupsid.py <domain>/<user>:<password>@<target_ip>
lookupsid.py <domain>/<user>@<target_ip> -hashes <lmhash>:<nthash>
samrdump.py
bash
# SAM database dumping
samrdump.py <domain>/<user>:<password>@<target_ip>
samrdump.py <domain>/<user>@<target_ip> -hashes <lmhash>:<nthash>
GetADUsers.py
bash
# Enumerate AD users
GetADUsers.py <domain>/<user>:<password> -dc-ip <target_ip>
GetADUsers.py <domain>/<user> -hashes <lmhash>:<nthash> -dc-ip <target_ip>
Password Attacks
Hydra
bash
# SMB password brute force
hydra -L <userlist> -P <passlist> <target_ip> smb
hydra -L <userlist> -P <passlist> -s 445 <target_ip> smb
hydra -L <userlist> -P <passlist> -M targets.txt smb
Nmap Brute Force
bash
nmap -p 445 --script smb-brute <target_ip>
nmap -p 445 --script smb-brute --script-args userdb=<userlist>,passdb=<passlist> <target_ip>
Medusa
bash
medusa -h <target_ip> -U <userlist> -P <passlist> -M smbnt
Useful Commands
Check SMB Signing
bash
nmap --script smb-security-mode -p 445 <target_ip>
nmap --script smb2-security-mode -p 445 <target_ip>
Check SMB Version
bash
nmap --script smb-protocols -p 445 <target_ip>
Mount SMB Shares
bash
# Linux mount
mount -t cifs //<target_ip>/<share> /mnt/<mountpoint> -o username=<user>,password=<pass>

# List files in share
smbclient //<target_ip>/<share> -U <user>%<pass> -c "ls"

# Download file
smbclient //<target_ip>/<share> -U <user>%<pass> -c "get file.txt"

# Upload file
smbclient //<target_ip>/<share> -U <user>%<pass> -c "put file.txt"
Net Command (Windows)
cmd
net view \\<target_ip>
net use \\<target_ip>\<share>
net user /domain
net group /domain
Common Shares
Share Name	Purpose
ADMIN$	Administrative share
C$	Default drive share
IPC$	Inter-process communication
NETLOGON	Domain logon scripts
SYSVOL	Domain system volume
PRINT$	Printer drivers
FAX$	Fax services
Data shares	Custom named shares
Important Notes
Authorization: Always ensure you have proper authorization before testing

Privileges: Some commands require specific privileges to work

Modern Systems: Null sessions may be restricted on modern Windows systems

SMB Signing: Watch for SMB signing requirements which can affect relay attacks

Firewalls: Consider network segmentation and firewall rules

Detection: Many of these techniques generate significant logs and may trigger alerts

Legal Compliance: Ensure all testing complies with relevant laws and regulations

Documentation: Keep detailed notes of all commands used and results obtained

Common Error Messages
NT_STATUS_ACCESS_DENIED - Permission issues

NT_STATUS_LOGON_FAILURE - Authentication failure

NT_STATUS_BAD_NETWORK_NAME - Share doesn't exist

NT_STATUS_CONNECTION_REFUSED - Service not running/blocked

Useful One-Liners
bash
# Quick SMB scan and enumeration
nmap -p 445 --script smb-os-discovery,smb-enum-shares,smb-enum-users <target_ip>

# Comprehensive SMB audit
enum4linux -a <target_ip> | tee enum4linux_output.txt

# Quick share listing with smbmap
smbmap -H <target_ip> -u "" -p "" | grep -v "Working"