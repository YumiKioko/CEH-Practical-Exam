# One-line Cheat Cards


- **01_Information_Security_and_Ethical_Hacking**: Understand methodology, rules of engagement, and phases of hacking (Recon → Scan → Gain Access → Maintain → Cover Tracks).

- **02_Reconnaissance_Techniques**: Combine passive OSINT and active DNS/port enumeration using whois, dig, nslookup, amass, nmap, gobuster, ffuf.

- **03_System_Hacking_and_Vulnerability_Analysis**: Investigate and exploit local/remote services with hydra, john, netcat, metasploit; crack hashes with hashcat/john.

- **04_Network_and_Perimeter_Hacking**: Map and attack network perimeter with nmap, tcpdump, Wireshark, aircrack-ng, bettercap, fping, traceroute.

- **05_Web_Application_Hacking**: Test web apps with Burp Suite, curl, nikto, sqlmap, ffuf/gobuster/feroxbuster and exploit misconfigurations.

- **06_Wireless_Hacking_and_Tools**: Audit Wi‑Fi using airmon/airodump/aireplay/aircrack, reaver, wash, kismet for discovery and capture.

- **07_Mobile_IoT_OT_and_Cloud_Cryptography**: Use apktool, frida, drozer for mobile; binwalk, radare2 for firmware; aws-cli/pacu for cloud enumeration.

- **amass**: Passive/active subdomain discovery: `amass enum -d example.com -o amass.txt`.

- **apktool**: Cheat not found; see full sheet.

- **aws_cli**: Query AWS resources: `aws s3 ls`, `aws ec2 describe-instances`.

- **bettercap**: Active network MITM and DNS spoofing framework.

- **binwalk**: Firmware analysis and extraction: `binwalk -e firmware.bin`.

- **burp_suite**: Intercept and modify HTTP(S) traffic via proxy; use Repeater for manual payload testing.

- **dig**: DNS querying tool: `dig @8.8.8.8 example.com ANY +short`.

- **dirb**: Simple directory brute-forcer using wordlists.

- **dnsdumpster**: Web-based DNS and subdomain mapping (dnsdumpster.com).

- **drozer**: Android app dynamic analysis platform.

- **feroxbuster**: Fast content discovery: `feroxbuster -u https://target -w wordlist`.

- **firmware_mod_kit**: Cheat not found; see full sheet.

- **frida**: Dynamic instrumentation toolkit for hooking app functions.

- **hashcat**: GPU-accelerated password cracking: `hashcat -m <type> -a 0 hash.txt wordlist`.

- **kismet**: Passive wireless discovery and IDS for 802.11 networks.

- **metasploit**: Framework for payloads/exploits and post-exploitation (msfconsole).

- **nmap**: Port/host discovery and service detection. `nmap -sS -sV -A target`.

- **nslookup**: Interactive DNS query tool: `nslookup` then `set type=MX`.

- **openssl**: Inspect TLS certs and test connections: `openssl s_client -connect target:443`.

- **owasp_zap**: Automated and manual web app scanning and proxying, good open-source alternative to Burp.

- **pacu**: AWS exploitation framework for post-exploitation testing.

- **ping**: ICMP reachability and latency test: `ping -c 4 target`.

- **radare2**: Reverse engineering and binary analysis (r2).

- **reaver**: WPS registrar attack to try recover WPA passphrases (use in lab only).

- **tcpdump**: CLI packet capture: `tcpdump -i eth0 -w capture.pcap`.

- **telnet**: Test connectivity to TCP ports: `telnet target 80`.

- **telnet_converted**: Cheat not found; see full sheet.

- **theharvester**: OSINT subdomain and email harvesting.

- **traceroute**: Show packet path to target: `traceroute example.com`.

- **traceroute_converted**: Cheat not found; see full sheet.

- **wash**: Scan for WPS-enabled APs.

- **whois**: Domain registration lookup: `whois example.com`.

- **whois_converted**: Cheat not found; see full sheet.

- **wireshark**: GUI packet analysis; use display filters e.g., `ip.addr==x.x.x.x`.
