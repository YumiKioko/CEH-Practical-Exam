
---
## Basic Syntax

```
snmpwalk -v [version] -c [community] [host] [OID]
```

- `-v`: SNMP version (1, 2c, or 3)
    
- `-c`: Community string (like a password, default is "public")
    
- `host`: Target IP or hostname
    
- `OID`: Optional – Object Identifier to start walking from (e.g., `.1.3.6.1.2.1` for MIB-2)

## Examples

### SNMPv2c Walk (Most common)

```
snmpwalk -v2c -c public 192.168.1.1
```

## SNMPv3 (Authenticated and Encrypted)

```
snmpwalk -v3 -u username -l authPriv -a MD5 -A password -x DES -X password 192.168.1.1
```

- `-u`: Username
    
- `-l`: Security level (`noAuthNoPriv`, `authNoPriv`, or `authPriv`)
    
- `-a`: Authentication protocol (MD5 or SHA)
    
- `-A`: Auth passphrase
    
- `-x`: Privacy protocol (DES or AES)
    
- `-X`: Privacy passphrase

## Notes

- Requires SNMP service enabled on the target.