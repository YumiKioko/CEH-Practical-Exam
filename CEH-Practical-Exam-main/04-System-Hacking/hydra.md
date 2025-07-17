## ⚙️ Basic Syntax
```
hydra [OPTIONS] [TARGET] [PROTOCOL]
```

## 🧰 Common Options

|Option|Description|
|---|---|
|`-l`|Login/username (single)|
|`-L`|File with list of usernames|
|`-p`|Password (single)|
|`-P`|File with list of passwords|
|`-s`|Port (if not default)|
|`-t`|Number of parallel connections (threads)|
|`-vV`|Verbose mode (show each login attempt)|
|`-f`|Exit after first valid login found|
|`-o`|Write results to file|
|`-e ns`|Try login as password and blank password|
|`-I`|Ignore errors|
|`-u`|Loop around users, not passwords|
|`-w`|Wait time (timeout) in seconds|

## 🔐 Supported Protocols (Common)

- **http-get**, **http-post**, **http-form-get**, **http-form-post**
    
- **ssh**
    
- **ftp**
    
- **telnet**
    
- **rdp**
    
- **smb**
    
- **vnc**
    
- **mysql**, **postgres**, **mssql**
    
- **smtp**, **pop3**, **imap**
    
- **snmp**, **ldap**
    
- Use `hydra -U` to see all supported services.

## 🚀 Example Usage

1. **FTP Brute-force**
```
hydra -l admin -P /usr/share/wordlists/rockyou.txt ftp://192.168.1.100
```

2. **SSH Brute-force**
```
hydra -L users.txt -P passwords.txt ssh://192.168.1.100
```

3. **HTTP POST Login Form Attack**
```
hydra -L users.txt -P passwords.txt 192.168.1.100 http-post-form "/login.php:user=^USER^&pass=^PASS^:Invalid login"
```

4. **RDP Login Brute-force**
```
hydra -L users.txt -P passwords.txt rdp://192.168.1.100
```

## Output Example
```
[22][ssh] host: 192.| Hash Type | Format Option                |
| --------- | ---------------------------- |
| MD5       | `--format=raw-md5`           |
| SHA1      | `--format=raw-sha1`          |
| NTLM      | `--format=nt`                |
| bcrypt    | `--format=bcrypt`            |
| zip       | Auto-detected via `zip2john` |
| pdf       | Auto-detected via `pdf2john` |-e ns` → Try login as password and blank password
















