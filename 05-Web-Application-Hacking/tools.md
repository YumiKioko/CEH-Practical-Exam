<<<<<<< HEAD
# Web Application Hacking Tools
=======
 Web Application Hacking Tools
>>>>>>> c1b4712547a17da4c827bb6759b6cfb87d5bc851

 Web Proxies

 Burp Suite
- Proxy: Interceptação de requisições
- Scanner: Scanning automático
- Intruder: Ataques automatizados
- Repeater: Manipulação de requisições

<<<<<<< HEAD
=======
 OWASP ZAP
- Proxy: Interceptação
- Active Scan: Scanning ativo
- Passive Scan: Scanning passivo

>>>>>>> c1b4712547a17da4c827bb6759b6cfb87d5bc851
 SQL Injection

 SQLMap
- Automated SQL Injection: Detecção e exploração automática
- Database Extraction: Extração de dados

 Directory/File Enumeration

 Gobuster
- Directory Brute Force: Descoberta de diretórios
- File Extension: Busca por extensões
- VHost: Virtual host discovery

 Dirbuster
- GUI Tool: Interface gráfica
- Multi-threaded: Busca paralela

 Web Vulnerability Scanners

 Nikto
- Web Server Scanner: Vulnerabilidades web
- CGI Scanner: Problemas em CGI

<<<<<<< HEAD
# Scripts Úteis
=======
 Wapiti
- Web Application Scanner: Vulnerabilidades em aplicações
- SQL Injection: Detecção de SQLi

 Scripts Úteis
>>>>>>> c1b4712547a17da4c827bb6759b6cfb87d5bc851


 SQLMap básico
sqlmap -u "http://target/page.php?id=1" --dbs
sqlmap -u "http://target/page.php?id=1" -D database --tables
sqlmap -u "http://target/page.php?id=1" -D database -T table --columns
sqlmap -u "http://target/page.php?id=1" -D database -T table -C column --dump

 Gobuster directory enumeration
gobuster dir -u http://target -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
gobuster dir -u http://target -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt,js

 Nikto scan
nikto -h http://target

 Wapiti scan
wapiti -u http://target

 Burp Suite CLI (se disponível)
java -jar burpsuite_pro.jar