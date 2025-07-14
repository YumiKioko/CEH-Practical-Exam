<<<<<<< HEAD
# Cryptography Tools
=======
 Cryptography Tools
>>>>>>> c1b4712547a17da4c827bb6759b6cfb87d5bc851

 Hash Identification

 Hash-Identifier
- hash-identifier: Identificação de tipos de hash
- hashid: Identificação moderna de hashes

 Hash Cracking

 John the Ripper
- john: Cracker de senhas clássico
- john --wordlist: Ataque de dicionário
- john --incremental: Ataque de força bruta

 Hashcat
- hashcat: GPU hash cracking
- hashcat -m: Especificação de modo
- hashcat -a: Tipo de ataque

 Cipher Tools

 Classical Ciphers
- caesar: Cifra de César
- vigenere: Cifra de Vigenère
- substitution: Cifra de substituição

 Modern Cryptography
- openssl: Toolkit criptográfico
- gpg: GNU Privacy Guard
- age: Modern encryption tool

 Online Tools (Referência)

 CyberChef
- Encoding/Decoding: Base64, URL, HTML
- Encryption/Decryption: AES, DES, RSA
- Hash Functions: MD5, SHA, etc.

 dCode
- Cipher Solver: Resolução automática
- Frequency Analysis: Análise de frequência

<<<<<<< HEAD
# Scripts
=======
 Scripts Úteis
>>>>>>> c1b4712547a17da4c827bb6759b6cfb87d5bc851

 Hash identification
hash-identifier
hashid hash.txt

 John the Ripper
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
john --show hashes.txt

 Hashcat
hashcat -m 0 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt
hashcat -m 1000 -a 3 hashes.txt ?a?a?a?a?a?a

 OpenSSL
openssl enc -aes-256-cbc -d -in encrypted.txt -out decrypted.txt
openssl dgst -md5 file.txt
openssl rand -base64 32

 Base64
echo "text" | base64
echo "dGV4dA==" | base64 -d

 Common hash types
 MD5: 32 hex chars
 SHA1: 40 hex chars
 SHA256: 64 hex chars
 NTLM: 32 hex chars