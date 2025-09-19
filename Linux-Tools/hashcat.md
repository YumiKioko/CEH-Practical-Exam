# Hashcat

**Description:**  
Hashcat is a high-performance password recovery tool supporting CPU/GPU cracking modes.

**Basic Syntax:**
```bash
hashcat -m <hash_type> -a <attack_mode> hashfile wordlist
```

**Common Options:**
- `-m` — hash type (e.g., `0` MD5, `1000` NTLM)  
- `-a` — attack mode (`0` straight, `3` mask, `6` combination, `7` hybrid)  
- `-o` — output file for cracked passwords  
- `--rules` — use rule-based mutations

**Examples:**
```bash
hashcat -m 0 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt
hashcat -m 1000 -a 3 ntlm.hash ?l?l?l?l?d?d
```