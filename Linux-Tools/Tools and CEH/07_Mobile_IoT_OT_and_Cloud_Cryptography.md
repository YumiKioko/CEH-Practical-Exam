# 07 - Mobile Platforms, IoT/OT, Cloud & Cryptography (combined brief)

**Purpose:** Specialized hacking domains — mobile, embedded, cloud, and cryptography basics (small CEH Practical weight each).

**Useful tools (added recommendations):**
- Mobile: `drozer`, `apktool`, `frida` — mobile app testing and dynamic analysis
- IoT/OT: `binwalk`, `firmware-mod-kit`, `radare2` — firmware analysis and reverse engineering
- Cloud: `aws-cli`, `pacu` — AWS enumeration and exploitation frameworks
- Cryptography: `john`, `hashcat` — cracking weak cryptographic hashes; `openssl` for certificate inspection

**Examples & quick tips:**
```bash
# inspect SSL certificate
openssl s_client -connect target:443 -showcerts
# basic hash cracking with hashcat (example)
hashcat -m 0 hash.txt /usr/share/wordlists/rockyou.txt
```

**Notes:** These topics appear in practical but usually as focused tasks; prepare basics and common tooling workflows.