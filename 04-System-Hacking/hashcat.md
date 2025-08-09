## Basic Syntax

```
hashcat [options] -m <hash-type> -a <attack-mode> <hashfile> <wordlist>
```

## 🧪 Common Options

| Option       | Description                                        |                                 |
| ------------ | -------------------------------------------------- | ------------------------------- |
| `-m`         | Hash type (see full list below)                    |                                 |
| `-a`         | Attack mode (0 = straight, 3 = brute-force, etc.)  |                                 |
| `-o`         | Output file for cracked hashes                     |                                 |
| `--show`     | Display cracked passwords                          |                                 |
| `--force`    | Ignore warnings (use with caution)                 |                                 |
| `--username` | Ignore username field (e.g., in `user:hash` files) | ## 🔢 Hash Type Examples (`-m`) |

| Hash Type    | Mode          |
| ------------ | ------------- |
| MD5          | `0`           |
| SHA1         | `100`         |
| SHA256       | `1400`        |
| NTLM         | `1000`        |
| bcrypt       | `3200`        |
| SHA512       | `1700`        |
| WPA/WPA2     | `22000` (new) |
| Office 2013+ | `9600`        |
| ZIP          | `17200`       |
| PDF          | `10500`       |
### Check all supported hash modes:
```
hashcat --help | grep -A 100 'Hash modes'
```

### 🎯 Attack Modes (`-a`)

| Mode | Type                   |
| ---- | ---------------------- |
| `0`  | Straight (dictionary)  |
| `1`  | Combination            |
| `3`  | Brute-force            |
| `6`  | Hybrid wordlist + mask |
| `7`  | Hybrid mask + wordlist |
## 🚀 Cracking Examples

1. **Dictionary Attack (Straight Mode)**
```
hashcat -m 0 -a 0 hashes.txt rockyou.txt
```

2. **Brute-Force Attack**
```
hashcat -m 0 -a 3 hashes.txt ?a?a?a?a?a?a
```
`-a` = all characters, 6 positions in this example

3. **Hybrid Attack (Wordlist + Mask)**
```
hashcat -m 0 -a 6 hashes.txt rockyou.txt ?d?d
```
Tries wordlist words followed by 2 digits

4. **Custom Charset Mask**
```
hashcat -m 0 -a 3 hashes.txt ?l?l?l?d?d
```
3 lowercase letters followed by 2 digits

### 📄 Viewing Cracked Passwords

```
hashcat --show -m 0 hashes.txt
```

## 🛠 Wordlist and Rules

### Apply Rules with Wordlist
```
hashcat -m 0 -a 0 -r rules/best64.rule hashes.txt rockyou.txt
```

### Use Built-in Rules

Located in `/usr/share/hashcat/rules/` or `rules/` directory in Hashcat package.

## ⏸ Pause / Resume / Restore

Pause

```
[Press P]
```

Resume

```
[Press R]
```

Restore session

```
hashcat --restore
```

## 🔐 Create Test Hashes

Use `hashcat-utils` or Linux tools:
```
echo -n "password" | md5sum
```

### 🧹 Clean Up and Reset

```
hashcat --restore --skip=0  # Resume from start
```

```
hashcat --session=myjob --status  # Check job status
```






























