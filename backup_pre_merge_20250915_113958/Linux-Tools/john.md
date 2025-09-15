# John the Ripper (JTR) Cheat Sheet

**John** is not for attacking live services. It's for **cracking password hashes** you've already obtained.

## The Golden Rule: Hash First, Then John
You use other tools to get password hashes (from a database, a captured handshake, a stolen file), then use John to crack them offline.

---

## Basic Syntax
```bash
john [options] [path-to-hash-file]
```

---

## 1. First Step: Identify Your Hash

**You MUST know what type of hash you have before you can crack it.**

```bash
# Use John's built-in identifier (best method)
john --list=formats | grep -i md5 # Replace 'md5' with what you think it is

# Or use the `hash-identifier` tool (often pre-installed)
hash-identifier
# Then paste your hash: 5f4dcc3b5aa765d61d8327deb882cf99

# Or use `hashid`
hashid '5f4dcc3b5aa765d61d8327deb882cf99'
```

### Common Hash Formats & John's Name for Them
| Hash Example | Type | John Format Name |
| :--- | :--- | :--- |
| `5f4dcc3b5aa765d61d8327deb882cf99` | MD5 | `raw-md5` |
| `$1$abc123$...` | MD5 Crypt | `md5crypt` |
| `$6$rounds=5000$...` | SHA-512 Crypt | `sha512crypt` |
| `aad3b435b51404eeaad3b435b51404ee` | LM (Windows) | `lm` |
| `NTLM_hash` | NT (Windows) | `nt` |

---

## 2. The Three Main Cracking Modes

### 1. Wordlist Attack (Fastest & Most Common)
```bash
# Basic attack with rockyou.txt
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt

# Specify the hash format
john --format=raw-md5 --wordlist=rockyou.txt hashes.txt

# Use rules to mutate words (e.g., add numbers, change case)
john --wordlist=rockyou.txt --rules hashes.txt
```

### 2. Single Crack Mode (Uses Usernames as Clues)
```bash
# Good if passwords are based on usernames (e.g., user: bob, password: bob123)
john --single hashes.txt
```

### 3. Incremental Mode (Pure Brute-Force)
```bash
# This will try every possible combination. It's slow but thorough.
john --incremental hashes.txt

# Use incremental on a specific format
john --format=raw-md5 --incremental hashes.txt
```

---

## 3. Practical Examples

### Crack Linux /etc/shadow Hashes
1.  You need both `/etc/passwd` and `/etc/shadow` files.
2.  Combine them with `unshadow`:
    ```bash
    unshadow /etc/passwd /etc/shadow > unshadowed.txt
    ```
3.  Crack the combined file:
    ```bash
    john --wordlist=rockyou.txt unshadowed.txt
    ```

### Crack Windows NTLM Hashes
```bash
# Crack NT hashes (from a SAM database dump)
john --format=nt --wordlist=rockyou.txt nt_hashes.txt

# Crack LM hashes (weaker, faster to crack)
john --format=lm --wordlist=rockyou.txt lm_hashes.txt
```

### Crack a Specific Hash Type
```bash
# Put a single hash in a file
echo '5f4dcc3b5aa765d61d8327deb882cf99' > hash.txt

# Crack an MD5 hash
john --format=raw-md5 --wordlist=rockyou.txt hash.txt

# Crack a sha512crypt hash (Linux)
john --format=sha512crypt --wordlist=rockyou.txt hash.txt
```

### Show Your Results
```bash
# After cracking, show all cracked passwords
john --show hashes.txt

# Show results for a specific format
john --show --format=raw-md5 hashes.txt
```

### Restore a interrupted Session
```bash
# John saves progress. To continue cracking:
john --restore
```

---

## 4. Performance Tips

```bash
# Use all your CPU cores (default is 1)
john --fork=4 --wordlist=rockyou.txt hashes.txt # Use 4 cores

# Use a GPU for much faster cracking (if supported)
john --format=raw-md5 --wordlist=rockyou.txt --device=1,2 hashes.txt
```

---

## 5. Cheat Sheet Table: Common Commands

| Task | Command |
| :--- | :--- |
| **Crack with wordlist** | `john --wordlist=rockyou.txt hashes.txt` |
| **Crack specific format** | `john --format=nt --wordlist=rockyou.txt hashes.txt` |
| **Use mutation rules** | `john --wordlist=rockyou.txt --rules hashes.txt` |
| **Brute-force** | `john --incremental hashes.txt` |
| **Show cracked passwords** | `john --show hashes.txt` |
| **Continue previous session** | `john --restore` |

---

## Summary Workflow

1.  **Get hashes** (from a database, file, or network capture).
2.  **Identify the hash type** (`hash-identifier` or `john --list=formats`).
3.  **Choose your attack**: `--wordlist` (fast), `--incremental` (slow), or `--single`.
4.  **Let John run**. Go get a coffee ☕.
5.  **Retrieve your passwords** with `john --show`.

**Remember:** John is for offline cracking. If you want to attack a live login (SSH, FTP, website), you need **Hydra**.