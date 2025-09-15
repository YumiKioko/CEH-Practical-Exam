## Basic Syntax

```
john [options] [hash_file]
```

## 🔐 Preparing the Hashes

1. Extract hashes with tools like `unshadow`, `zip2john`, `pdf2john`, etc.
2. Save them into a file (e.g., `hashes.txt`)
3. Run John on that file

## 📥 Extract Hash Examples

### Unix Shadow File

```
unshadow /etc/passwd /etc/shadow > hashes.txt
```

### ZIP File

```
zip2john secret.zip > zip.hash
```

### PDF File

```
pdf2john confidential.pdf > pdf.hash
```

## 🚀 Cracking Examples

1. **Wordlist Attack**

```
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
```

2. **Incremental Brute-force**

```
john --incremental hashes.txt
```

3. **Rules-based Attack (Hybrid)**

```
john --wordlist=rockyou.txt --rules hashes.txt
```


## 🛠 Other Useful Commands

| Command                                | Description                      |                      |
| -------------------------------------- | -------------------------------- | -------------------- |
| `john --show hashes.txt`               | Show cracked passwords           |                      |
| `john --format=raw-md5 hashes.txt`     | Specify hash format              |                      |
| `john --test`                          | Run performance benchmark        |                      |
| `john --restore`                       | Restore from a previous session  |                      |
| `john --session=name`                  | Save session under a custom name |                      |
| `john --list=formats`                  | List all supported hash types    |                      |
| `john --wordlist=wl.txt --rules=Jumbo` | Use enhanced rules (Jumbo patch) | ## 📂 Output Example |

### 📂 Output Example

After cracking:
```
john --show hashes.txt
```

```
user1:password123:1001:...
```

## 🔍 Identify Unknown Hash Types

Use the tool:

```
hashid <hash>
```
or

```
hash-identifier
```


## 🔧 Format Examples

|Hash Type|Format Option|
|---|---|
|MD5|`--format=raw-md5`|
|SHA1|`--format=raw-sha1`|
|NTLM|`--format=nt`|
|bcrypt|`--format=bcrypt`|
|zip|Auto-detected via `zip2john`|
|pdf|Auto-detected via `pdf2john`|




































