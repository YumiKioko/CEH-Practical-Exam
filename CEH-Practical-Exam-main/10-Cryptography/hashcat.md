
## Basic Hashcat Syntax

```
hashcat -m <hash-mode> -a <attack-mode> -o <output-file> <hash-file> <wordlist>
```

- `-m` → hash mode (number from your list, e.g., 0 for MD5)
- `-a` → attack mode (0 = dictionary, 3 = brute-force, 6 = hybrid, etc.)
- `-o` → output file (where cracked hashes go)
- `<hash-file>` → file with hashes
- `<wordlist>` → wordlist to use (like `rockyou.txt`)


## 📦 Example Hash Modes from Your List (these examples are part of the information available from the official [Hashcat example hashes list](https://hashcat.net/wiki/doku.php?id=example_hashes))

|Hash Name|Hashcat Mode (`-m`)|

|MD5|0|
|md5($pass.$salt)|10|
|md5($salt.$pass)|20|
|md5(utf16le($pass).$salt)|30|
|md5($salt.utf16le($pass))|40|
|HMAC-MD5 (key = $pass)|50|
|HMAC-MD5 (key = $salt)|60|


 📄 Example Hash File

For salted hashes, the file should have:


<hash>:<salt>


Example (for mode 10):


01dfae6e5d4d90d9892622325959afbe:7050461


Example Commands

Crack basic MD5 (mode 0)


hashcat -m 0 -a 0 -o cracked.txt hashes.txt rockyou.txt


hashcat -m 0 -a 0 -o cracked.txt hashes.txt rockyou.txt


✅ Crack salted md5($pass.$salt) (mode 10)

hashcat -m 10 -a 0 -o cracked.txt hashes.txt rockyou.txt


✅ Crack a **single hash without a file**


hashcat -m 0 -a 0 -o cracked.txt "8743b52063cd84097a65d1633f5c74f5" rockyou.txt


✅ Example of a **hash from /etc/shadow (SHA512crypt)**


$6$m6VmzKTbzCD/.I10$cKOvZZ8/rsYwHd.pE099ZRwM686p/Ep13h7pFMBCG4t7IukRqc/fXlA1gHXh9F2CbwmD4Epi1Wgh.Cl.VV1mb/


Command:

hashcat -m 1800 -a 0 shadow_hashes.txt rockyou.txt


**Important:** In the `/etc/shadow` file, each line includes multiple fields separated by colons, like:


username:hash:lastchanged:min:max:warn:inactive:expire


You must extract **only the hash field** (the second field) and remove the username and the trailing fields (like `:18796:0:99999:7:::`) because Hashcat only expects the raw hash, not system metadata.

To extract just the hash:

cut -d: -f2 shadow.txt > hash.txt


This cuts out only the hash portion, ready for Hashcat. In detail, the `/etc/shadow` line has this structure: `username:hash:lastchanged:min:max:warn:inactive:expire`. The `username` is the account name, the `hash` is the encrypted password (e.g., `$6$...` for SHA512crypt), and the other fields store system management info like when the password was last changed, how long it’s valid, and when to warn or disable the account. Hashcat only needs the hash part (`$6$...`). Here’s a clearer breakdown of the `/etc/shadow` structure, with each field on a separate line:

- `username` → the account name (e.g., `root`)
- `hash` → the encrypted password (e.g., `$6$...` for SHA512crypt)
- `lastchanged` → days since Jan 1, 1970, when the password was last changed
- `min` → minimum days between password changes
- `max` → maximum days the password is valid
- `warn` → days before expiration to warn the user
- `inactive` → days after expiration before account is disabled
- `expire` → account expiration date (days since Jan 1, 1970)  
    Keeping the extra fields confuses Hashcat and causes errors like `Token length exception`.

✅ Example cracking result for the shadow hash:


hashcat -m 1800 -a 0 -o cracked.txt hash.txt /usr/share/seclists/Passwords/xato-net-10-million-passwords-1000000.txt


Example output:

- Status: Cracked
- Hash mode: 1800 (sha512crypt $6$)
- Hash target: $6$m6VmzKTbzCD/.I10$cKOvZZ8/rsYwHd.pE099ZRwM686p/Ep...VV1mb/
- Password found - stored in the "cracked.txt"


cat cracked.txt


![[Pasted image 20250502144545.png]]

👉 In this case, the cracked password was: `Password1`

✅ Brute-force 6-digit numeric MD5

bash
hashcat -m 0 -a 3 -o cracked.txt hashes.txt ?d?d?d?d?d?d


✅ Hybrid wordlist + numeric append

bash
hashcat -m 0 -a 6 -o cracked.txt hashes.txt rockyou.txt ?d?d


---

 ⚡ Best Practices

- Always test with `--force` **only if needed** (avoid if possible)
- Use `-w 3` or `-w 4` for faster workload on strong GPUs
- Add `--status` and `--status-timer=10` to see progress
- Save sessions: `--session=myjob` → resume later with `--restore`

---

 🧩 Example Salted Hash Handling

If your hash file has:


fc741db0a2968c39d9c2a5cc75b05370:1234


You would run (HMAC-MD5, key = $pass, mode 50):

bash
hashcat -m 50 -a 0 -o cracked.txt hashes.txt rockyou.txt


---
 📂 Where does Hashcat store cracked hashes (the potfile)?

Hashcat automatically stores cracked hashes in a **potfile** ("passwords of today" file), typically located at:


~/.hashcat/hashcat.potfile


This file keeps track of all cracked hashes so you don’t need to crack them again in future runs. You can disable it with `--potfile-disable` or specify a custom location with `--potfile-path <path>`.