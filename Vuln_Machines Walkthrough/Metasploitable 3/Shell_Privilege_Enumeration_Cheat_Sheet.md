# Shell User Privilege & Privilege Escalation Cheat Sheet

This document combines Linux and Windows user privilege enumeration with post-exploitation privilege escalation checks in a single reference. Suitable for educational and legal penetration testing scenarios.

---

## Table of Contents
1. [Linux: User Privilege & Permission Enumeration](#linux-user-privilege--permission-enumeration)
2. [Windows: User Privilege & Permission Enumeration](#windows-user-privilege--permission-enumeration)
3. [Linux: Privilege Escalation Checks](#linux-privilege-escalation-checks)
4. [Windows: Privilege Escalation Checks](#windows-privilege-escalation-checks)
5. [Workflow for Post-Shell Enumeration](#workflow-for-post-shell-enumeration)

---

## Linux: User Privilege & Permission Enumeration

### Identify Current User
```bash
whoami          # Current username
id              # UID, GID, and groups
groups          # All groups user belongs to
```

### Check Sudo Privileges
```bash
sudo -l         # Commands user can run with sudo
```

### Check File Permissions
```bash
ls -l /path/to/file_or_dir        # Detailed file permissions
find / -perm -4000 -type f 2>/dev/null  # Find setuid binaries
```

### Environment & System Info
```bash
env             # Environment variables
uname -a        # Kernel and architecture
cat /etc/os-release   # Linux distribution info
```

### Running Processes & Services
```bash
ps aux          # Running processes
systemctl list-units --type=service   # Active systemd services
```

### Terminal Upgrade (Optional)
```bash
python -c 'import pty; pty.spawn("/bin/bash")'
export SHELL=/bin/bash
export TERM=xterm
stty rows 40 columns 100
```

---

## Windows: User Privilege & Permission Enumeration

### Identify Current User
```powershell
whoami
whoami /groups   # Group memberships
```

### Check Admin Rights & Privileges
```powershell
net session       # Admin-only
whoami /priv      # Lists privileges like SeDebugPrivilege
```

### File & Directory Permissions
```powershell
icacls C:\path\to\file
```

### System Info
```powershell
systeminfo        # OS version, patch level, local users
```

### Optional Enumeration Tools
- `wmic useraccount get name,sid` – list users and SIDs
- `Get-LocalGroupMember Administrators` – users in admin group

---

## Linux: Privilege Escalation Checks

### 1. Sudo Privileges
```bash
sudo -l
```
- Look for commands allowed as root or with NOPASSWD.

### 2. Examine Sudoers Files
```bash
cat /etc/sudoers
cat /etc/sudoers.d/*
```

### 3. SUID Binaries
```bash
find / -perm -4000 -type f 2>/dev/null
```
- Some SUID binaries (vim, less, find) allow shell escapes.

### 4. Root-owned Scripts & Cron Jobs
```bash
ls -l /etc/cron* /var/spool/cron*
```
- Editable scripts run by root may be exploited.

### 5. Processes Running as Root
```bash
ps aux
```
- Check for manipulable processes.

---

## Windows: Privilege Escalation Checks

### 1. Group Membership
```powershell
whoami /groups
```
- Membership in Administrators or Power Users allows elevated execution.

### 2. User Privileges
```powershell
whoami /priv
```
- Check for SeDebugPrivilege, SeImpersonatePrivilege, etc.

### 3. Scheduled Tasks
```powershell
schtasks /query /fo LIST /v
```
- Tasks running as SYSTEM/Admin may be exploitable if user can edit.

### 4. SYSTEM Services
```powershell
Get-WmiObject Win32_Service | where { $_.StartName -eq "LocalSystem" }
```
- Check for services that can be influenced.

### 5. File Permissions for Elevated Execution
```powershell
icacls C:\path\to\file
```

### 6. Optional Tools
- **WinPEAS**, **PowerUp** – automated privilege escalation enumeration.

---

## Workflow for Post-Shell Enumeration
1. Identify current user and groups (`whoami` / `id`)
2. Check sudo/admin privileges (`sudo -l` / `whoami /priv`)
3. Enumerate SUID binaries (Linux) or SYSTEM services/tasks (Windows)
4. Check editable scripts, cron jobs, or scheduled tasks
5. Look for writable executables run by root/admin
6. Upgrade shell for better interactivity (Linux PTY, Windows PowerShell interactive session)

---

**Note:** Use these commands only on systems you are authorized to test.
