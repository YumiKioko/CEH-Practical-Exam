
## What is Evil-WinRM?

Evil-WinRM is a powerful post-exploitation tool used by penetration testers and red teamers to interact with remote Windows machines over the WinRM (Windows Remote Management) service.

### Main Function:

Evil-WinRM allows you to establish a remote PowerShell shell on a Windows system using valid credentials via WinRM. This gives you command-line access similar to being on the machine.
### Use Case:

If you have:

- A username    
- A password or NTLM hash
- WinRM enabled on the target

Then you can run:

```
evil-winrm -i <target-ip> -u <username> -p <password>
```

or with an hash

```
evil-winrm -i <target-ip> -u <username> -H <hash>
```

And get a remote PowerShell session.

### Key Features:

- Remote PowerShell shell via WinRM
- File upload/download
- Execute local PowerShell scripts
- Load and run custom post-exploitation tools (e.g. Mimikatz, PowerView)
- Supports authentication via password or NTLM hash

### Why It's Useful:

Evil-WinRM is essential in Windows post-exploitation scenarios. It provides:

- Easy access to the system for reconnaissance
- Capability to dump credentials and escalate privileges
- Lateral movement using PowerShell tools

### Is Evil-WinRM part of Impacket?

- No, Evil-WinRM is not part of Impacket.
- Evil-WinRM is a Ruby tool focused on WinRM access
- Impacket is a Python library with tools for SMB, WMI, Kerberos, etc.
- Both are commonly used together, but they serve different purposes.

### Installation on Kali Linux:

Update your system:

```
sudo apt update
```

Install Ruby and dependencies:

```
sudo apt install ruby ruby-dev
```

Install Evil-WinRM:

```
sudo gem install evil-winrm
```

Verify Installation:

```
evil-winrm -h
```

You should see the help menu if installed correctly.

You can now use Evil-WinRM for remote access during engagements where WinRM is available and you have valid credentials.