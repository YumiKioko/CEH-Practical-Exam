Hydra HTTP POST Brute-Force Guide hydra 

Hydra is a **network login cracker** widely used for **brute-force password attacks** across various protocols (SSH, FTP, HTTP, etc.). This guide focuses on **brute-forcing HTTP POST login forms**.

General Syntax


hydra -l username -P wordlist.txt server service


 Parameters:

- `-l username`: Specifies a **single username**.
    
- `-P wordlist.txt`: Specifies a **password wordlist** file.
    
- `server`: The **target server's hostname or IP address**.
    
- `service`: The **protocol or service module** to attack (e.g., ssh, ftp, http-post-form).
    

 Example Command


hydra -L names.txt -p test -t 20 10.0.2.3 http-post-form "/4cdab8ca92e379604ae1e1bbb99977c7.ctf.hacker101.com/login:username=^USER^&password=^PASS^:Invalid username"


 Flag Summary:

- `-L names.txt`: Username **wordlist**.
    
- `-p test`: A **single password** (`test`).
    
- `-t 20`: **20 parallel tasks** (threads).
    
- `10.0.2.3`: Target **IP address**.
    
- `http-post-form`: Specifies the **HTTP POST module**.
    
- `"/path:POST-DATA:FAILURE-CONDITION"`: HTTP POST form parameters.
    

 Step-by-Step Breakdown

 1. `hydra`

- The main **Hydra program**.
    
- Supports various protocols for **brute-force attacks**.
    

 2. `-L names.txt`

- **`-L`** specifies a **username list** file.
    
- Hydra reads **each line** in `names.txt` as a potential username.
    
- Performs a **dictionary attack** on usernames.
    

 3. `-p test`

- **`-p`** sets a **single password** (`test`).
    
- Each username from `names.txt` is tested against **password `test`**.
    
- Alternatives:
    
    - `-p password`: Single password.
        
    - `-P passwords.txt`: **Password list**.
        

 4. `-t 20`

- **`-t`** sets the **number of parallel tasks (threads)**.
    
- Enables **20 concurrent attempts**, increasing speed.
    
- Caution: Higher threads = higher **detection risk** and potential **target overload**.
    

---

 5. `10.0.2.3`

- Target machine's **IP address**.
    
- Hydra sends login attempts to this machine.
    

 6. `http-post-form`

- Specifies the **Hydra module** for **HTTP POST login forms**.
    
- Other modules: `ssh`, `ftp`, `telnet`, etc.
    
 7. HTTP POST Form Format


"URL:POST-DATA:FAILURE-CONDITION"


 Example:


"/4cdab8ca92e379604ae1e1bbb99977c7.ctf.hacker101.com/login:username=^USER^&password=^PASS^:Invalid username"


- **URL**: `/4cdab8ca92e379604ae1e1bbb99977c7.ctf.hacker101.com/login`
    
    - Path to the **login page**.
        
- **POST-DATA**: `username=^USER^&password=^PASS^`
    
    - Data sent via POST.
        
    - Placeholders:
        
        - `^USER^`: Replaced by **each username** from `names.txt`.
            
        - `^PASS^`: Replaced by the **password `test`**.
            
- **FAILURE-CONDITION**: `Invalid username`
    
    - Hydra scans the **server's response** for this string.
        
    - If found, it marks the attempt as **failed**.
        
    - If **not found**, Hydra assumes the login **succeeded**.
        

 Extra Tips

- Add **verbosity** with `-vV` to print **each login attempt**.
    
- Use `-d` for **debugging** output (reveals timeouts, connection issues, etc.).
    
- Adjust **thread count (`-t`)** based on **target stability** and **stealth requirements**.
    
- Use `-s PORT` to specify a **non-default port** for the service.
    
- Adjust **thread count (`-t`)** based on **target stability** and **stealth requirements**.
    
- Use `-s PORT` to specify a **non-default port** for the service.
    

 Verbose Example:


hydra -L names.txt -p test -t 20 -vV 10.0.2.3 http-post-form "/4cdab8ca92e379604ae1e1bbb99977c7.ctf.hacker101.com/login:username=^USER^&password=^PASS^:Invalid username"



 Additional Examples

 1. FTP Brute-Force


hydra -l mark -P /usr/share/wordlists/rockyou.txt 10.10.156.50 ftp


- Uses **`mark`** as the username.
    
- Iterates over **passwords** from `rockyou.txt` against the **FTP server**.
    


 2. FTP with URI Format


hydra -l mark -P /usr/share/wordlists/rockyou.txt ftp://10.10.156.50


- Equivalent to the previous FTP example.
    
- `10.10.156.50 ftp` is the same as `ftp://10.10.156.50`.
    


 3. SSH Brute-Force


hydra -l frank -P /usr/share/wordlists/rockyou.txt 10.10.156.50 ssh


- Uses **`frank`** as the username.
    
- Attempts **SSH login** with different passwords.
    

---

 Useful Optional Arguments

- `-s PORT`: Specify a **non-default port** (e.g., `-s 2222` for SSH on port 2222).
    
- `-V` or `-vV`: Enable **verbose output** (displays each username/password combination being tried).
    
- `-t n`: Define the **number of parallel connections** (e.g., `-t 16` for 16 threads).
    
- `-d`: Activate **debugging mode** (provides detailed information about connection attempts).
    

Once Hydra finds valid credentials, you can **terminate the process with CTRL-C**.

> **TryHackMe Tip:** In TryHackMe tasks, brute-force attacks are expected to finish **within five minutes**. In real-world scenarios, these attacks can take much longer. Using verbosity (`-vV`) or debugging (`-d`) helps monitor progress effectively.

- `-V` or `-vV`: **Verbose output** (shows each username/password combination attempted).
    
- `-t n`: **Number of parallel connections** (e.g., `-t 16` = 16 threads).
    
- `-d`: **Debugging mode** (reveals connection issues, timeouts, etc.).
    

> **Note:** Once the password is found, you can **stop Hydra with CTRL-C**. In TryHackMe tasks, attacks are expected to finish **within five minutes**. In real-life scenarios, attacks may **take much longer**. Verbosity (`-vV`) and debugging (`-d`) are useful for monitoring progress.