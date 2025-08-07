### Basic Network Discovery

```bash

nmap -sn <IP>/24

```
  
### Full Port Scan with Service and OS Detection

```bash

nmap -sS -sCV -O -A -p- <IP>

```
  
### Scan without DNS Resolution

```bash

nmap -Pn -n -T4 -sCV <IP>

```


- `-sS`: TCP SYN scan

- `-sC`: Default scripts

- `-sV`: Version detection

- `-O`: OS detection

- `-A`: Aggressive scan

- `-Pn`: Treat all hosts as up

- `-n`: Skip DNS resolution

- `-T4`: Speed up scan