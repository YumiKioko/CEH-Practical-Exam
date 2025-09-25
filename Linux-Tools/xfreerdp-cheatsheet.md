# xfreerdp Cheat Sheet

`xfreerdp` is a free RDP (Remote Desktop Protocol) client for Linux and other systems.

---

## Basic Syntax

```bash
xfreerdp [options] server[:port]
```

---

## Common Options

| Option | Description |
|--------|-------------|
| `/u:USERNAME` | Username for login |
| `/p:PASSWORD` | Password for login (use with caution) |
| `/d:DOMAIN` | Domain name |
| `/v:SERVER[:PORT]` | Server address and optional port |
| `/cert:ignore` | Ignore certificate warnings |
| `/f` | Fullscreen mode |
| `/w:WIDTH /h:HEIGHT` | Set custom resolution |
| `/dynamic-resolution` | Enable dynamic resizing of window |
| `/scale:NUM` | Scale display (e.g. `/scale:140`) |
| `/clipboard` | Enable clipboard redirection |
| `/microphone` | Redirect local microphone |
| `/sound` | Redirect audio output |
| `/drive:NAME,PATH` | Share a local folder |
| `/printer` | Redirect local printers |
| `/multimon` | Use multiple monitors |
| `/sec:rdp` | Force RDP security protocol |
| `/sec:tls` | Force TLS security protocol |
| `/sec:nla` | Force NLA authentication |
| `/admin` | Connect to console/admin session |
| `/log-level:LEVEL` | Logging (trace, debug, info, warn, error, fatal) |

---

## Examples

### Connect with username & password prompt
```bash
xfreerdp /u:myuser /v:192.168.1.10
```

### Fullscreen connection
```bash
xfreerdp /u:myuser /p:mypassword /v:server.example.com /f
```

### Set resolution
```bash
xfreerdp /u:admin /p:secret /v:10.0.0.5 /w:1280 /h:720
```

### Dynamic resolution (resize window freely)
```bash
xfreerdp /u:admin /v:10.0.0.5 /dynamic-resolution
```

### Clipboard & audio forwarding
```bash
xfreerdp /u:user /v:rdpserver.local /clipboard /sound
```

### Share local folder
```bash
xfreerdp /u:user /v:rdpserver.local /drive:share,/home/user/share
```

### Multi-monitor
```bash
xfreerdp /u:user /v:rdpserver.local /multimon
```

### Ignore cert warnings
```bash
xfreerdp /u:user /v:192.168.1.100 /cert:ignore
```

### Admin session
```bash
xfreerdp /u:administrator /v:server.local /admin
```

---

## Useful Tips

- If you don’t provide `/p:`, you’ll be prompted for the password.
- Use `/cert:ignore` when testing or connecting to machines with self-signed certs.
- Combine `/dynamic-resolution` with windowed mode for the best experience.
- Use `/log-level:debug` for troubleshooting.
