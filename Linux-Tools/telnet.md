# Telnet

**Description:**\
Telnet provides text-based communication over a virtual terminal
connection. (Insecure, use SSH instead.)

**Basic Syntax:**

``` bash
telnet [host] [port]
```

**Use Cases:** - Test connectivity to a port\
- Manually interact with services (SMTP, HTTP, etc.)\
- Debug network services

**Examples:**

``` bash
telnet google.com 80       # Test HTTP
telnet mail.server.com 25  # Test SMTP
telnet 192.168.1.1 23      # Connect to Telnet service
```

**Common Service Ports:** - 21 FTP\
- 22 SSH\
- 25 SMTP\
- 80 HTTP\
- 110 POP3\
- 143 IMAP\
- 443 HTTPS

**Interactive Commands:** - `Ctrl+]` → `quit` → Exit telnet\
- Type commands directly to interact with service
