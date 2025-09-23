# OWASP ZAP

**Description:**  
ZAP is an open-source web application security scanner and proxy (alternative to Burp).

**Basic Usage:**  
- Start ZAP GUI or run headless scans with the CLI.  
- Configure your browser proxy to 127.0.0.1:8080 to intercept traffic.

**Useful Features:**  
- Active and passive scanners, spidering, fuzzer, API for automation.

**Example CLI scan (basic):**
```bash
zap.sh -cmd -quickurl https://target -quickout report.html
```