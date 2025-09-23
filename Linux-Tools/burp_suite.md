# Burp Suite

**Description:**  
Burp Suite is a web application security testing platform (proxy, scanner, intruder, repeater).

**Basic Workflow:**  
1. Configure browser to use Burp as proxy (e.g., 127.0.0.1:8080).  
2. Intercept & modify requests with Proxy.  
3. Use Repeater for manual testing and Intruder for automated fuzzing.  
4. Scanner (Professional) identifies vulnerabilities automatically.

**Common Tips:**  
- Install Burp CA cert in your browser to intercept HTTPS.  
- Use session handling rules for CSRF/anti-CSRF tokens.  
- Save project files for reporting.

**CLI:** `burpsuite` (varies by edition)