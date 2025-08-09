### ⚙️ Basic Syntax

```
nikto -h <target>
```

## 🔧 Common Options

| Option            | Description                                        |                     |
| ----------------- | -------------------------------------------------- | ------------------- |
| `-h`              | Target hostname or IP                              |                     |
| `-p`              | Port number (default 80)                           |                     |
| `-ssl`            | Force SSL                                          |                     |
| `-Tuning x`       | Tuning options (select types of tests)             |                     |
| `-output`         | Save output to file                                |                     |
| `-Format`         | Output format (`txt`, `html`, `csv`, `json`, etc.) |                     |
| `-evasion x`      | Use evasion techniques                             |                     |
| `-useragent <UA>` | Set custom user-agent                              |                     |
| `-useproxy`       | Use system proxy (from env var)                    | ## 🧪 Example Usage |
### 🧪 Example Usage
### Basic scan:

```
nikto -h http://target.com
```

### Scan HTTPS:

```
nikto -h https://secure.site.com
```

### Scan specific port:

```
nikto -h http://target.com -p 8080
```

### Save as HTML report:

```
nikto -h http://target.com -output report.html -Format html
```

## 🎯 Tuning Options

Select specific types of tests (can combine):

| Code | Description            |
| ---- | ---------------------- |
| `0`  | File upload            |
| `1`  | Interesting files      |
| `2`  | Misconfigurations      |
| `3`  | Information disclosure |
| `4`  | Injection (XSS, etc.)  |
| `5`  | Remote file retrieval  |
| `6`  | Denial of Service      |
| `7`  | Remote execution       |
| `8`  | Command execution      |
| `9`  | SQL injection          |
| `a`  | Authentication bypass  |
### Example:

```
nikto -h http://target.com -Tuning 123
```

## 🛡️ Evasion Techniques

| Option | Description                     |
| ------ | ------------------------------- |
| `1`    | Random URI encoding             |
| `2`    | Random user agent               |
| `3`    | Append fake parameters          |
| `4`    | Premature URL ending            |
| `5`    | Use Windows directory separator |
| `6`    | Self-referencing path (`/./`)   |
| `7`    | Fake session IDs                |
| `8`    | Use whitespace in request       |
| `9`    | Tab as request separator        |
### Example:

```
nikto -h http://target.com -evasion 1,3,6
```

### 🧾 Output Formats

```
-Format txt
-Format html
-Format csv
-Format json
```

## 📁 Useful Directories

- Wordlists and plugins:

```
/usr/share/nikto/
```
































































