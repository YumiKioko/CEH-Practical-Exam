# sqlmap with Burp — practical guide

> **Important:** Only use these techniques on systems you own or have explicit authorization to test (DVWA, Juice Shop, lab VM, or written permission).

---

## Quick overview

1. Intercept the HTTP(S) request in Burp (Proxy → HTTP history).  
2. Save the raw request to a file (right-click → **Save item** / Copy to file).  
3. Run **sqlmap** using that saved request (`-r request.txt`) and optionally tell sqlmap to use Burp as a proxy to inspect/edit traffic.  
4. Review results and iterate (or tweak payloads in Burp Repeater and re-run sqlmap with `-r`).

---

## Common workflows & examples

### A — Fast: feed a saved Burp request to sqlmap

1. In Burp → Proxy → HTTP history, find the request. Right-click → **Save item** → save the raw request as `req.txt`.
2. Run sqlmap:

```bash
sqlmap -r req.txt --batch -p id --dbs
```

`--batch` picks defaults (noninteractive). `-p id` targets parameter named `id` (adjust). `--dbs` enumerates databases.

### B — Proxy traffic through Burp (inspect/edit live)

If you want sqlmap requests to go through Burp (default Burp proxy `127.0.0.1:8080`):

```bash
sqlmap -u "https://example.com/page.php?id=1" --proxy="http://127.0.0.1:8080" --ignore-ssl-errors --batch -p id --dbs
```

Notes:
- `--proxy="http://127.0.0.1:8080"` forces sqlmap to send traffic through Burp.  
- If target is HTTPS you may see SSL warnings — use `--ignore-ssl-errors` to bypass certificate errors while testing (only on authorized targets).  
- Use `--proxy-cred` if your proxy requires auth: `--proxy-cred user:pass`.

### C — Use cookie/header/auth from Burp

If you captured a request in Burp with special cookies/headers (e.g. session token), either:

- Use the `-r req.txt` method (recommended — uses the exact raw request), or
- Recreate headers/cookies on command line:

```bash
sqlmap -u "https://example.com/page.php?id=1" --cookie="PHPSESSID=abcd; other=val" --headers="User-Agent: myUA" --proxy="http://127.0.0.1:8080" -p id --batch --dbs
```

### D — Example raw request file (`req.txt`) format for `-r`

Save exactly what Burp shows for the raw request. Example:

```
GET /vuln.php?id=1 HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0
Accept: */*
Cookie: PHPSESSID=abcd1234
Connection: close

```

Then:

```bash
sqlmap -r req.txt --batch -p id --dbs
```

---

## Useful sqlmap options for Burp-driven testing

- `-r FILE` — use raw request file from Burp.  
- `--proxy="http://127.0.0.1:8080"` — route through Burp.  
- `--ignore-ssl-errors` — ignore SSL cert problems (use carefully).  
- `--data="param1=val1&param2=val2"` — POST body (if not using `-r`).  
- `-p PARAM` — explicitly set parameter(s) to test.  
- `--cookie="..."` and `--headers="Header: value"` — supply auth headers.  
- `--level N` / `--risk N` — deeper tests (higher values = more requests/payloads).  
- `--technique=BEUSTQ` — control techniques (Boolean, Error, Union, Stacked, Time, etc.).  
- `--tamper=script1,script2` — use tamper scripts (helpful for filters).  
- `--threads=NUM` — concurrency.  
- `--dump` / `--dbs` / `--tables` / `--columns` — enumerate/dump as needed.  
- `--batch` — noninteractive mode.

---

## Tips & troubleshooting

- If sqlmap appears not to reach Burp: confirm Burp proxy is listening (Proxy → Options → Interface 127.0.0.1:8080) and **intercept is off** (or on, if you want to modify each request).
- For HTTPS targets: using `--proxy` makes sqlmap use an HTTP proxy and Burp will handle the TLS; if you get errors, add `--ignore-ssl-errors`.
- Use `-v 3` (or higher) to increase verbosity for debugging.
- If the app has CSRF tokens or one-time tokens, use `-r` with a replayable request or automate token refresh (sqlmap has `--csrf-token` option for some flows).
- If the app blocks or rate-limits, lower `--threads`, increase `--timeout`, or use `--delay`/`--randomize`.
- Use Burp Repeater to manually verify injection before running automated sqlmap. That reduces false positives and noisy scanning.
- For complex multi-step auth flows, capture and save the exact authenticated request (with cookies/headers) and use `-r`.

---

## Burp integrations & extras

- There are Burp extensions that integrate with sqlmap (check the BApp store for “SQLMap” or “SQLi” plugins). They can send a single request to a local sqlmap instance or construct command lines for you.
- Use Burp Collaborator to detect certain blind injection callbacks, but note sqlmap has its own techniques for blind/time-based tests.

---

## Safety & ethics (must-read)

- **Do not** run sqlmap against systems you do not own or do not have explicit permission to test. Doing so is illegal in many jurisdictions and can cause damage.  
- Use controlled environments (DVWA, bWAPP, Juice Shop, deliberately vulnerable VMs) or a signed authorization/pen test engagement.  
- Keep logs of what you test and get permission in writing.

---

## Next steps

If you want, I can:

- produce a ready-to-run example `req.txt` tailored to a sample DVWA request, or
- show the exact sqlmap command you should use for a specific request you paste here (only if you have permission to test).

Tell me which and I’ll add it to the file or create a new one.

