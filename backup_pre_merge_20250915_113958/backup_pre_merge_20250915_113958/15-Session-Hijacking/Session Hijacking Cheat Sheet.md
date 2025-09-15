# Session Hijacking Cheat Sheet

**Disclaimer:** This information is for educational purposes and security testing only. Always obtain explicit permission before testing any system.

## 🎯 What is Session Hijacking?
The exploitation of a valid computer session—sometimes also called a **session key**—to gain unauthorized access to information or services in a computer system.

---

## 1. Session Basics

### How Sessions Work
1.  User logs in → Server creates a **Session ID**
2.  Session ID is stored:
    *   **Server-side:** In memory/database
    *   **Client-side:** In a cookie (`PHPSESSID`, `JSESSIONID`, `ASP.NET_SessionId`)
3.  Browser sends the Session ID with each subsequent request
4.  Server validates the ID to authenticate the user

### Common Session Token Locations
| Location | Example |
| :--- | :--- |
| **Cookie** | `Cookie: PHPSESSID=abc123def456;` |
| **URL Parameter** | `https://site.com/dashboard?sid=abc123def456` |
| **Hidden Form Field** | `<input type="hidden" name="sessid" value="abc123def456">` |

---

## 2. Reconnaissance & Discovery

### Identify Session Management
```bash
# Check cookies in browser
F12 → Application → Cookies

# Use curl to inspect headers
curl -I http://target.com
curl -v http://target.com/login

# Check for URL parameters
https://target.com?sessionid=XXX