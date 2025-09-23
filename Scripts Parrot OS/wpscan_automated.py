import os
import time

def verificar_flags(entrada):
    flags = []
    
    # Se o URL indicar um site WordPress
    if "wp-content" in entrada.lower():
        flags.append("--no-banner")  # Desabilita o banner de informações
        print("Detectado WordPress (wp-content). Usando flags para otimizar a execução.")
    
    # Flags personalizadas
    # Enumerar usuários
    enumerate_users = input("Deseja enumerar usuários? (s/n): ").strip().lower()
    if enumerate_users == 's':
        flags.append("--enumerate u")
        print("Flag de enumeração de usuários ativada.")
    
    # Detectar plugins mistos
    detect_plugins = input("Deseja detectar plugins mistos? (s/n): ").strip().lower()
    if detect_plugins == 's':
        flags.append("--plugins-detection mixed")
        print("Flag de detecção de plugins mistos ativada.")
    
    # Você pode adicionar mais verificações para outras flags conforme necessário
    
    return flags

def executar_wpscan(url, flags, log_file):
    # Construção do comando WPScan
    comando = f"wpscan --url {url} {' '.join(flags)} --batch"
    
    # Abre o arquivo de log para adicionar a saída
    with open(log_file, "a") as log:
        log.write(f"\n\n----- Início da execução: {time.ctime()} -----\n")
        log.write(f"Comando Executado: {comando}\n")
        
        # Redireciona a saída do comando para o arquivo de log
        log.write("Resultado do WPScan:\n")
        os.system(f"{comando} >> {log_file} 2>&1")
        log.write("\n----- Fim da execução -----\n")

def main():
    print("Bem-vindo ao script automatizado de execução do WPScan!")
    url = input("Digite o URL do site WordPress para testar (exemplo: http://exemplo.com): ").strip()

    if not url:
        print("URL inválida. Saindo...")
        return

    print(f"Analisando o URL: {url}")

    # Verificar flags adicionais
    flags = verificar_flags(url)
    
    # Caminho do arquivo de log
    log_file = "wpscan_results.log"
    
    # Executar o WPScan e registrar o resultado no log
    executar_wpscan(url, flags, log_file)

    print(f"Execução concluída. Os resultados foram registrados em {log_file}.")

if __name__ == "__main__":
    main()
