import os
import time

def verificar_flags(entrada):
    flags = []
    if "?" in entrada:
        # Caso exista um parâmetro na URL, como `?id=1`
        flags.append("--risk=3 --level=5")
        print("Detectado parâmetro de URL. Usando flags padrão de risco e nível alto.")
    if "union" in entrada.lower():
        # Se encontrar a palavra "union" no URL, pode estar relacionado a uma SQLi com UNION
        flags.append("--technique=U")
        print("Detectada possível técnica UNION. Usando flag de técnica específica.")
    # Podemos adicionar mais verificações aqui com base na URL fornecida

    return flags

def executar_sqlmap(url, flags, log_file):
    # Criação do comando para executar o SQLMap
    comando = f"sqlmap -u {url} {' '.join(flags)} --batch"
    
    # Abre o arquivo de log para adicionar a saída
    with open(log_file, "a") as log:
        log.write(f"\n\n----- Início da execução: {time.ctime()} -----\n")
        log.write(f"Comando Executado: {comando}\n")
        
        # Redireciona a saída do comando para o arquivo de log
        log.write("Resultado do SQLMap:\n")
        os.system(f"{comando} >> {log_file} 2>&1")
        log.write("\n----- Fim da execução -----\n")

def main():
    print("Bem-vindo ao script automatizado de execução do SQLMap!")
    url = input("Digite o URL para testar (exemplo: http://exemplo.com/page?id=1): ").strip()

    if not url:
        print("URL inválida. Saindo...")
        return

    print(f"Analisando o URL: {url}")

    # Verificar flags adicionais
    flags = verificar_flags(url)
    
    # Caminho do arquivo de log
    log_file = "sqlmap_results.log"
    
    # Executar o SQLMap e registrar o resultado no log
    executar_sqlmap(url, flags, log_file)

    print(f"Execução concluída. Os resultados foram registrados em {log_file}.")

if __name__ == "__main__":
    main()
