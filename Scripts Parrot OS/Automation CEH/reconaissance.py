import os
import subprocess
import sys

def install_tool(tool_name, install_command):
    """Função para instalar ferramentas caso não estejam presentes"""
    try:
        subprocess.run(tool_name, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError:
        print(f"{tool_name} não encontrado. Instalando...")
        try:
            subprocess.run(install_command, check=True, shell=True)
        except subprocess.CalledProcessError:
            print(f"Falha ao instalar {tool_name}. Continuando sem a ferramenta.")
            return False
    return True

def run_reconnaissance():
    """Realiza o reconhecimento com ferramentas como Nmap, Whois, etc."""
    tools = {
        "nmap": "sudo apt-get install nmap -y",
        "whois": "sudo apt-get install whois -y"
    }

    # Instala as ferramentas necessárias
    for tool, install_cmd in tools.items():
        install_tool(tool, install_cmd)

    # Realiza o scan de porta com Nmap
    target_ip = "192.168.1.1"  # Exemplo de IP alvo
    nmap_cmd = f"nmap -sP {target_ip}"
    print(f"Executando comando Nmap: {nmap_cmd}")
    subprocess.run(nmap_cmd, shell=True)

    # Realiza a consulta Whois
    whois_cmd = f"whois {target_ip}"
    print(f"Executando comando Whois: {whois_cmd}")
    subprocess.run(whois_cmd, shell=True)

    # Geração de Relatório
    with open("recon_report.txt", "w") as report:
        report.write(f"Reconhecimento realizado para {target_ip} com Nmap e Whois.\n")

    print("Reconhecimento finalizado. Relatório gerado: recon_report.txt")

    # Limpeza de Logs (exemplo simplificado)
    os.remove("recon_report.txt")

# Execução do Reconhecimento
run_reconnaissance()
