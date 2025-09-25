import os
import subprocess
import sys
import time
import shutil
import threading

def check_installation(tool_name, install_cmd):
    """Verifica se a ferramenta está instalada, caso contrário, instala-a."""
    try:
        subprocess.run([tool_name, '--version'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        print(f"{tool_name} já está instalado.")
    except FileNotFoundError:
        print(f"{tool_name} não encontrado. Instalando...")
        os.system(install_cmd)

def reconnaissance(target):
    """Fase de reconhecimento: coleta informações sobre o alvo."""
    check_installation('whois', 'sudo apt-get install whois -y')
    check_installation('nslookup', 'sudo apt-get install dnsutils -y')
    
    recon_output = "recon_report.txt"
    with open(recon_output, "w") as f:
        f.write("=== Reconhecimento ===\n")
        f.write(subprocess.getoutput(f"whois {target}"))
        f.write("\n\n")
        f.write(subprocess.getoutput(f"nslookup {target}"))
    
    print(f"Reconhecimento concluído. Relatório salvo em {recon_output}")

def enumeration(target):
    """Fase de enumeração: identifica serviços e portas abertas."""
    check_installation('nmap', 'sudo apt-get install nmap -y')
    
    enum_output = "enum_report.txt"
    subprocess.run(["nmap", "-T4", "-sS", "-sV", "-oN", enum_output, target], check=True)
    print(f"Enumeração concluída. Relatório salvo em {enum_output}")

def vulnerability_analysis(target):
    """Fase de análise de vulnerabilidades."""
    check_installation('nikto', 'sudo apt-get install nikto -y')
    check_installation('zap-cli', 'pip install zapcli')
    
    vuln_output = "vuln_report.txt"
    subprocess.run(["nikto", "-h", target, "-o", vuln_output], check=True)
    print(f"Análise de vulnerabilidades concluída. Relatório salvo em {vuln_output}")

def start_zap_daemon():
    """Start OWASP ZAP in daemon mode."""
    zap_script = "/usr/share/zaproxy/zap.sh"
    if os.path.exists(zap_script):
        print("Iniciando OWASP ZAP em modo daemon...")
        subprocess.run([zap_script, '-daemon'], check=True)
    else:
        print("Erro: zap.sh não encontrado. Verifique a instalação do ZAP.")
        sys.exit(1)

def exploitation(target):
    """Fase de exploração (simulada)."""
    print("Exploitation simulada - não incluído para evitar danos.")

def generate_report():
    """Gera um relatório HTML consolidado com mitigações."""
    report_html = "report.html"
    vulnerabilities = {
        "SSL Insecure": "Atualize a configuração SSL/TLS do servidor para usar apenas protocolos seguros.",
        "XSS": "Implemente filtros de entrada e use Content Security Policy (CSP).",
        "SQL Injection": "Use prepared statements e sanitize os inputs do usuário.",
        "Open Ports": "Restrinja portas desnecessárias e implemente firewall adequado."
    }
    
    with open(report_html, "w") as f:
        f.write("<html><head><title>Relatório de Teste de Penetração</title></head><body>")
        f.write("<h1>Relatório de Teste de Penetração</h1>")
        
        for scan_report in ["recon_report.txt", "enum_report.txt", "vuln_report.txt"]:
            if os.path.exists(scan_report):
                with open(scan_report, "r") as report:
                    content = report.read()
                    f.write(f"<h2>{scan_report}</h2><pre>{content}</pre>")
                    for vuln, fix in vulnerabilities.items():
                        if vuln.lower() in content.lower():
                            f.write(f"<p><b>Mitigação:</b> {fix}</p>")
        
        f.write("</body></html>")
    print(f"Relatório gerado em {report_html}")

def cleanup():
    """Remove logs e artefatos temporários."""
    files_to_remove = ["recon_report.txt", "enum_report.txt", "vuln_report.txt"]
    for file in files_to_remove:
        if os.path.exists(file):
            os.remove(file)
    print("Logs e artefatos removidos.")

def main():
    if len(sys.argv) < 3:
        print("Uso: python script.py <tipo> <alvo>")
        sys.exit(1)
    
    scan_type = sys.argv[1]
    target = sys.argv[2]
    
    if scan_type == "ceh":
        threads = []
        
        # Rodando as fases em paralelo
        for func in [reconnaissance, enumeration, vulnerability_analysis]:
            t = threading.Thread(target=func, args=(target,))
            t.start()
            threads.append(t)
        
        for t in threads:
            t.join()
        
        exploitation(target)
        start_zap_daemon()  # Iniciar o ZAP em modo daemon
        generate_report()
        cleanup()
    else:
        print("Tipo inválido. Use 'ceh'")
        sys.exit(1)
    
    print("Análise concluída. Relatório gerado e limpeza feita.")

if __name__ == "__main__":
    main()
