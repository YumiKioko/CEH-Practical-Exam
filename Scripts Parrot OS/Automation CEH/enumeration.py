#!/bin/bash

# Instalar ferramentas necessárias
install_tool() {
    if ! command -v $1 &> /dev/null
    then
        echo "$1 não encontrado. Instalando..."
        sudo apt-get install $2 -y
    fi
}

# Verifica e instala as ferramentas
install_tool "enum4linux" "enum4linux"
install_tool "nmap" "nmap"

# Alvo
target_ip="192.168.1.1"

# Realiza a enumeração com enum4linux
echo "Realizando enumeração com enum4linux..."
enum4linux -a $target_ip > enum_report.txt

# Realiza a enumeração com Nmap
echo "Realizando enumeração de serviços com Nmap..."
nmap -sV $target_ip > nmap_enum_report.txt

# Geração de relatório final
echo "Relatório de enumeração gerado."

# Limpeza dos arquivos de log
rm -f enum_report.txt
rm -f nmap_enum_report.txt
