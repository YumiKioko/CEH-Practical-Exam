#!/bin/bash

set -e

echo "[*] Starting CEH v12 environment setup..."

# Track installed items
declare -a installed_pkgs
declare -a installed_pip3
declare -a installed_gems
declare -a cloned_repos

is_installed() {
  dpkg -l "$1" &> /dev/null
}

is_pip3_installed() {
  pip3 show "$1" &> /dev/null
}

is_gem_installed() {
  gem list | grep -q "^$1 "
}

echo "[*] Updating system..."
sudo apt update && sudo apt full-upgrade -y

PKGS=(
  build-essential linux-headers-$(uname -r) dkms git curl wget unzip jq rlwrap tmux screen flameshot net-tools
  python3 python3-pip python-is-python3 python2 ruby ruby-dev zsh gdb gdbserver
  nmap netcat-traditional netcat-openbsd hping3 tcpdump wireshark arp-scan smbclient smbmap nbtscan onesixtyone enum4linux dnsutils whois cifs-utils
  metasploit-framework exploitdb searchsploit gobuster wfuzz dirb dirbuster nikto sqlmap wafw00f hydra john hashcat seclists wordlists crunch cewl
  binwalk steghide radare2 cutter gparted lsof strace ltrace ffuf masscan neo4j openvpn wireguard curl wget bettercap
)

echo "[*] Installing APT packages..."
for pkg in "${PKGS[@]}"; do
  if is_installed "$pkg"; then
    echo " - $pkg already installed."
  else
    echo " - Installing $pkg..."
    sudo apt install -y "$pkg"
    installed_pkgs+=("$pkg")
  fi
done

# pip2 install
if ! command -v pip2 &> /dev/null; then
  echo "[*] Installing pip for Python2..."
  curl https://bootstrap.pypa.io/pip/2.7/get-pip.py -o get-pip.py
  sudo python2 get-pip.py
  rm get-pip.py
  installed_pkgs+=("python2-pip")
else
  echo " - pip2 already installed."
fi

# Ruby gem evil-winrm
if is_gem_installed evil-winrm; then
  echo " - evil-winrm gem already installed."
else
  echo " - Installing evil-winrm gem..."
  sudo gem install evil-winrm
  installed_gems+=("evil-winrm")
fi

# Python3 packages - only simple ones here, impacket and CME handled later
for pkg in hydra john hashcat; do
  if is_installed "$pkg"; then
    echo " - $pkg already installed."
  else
    sudo apt install -y "$pkg"
    installed_pkgs+=("$pkg")
  fi
done

# Clone git repos
TOOLS_DIR=~/Tools
mkdir -p "$TOOLS_DIR"
cd "$TOOLS_DIR"

declare -A repos=(
  ["PEASS-ng"]="https://github.com/carlospolop/PEASS-ng.git"
  ["LinEnum"]="https://github.com/rebootuser/LinEnum.git"
  ["linux-smart-enumeration"]="https://github.com/diego-treitos/linux-smart-enumeration.git"
  ["windapsearch"]="https://github.com/ropnop/windapsearch.git"
  ["nishang"]="https://github.com/samratashok/nishang.git"
  ["Responder"]="https://github.com/lgandx/Responder.git"
)

for repo in "${!repos[@]}"; do
  if [ -d "$repo" ]; then
    echo " - Repo $repo already cloned."
  else
    echo " - Cloning $repo..."
    git clone "${repos[$repo]}"
    cloned_repos+=("$repo")
  fi
done

echo "[*] Setting keyboard layout to Portuguese (no dead keys)..."
setxkbmap -layout pt -variant nodeadkeys

# ==== New section for impacket and crackmapexec ====

echo
echo "[*] Verifying impacket installation..."

if dpkg -l | grep -q python3-impacket; then
  echo " - impacket installed via apt. Ensuring examples repo..."
  if [ ! -d ~/Tools/impacket ]; then
    git clone https://github.com/SecureAuthCorp/impacket.git ~/Tools/impacket
  else
    echo " - impacket repo already exists."
  fi
  echo " - Testing secretsdump.py help:"
  python3 ~/Tools/impacket/examples/secretsdump.py -h || echo "  [!] Error running secretsdump.py"
else
  echo " - impacket not installed via apt, installing/upgrading via pip3..."
  pip3 install --upgrade impacket
  echo " - Testing secretsdump help:"
  python3 -m impacket.examples.secretsdump -h || echo "  [!] Error running secretsdump"
fi

echo
echo "[*] Verifying crackmapexec..."

if command -v crackmapexec &> /dev/null; then
  echo " - crackmapexec already installed, version:"
  crackmapexec --version || echo "  [!] Error running crackmapexec"
else
  echo " - crackmapexec not found, installing official release..."
  cd /tmp
  wget -q https://github.com/byt3bl33d3r/CrackMapExec/releases/download/v5.0.3/crackmapexec-linux.zip
  unzip -o crackmapexec-linux.zip
  sudo mv crackmapexec /usr/local/bin/
  sudo chmod +x /usr/local/bin/crackmapexec
  rm crackmapexec-linux.zip
  echo " - Testing crackmapexec --version:"
  crackmapexec --version || echo "  [!] Error running crackmapexec"
fi

# ================================

echo
echo "===================== Summary of Changes ====================="
if [ ${#installed_pkgs[@]} -eq 0 ] && [ ${#installed_pip3[@]} -eq 0 ] && [ ${#installed_gems[@]} -eq 0 ] && [ ${#cloned_repos[@]} -eq 0 ]; then
  echo "No new tools or packages were installed or cloned. Your system is up to date."
else
  if [ ${#installed_pkgs[@]} -ne 0 ]; then
    echo "APT packages installed:"
    printf '  - %s\n' "${installed_pkgs[@]}"
  fi
  if [ ${#installed_pip3[@]} -ne 0 ]; then
    echo "Python3 packages installed via pip3:"
    printf '  - %s\n' "${installed_pip3[@]}"
  fi
  if [ ${#installed_gems[@]} -ne 0 ]; then
    echo "Ruby gems installed:"
    printf '  - %s\n' "${installed_gems[@]}"
  fi
  if [ ${#cloned_repos[@]} -ne 0 ]; then
    echo "Git repositories cloned:"
    printf '  - %s\n' "${cloned_repos[@]}"
  fi
fi
echo "=============================================================="
echo
echo "[✔] CEH v12 practical environment setup completed."
echo "[!] Reminder: Download BloodHound GUI manually from https://github.com/BloodHoundAD/BloodHound/releases"
echo "[!] Remember to start Neo4j with: sudo systemctl start neo4j"
echo "[!] Reboot your system to ensure all changes take effect."
