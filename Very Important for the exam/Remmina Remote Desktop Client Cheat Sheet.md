
```markdown
# Remmina Remote Desktop Client Cheat Sheet

## Overview
Remmina is a feature-rich remote desktop client for Linux systems supporting multiple protocols including RDP, VNC, SSH, and SPICE.

## Installation

### Ubuntu/Debian
```bash
sudo apt update
sudo apt install remmina remmina-plugin-*
```

### Fedora/RHEL
```bash
sudo dnf install remmina remmina-plugins-*
```

### Install Specific Protocol Plugins
```bash
# RDP plugin
sudo apt install remmina-plugin-rdp

# VNC plugin  
sudo apt install remmina-plugin-vnc

# SSH plugin
sudo apt install remmina-plugin-ssh

# SPICE plugin
sudo apt install remmina-plugin-spice
```

## Basic Usage

### Starting Remmina
```bash
remmina
```

### Keyboard Shortcuts
```
Ctrl+N          - New connection
Ctrl+Q          - Quick connect dialog
Ctrl+Alt+Enter  - Toggle fullscreen
Ctrl+Alt+F      - Switch to fullscreen
Ctrl+Alt+S      - Take screenshot
Ctrl+Alt+C      - Open preferences
Ctrl+Alt+T      - New terminal (SSH)
Ctrl+Alt+K      - Show keyboard shortcuts
```

## Connection Types

### RDP Connections
- **Server**: `hostname:port` or `IP:port`
- **Username**: Domain\user or user@domain
- **Password**: Your login credentials
- **Domain**: (Optional) Windows domain
- **Resolution**: Set display resolution
- **Color depth**: 16, 24, or 32-bit

### VNC Connections
- **Server**: `hostname:port` or `IP:port`
- **Quality**: Adjust for bandwidth
- **View only**: Read-only mode
- **Clipboard sync**: Share clipboard

### SSH Connections
- **Server**: `hostname` or `IP`
- **Username**: SSH user
- **Authentication**: Password or SSH key
- **Execute command**: Run specific command

## Downloading Files from Windows to Linux

### Method 1: RDP Drive Redirection (Recommended)

#### Setup in Remmina:
1. Create/edit RDP connection
2. Go to **Advanced** tab
3. Find **Share folder** section
4. Click **+** to add local Linux folders to share
5. Configure share settings:
   ```
   Local folder: /home/username/Downloads
   Share name: LinuxDownloads (auto-generated)
   ```

#### Access from Windows:
1. Connect via RDP
2. Open **File Explorer** on Windows
3. Navigate to **Network Drives** or **This PC**
4. Look for `\\tsclient` shares or drives named like `LinuxDownloads on 'remmina-pc' (Z:)`
5. Copy files from Windows to the network drive to download to Linux

### Method 2: SSH File Transfer

#### Setup SSH on Windows:
```powershell
# Windows 10/11 - Enable SSH Server
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Start-Service sshd
Set-Service -Name sshd -StartupType 'Automatic'
```

#### Using Remmina SSH File Transfer:
1. Configure SSH connection in Remmina
2. Connect via SSH
3. Click **File Transfer** button (folder icon)
4. Drag files between local/remote panels

#### Command Line SCP:
```bash
# Download single file
scp username@windows_ip:/path/to/file /home/username/Downloads/

# Download entire directory
scp -r username@windows_ip:/path/to/folder /home/username/Downloads/

# Example:
scp john@192.168.1.100:/Users/John/Documents/report.pdf ~/Downloads/
```

### Method 3: SMB/CIFS Shares

#### Setup Windows Share:
1. Right-click folder → **Properties** → **Sharing** tab
2. Click **Share...** and add users
3. Note the computer name: `hostname`

#### Access from Linux:
```bash
# Install SMB client
sudo apt install cifs-utils smbclient

# Browse available shares
smbclient -L //windows_computer -U username

# Mount Windows share
mkdir ~/windows_share
sudo mount -t cifs //windows_computer/SharedFolder ~/windows_share -o username=windows_user,password=your_password

# Copy files
cp ~/windows_share/file.txt ~/Downloads/
```

### Method 4: Using smbclient Interactive
```bash
smbclient //windows_ip/ShareName -U user
smb: \> get file.txt
smb: \> mget *.pdf          # Multiple files
smb: \> prompt             # Turn off prompts
smb: \> recurse            # Recursive mode
smb: \> mget *             # Get all files
```

## Advanced Features

### Connection Management
- **Groups**: Organize connections into folders
- **Favorites**: Star frequently used connections
- **Templates**: Save connection templates
- **Search**: Quickly find connections

### Display Settings
- **Fullscreen**: `F11` or `Ctrl+Alt+Enter`
- **Scale**: Fit to window or actual size
- **Aspect ratio**: Maintain or stretch
- **Multi-monitor**: Span across multiple displays

### SSH Tunnel
1. Enable SSH tunnel in connection settings
2. Configure SSH connection details
3. Tunnel other protocols through SSH

### File Transfer Features
- **RDP**: Drive redirection for file sharing
- **SSH**: Built-in SFTP file transfer
- **SPICE**: File sharing capabilities
- **Clipboard**: Shared clipboard support

## Command Line Usage

### Basic Connection
```bash
remmina -c connection_file.remmina
```

### Connect via Protocol
```bash
remmina -c rdp://username@hostname
remmina -c vnc://hostname:port
remmina -c ssh://user@hostname
```

### One-time Connection
```bash
remmina -t rdp -s hostname -u username
```

## Configuration Files

### Main Configuration
```bash
~/.config/remmina/remmina.pref
```

### Connection Files
```bash
~/.local/share/remmina/  # Connection files (.remmina)
```

## Troubleshooting File Transfers

### RDP Shares Not Appearing
```cmd
# In Windows Command Prompt, check shares
net use
# Should show tsclient shares

# If shares not visible:
# 1. Check Windows Group Policy
# 2. Verify RDP drive redirection enabled
# 3. Restart Remmina connection
```

### SSH Connection Issues
```bash
# Test SSH connection
ssh username@windows_ip

# Check SSH service on Windows
Get-Service sshd

# Verify firewall rules
```

### SMB Share Problems
```bash
# Check if SMB ports are open
telnet windows_ip 445

# View detailed SMB info
smbstatus

# Reset SMB connection
sudo umount ~/windows_share
```

## Performance Optimization

### For Slow Connections
- Lower color depth (16-bit instead of 32-bit)
- Disable wallpaper and themes on remote Windows
- Use compression for low bandwidth
- Reduce display resolution

### For File Transfers
- **Large files**: Use SCP or SMB for better performance
- **Many small files**: RDP drive redirection works well
- **Regular transfers**: Set up mounted network shares

## Security Best Practices

### General Security
- Use VPN for remote connections
- Enable Network Level Authentication (RDP)
- Use strong passwords
- Keep software updated

### SSH Security
```bash
# Use key-based authentication
ssh-keygen -t rsa -b 4096
ssh-copy-id user@windows_ip

# Change default SSH port
# Use fail2ban for protection
```

### SMB Security
- Use SMB3 when possible
- Disable SMB1 if not needed
- Use firewall rules to restrict access

## Common Ports
```
RDP: 3389
VNC: 5900+ (5900 for display :0)
SSH: 22
SMB: 445
```

## Quick Reference

### Most Common File Transfer Methods
1. **RDP Drive Redirection** - Easiest for occasional transfers
2. **SCP/SSH** - Most secure for regular transfers
3. **SMB Shares** - Best for large files and network integration

### File Transfer Commands Summary
```bash
# SCP - Secure copy over SSH
scp user@windows_ip:/path/file ~/Downloads/

# RDP - Through Remmina GUI
# Configure share folder in Advanced tab

# SMB - Network file sharing
smbclient //windows_ip/share -U user
# or mount with cifs
```

This cheat sheet covers all essential Remmina functionality including comprehensive file transfer methods between Windows and Linux systems.
```

I've created a comprehensive markdown file that includes:

1. **Complete Remmina basics** - installation, usage, connection types
2. **Detailed file transfer methods** - 4 different approaches with step-by-step instructions
3. **Troubleshooting sections** - for each transfer method
4. **Security considerations** - best practices for safe file transfers
5. **Quick reference** - easy-to-find commands and methods
6. **Code formatting** - proper markdown syntax for commands and examples

The file is organized logically from basic to advanced topics, making it easy to find the information you need for downloading files from Windows to Linux using Remmina.