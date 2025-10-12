# Transfer Files from Windows 11 to Parrot (via Remmina RDP)

When connected to **Parrot OS** using **Remmina (RDP)**, you have several options to copy a file (e.g., `imap-version-scan.sh`) from **Windows 11** into Parrot.

---

## Option A — Use Remmina’s Folder/Drive Redirection (Easy GUI)
1. Close the RDP session. In Remmina, open the connection profile and click **Edit**.  
2. Go to the **Advanced** tab and enable **Share folder** / **Redirect folder**.  
3. Choose a Windows folder (e.g. `C:\Users\You\Downloads`).  
4. Reconnect via Remmina. The shared folder will appear in Parrot under `/media/rdpdrive/` or similar.  
5. Copy the file into your home directory:
   ```bash
   cp /media/rdpdrive/imap-version-scan.sh ~/
   chmod +x ~/imap-version-scan.sh
   ```

---

## Option B — Share a Windows Folder and Mount It on Parrot
### On Windows 11:
1. Right-click the folder (e.g. `C:\Users\You\Downloads`) → **Properties → Sharing → Advanced Sharing**.  
2. Enable **Share this folder**, set a name (e.g. `winshare`), and give permissions.  
3. Run `ipconfig` in PowerShell to find your Windows IPv4 address.

### On Parrot:
```bash
sudo apt update
sudo apt install cifs-utils -y

# Create mountpoint
sudo mkdir -p /mnt/windows

# Mount (replace values)
sudo mount -t cifs //WINDOWS_IP/winshare /mnt/windows -o username=WINDOWS_USER,domain=WORKGROUP,uid=$(id -u),gid=$(id -g)

# Copy file
cp /mnt/windows/imap-version-scan.sh ~/
chmod +x ~/imap-version-scan.sh

# Unmount when done
sudo umount /mnt/windows
```

---

## Option C — Use smbclient (Interactive)
```bash
sudo apt update
sudo apt install smbclient -y

# Connect to the Windows share
smbclient //WINDOWS_IP/winshare -U WINDOWS_USER

# In smbclient prompt:
# > ls
# > get imap-version-scan.sh
# > exit
```

The file will be downloaded to your current directory in Parrot.

---

## Option D — Use SCP from Windows (Requires SSH on Parrot)
If SSH is enabled on Parrot, you can transfer directly from Windows.

### From PowerShell on Windows:
```powershell
scp C:\path\to\imap-version-scan.sh parrotuser@PARROT_IP:/home/parrotuser/
```

If Parrot SSH is on a non-default port (e.g. 2222):
```powershell
scp -P 2222 C:\path\to\imap-version-scan.sh parrotuser@PARROT_IP:/home/parrotuser/
```

### On Parrot, make it executable:
```bash
chmod +x ~/imap-version-scan.sh
```

---

## Quick Tips
- Check if SSH is running on Parrot:
  ```bash
  sudo systemctl status ssh
  ```
- Find Windows IP:
  ```powershell
  ipconfig
  ```
- If CIFS mount fails, try specifying version: `-o vers=3.0`.

---

✅ Recommendation:  
- Use **Option A** (Remmina share) if available.  
- Use **Option B/C** (SMB share) if you can’t enable RDP sharing.  
- Use **Option D** (SCP) if SSH is enabled — usually the fastest and cleanest.
