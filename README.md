#Windows Privilege Escalation – Password Hunting Cheatsheet
1. Findstr (File-based Hunting)
   
:: Search common config/text files
findstr /si password *.txt *.ini *.config

:: Search full C: drive for passwords
findstr /si password c:\*.txt c:\*.ini c:\*.config

:: Search all files for multiple keywords
findstr /si "password pass pwd user admin login" *.*

:: Search Desktop & Documents of all users
findstr /si password "C:\Users\*\Desktop\*" "C:\Users\*\Documents\*"

:: Search registry dump files (if exported)
findstr /si password *.reg

:: Search inside Program Files
findstr /si password "C:\Program Files\*.*"


2. Registry Hunting
:: Look for stored RDP / Winlogon creds
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

:: Look for auto-logon passwords
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"

:: Search registry for "password"
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s


3. Saved Credentials & Services
:: List saved credentials
cmdkey /list

:: Check services for stored creds
sc qc <servicename>

:: Search scheduled tasks (often store passwords)
schtasks /query /fo LIST /v


4. File Content Check
:: Print content of a file
type filename.txt

:: Search inside log files
findstr /si password *.log


5. PowerShell Alternatives
# Search for "password" inside all files
Get-ChildItem -Recurse | Select-String -Pattern "password"

# Search only in config files
Select-String -Path *.config -Pattern "password"

# Check for stored credentials in registry
Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'


6. Network & App Creds
:: Check Wi-Fi passwords (Admin needed)
netsh wlan show profile
netsh wlan show profile name="SSID" key=clear

:: Look at IIS config (web passwords)
type C:\inetpub\wwwroot\web.config | findstr connectionString


7. Bonus – Interesting Files to Hunt

web.config, db.config, app.config

.ini, .bat, .ps1, .vbs, .xml

Log files in C:\Windows\System32\LogFiles\

Backup files: .bak, .old, .zip
