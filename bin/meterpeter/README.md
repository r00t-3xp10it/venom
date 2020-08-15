### PROJECT
   my_meterp(r)eter_Server [**`STABLE`**] <br />

### AUTHOR
   @r00t-3xp10it { version 2.10 }<br />
   Original Shell: @ZHacker13 **'https://github.com/ZHacker13/ReverseTCPShell'**

**Article Quick Jump List**<br />
- **[meterpeter Project Description](https://github.com/r00t-3xp10it/meterpeter/blob/master/README.md#description)**<br />
- **[List Of Available Modules](https://github.com/r00t-3xp10it/meterpeter/blob/master/README.md#meterpeter-server-available-modules)**<br />
- **[How To - Under Linux Distributions](https://github.com/r00t-3xp10it/meterpeter/blob/master/README.md#attacker-machine-linux-kali)**<br />
- **[How To - Under Windows Distributions](https://github.com/r00t-3xp10it/meterpeter/blob/master/README.md#attacker-machiner-windows-pc)**<br />
- **[Windows Defender (Target Related)](https://github.com/r00t-3xp10it/meterpeter/blob/master/README.md#remark-about-windows-defender)**<br />
- **[Some meterpeter Screenshots](https://github.com/r00t-3xp10it/meterpeter/blob/master/README.md#meterpeter-screenshots)**<br />
- **[Special Thanks|Contributions|Videos](https://github.com/r00t-3xp10it/meterpeter/blob/master/README.md#video-tutorials)**<br />
- **[How To - Use PS2EXE to convert ps1 scripts to standalone executables](https://github.com/r00t-3xp10it/meterpeter/blob/master/README.md#Use-PS2EXE-to-convert-ps1-scripts-to-standalone-executables)**<br />
- **[Please Read my WIKI for Detailed information about each Module](https://github.com/r00t-3xp10it/meterpeter/wiki)**<br />

---

<br />

### DESCRIPTION
   **meterpeter** - This PS1 starts a listener Server on a Windows|Linux attacker machine and generates oneliner PS reverse shell payloads obfuscated in ANCII|BXOR with a random secret key and another layer of Characters/Variables Obfuscation to be executed on the victim machine (The payload will also execute AMSI reflection bypass in current session to evade AMSI detection while working). You can also recive the generated oneliner reverse shell connection via netcat. (in this case you will lose the C2 functionalities like screenshot, upload, download files, Keylogger, AdvInfo, PostExploitation, etc)<br /><br />meterpeter payloads/droppers can be executed using User or Administrator Privileges depending of the cenario (executing the Client as Administrator will unlock ALL Server Modules, amsi bypasses, etc.). Droppers will mimic a Fake KB Security Update while in background Downloads and executes our Client in $env:tmp trusted location, with the intent of evading  Windows Defender Exploit Guard. meterpeter payloads|droppers are FUD (dont test samples on VirusTotal).<br /><br />This project has been inspired in the work of @ZHacker13 from GitHub **->** [github.com/ZHacker13/ReverseTCPShell](https://github.com/ZHacker13/ReverseTCPShell) **<-**<br />
![banner](https://user-images.githubusercontent.com/23490060/74566700-fba1c780-4f6b-11ea-85a0-ac26576302b3.png)<br />

<br />

   This Project allows Attackers to execute **'meterpeter.ps1'** under **'Linux'** or **'Windows'** distributions. Under Linux distros users required to install **powershell** and **apache2** webserver, Under Windows its optional the install of **python3** http.server to deliver payloads under LAN networks. If this requirements are **NOT** met, then Client will be written in meterpeter working directory for manual deliver <- In this ocassion execute your Client.ps1 in **$env:tmp** ('recomended').
![pythonserver](https://user-images.githubusercontent.com/23490060/74612205-1bb3c100-50fb-11ea-8138-a3c9649a8201.png)

<br />

**meterpeter Modules Shortcuts**<br />
meterpeter prompt reveals us some of the shortcuts we have available to use.
![Shortcuts](https://user-images.githubusercontent.com/23490060/75630967-ad84f900-5be6-11ea-9810-7430cb72663c.png)

- **[Quick Jump List](https://github.com/r00t-3xp10it/meterpeter/blob/master/README.md#project)**<br />
---

<br /><br />

### meterpeter (Server) available modules
**{ [Please Read my WIKI for Detailed information about each Module](https://github.com/r00t-3xp10it/meterpeter/wiki) }**<br />
![keylogger](https://user-images.githubusercontent.com/23490060/74612250-79e0a400-50fb-11ea-8f21-60cd34c314aa.png)<br />

- **Info**       : Quick Retrieve of Target PC Information
- **AdvInfo**    : Advanced Gather Information Modules (Sub-Menu)
  - **ListAdm**  : Retrieve Client Shell Path|Privileges
  - **ListAcc**  : Retrieve Remote-Host Accounts List
  - **ListSmb**  : Retrieve Remote-Host SMB shares List
  - **ListDns**  : Retrieve Remote-Host DNS Entrys List
  - **ListApp**  : Retrieve Remote-Host Installed Applications List
  - **ListTask** : Remote-Host Schedule Tasks Module (Sub-Menu)
    - **Check**    : Retrieve Schedule Tasks List
    - **Inform**   : Schedule Taks Verbose Information
    - **Create**   : Create Remote-Host New Tasks
    - **Delete**   : Delete Remote-Host Tasks
  - **ListRece** : Retrieve Remote-Host Recent Folder Contents
  - **ListPriv** : Remote-Host Weak Service|Folders permissions (Sub-Menu)
    - **Check**   : Retrieve Folder Permissions
    - **WeakDir** : Search for Folders weak Permissions recursive
    - **Service** : Search for Unquoted Service Paths vulnerability
    - **RottenP** : Search for Rotten Potato Privilege Vulnerability
    - **RegACL**  : Search for weak permissions on registry
  - **StartUp**  : Retrieve Remote-Host StartUp Folder Contents
  - **ListDriv** : Retrieve Remote-Host Drives Available List
  - **ListRun**  : Retrieve Remote-Host Startup Run Entrys
  - **ListProc** : Remote-Host Processe(s) (Sub-Menu)
    - **Check**    : Retrieve Remote Processe(s) Running
    - **KillProc** : Kill Remote Process By DisplayName
  - **ListConn** : Retrieve Remote-Host Active TCP Connections List
  - **ListIpv4** : Retrieve Remote-Host IPv4 Network Statistics List
  - **ListWifi** : Remote-Host Profiles/SSID/Passwords (Sub-Menu)
    - **ListProf**  : Retrieve Remote-Host wifi Profile
    - **ListNetw**  : Retrieve wifi Available networks List
    - **ListSSID**  : Retrieve Remote-Host SSID Entrys List
    - **SSIDPass**  : Retrieve Stored SSID passwords
- **Session**    : Retrieve C2 Server Connection Status.
- **Upload**     : Upload File from Local-Host to Remote-Host.
- **Download**   : Download File from Remote-Host to Local-Host.
- **Screenshot** : Save Screenshot from Remote-Host to Local-Host.
- **keylogger**  : Remote-Host Keylogger (Sub-Menu)
  - **Install**  : Install Remote keylogger
  - **StartK**   : Start remote keylogger
  - **ReadLog**  : Read keystrokes logfile
  - **StopKP**   : Stop keylogger Process(s)
- **PostExploit**: Post-Exploitation Modules (Sub-Menu)
  - **Escalate** : WSReset.exe Privilege Escalation (Sub-Menu)
    - **SluiEOP**   : Execute one command with admin privs (SYSTEM)
    - **Getsystem** : Escalate Client Privileges (UserLand -> SYSTEM)
    - **Delete**    : Delete Old Priv Escalation Configurations
  - **CamSnap**  : Manipulate remote webcam (sub-menu)
    - **Device**    : List Remote-Host webcams available
    - **Snap**      : Take Remote-Host screenshot (Default webcam)
    - **Manual**    : Manual sellect webcam device to use (device name)
  - **Persist**  : Remote Persist Client (Sub-Menu)
    - **Beacon**    : Persiste Client Using startup Folder (beacon home from xx to xx sec)
    - **RUNONCE**   : Persiste Client using REGISTRY:RunOnce Key
    - **REGRUN**    : Persiste Client using REGISTRY:Run Key
    - **Schtasks**  : Make Client Beacon Home with xx minuts of Interval
    - **WinLogon**  : Persiste Client using WinLogon REGISTRY:Userinit Key
  - **Restart**  : Restart in xx seconds
  - **ListLog**  : List/Delete EventLogs Module (Sub-Menu)
    - **Check**     : Retrieve Remote-Host EventLogs List
    - **DelLogs**   : Delete  Remote-Host EventLogs (eventvwr)
    - **DelFull**   : Delete  Remote-Host LogFiles from Disk
  - **SetMace**  : Change files date/time TimeStomp
  - **ListPas**  : Search for passwords in txt Files
  - **ListDir**  : Search for hidden folders recursive
  - **GoogleX**  : Open Remote Browser in google sphere (prank)
  - **LockPC**   : Lock Remote workstation (prank|refresh explorer)
  - **SpeakPC**  : Make Remote-Host Speak your sentence (prank)
  - **AMSIset**  : Enable/Disable AMSI Module (Sub-Menu)
    - **Disable**   : Disable AMSI in REGISTRY:hklm|hkcu
    - **Enable**    : Enable  AMSI in REGISTRY:hklm|hkcu
  - **ListCred** : Retrieve Remote-Host cmdkey stored Creds
  - **UACSet**   : Enable/Disable remote UAC Module (Sub-Menu)
    - **Disable**   : Disable UAC in REGISTRY:hklm
    - **Enable**    : Enable  UAC in REGISTRY:hklm
  - **ASLRSet**  : Enable/Disable ASLR Module (Sub-Menu)
    - **Disable**   : Disable ASLR in REGISTRY:hklm
    - **Enable**    : Enable  ASLR in REGISTRY:hklm
  - **TaskMan**  : Enable/Disable TaskManager Module (Sub-Menu)
    - **Disable**   : Disable TaskManager in REGISTRY:hklm
    - **Enable**    : Enable  TaskManager in REGISTRY:hklm
  - **Firewall** : Enable/Disable Remote Firewall Module (Sub-Menu)
    - **Check**     : Review Remote-Host Firewall Settings
    - **Disable**   : Disable Remote-Host Firewall
    - **Enable**    : Enable  Remote-Host Firewall
  - **Defender** : Enable/Disable Windows Defender Module (Sub-Menu)
    - **Disable**   : Disable Remote-Host Windows Defender
    - **Enable**    : Enable  Remote-Host Windows Defender
  - **DumpSAM**  : Dump SAM/SYSTEM Credentials to a remote location
  - **Dnspoof**  : Hijack Entrys in hosts file Module (Sub-Menu)
    - **Check**     : Review Remote-Host hosts File
    - **Spoof**     : Add Entrys to Remote-Host hosts File
    - **Default**   : Defaults Remote-Host hosts File
  - **NoDrive**  : Hide Drives from Explorer Module (Sub-Menu)
    - **Disable**   : Hide Drives from explorer in REGISTRY:hklm
    - **Enable**    : Enable Drives from explorer in REGISTRY:hklm
  - **CredPhi**  : Phishing for remote logon credentials
    - **OldBox**   : Trigger Remote Phishing PS Script (Windows 7 or less)
    - **NewBox**   : Trigger Remote Phishing PS Script (Windows 7 or above)
    - **ReadLog**   : Read Remote Phishing LogFile
  - **Browser**   : Enumerate Installed Browsers (IE,FIREFOX,CHROME)
- **exit**       : Exit Reverse TCP Shell (Server + Client).

- **[Please Read my WIKI for Detailed information about each Module](https://github.com/r00t-3xp10it/meterpeter/wiki)**<br />
- **[Quick Jump List](https://github.com/r00t-3xp10it/meterpeter/blob/master/README.md#project)**<br />

---

<br /><br />

### ATTACKER MACHINE: [Linux Kali]
      Warning: powershell under linux distributions its only available for x64 bits archs ..
![linux](https://user-images.githubusercontent.com/23490060/74575258-26951700-4f7e-11ea-832c-512dce1c97cc.png)

<br />

#### Install Powershell (Linux x64 bits)
```
apt-get update && apt-get install -y powershell
```

#### Install Apache2
```
apt-get install Apache2
```

#### Start Apache2 WebServer
```
service apache2 start
```

#### Start C2 Server (Local)
```
cd meterpeter
pwsh -File meterpeter.ps1
```

#### Deliver Dropper/Payload To Target Machine (apache2)
```
USE THE 'Attack Vector URL' TO DELIVER 'Update-KB4524147.zip' (dropper) TO TARGET ..
UNZIP (IN DESKTOP) AND EXECUTE 'Update-KB4524147.bat' (Run As Administrator)..
```

#### Remark:

     IF dropper.bat its executed: Then the Client will use $env:tmp has its working directory ('recomended')..
     IF Attacker decided to manualy execute Client: Then Client remote location (pwd) will be used has working dir .


- **[Quick Jump List](https://github.com/r00t-3xp10it/meterpeter/blob/master/README.md#project)**<br />

---

<br /><br />

### ATTACKER MACHINER: [Windows PC]
![frd](https://user-images.githubusercontent.com/23490060/74575907-b76cf200-4f80-11ea-8f44-ddd79fbd812f.png)

<br />

#### Install Python3 (optional)
Install Python3 (http.Server) to deliver payloads under LAN networks ..<br />
```
https://www.python.org/downloads/release/python-381/
```

#### Start C2 Server (Local)
```
cd meterpeter
powershell Set-ExecutionPolicy Unrestricted -Scope CurrentUser
powershell -File meterpeter.ps1
```

**Remark**
- meterpeter.ps1 delivers Dropper/Payload using python3 http.server. IF attacker has python3 installed.<br />
  **'If NOT then the payload (Client) its written in Server Local [Working Directory](https://github.com/r00t-3xp10it/meterpeter/wiki/How-To-Display%7CChange-'Client'-Working-Directory) to be Manualy Deliver'** ..

- Remmnenber to close the http.server terminal after the target have recived the two files (Dropper & Client)<br />
  **'And we have recived the connection in our meterpeter Server { to prevent Server|Client connection errors }'**<br /><br />

#### Deliver Dropper/Payload To Target Machine (manual OR python3)
```
DELIVER 'Update-KB4524147' (.ps1=manual) OR (.zip=automated|silentExec) TO TARGET ..
```

#### Remark:

     IF dropper.bat its executed: Then the Client will use $env:tmp has its working directory ('recomended')..
     IF Attacker decided to manualy execute Client: Then Client remote location (pwd) will be used has working dir .

- **[Quick Jump List](https://github.com/r00t-3xp10it/meterpeter/blob/master/README.md#project)**<br />

---

<br />

### Use PS2EXE to convert ps1 scripts to standalone executables

<br />

**PS2EXE BY**  : Ingo Karstein | MScholtes<br />
**Description**: Script to convert powershell scripts to standalone executables<br />
**Source**     : https://gallery.technet.microsoft.com/scriptcenter/PS2EXE-GUI-Convert-e7cb69d5<br /><br />

`meterpeter users can use this script (manually) to convert the Client.ps1 to Client.exe`<br /><br />

- 1º - Copy **`'Update-KB4524147.ps1'`** build by meterpeter C2 to **`'PS2EXE'`** directory.
- 2º - Open Powershell terminal console in **`'PS2EXE'`** directory (none admin privs required)
- 3º - Execute the follow command to convert the Client.ps1 to standalone executable<br />

```
.\ps2exe.ps1 -inputFile 'Update-KB4524147.ps1' -outputFile 'Update-KB4524147.exe' -iconFile 'meterpeter.ico' -title 'meterpeter binary file' -version '2.10.6' -description 'meterpeter binary file' -product 'meterpeter C2 Client' -company 'Microsoft Corporation' -copyright '©Microsoft Corporation. All Rights Reserved' -noConsole -noVisualStyles -noError
```

![final](https://user-images.githubusercontent.com/23490060/88741165-d75f2f00-d136-11ea-8761-28b690f0ddf3.png)

- **`REMARK:`** Client.exe (created by PS2EXEC) migth **malfunction** with meterpeter **mimiratz scripts**.

- **[Quick Jump List](https://github.com/r00t-3xp10it/meterpeter/blob/master/README.md#project)**<br />

---


<br />

### Remark About Windows Defender:
Using **keylogger** Module without the **Client** been executed as administrator, will trigger this kind of warnings by Windows Defender **AMSI** mechanism. IF the **Client** is executed as administrator and target machine as powershell **version 2** installed, then the keylogger execution its achieved using PSv2 (**bypassing Windows Defender AMSI|DEP|ASLR defenses**). The same method its also valid for **persistence** Module, executing our client using powershell version 2 (PS downgrade Attack).<br /><br />
**meterpeter.ps1 - Payloads|Droppers are FUD (Fully UnDetected) by AntiVirus (Please dont test samples on VirusTotal)**<br />
![AV](https://user-images.githubusercontent.com/23490060/74576599-6f030380-4f83-11ea-8e10-bdeefeb0b547.png)
<br />
Remenbering that **Dropper.bat** even IF executed without Administrator Privileges, will try to bypass many defensive mechanisms.. for that alone plays a main role in all this process ..<br /> 

<br />

#### Final Notes:
Remember to set your PS execution Policy to default (attacker) After having used meterpeter in your pentestings.<br />
meterpeter.ps1 for obvious reasons will **NOT** revert the target PS Policy to Restricted (default) to facilitate next<br />
incursions into Remote-Host (**in persistence cenario Demonstrations**) ..
```
powershell Set-ExecutionPolicy Restricted -Scope CurrentUser
```

- **[Quick Jump List](https://github.com/r00t-3xp10it/meterpeter/blob/master/README.md#project)**<br />

---

<br />

### meterpeter Screenshots:
![screenshot](https://user-images.githubusercontent.com/23490060/74612209-22423880-50fb-11ea-8c1d-66a9a14e18f7.png)
![uacoff](https://user-images.githubusercontent.com/23490060/74612213-266e5600-50fb-11ea-8557-b06c3ff93e09.png)
![taskoff](https://user-images.githubusercontent.com/23490060/74618345-3b61de00-5129-11ea-8e78-4834107a01a3.png)
![mace](https://user-images.githubusercontent.com/23490060/74764142-1a100780-5279-11ea-9e18-09f2e555baca.png)

---


<br />

### Video Tutorials:
meterpeter Under Windows Distros: https://www.youtube.com/watch?v=d2npuCXsMvE<br />
meterpeter Under Linux Distros: https://www.youtube.com/watch?v=CmMbWmN246E<br /><br />

### Special Thanks:
**@ZHacker13** (Original Rev Shell) | **@tedburke** (CommandCam.exe binary) <br />
**@codings9** (debugging project under Windows|Linux Distros)<br /><br />
- **[meterpeter WIKI pages (Oficial Documentation)](https://github.com/r00t-3xp10it/meterpeter/wiki)**<br />
- **[Jump To Top of this readme File](https://github.com/r00t-3xp10it/meterpeter/blob/master/README.md#project)**<br />
---


