### PROJECT:
   my_meterp(r)eter_Server<br />
   'For Guys Like Me that Misses the meterpreter Prompt, In our redteam engagements using reverse shells' d(^_^)b<br />

### AUTHOR:
   @r00t-3xp10it { version 2.7 }<br />
   Original Shell: @ZHacker13 **'https://github.com/ZHacker13/ReverseTCPShell'**

### Quick Jump List:
[meterpeter Project Description](https://github.com/r00t-3xp10it/meterpeter/blob/master/README.md#description)<br />
[How to change client working dir](https://github.com/r00t-3xp10it/meterpeter/blob/master/README.md#how-to-displaychange-client-working-directory)<br />
[How To - Under Linux Distributions](https://github.com/r00t-3xp10it/meterpeter/blob/master/README.md#attacker-machine-linux-kali)<br />
[How To - Under Windows Distributions](https://github.com/r00t-3xp10it/meterpeter/blob/master/README.md#attacker-machiner-windows-pc)<br />
[List Of Available Modules](https://github.com/r00t-3xp10it/meterpeter/blob/master/README.md#currently-available-modules)<br />
[Windows Defender (Target Related)](https://github.com/r00t-3xp10it/meterpeter/blob/master/README.md#remark-about-windows-defender)<br />
[Some meterpeter Screenshots](https://github.com/r00t-3xp10it/meterpeter/blob/master/README.md#meterpeter-screenshots)<br />
[Two meterpeter video tutorials](https://github.com/r00t-3xp10it/meterpeter/blob/master/README.md#videos)<br />
[Special Thanks|Contributions](https://github.com/r00t-3xp10it/meterpeter/blob/master/README.md#special-thanks)<br />

---

<br />

### DESCRIPTION:
   **meterpeter** - This PS1 starts a listener Server on a Windows|Linux attacker machine and generates oneliner PS reverse shell payloads obfuscated in ANCII|BXOR with a random secret key and another layer of Characters/Variables Obfuscation to be executed on the victim machine (The payload will also execute AMSI reflection bypass in current session to evade AMSI detection while working). You can also recive the generated oneliner reverse shell connection via netcat. (in this case you will lose the C2 functionalities like screenshot, upload, download files, Keylogger, AdvInfo, PostExploitation, etc)<br /><br />meterpeter payloads/droppers can be executed using User or Administrator Privileges depending of the cenario (executing the Client as Administrator will unlock ALL Server Modules, amsi bypasses, etc.). Droppers will mimic a Fake KB Security Update while in background Downloads and executes our Client in $env:tmp trusted location, with the intent of evading  Windows Defender Exploit Guard. meterpeter payloads|droppers are FUD (dont test samples on VirusTotal).<br /><br />This project has been inspired in the work of @ZHacker13 from GitHub **->** [github.com/ZHacker13/ReverseTCPShell](https://github.com/ZHacker13/ReverseTCPShell) **<-**<br />
![banner](https://user-images.githubusercontent.com/23490060/74566700-fba1c780-4f6b-11ea-85a0-ac26576302b3.png)<br />

<br />

   This Project allows Attackers to execute **'meterpeter.ps1'** under **'Linux'** or **'Windows'** distributions. Under Linux distros users required to install **powershell** and **apache2** webserver, Under Windows its optional the install of **python3** http.server to deliver payloads under LAN networks. If this requirements are **NOT** met, then Client will be written in meterpeter working directory for manual deliver <- In this ocassion execute your Client.ps1 in **$env:tmp** ('recomended').
![pythonserver](https://user-images.githubusercontent.com/23490060/74612205-1bb3c100-50fb-11ea-8138-a3c9649a8201.png)

<br />

#### How To Display|Change 'Client' Working Directory:
**Client** Remote Working directory its located in **$env:tmp**, But meterpeter gives us access to one **'Interactive powershell console',** that means that all powershell commands executed in **' :meterpeter> '** prompt will be executed remotely.<br />
![dirs1](https://user-images.githubusercontent.com/23490060/75086920-d8f64c80-5531-11ea-9420-43f0ab947d0d.png)
![dirs2](https://user-images.githubusercontent.com/23490060/75086924-e01d5a80-5531-11ea-84a5-87fcc1aa6818.png)

[Quick Jump List](https://github.com/r00t-3xp10it/meterpeter/blob/master/README.md#quick-jump-list)<br />

---

<br />

### Currently available modules:
![keylogger](https://user-images.githubusercontent.com/23490060/74612250-79e0a400-50fb-11ea-8f21-60cd34c314aa.png)

- **Info**       : Retrieve Target PC Information
- **AdvInfo**    : Advanced Gather Information Modules [Sub-Menu]
  - **ListAdm**  : Retrieve Client Shell Path|Privileges
  - **ListAcc**  : Retrieve Remote-Host Accounts List
  - **ListSmb**  : Retrieve Remote-Host SMB shares List
  - **ListDns**  : Retrieve Remote-Host DNS Entrys List
  - **ListApp**  : Retrieve Remote-Host Installed Applications List
  - **ListTask** : Retrieve Remote-Host Schedule Tasks List [Sub-Menu]
    - **Check**    : Retrieve Schedule Tasks List
    - **Inform**   : Advanced Info Single Task Information
    - **Create**   : Create Remote-Host New Task
    - **Delete**   : Delete Remote-Host Single Task
  - **ListRece** : Retrieve Remote-Host Recent Folder Contents
  - **StartUp**  : Retrieve Remote-Host StartUp Folder Contents
  - **ListDriv** : Retrieve Remote-Host Drives Available List
  - **ListRun**  : Retrieve Remote-Host Startup Run Entrys
  - **ListProc** : Remote-Host Processe(s) [Sub-Menu]
    - **Check**    : Retrieve Remote Processe(s) Running List
    - **KillProc** : Kill Remote Process By Name From Running
  - **ListConn** : Retrieve Remote-Host Active TCP Connections List
  - **ListIpv4** : Retrieve Remote-Host IPv4 Network Statistics List
  - **ListWifi** : Remote-Host Profiles/SSID/Passwords [Sub-Menu]
    - **ListProf**  : Retrieve Remote-Host wifi Profile
    - **ListNetw**  : Retrieve wifi Available networks List
    - **ListSSID**  : Retrieve Remote-Host SSID Entrys List
    - **SSIDPass**  : Retrieve Stored SSID passwords
- **Session**    : Retrieve C2 Server Connection Status.
- **Upload**     : Upload File from Local-Host to Remote-Host.
- **Download**   : Download File from Remote-Host to Local-Host.
- **Screenshot** : Save Screenshot from Remote-Host to Local-Host.
- **keylogger**  : Remote-Host Keylogger [Sub-Menu].
  - **Install**  : Install Remote keylogger
  - **StartK**   : Start remote keylogger
  - **ReadLog**  : Read keystrokes logfile
  - **StopKP**   : Stop keylogger Process(s)
- **PostExploit**: Post-Exploitation Modules [Sub-Menu]
  - **Persist**  : Remote Persist Client [Sub-Menu]
    - **StartUp**   : Persiste Client Using startup Folder
    - **REGRUN**    : Persiste Client using REGISTRY:Run Key
    - **WinLogon**  : Persiste Client using WinLogon REGISTRY:Userinit Key
  - **Restart**  : Restart in xx seconds
  - **ListLog**  : List/Delete EventLogs Module [Sub-Menu]
    - **Check**     : Retrieve Remote-Host EventLogs List
    - **DelLogs**   : Delete  Remote-Host EventLogs (eventvwr)
    - **DelFull**   : Delete  Remote-Host LogFiles from Disk
  - **SetMace**  : Change files date/time TimeStomp
  - **ListPas**  : Search for passwords in txt Files
  - **GoogleX**  : Open Remote Browser in google sphere (prank)
  - **LockPC**   : Lock Remote workstation (prank|refresh explorer)
  - **SpeakPC**  : Make Remote-Host Speak your sentence
  - **AMSIset**  : Enable/Disable AMSI Module [Sub-Menu]
    - **Disable**   : Disable AMSI in REGISTRY:hklm|hkcu
    - **Enable**    : Enable  AMSI in REGISTRY:hklm|hkcu
  - **UACSet**   : Enable/Disable remote UAC Module [Sub-Menu]
    - **Disable**   : Disable UAC in REGISTRY:hklm
    - **Enable**    : Enable  UAC in REGISTRY:hklm
  - **TaskMan**  : Enable/Disable TaskManager Module [Sub-Menu]
    - **Disable**   : Disable TaskManager in REGISTRY:hklm
    - **Enable**    : Enable  TaskManager in REGISTRY:hklm
  - **Firewall** : Enable/Disable Remote Firewall Module [Sub-Menu]
    - **Check**     : Review Remote-Host Firewall Settings
    - **Disable**   : Disable Remote-Host Firewall
    - **Enable**    : Enable  Remote-Host Firewall
  - **DumpSAM**  : Dump SAM/SYSTEM Credentials to a remote location
  - **Dnspoof**  : Hijack Entrys in hosts file Module [Sub-Menu]
    - **Check**     : Review Remote-Host hosts File
    - **Spoof**     : Add Entrys to Remote-Host hosts File
    - **Default**   : Defaults Remote-Host hosts File
  - **NoDrive**  : Hide Drives from Explorer Module [Sub-Menu]
    - **Disable**   : Hide Drives from explorer in REGISTRY:hklm
    - **Enable**    : Enable Drives from explorer in REGISTRY:hklm
- **exit**       : Exit Reverse TCP Shell (Server + Client).

[Quick Jump List](https://github.com/r00t-3xp10it/meterpeter/blob/master/README.md#quick-jump-list)<br />

---

<br /><br />

### ATTACKER MACHINE: [Linux Kali]
      Warning: powershell under linux distributions its only available for x64 archs ..
![linux](https://user-images.githubusercontent.com/23490060/74575258-26951700-4f7e-11ea-832c-512dce1c97cc.png)

<br />

#### Install Powershell (Linux)
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
pwsh Set-ExecutionPolicy Unrestricted -Scope CurrentUser
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


[Quick Jump List](https://github.com/r00t-3xp10it/meterpeter/blob/master/README.md#quick-jump-list)<br />

---

<br /><br />

### ATTACKER MACHINER: [Windows PC]
![frd](https://user-images.githubusercontent.com/23490060/74575907-b76cf200-4f80-11ea-8f44-ddd79fbd812f.png)

<br />

#### Install Python3 (optional)
```
https://www.python.org/downloads/release/python-381/
```

#### Start C2 Server (Local)
```
cd meterpeter
powershell Set-ExecutionPolicy Unrestricted -Scope CurrentUser
powershell -File meterpeter.ps1
```

     Remark:
     -------
     meterpeter.ps1 delivers Dropper/Payload using python3 http.server. IF attacker has python3 installed
     If NOT then the payload (Client) its written in Server Local Working Directory to be Manualy Deliver ..

     Remmnenber to close the http.server terminal after the target have recived the two files (Dropper & Client)
     and we have recived the connection back in our meterpeter Server { to prevent Server|Client connection errors }

#### Deliver Dropper/Payload To Target Machine (manual OR python3)
```
DELIVER 'Update-KB4524147' (.ps1=manual) OR (.zip=automated|silentExec) TO TARGET ..
```

#### Remark:

     IF dropper.bat its executed: Then the Client will use $env:tmp has its working directory ('recomended')..
     IF Attacker decided to manualy execute Client: Then Client remote location (pwd) will be used has working dir .

[Quick Jump List](https://github.com/r00t-3xp10it/meterpeter/blob/master/README.md#quick-jump-list)<br />

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
**meterpeter Settings File**<br />
Allow Attackers to **automate** the creation of payloads (Client) without the need of User inputs. To activate it Attacker just need to edit the **Settings file**, change is values and then rename it from **'settingZZZ'** to **'Settings'** before executing the Server.

[Quick Jump List](https://github.com/r00t-3xp10it/meterpeter/blob/master/README.md#quick-jump-list)<br />

---

<br />

### meterpeter Screenshots:
![screenshot](https://user-images.githubusercontent.com/23490060/74612209-22423880-50fb-11ea-8c1d-66a9a14e18f7.png)
![dnshijack](https://user-images.githubusercontent.com/23490060/74612220-2cfccd80-50fb-11ea-9bfa-7b32d503d306.png)
![delogs](https://user-images.githubusercontent.com/23490060/74612217-2a01dd00-50fb-11ea-9dd4-0ea93b0dfcb1.png)
![uacoff](https://user-images.githubusercontent.com/23490060/74612213-266e5600-50fb-11ea-8557-b06c3ff93e09.png)
![keylogger](https://user-images.githubusercontent.com/23490060/74612250-79e0a400-50fb-11ea-8f21-60cd34c314aa.png)
![dumpsam](https://user-images.githubusercontent.com/23490060/74611908-43edf080-50f8-11ea-81a2-71cbf3d82123.png)
![taskoff](https://user-images.githubusercontent.com/23490060/74618345-3b61de00-5129-11ea-8e78-4834107a01a3.png)
![mace](https://user-images.githubusercontent.com/23490060/74764142-1a100780-5279-11ea-9e18-09f2e555baca.png)

---

<br />

### Video Tutorials:
meterpeter Under Windows Distros: https://youtu.be/5_VLBWYUuJ8<br />
meterpeter Under Linux Distros: http://Not-recorded-yet<br />


<br />

### Special Thanks:
**@ZHacker13** (Original Rev Shell) | **@codings9** (debugging project under Windows|Linux)<br />
[Jump To Top of this readme File](https://github.com/r00t-3xp10it/meterpeter/blob/master/README.md#project)


