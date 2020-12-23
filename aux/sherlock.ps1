<#
.SYNOPSIS
   find missing software patchs for privilege escalation (windows).

   Author: @_RastaMouse (Deprecated)
   Update: @r00t-3xp10it (v1.2)
   Tested Under: Windows 10 - Build 18363
   Required Dependencies: none
   Optional Dependencies: none
   PS cmdlet Dev version: v1.2

.DESCRIPTION
   Cmdlet to find missing software patchs for privilege escalation (windows).
   This CmdLet continues @_RastaMouse (Deprecated) Module with new 2020 CVE's

.NOTES
   RTM    OS Version
   ---    ----------
   6002   Vista SP2/2008 SP2
   7600   7/2008 R2
   7601   7 SP1/2008 R2 SP1
   9200   8/2012
   9600   8.1/2012 R2
   10240  10 Threshold
   10586  10 Threshold 2
   14393  10 Redstone/2016
   15063  10 Redstone 2
   16299  10 Redstone 3
   17134  10 Redstone 4

   Id  CVE's to test
   --  -------------
   1   MS10-015
   2   MS10-092
   3   MS13-053
   4   MS13-081
   5   MS14-058
   6   MS15-051
   7   MS15-078
   8   MS16-016
   9   MS16-032
   10  MS16-034
   11  MS16-135
   12  CVE-2017-7199
   13  CVE-2019-1458 (v1.2)
   14  CVE-2020-0624 (v1.2)
   15  CVE-2020-0642 (v1.2)
   16  CVE-2020-1054 (v1.2)
   17  CVE-2020-5752 (v1.2)
   18  CVE-2020-13162 (v1.2)
   
.EXAMPLE
   PS C:\> Get-Help .\Sherlock.ps1 -full
   Access This cmdlet Comment_Based_Help

.EXAMPLE
   PS C:\> Import-Module $Env:TMP\Sherlock.ps1 -Force;Get-HotFixs
   Import module, Find missing KB packages Updates (HotFix)

.EXAMPLE
   PS C:\> Import-Module $Env:TMP\Sherlock.ps1 -Force;Find-AllVulns
   Import module and scan for all CVE's vulnerabilitys status

.EXAMPLE
   PS C:\> Import-Module -Name "$Env:TMP\Sherlock.ps1" -Force;Get-HotFixs;Find-AllVulns
   Import module, Find missing KB packages and scan for all CVE's vulnerabilitys status

.INPUTS
   None. You cannot pipe objects into Sherlock.ps1

.OUTPUTS
   Title      : TrackPopupMenu Win32k Null Point Dereference
   MSBulletin : MS14-058
   CVEID      : 2014-4113
   Link       : https://www.exploit-db.com/exploits/35101/
   VulnStatus : Appers Vulnerable

   Title      : Win32k Elevation of Privileges
   MSBulletin : MS13-036
   CVEID      : 2020-0624
   Link       : https://tinyurl.com/ybpz7k6y
   VulnStatus : Not Vulnerable

.LINK
    https://www.exploit-db.com/
    https://github.com/r00t-3xp10it/venom
    https://packetstormsecurity.com/files/os/windows/
    https://github.com/r00t-3xp10it/venom/tree/master/aux/Sherlock.ps1
#>


## Variable declarations
$KBDataEntrys = "16"
$CveDataBaseId = "18"
$CmdletVersion = "v1.2"
$IntDataBase = "23/12/2020"
$Global:ExploitTable = $null
$OSVersion = (Get-WmiObject Win32_OperatingSystem).version
$host.UI.RawUI.WindowTitle = "@Sherlock $CmdletVersion {SSA@RedTeam}"

function Sherlock-Banner {

   <#
   .SYNOPSIS
      Author: r00t-3xp10it
      Displays Sherlock v1.2 Script Banner
   #>

   ## Create Data Table for output
   $MajorVersion = [int]$OSVersion.split(".")[0]
   $mytable = New-Object System.Data.DataTable
   $mytable.Columns.Add("ModuleName")|Out-Null
   $mytable.Columns.Add("CVE-entrys")|Out-Null
   $mytable.Columns.Add("OS")|Out-Null
   $mytable.Columns.Add("CVE-dataBase")|Out-Null
   $mytable.Rows.Add("Sherlock",
                     "$CveDataBaseId",
                     "W$MajorVersion",
                     "$IntDataBase")|Out-Null

   ## Display Data Table
   $mytable|Format-Table -AutoSize > $Env:TMP\MyTable.log
   Get-Content -Path "$Env:TMP\MyTable.log"
   Remove-Item -Path "$Env:TMP\MyTable.log" -Force
}

function Get-HotFixs {
[int]$Count = 0

   <#
   .SYNOPSIS
      Author: r00t-3xp10it
      Find missing KB packages

   .NOTES
      LogFile: systeminfo.txt
      Contains the output of 'Get-HotFix' cmdline
      to be compared againts Sherlock $dATAbASE list

   .EXAMPLE
      Import-Module -Name "$Env:TMP\Sherlock.ps1" -Force;Get-HotFixs
   #>

   $MajorVersion = [int]$OSVersion.split(".")[0]
   ## Create Data Table for output
   $mytable = New-Object System.Data.DataTable
   $mytable.Columns.Add("ModuleName")|Out-Null
   $mytable.Columns.Add("KB-entrys")|Out-Null
   $mytable.Columns.Add("OS")|Out-Null
   $mytable.Columns.Add("KB-dataBase")|Out-Null
   $mytable.Rows.Add("Sherlock",
                     "$KBDataEntrys",
                     "W$MajorVersion",
                     "$IntDataBase")|Out-Null

   ## Display Data Table
   $mytable|Format-Table -AutoSize > $Env:TMP\MyTable.log
   Get-Content -Path "$Env:TMP\MyTable.log"
   Remove-Item -Path "$Env:TMP\MyTable.log" -Force

   ## Generates system report file
   $GetKBId = Get-HotFix|Select-Object HotFixID|findstr /V "HotFixID --------"
   $data = $GetKBId -replace ' ','';echo $data > $Env:TMP\systeminfo.txt

   ## Sherlock $dATAbASE lists
   $MajorVersion = [int]$OSVersion.split(".")[0]
   If($MajorVersion -eq 10){## Windows 10
      $dATAbASE = @(
         "KB4552931","KB4497165","KB4515383",
         "KB4516115","KB4517245","KB4521863",#"KB3245007", ## Fake KB entry for debug
         "KB4524569","KB4528759","KB4537759",
         "KB4538674","KB4541338","KB4552152",
         "KB4559309","KB4560959","KB4561600",
         "KB4560960"
      )
   }ElseIf($MajorVersion -eq 8){## Windows (8|8.1)
      $dATAbASE = @(
         "KB4552931","KB4497165","KB4515383",
         "KB4516115","KB4517245","KB4521863",
         "KB4524569","KB4528759","KB4537759",
         "KB4538674","KB4541338","KB4552152",
         "KB4559309","KB4560959","KB4561600",
         "KB4560960"
      )
  }ElseIf($MajorVersion -eq 7){## Windows 7
      $dATAbASE = @(
         "KB4552931","KB4497165","KB4515383",
         "KB4516115","KB4517245","KB4521863",
         "KB4524569","KB4528759","KB4537759",
         "KB4538674","KB4541338","KB4552152",
         "KB4559309","KB4560959","KB4561600",
         "KB4560960"
      )
  }ElseIf($MajorVersion -eq "Vista"){## Windows Vista
      $dATAbASE = @(
         "KB4552931","KB4497165","KB4515383",
         "KB4516115","KB4517245","KB4521863",
         "KB4524569","KB4528759","KB4537759",
         "KB4538674","KB4541338","KB4552152",
         "KB4559309","KB4560959","KB4561600",
         "KB4560960"
      )
  }Else{
     $dATAbASE = "Not supported under W$MajorVersion systems"
     $bypass = "True" ## Operative System NOT supported
  }

   ## Put systeminfo.txt contents into an array list
   [System.Collections.ArrayList]$LocalKBLog = Get-Content "$Env:TMP\systeminfo.txt" -EA SilentlyContinue
   Write-Host "Id HotFixID   Status     VulnState"
   Write-Host "-- ---------  ---------  ---------"

   ## Compare the two Lists together
   ForEach($KBkey in $dATAbASE){
      Start-Sleep -Milliseconds 600
      If(-not($LocalKBLog -Match $KBkey)){$Count++
         If($bypass -eq "True"){## Operative System NOT supported output
            Write-Host "$Count  <$KBkey>" -ForeGroundColor Red -BackGroundColor Black
         }Else{
            Write-Host "$Count  $KBkey  <Missing>  <NotFound>" -ForeGroundColor Red -BackGroundColor Black         
         }
         Start-Sleep -Milliseconds 250
      }Else{
         Write-Host "+  $KBkey  Installed  Patched" -ForeGroundColor Green
      }
   }
   Write-Host ""
   If(Test-Path -Path "$Env:TMP\systeminfo.txt"){
      Remove-Item "$Env:TMP\systeminfo.txt" -Force
   }
}

function Get-FileVersionInfo($FilePath){
    $VersionInfo = (Get-Item $FilePath -EA SilentlyContinue).VersionInfo
    $FileVersion = ( "{0}.{1}.{2}.{3}" -f $VersionInfo.FileMajorPart, $VersionInfo.FileMinorPart, $VersionInfo.FileBuildPart, $VersionInfo.FilePrivatePart )
    return $FileVersion
}

function Get-InstalledSoftware($SoftwareName){
    $SoftwareVersion = Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -eq $SoftwareName } | Select-Object Version
    $SoftwareVersion = $SoftwareVersion.Version  # I have no idea what I'm doing
    return $SoftwareVersion
}

function Get-Architecture {
    # This is the CPU architecture.  Returns "64 bits" or "32-bit".
    $CPUArchitecture = (Get-WmiObject Win32_OperatingSystem).OSArchitecture
    # This is the process architecture, e.g. are we an x86 process running on a 64-bit system.  Retuns "AMD64" or "x86".
    $ProcessArchitecture = $env:PROCESSOR_ARCHITECTURE
    return $CPUArchitecture, $ProcessArchitecture
}

function Get-CPUCoreCount {
    $CoreCount = (Get-WmiObject Win32_Processor).NumberOfLogicalProcessors
    return $CoreCount
}

function New-ExploitTable {

    ## Create the table
    $Global:ExploitTable = New-Object System.Data.DataTable

    ## Create the columns
    $Global:ExploitTable.Columns.Add("Title")
    $Global:ExploitTable.Columns.Add("MSBulletin")
    $Global:ExploitTable.Columns.Add("CVEID")
    $Global:ExploitTable.Columns.Add("Link")
    $Global:ExploitTable.Columns.Add("VulnStatus")

    ## Exploit MS10
    $Global:ExploitTable.Rows.Add("User Mode to Ring (KiTrap0D)","MS10-015","2010-0232","https://www.exploit-db.com/exploits/11199/")
    $Global:ExploitTable.Rows.Add("Task Scheduler .XML","MS10-092","2010-3338, 2010-3888","https://www.exploit-db.com/exploits/19930/")
    ## Exploit MS13
    $Global:ExploitTable.Rows.Add("NTUserMessageCall Win32k Kernel Pool Overflow","MS13-053","2013-1300","https://www.exploit-db.com/exploits/33213/")
    $Global:ExploitTable.Rows.Add("TrackPopupMenuEx Win32k NULL Page","MS13-081","2013-3881","https://www.exploit-db.com/exploits/31576/")
    ## Exploit MS14
    $Global:ExploitTable.Rows.Add("TrackPopupMenu Win32k Null Pointer Dereference","MS14-058","2014-4113","https://www.exploit-db.com/exploits/35101/")
    ## Exploit MS15
    $Global:ExploitTable.Rows.Add("ClientCopyImage Win32k","MS15-051","2015-1701, 2015-2433","https://www.exploit-db.com/exploits/37367/")
    $Global:ExploitTable.Rows.Add("Font Driver Buffer Overflow","MS15-078","2015-2426, 2015-2433","https://www.exploit-db.com/exploits/38222/")
    ## Exploit MS16
    $Global:ExploitTable.Rows.Add("'mrxdav.sys' WebDAV","MS16-016","2016-0051","https://www.exploit-db.com/exploits/40085/")
    $Global:ExploitTable.Rows.Add("Secondary Logon Handle","MS16-032","2016-0099","https://www.exploit-db.com/exploits/39719/")
    $Global:ExploitTable.Rows.Add("Windows Kernel-Mode Drivers EoP","MS16-034","2016-0093/94/95/96","https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS16-034?")
    $Global:ExploitTable.Rows.Add("Win32k Elevation of Privilege","MS16-135","2016-7255","https://github.com/FuzzySecurity/PSKernel-Primitives/tree/master/Sample-Exploits/MS16-135")
    ## Miscs that aren't MS
    $Global:ExploitTable.Rows.Add("Nessus Agent 6.6.2 - 6.10.3","N/A","2017-7199","https://aspe1337.blogspot.co.uk/2017/04/writeup-of-cve-2017-7199.html")

    ## r00t-3xp10it update (v1.2)
    $Global:ExploitTable.Rows.Add("Win32k Uninitialized Variable Elevation of Privileges","N/A","2019-1458","https://packetstormsecurity.com/files/159569/Microsoft-Windows-Uninitialized-Variable-Local-Privilege-Escalation.html")
    $Global:ExploitTable.Rows.Add("Win32k Elevation of Privileges","MS13-036","2020-0624","https://tinyurl.com/ybpz7k6y")
    $Global:ExploitTable.Rows.Add("Win32k Elevation of Privileges","N/A","2020-0642","https://packetstormsecurity.com/files/158729/Microsoft-Windows-Win32k-Privilege-Escalation.html")
    $Global:ExploitTable.Rows.Add("DrawIconEx Win32k Elevation of Privileges","N/A","2020-1054","https://packetstormsecurity.com/files/160515/Microsoft-Windows-DrawIconEx-Local-Privilege-Escalation.html")
    $Global:ExploitTable.Rows.Add("Druva inSync Local Elevation of Privileges","N/A","2020-5752","https://packetstormsecurity.com/files/160404/Druva-inSync-Windows-Client-6.6.3-Privilege-Escalation.html")
    $Global:ExploitTable.Rows.Add("Pulse Secure Client Local Elevation of Privileges","N/A","2020-13162","https://packetstormsecurity.com/files/158117/Pulse-Secure-Client-For-Windows-Local-Privilege-Escalation.html")



}

function Set-ExploitTable ($MSBulletin, $VulnStatus){
    If($MSBulletin -like "MS*"){
        $Global:ExploitTable|Where-Object { $_.MSBulletin -eq $MSBulletin
        } | ForEach-Object {
            $_.VulnStatus = $VulnStatus
        }

    }Else{

        $Global:ExploitTable|Where-Object { $_.CVEID -eq $MSBulletin
        } | ForEach-Object {
            $_.VulnStatus = $VulnStatus
        }
    }
}

function Get-Results {
    Write-Host ""
    Sherlock-Banner
    $Global:ExploitTable
}

function Find-AllVulns {

    If(-not($Global:ExploitTable)){
        $null = New-ExploitTable
    }

        Find-MS10015
        Find-MS10092
        Find-MS13053
        Find-MS13081
        Find-MS14058
        Find-MS15051
        Find-MS15078
        Find-MS16016
        Find-MS16032
        Find-MS16034
        Find-MS16135
        Find-CVE20177199
        ## version 1.2 update
        Find-CVE20191458
        Find-CVE20200624
        Find-CVE20200642
        Find-CVE20201054
        Find-CVE20205752
        Find-CVE202013162

        Get-Results
}


function Find-MS10015 {

    $MSBulletin = "MS10-015"
    $Architecture = Get-Architecture
    If($Architecture[0] -eq "64 bits"){
        $VulnStatus = "Not supported on 64-bits systems"
    }Else{
        $Path = $env:windir + "\system32\ntoskrnl.exe"
        $VersionInfo = (Get-Item $Path -EA SilentlyContinue).VersionInfo.ProductVersion
        $VersionInfo = $VersionInfo.Split(".")
        $Build = $VersionInfo[2]
        $Revision = $VersionInfo[3].Split(" ")[0]
        switch($Build){
            7600 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le "20591" ] }
            default { $VulnStatus = "Not Vulnerable" }
        }
    }
    Set-ExploitTable $MSBulletin $VulnStatus
}

function Find-MS10092 {

    $MSBulletin = "MS10-092"
    $Architecture = Get-Architecture
    If($Architecture[1] -eq "AMD64" -or $Architecture[0] -eq "32-bit"){
        $Path = $env:windir + "\system32\schedsvc.dll"
    }ElseIf($Architecture[0] -eq "64 bits" -and $Architecture[1] -eq "x86"){
        $Path = $env:windir + "\sysnative\schedsvc.dll"
    }

        $VersionInfo = (Get-Item $Path -EA SilentlyContinue).VersionInfo.ProductVersion
        $VersionInfo = $VersionInfo.Split(".")
        $Build = $VersionInfo[2]
        $Revision = $VersionInfo[3].Split(" ")[0]

        switch($Build){
            7600 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le "20830" ] }
            default { $VulnStatus = "Not Vulnerable" }
        }
    Set-ExploitTable $MSBulletin $VulnStatus
}

function Find-MS13053 {

    $MSBulletin = "MS13-053"
    $Architecture = Get-Architecture
    If($Architecture[0] -eq "64 bits"){
        $VulnStatus = "Not supported on 64-bits systems"
    }Else{
        $Path = $env:windir + "\system32\win32k.sys"
        $VersionInfo = (Get-Item $Path -EA SilentlyContinue).VersionInfo.ProductVersion
        $VersionInfo = $VersionInfo.Split(".")

        $Build = $VersionInfo[2]
        $Revision = $VersionInfo[3].Split(" ")[0]

        switch($Build){
            7600 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -ge "17000" ] }
            7601 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le "22348" ] }
            9200 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le "20732" ] }
            default { $VulnStatus = "Not Vulnerable" }
        }
    }
    Set-ExploitTable $MSBulletin $VulnStatus
}

function Find-MS13081 {

    $MSBulletin = "MS13-081"
    $Architecture = Get-Architecture
    If($Architecture[0] -eq "64 bits"){
        $VulnStatus = "Not supported on 64-bits systems"
    }Else{

        $Path = $env:windir + "\system32\win32k.sys"
        $VersionInfo = (Get-Item $Path -EA SilentlyContinue).VersionInfo.ProductVersion
        $VersionInfo = $VersionInfo.Split(".")

        $Build = $VersionInfo[2]
        $Revision = $VersionInfo[3].Split(" ")[0]

        switch($Build){
            7600 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -ge "18000" ] }
            7601 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le "22435" ] }
            9200 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le "20807" ] }
            default { $VulnStatus = "Not Vulnerable" }
        }
    }
    Set-ExploitTable $MSBulletin $VulnStatus
}

function Find-MS14058 {

    $MSBulletin = "MS14-058"
    $Architecture = Get-Architecture
    If($Architecture[1] -eq "AMD64" -or $Architecture[0] -eq "32-bit"){
        $Path = $env:windir + "\system32\win32k.sys"
    }ElseIf($Architecture[0] -eq "64 bits" -and $Architecture[1] -eq "x86"){
        $Path = $env:windir + "\sysnative\win32k.sys"
    }

        $VersionInfo = (Get-Item $Path -EA SilentlyContinue).VersionInfo.ProductVersion
        $VersionInfo = $VersionInfo.Split(".")

        $Build = $VersionInfo[2]
        $Revision = $VersionInfo[3].Split(" ")[0]

        switch($Build){
            7600 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -ge "18000" ] }
            7601 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le "22823" ] }
            9200 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le "21247" ] }
            9600 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le "17353" ] }
            default { $VulnStatus = "Not Vulnerable" }
        }
    Set-ExploitTable $MSBulletin $VulnStatus
}

function Find-MS15051 {

    $MSBulletin = "MS15-051"
    $Architecture = Get-Architecture
    If($Architecture[1] -eq "AMD64" -or $Architecture[0] -eq "32-bit"){
        $Path = $env:windir + "\system32\win32k.sys"
    }ElseIf($Architecture[0] -eq "64 bits" -and $Architecture[1] -eq "x86"){
        $Path = $env:windir + "\sysnative\win32k.sys"
    }

        $VersionInfo = (Get-Item $Path -EA SilentlyContinue).VersionInfo.ProductVersion
        $VersionInfo = $VersionInfo.Split(".")

        $Build = $VersionInfo[2]
        $Revision = $VersionInfo[3].Split(" ")[0]

        switch($Build){
            7600 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le "18000" ] }
            7601 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le "22823" ] }
            9200 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le "21247" ] }
            9600 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le "17353" ] }
            default { $VulnStatus = "Not Vulnerable" }
        }
    Set-ExploitTable $MSBulletin $VulnStatus
}

function Find-MS15078 {

    $MSBulletin = "MS15-078"
    $Path = $env:windir + "\system32\atmfd.dll"
    If(Test-Path -Path "$Path" -EA SilentlyContinue){## Fucking error
       $VersionInfo = (Get-Item $Path -EA SilentlyContinue).VersionInfo.ProductVersion
       $VersionInfo = $VersionInfo.Split(" ")
       $Revision = $VersionInfo[2]
    }Else{
      $VulnStatus = "Not Vulnerable"
    }

    switch($Revision){
        243 { $VulnStatus = "Appears Vulnerable" }
        default { $VulnStatus = "Not Vulnerable" }
    }
    Set-ExploitTable $MSBulletin $VulnStatus
}

function Find-MS16016 {

    $MSBulletin = "MS16-016"
    $Architecture = Get-Architecture
    If($Architecture[0] -eq "64 bits"){
        $VulnStatus = "Not supported on 64-bits systems"
    }Else{

        $Path = $env:windir + "\system32\drivers\mrxdav.sys"
        $VersionInfo = (Get-Item $Path -EA SilentlyContinue).VersionInfo.ProductVersion
        $VersionInfo = $VersionInfo.Split(".")

        $Build = $VersionInfo[2]
        $Revision = $VersionInfo[3].Split(" ")[0]

        switch($Build){
            7600 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le "16000" ] }
            7601 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le "23317" ] }
            9200 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le "21738" ] }
            9600 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le "18189" ] }
            10240 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le "16683" ] }
            10586 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le "103" ] }
            default { $VulnStatus = "Not Vulnerable" }
        }
    }
    Set-ExploitTable $MSBulletin $VulnStatus
}

function Find-MS16032 {

    $MSBulletin = "MS16-032"
    $CPUCount = Get-CPUCoreCount

    If($CPUCount -eq "1"){
        $VulnStatus = "Not Supported on single-core systems"
    }Else{
    
        $Architecture = Get-Architecture
        If($Architecture[1] -eq "AMD64" -or $Architecture[0] -eq "32-bit"){
            $Path = $env:windir + "\system32\seclogon.dll"
        }ElseIf($Architecture[0] -eq "64 bits" -and $Architecture[1] -eq "x86"){
            $Path = $env:windir + "\sysnative\seclogon.dll"
        } 

            $VersionInfo = (Get-Item $Path -EA SilentlyContinue).VersionInfo.ProductVersion
            $VersionInfo = $VersionInfo.Split(".")

            $Build = [int]$VersionInfo[2]
            $Revision = [int]$VersionInfo[3].Split(" ")[0]

            switch($Build){
                6002 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revison -lt 19598 -Or ( $Revision -ge 23000 -And $Revision -le 23909 ) ] }
                7600 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le 19148 ] }
                7601 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -lt 19148 -Or ( $Revision -ge 23000 -And $Revision -le 23347 ) ] }
                9200 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revison -lt 17649 -Or ( $Revision -ge 21000 -And $Revision -le 21767 ) ] }
                9600 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revison -lt 18230 ] }
                10240 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -lt 16724 ] }
                10586 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le 161 ] }
                default { $VulnStatus = "Not Vulnerable" }
            }
    }
    Set-ExploitTable $MSBulletin $VulnStatus
}

function Find-MS16034 {

    $MSBulletin = "MS16-034"
    $Architecture = Get-Architecture
    If($Architecture[1] -eq "AMD64" -or $Architecture[0] -eq "32-bit"){
        $Path = $env:windir + "\system32\win32k.sys"
    }ElseIf($Architecture[0] -eq "64 bits" -and $Architecture[1] -eq "x86"){
        $Path = $env:windir + "\sysnative\win32k.sys"
    } 

    $VersionInfo = (Get-Item $Path -EA SilentlyContinue).VersionInfo.ProductVersion
    $VersionInfo = $VersionInfo.Split(".")

    $Build = [int]$VersionInfo[2]
    $Revision = [int]$VersionInfo[3].Split(" ")[0]

    switch($Build){
        6002 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revison -lt 19597 -Or $Revision -lt 23908 ] }
        7601 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -lt 19145 -Or $Revision -lt 23346 ] }
        9200 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revison -lt 17647 -Or $Revision -lt 21766 ] }
        9600 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revison -lt 18228 ] }
        default { $VulnStatus = "Not Vulnerable" }
    }
    Set-ExploitTable $MSBulletin $VulnStatus
}

function Find-CVE20177199 {

    $CVEID = "2017-7199"
    $SoftwareVersion = Get-InstalledSoftware "Nessus Agent"
    If(-not($SoftwareVersion)){
        $VulnStatus = "Not Vulnerable"
    }Else{

        $SoftwareVersion = $SoftwareVersion.Split(".")
        $Major = [int]$SoftwareVersion[0]
        $Minor = [int]$SoftwareVersion[1]
        $Build = [int]$SoftwareVersion[2]

        switch($Major){
        6 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Minor -eq 10 -and $Build -le 3 -Or ( $Minor -eq 6 -and $Build -le 2 ) -Or ( $Minor -le 9 -and $Minor -ge 7 ) ] } # 6.6.2 - 6.10.3
        default { $VulnStatus = "Not Vulnerable" }
        }
    }
    Set-ExploitTable $CVEID $VulnStatus
}

function Find-MS16135 {

    $MSBulletin = "MS16-135"
    $Architecture = Get-Architecture
    If($Architecture[1] -eq "AMD64" -or $Architecture[0] -eq "32-bit"){
        $Path = $env:windir + "\system32\win32k.sys"
    }ElseIf($Architecture[0] -eq "64 bits" -and $Architecture[1] -eq "x86"){
        $Path = $env:windir + "\sysnative\win32k.sys"
    }

        $VersionInfo = (Get-Item $Path -EA SilentlyContinue).VersionInfo.ProductVersion
        $VersionInfo = $VersionInfo.Split(".")
        
        $Build = [int]$VersionInfo[2]
        $Revision = [int]$VersionInfo[3].Split(" ")[0]

        switch($Build){
            7601 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -lt 23584 ] }
            9600 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le 18524 ] }
            10240 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le 16384 ] }
            10586 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le 19 ] }
            14393 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le 446 ] }
            default { $VulnStatus = "Not Vulnerable" }
        }
    Set-ExploitTable $MSBulletin $VulnStatus
}

# -------------------------------------------------------------------------------------------------------

   <#
   .SYNOPSIS
      Author: @r00t-3xp10it
      Sherlock version v1.2 update

   .DESCRIPTION
      The next functions are related to new 2020 EOP CVE's

   .LINK
      https://www.exploit-db.com/
      https://packetstormsecurity.com/files/os/windows/
   #>

# -------------------------------------------------------------------------------------------------------

function Find-CVE20191458 {

   <#
   .SYNOPSIS
      Author: r00t-3xp10it
      Win32k Uninitialized Variable Elevation of Privileges

   .DESCRIPTION
      CVE: 2019-1458
      MSBulletin: N/A
      Affected systems:
         Windows 7 and Windows Server 2008 R2   - 6.1.7601.24540
         Windows 8.1 and Windows Server 2012 R2 - 6.3.9600.19574
         Windows 10 v1507                       - 10.0.10240.18427
         Windows 10 v1511                       - 10.0.10586.99999
         Windows 10 v1607                       - 10.0.14393.3383
   #>

    $MSBulletin = "N/A"
    $CVEID = "2019-1458"
    $Architecture = Get-Architecture
    $ArchBuildBits = $Architecture[0]
    $FilePath = $Env:WINDIR + "\System32\Win32k.sys"

    ## Check for OS affected version/arch (Windows 10 x64)
    $MajorVersion = [int]$OSVersion.split(".")[0]
    If(-not($MajorVersion -eq 7 -or $MajorVersion -eq 8 -or $MajorVersion -eq 10) -and $Architecture[0] -ne "64 bits"){
        $VulnStatus = "Not supported on Windows $MajorVersion ($ArchBuildBits) systems"
    }Else{
       
       $SoftwareVersion = (Get-Item "$FilePath" -EA SilentlyContinue).VersionInfo.ProductVersion
       If(-not($SoftwareVersion)){## Win32k appl not found
           $VulnStatus = "Not Vulnerable (Win32k driver not found)"
       }Else{

          ## Affected: < 10.0.14393.3383 (Windows 10)
          $Major = $SoftwareVersion.Split(".")[2]
          $Revision = [int]$SoftwareVersion.Split(".")[3]

           switch($Major){
           7601 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -lt 24540 ] }
           9600 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -lt 19574 ] }
           10240 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -lt 18427 ] }
           10586 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -lt 99999 ] }
           14393 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -lt 3383 ] }
           default { $VulnStatus = "Not Vulnerable" }
           }
       }
    }
    Set-ExploitTable $CVEID $VulnStatus
}

function Find-CVE20200624 {

   <#
   .SYNOPSIS
      Author: r00t-3xp10it
      Win32k.sys Local Privilege Escalation

   .DESCRIPTION
      CVE: 2020-0624
      MSBulletin: MS13-036
      Affected systems:
         Windows 10 (1903)
         Windows 10 (1909)
         Windows Server Version 1909 (Core)
   #>

    $CVEID = "2020-0624"
    $MSBulletin = "MS13-036"
    $FilePath = $Env:WINDIR + "\System32\Win32k.sys"

    ## Check for OS affected version (Windows 10)
    $MajorVersion = [int]$OSVersion.split(".")[0]
    If($MajorVersion -ne 10){## Affected version number (Windows)
        $VulnStatus = "Not supported on Windows $MajorVersion systems"
    }Else{

       $SoftwareVersion = (Get-Item "$FilePath" -EA SilentlyContinue).VersionInfo.ProductVersion
       If(-not($SoftwareVersion)){## Win32k.sys driver not found
           $VulnStatus = "Not Vulnerable (Win32k.sys driver not found)"
       }Else{

          $Major = [int]$SoftwareVersion.split(".")[2]
          $Revision = [int]$SoftwareVersion.Split(".")[3]

           switch($Major){
           18362 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -lt 900 ] }
           default { $VulnStatus = "Not Vulnerable" }
           }
       }
    }
    Set-ExploitTable $CVEID $VulnStatus
}

function Find-CVE20200642 {

   <#
   .SYNOPSIS
      Author: r00t-3xp10it
      Win32k.sys Local Privilege Escalation

   .DESCRIPTION
      CVE: 2020-0642
      MSBulletin: N/A
      Affected systems:
         Windows 10 (1909)
         Windows Server Version 1909 (Core)
   #>

    $CVEID = "2020-0642"
    $MSBulletin = "N/A"
    $FilePath = $Env:WINDIR + "\System32\Win32k.sys"

    ## Check for OS affected version (Windows Server|10)
    $MajorVersion = [int]$OSVersion.split(".")[0]
    If($MajorVersion -ne 10){## Affected version number (Windows)
        $VulnStatus = "Not supported on Windows $MajorVersion systems"
    }Else{

       $SoftwareVersion = (Get-Item "$FilePath" -EA SilentlyContinue).VersionInfo.ProductVersion
       If(-not($SoftwareVersion)){## Win32k.sys driver not found
           $VulnStatus = "Not Vulnerable (Win32k.sys driver not found)"
       }Else{

          ## Vuln: =< 5.1.2600.1330
          $Major = [int]$SoftwareVersion.split(".")[2]
          $Revision = [int]$SoftwareVersion.Split(".")[3]

           switch($Major){
           2600 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le 1329 ] }
           default { $VulnStatus = "Not Vulnerable" }
           }
       }
    }
    Set-ExploitTable $CVEID $VulnStatus
}



function Find-CVE20201054 {

   <#
   .SYNOPSIS
      Author: r00t-3xp10it
      DrawIconEx Win32k.sys Local Privilege Escalation

   .DESCRIPTION
      CVE: 2020-1054
      MSBulletin: N/A
      Affected systems:
         Windows 7 SP1
   #>

    $CVEID = "2020-1054"
    $MSBulletin = "N/A"
    $FilePath = $Env:WINDIR + "\System32\Win32k.sys"

    ## Check for OS affected version (Windows 7 SP1)
    $MajorVersion = [int]$OSVersion.split(".")[0]
    If($MajorVersion -ne 7){## Affected version number (Windows)
        $VulnStatus = "Not supported on Windows $MajorVersion systems"
    }Else{

       $SoftwareVersion = (Get-Item "$FilePath" -EA SilentlyContinue).VersionInfo.ProductVersion
       If(-not($SoftwareVersion)){## Win32k.sys driver not found
           $VulnStatus = "Not Vulnerable (Win32k.sys driver not found)"
       }Else{

          ## Affected: 6.1.7601.24553 (SP1) | 6.1.7601.24542
          $Major = [int]$SoftwareVersion.split(".")[2]
          $Revision = [int]$SoftwareVersion.Split(".")[3]

           switch($Major){
           7601 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le 24553 ] } # Windows 7 SP1
           default { $VulnStatus = "Not Vulnerable" }
           }
       }
    }
    Set-ExploitTable $CVEID $VulnStatus
}

function Find-CVE20205752 {

   <#
   .SYNOPSIS
      Author: r00t-3xp10it
      Druva inSync Local Privilege Escalation

   .DESCRIPTION
      CVE: 2020-5752
      MSBulletin: N/A
      Affected systems:
         Windows 10 (x64)
   #>

    $MSBulletin = "N/A"
    $CVEID = "2020-5752"
    $Architecture = Get-Architecture
    $ArchBuildBits = $Architecture[0]

    ## Check for OS affected version/arch (Windows 10 x64)
    $MajorVersion = [int]$OSVersion.split(".")[0]
    If(-not($MajorVersion -eq 10 -and $Architecture[0] -eq "64 bits")){
        $VulnStatus = "Not supported on Windows $MajorVersion ($ArchBuildBits) systems"
    }Else{

       ## Find druva.exe absoluct install path
       # Default Path: ${Env:PROGRAMFILES(x86)}\Druva\inSync4\druva.exe
       $SearchFilePath = (Get-ChildItem -Path ${Env:PROGRAMFILES(x86)}\Druva\, $Env:PROGRAMFILES\Druva\, $Env:LOCALAPPDATA\Programs\Druva\ -Filter druva.exe -Recurse -ErrorAction SilentlyContinue -Force).fullname
       If(-not($SearchFilepath)){## Add value to $FilePath or else 'Get-Item' pops up an error if $null
          $FilePath = ${Env:PROGRAMFILES(x86)} + "\Druva\inSync4\druva.exe"
       }Else{
          $FilePath = $SearchFilePath[0]
       }
       
       $SoftwareVersion = (Get-Item "$FilePath" -EA SilentlyContinue).VersionInfo.ProductVersion
       If(-not($SoftwareVersion)){## druva.exe appl not found
           $VulnStatus = "Not Vulnerable (druva.exe not found)"
       }Else{

          ## Affected: < 6.6.3 (Windows 10 x64)
          $Major = [int]$SoftwareVersion.split(".")[1]
          $Revision = [int]$SoftwareVersion.Split(".")[2]

           switch($Major){
           6 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -lt 3 ] }
           default { $VulnStatus = "Not Vulnerable" }
           }
       }
    }
    Set-ExploitTable $CVEID $VulnStatus
}

function Find-CVE202013162 {

   <#
   .SYNOPSIS
      Author: r00t-3xp10it
      Pulse Secure Client Local Elevation of Privileges

   .DESCRIPTION
      CVE: 2020-13162
      MSBulletin: N/A
      Affected systems:
         windows 8.1
         Windows 10 (1909)
   #>

    $MSBulletin = "N/A"
    $CVEID = "2020-13162"
    $Architecture = Get-Architecture
    $ArchBuildBits = $Architecture[0]

    ## Check for OS affected version/arch
    $MajorVersion = [int]$OSVersion.split(".")[0]
    If(-not($MajorVersion -eq 8 -or $MajorVersion -eq 10)){
        $VulnStatus = "Not supported on Windows $MajorVersion systems"
    }Else{

       ## Find PulseSecureService.exe absoluct install path
       # Default Path: ${Env:PROGRAMFILES(x86)}\Common Files\Pulse Secure\JUNS\PulseSecureService.exe
       $SearchFilePath = (Get-ChildItem -Path "${Env:PROGRAMFILES(x86)}\Common Files\", "$Env:PROGRAMFILES\Common Files\", "$Env:LOCALAPPDATA\Programs\Common Files\" -Filter PulseSecureService.exe -Recurse -ErrorAction SilentlyContinue -Force).fullname
       If(-not($SearchFilepath)){## Add value to $FilePath or else 'Get-Item' pops up an error if $null
          $FilePath = ${Env:PROGRAMFILES(x86)} + "\Common Files\Pulse Secure\JUNS\PulseSecureService.exe"
       }Else{
          $FilePath = $SearchFilePath
       }
       
       $SoftwareVersion = (Get-Item "$FilePath" -EA SilentlyContinue).VersionInfo.ProductVersion
       If(-not($SoftwareVersion)){## PulseSecureService.exe appl not found
           $VulnStatus = "Not Vulnerable (PulseSecureService.exe not found)"
       }Else{

          ## Affected: < 9.1.6 (Windows 8|10)
          $Major = [int]$SoftwareVersion.split(",")[1]
          $Revision = [int]$SoftwareVersion.Split(",")[2]

           switch($Major){
           1 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -lt 6 ] }
           default { $VulnStatus = "Not Vulnerable" }
           }
       }
    }
    Set-ExploitTable $CVEID $VulnStatus
}
