<#
.SYNOPSIS
   Find missing software patchs for privilege escalation (windows).

   Author: @_RastaMouse (Deprecated)
   Update: @r00t-3xp10it (v1.3.4)
   Tested Under: Windows 10 (18363) x64 bits
   Required Dependencies: none
   Optional Dependencies: none
   PS cmdlet Dev version: v1.3.4

.DESCRIPTION
   Cmdlet to find missing software patchs for privilege escalation (windows).
   This CmdLet continues @_RastaMouse (Deprecated) Module with new 2020 CVE
   entrys and a new function to find missing security KB patches by comparing
   the list of installed patches againts Sherlock KB List entrys ($dATAbASE).
   This Cmdlet also Searchs for 'Unquoted service paths' (EoP vulnerability) and
   recursive search for folders with Everyone:(F) permissions ($Env:PROGRAMFILES)

.NOTES
   Vulnerabilitys/CVE's to test
   ----------------------------
   MS10-015, MS10-092, MS13-053, MS13-081
   MS14-058, MS15-051, MS15-078, MS16-016
   MS16-032, MS16-034, MS16-135

   CVE-2017-7199, CVE-2019-1215, CVE-2019-1458
   CVE-2020-005, CVE-2020-0624, CVE-2020-0642
   CVE-2020-1048, CVE-2020-1054, CVE-2020-5752
   CVE-2020-13162, CVE-2020-17382, CVE-2020-17008
   CVE-2020-25106, CVE-2021-1642
   
.EXAMPLE
   PS C:\> Get-Help .\Sherlock.ps1 -full
   Access This cmdlet Comment_Based_Help

.EXAMPLE
   PS C:\> Import-Module $Env:TMP\Sherlock.ps1 -Force
   Force the reload of this Module if allready exists
   Remark: Importing Module its Mandatory condiction

.EXAMPLE
   PS C:\> Get-GroupNames
   List ALL Group Names Available

.EXAMPLE
   PS C:\> Get-HotFixs
   Find missing security KB packages (HotFix Id)

.EXAMPLE
   PS C:\> Get-Rotten
   Find Rotten Potato vuln privilege settings (EoP)

.EXAMPLE
   PS C:\> Get-Unquoted
   Find Unquoted service paths (EoP vulnerability)

.EXAMPLE
   PS C:\> Get-Paths
   Find weak directory permissions - Everyone:(F)

.EXAMPLE
   PS C:\> Get-Paths Modify
   SYNTAX: Get-Paths <FileSystemRigths>
   Get-Paths 1º arg accepts Everyone:(FileSystemRigths) value.

.EXAMPLE
   PS C:\> Get-Paths FullControl BUILTIN\Users
   SYNTAX: Get-Paths <FileSystemRigths> <IdentityReference>
   Get-Paths 2º arg accepts the Group Name (Everyone|BUILTIN\Users)

.EXAMPLE
   PS C:\> Get-RegPaths
   Find Weak Services Registry Permissions Everyone:(F)

.EXAMPLE
   PS C:\> Get-RegPaths BUILTIN\Users
   SYNTAX: Get-RegPaths <IdentityReference>
   Get-RegPaths arg accepts the Group Name (Everyone|BUILTIN\Users)

.EXAMPLE
   PS C:\> Get-ModifiableRegPaths
   Checks the permissions of a given registry key and
   returns the ones that the current user can modify.
    
.EXAMPLE
   PS C:\> Get-DllHijack
   Find DLL's prone to hijacking (EoP).

.EXAMPLE
   PS C:\> Get-DllHijack EnvPaths
   SYNTAX: Get-DllHijack <EnvPaths-Argument>
   Checks if the current %PATH% has any directories
   that Migth be writeable (W) by the current user.

.EXAMPLE
   PS C:\> Find-AllVulns
   Scan pre-defined CVE's using Sherlock $dATAbASE

.EXAMPLE
   PS C:\> Use-AllModules
   Run ALL Sherlock enumeration modules (defaultRecon)

.EXAMPLE
   PS C:\> Use-AllModules FullRecon
   Run ALL Sherlock enumeration modules (FullRecon)

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
    http://www.catalog.update.microsoft.com/
    https://packetstormsecurity.com/files/os/windows/
    https://github.com/r00t-3xp10it/venom/tree/master/aux/Sherlock.ps1
    https://github.com/r00t-3xp10it/venom/wiki/Find-missing-software-patchs%5CPaths-for-privilege-escalation-(windows)
#>


## Var declarations
$CveDataBaseId = "25"        ## 25 CVE's entrys available ($dATAbASE)
$CmdletVersion = "v1.3.4"    ## Sherlock CmdLet develop version number
$CVEdataBase = "13/01/2021"  ## Global $dATAbASE (CVE) last update date
$Global:ExploitTable = $null ## Global Output DataTable
$ProcessArchitecture = $env:PROCESSOR_ARCHITECTURE
$OSVersion = (Get-WmiObject Win32_OperatingSystem).version
$host.UI.RawUI.WindowTitle = "@Sherlock $CmdletVersion {SSA@RedTeam}"
$IsClientAdmin = [bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -Match "S-1-5-32-544")


function Use-AllModules {
$UserImput = $args[0] ## User Imputs

   <#
   .SYNOPSIS
      Author: r00t-3xp10it
      Helper - Run ALL Sherlock enumeration modules

   .EXAMPLE
      PS C:\> Use-AllModules

   .EXAMPLE
      PS C:\> Use-AllModules FullRecon
      Permissions to scan: FullControl(F), Write(W), Modify(M)
      Group Names to scan: Everyone, BUILTIN\Users, NT AUTHORITY\INTERACTIVE

   .NOTES
      Be prepaired for huge outputs If used the 'FullRecon' @argument.
      Because it will loop through all permissions and all Group Names.
   #>

   ## Get Group Name in diferent languages
   # NOTE: England, Portugal, France, Germany, Bielorussia, Indonesia, Holland, Romania, Russia, Croacia 
   $FindGroup = whoami /groups|findstr /C:"Everyone" /C:"Todos" /C:"Tout" /C:"Alle" /C:"YÑÐµ" /C:"Semua" /C:"Allemaal" /C:"Toate" /C:"Bce" /C:"Svi"|Select-Object -First 1
   $SplitString = $FindGroup -split(" ");$GroupEveryone = $SplitString[0] -replace ' ',''

   ## Get Group Name (BUILTIN\users) in diferent languages
   # NOTE: England, Portugal, France, Germany, Indonesia, Holland, Romania, Croacia 
   $FindGroupUser = whoami /groups|findstr /C:"BUILTIN\Users" /C:"BUILTIN\Utilizadores" /C:"BUILTIN\Utilisateurs" /C:"BUILTIN\Benutzer" /C:"BUILTIN\Pengguna" /C:"BUILTIN\Gebruikers" /C:"BUILTIN\Utilizatori" /C:"BUILTIN\Korisnici"|Select-Object -First 1
   $SplitStringUser = $FindGroupUser -split(" ");$GroupNameUsers = $SplitStringUser[0] -replace ' ',''

   ## Default values if none string its found in permissions/groupname query
   If(-not($GroupEveryone) -or $GroupEveryone -ieq $null){$GroupEveryone = "Everyone"}
   If(-not($GroupNameUsers) -or $GroupNameUsers -ieq $null){$GroupNameUsers = "BUILTIN\Users"}

   ## Permissions/GroupName database
   $Permissions = @(## Permissions List
      "FullControl","Write","Modify"
   )
   $GroupsList = @(## Group Name List
      "$GroupEveryone","$GroupNameUsers",
      "NT AUTHORITY\INTERACTIVE"
   )

   ## Run ALL modules
   Get-HotFixs;Get-Rotten;Get-Unquoted
   If($UserImput -ieq "FullRecon"){## Agressive enumeration
      ## Be prepaired for huge outputs with this test :)
      ForEach($PrivsToken in $Permissions){## Loop through permissions list
         ForEach($ItemToken in $GroupsList){## Loop through Group Names List
            Get-Paths $PrivsToken $ItemToken
         }
      }
      ForEach($GroupsToken in $GroupsList){## Loop through Group Names List
         Get-RegPaths $GroupsToken
      }
      Get-ModifiableRegPaths;Get-DllHijack;Find-AllVulns
      Get-DllHijack EnvPaths;cmdkey /List  ## Get stored credentials to use with RUNAS
   }ElseIf(-not($UserImput) -or $UserImput -ieq $null){## Default Enumeration
      Get-Paths FullControl $GroupEveryone
      Get-RegPaths $GroupEveryone 
      Get-DllHijack;Find-AllVulns
   }
   Write-Host ""
}

function Get-GroupNames {

   <#
   .SYNOPSIS
      Author: r00t-3xp10it
      Helper - List ALL Group Names Available

   .EXAMPLE
      PS C:\> Get-GroupNames

   .OUTPUTS
      Group Name                                                 Type             SID          Attributes
      ========================================================== ================ ============ ==================================================
      Todos                                                      Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
      NT AUTHORITY\Conta local e membro do grupo Administradores Well-known group S-1-5-114    Group used for deny only
      BUILTIN\Administradores                                    Alias            S-1-5-32-544 Group used for deny only
      BUILTIN\Utilizadores                                       Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
      BUILTIN\Utilizadores do registo de desempenho              Alias            S-1-5-32-559 Mandatory group, Enabled by default, Enabled group
      NT AUTHORITY\INTERACTIVE                                   Well-known group S-1-5-4      Mandatory group, Enabled by default, Enabled group
      INICIO DE SESSAO NA CONSOLA                                Well-known group S-1-2-1      Mandatory group, Enabled by default, Enabled group
      NT AUTHORITY\Utilizadores Autenticados                     Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
      NT AUTHORITY\Esta organizacao                              Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
      NT AUTHORITY\Conta local                                   Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group
      LOCAL                                                      Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group
      NT AUTHORITY\Autenticacao NTLM                             Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
   #>

   ## Display available Groups
   $ListGroups = whoami /groups|findstr /V "GROUP INFORMATION ----- Label"
   echo $ListGroups > $Env:TMP\Groups.log
   Get-Content -Path "$Env:TMP\Groups.log"
   Remove-Item -Path "$Env:TMP\Groups.log" -Force
   Start-Sleep -Seconds 1;Write-Host ""
}

function Sherlock-Banner {

   <#
   .SYNOPSIS
      Author: r00t-3xp10it
      Sherlock CVE function banner
   #>

   ## Create Data Table for output
   $MajorVersion = [int]$OSVersion.split(".")[0]
   $mytable = New-Object System.Data.DataTable
   $mytable.Columns.Add("ModuleName")|Out-Null
   $mytable.Columns.Add("Entrys")|Out-Null
   $mytable.Columns.Add("OS")|Out-Null
   $mytable.Columns.Add("Arch")|Out-Null
   $mytable.Columns.Add("DataBase")|Out-Null
   $mytable.Rows.Add("Sherlock",
                     "$CveDataBaseId",
                     "W$MajorVersion",
                     "$ProcessArchitecture",
                     "$CVEdataBase")|Out-Null

   ## Display Data Table
   $mytable|Format-Table -AutoSize > $Env:TMP\MyTable.log
   Get-Content -Path "$Env:TMP\MyTable.log"
   Remove-Item -Path "$Env:TMP\MyTable.log" -Force
   Start-sleep -Seconds 2
}

function Get-Unquoted {

   <#
   .SYNOPSIS
      Author: r00t-3xp10it
      Find Unquoted service vulnerable paths (EoP)

   .NOTES
      This function searchs for Unquoted service vuln paths.
      Remark: Its required an 'exe-service' (msfvenom) payload
      to successfuly exploit Unquoted service paths vulnerability.

   .EXAMPLE
      PS C:\> Get-Unquoted
      Find Unquoted service vulnerable paths (EoP vulnerability)
   #>

   ## Create Data Table for output
   $MajorVersion = [int]$OSVersion.split(".")[0]
   $mytable = New-Object System.Data.DataTable
   $mytable.Columns.Add("ModuleName")|Out-Null
   $mytable.Columns.Add("OS")|Out-Null
   $mytable.Columns.Add("Arch")|Out-Null
   $mytable.Columns.Add("SearchFor")|Out-Null
   $mytable.Rows.Add("Sherlock",
                     "W$MajorVersion",
                     "$ProcessArchitecture",
                     "UnquotedPaths")|Out-Null

   ## Display Data Table
   $mytable|Format-Table -AutoSize > $Env:TMP\MyTable.log
   Get-Content -Path "$Env:TMP\MyTable.log"
   Remove-Item -Path "$Env:TMP\MyTable.log" -Force


   ## Search for Unquoted service paths (StartMode = Auto StartName = LocalSystem)
   gwmi -class Win32_Service -Property Name,DisplayName,PathName,StartMode,StartName|Where {
         $_.StartMode -eq "Auto" -and $_.StartName -eq 'LocalSystem' -and $_.PathName -NotLike "C:\Windows*" -and $_.PathName -NotMatch '"*"'
      }|Select PathName,Name > $Env:TMP\GetPaths.log
   If(Test-Path -Path "$Env:TMP\GetPaths.log" -EA SilentlyContinue){
      Get-Content -Path "$Env:TMP\GetPaths.log"
      Remove-Item -path "$Env:TMP\GetPaths.log" -Force
      Start-Sleep -Seconds 2
   }
}

function Get-Paths {
[int]$Count = 0 ## Loop counter

   <#
   .SYNOPSIS
      Author: r00t-3xp10it
      Find weak Directory permissions (EoP)

   .EXAMPLE
      PS C:\> Get-Paths
      Search recursive for folders with Everyone:(F) permissions

   .EXAMPLE
      PS C:\> Get-Paths Modify
      SYNTAX: Get-Paths <FileSystemRigths>
      Get-Paths 1º arg accepts Everyone:(FileSystemRigths) value.

   .EXAMPLE
      PS C:\> Get-Paths FullControl BUILTIN\Users
      Get-Paths 2º arg accepts the Group Name (Everyone|BUILTIN\Users)
      REMARK: Use double quotes if Group Name contains any empty spaces in Name
   #>

   ## Search for weak directory permissions
   $param1 = $args[0] ## User Imput => FileSystemRights (ReadAndExecute)
   $param2 = $args[1] ## User Imput => Group Name (BUILTIN\Users)
   If($param1 -ieq $null){$param1 = "FullControl"}## Default FileSystemRights value
   If($param2 -ieq $null){$param2 = "Everyone"}## Default Group Name value

      ## Escaping backslash's and quotes because of:
      # NT AUTHORITY\INTERACTIVE empty spaces in User Imputs
      If($param2 -Match '"' -and $param2 -Match '\\'){
         $UserGroup = $param2 -replace '\\','\\' -replace '"',''
      }ElseIf($param2 -Match '\\'){
         $UserGroup = $param2 -replace '\\','\\'
      }ElseIf($param2 -Match '"'){
         $UserGroup = $param2 -replace '"',''
      }Else{## Group Name without backslash's
         $UserGroup = $param2  
      }

      ## Create Data Table for output
      $MajorVersion = [int]$OSVersion.split(".")[0]
      $mytable = New-Object System.Data.DataTable
      $mytable.Columns.Add("ModuleName")|Out-Null
      $mytable.Columns.Add("OS")|Out-Null
      $mytable.Columns.Add("Arch")|Out-Null
      $mytable.Columns.Add("SearchDACL")|Out-Null
      $mytable.Columns.Add("GroupName")|Out-Null
      $mytable.Rows.Add("Sherlock",
                        "W$MajorVersion",
                        "$ProcessArchitecture",
                        "$param1",
                        "$param2")|Out-Null

      ## Display Data Table
      $mytable|Format-Table -AutoSize > $Env:TMP\MyTable.log
      Get-Content -Path "$Env:TMP\MyTable.log"
      Remove-Item -Path "$Env:TMP\MyTable.log" -Force

      ## Directorys to search recursive: $Env:PROGRAMFILES, ${Env:PROGRAMFILES(x86)}, $Env:LOCALAPPDATA\Programs\
      $dAtAbAsEList = Get-ChildItem  -Path "$Env:PROGRAMFILES", "${Env:PROGRAMFILES(x86)}", "$Env:LOCALAPPDATA\Programs\" -Recurse -ErrorAction SilentlyContinue -Force|Where { $_.PSIsContainer }|Select -ExpandProperty FullName
      ForEach($Token in $dAtAbAsEList){## Loop truth Get-ChildItem Items (Paths)
         If(-not($Token -Match 'WindowsApps')){## Exclude => WindowsApps folder [UnauthorizedAccessException]
            $IsInHerit = (Get-Acl "$Token").Access.IsInherited|Select -First 1
            (Get-Acl "$Token").Access|Where {## Search for Everyone:(F) folder permissions (default)
               $CleanOutput = $_.FileSystemRights -Match "$param1" -and $_.IdentityReference -Match "$UserGroup" ## <-- In my system the IdentityReference is: 'Todos'
               If($CleanOutput){$Count++ ##  Write the Table 'IF' found any vulnerable permissions
                  Write-Host "`nVulnId            : ${Count}::ACL (Mitre T1222)"
                  Write-Host "FolderPath        : $Token" -ForegroundColor Yellow
                  Write-Host "FileSystemRights  : $param1"
                  Write-Host "IdentityReference : $UserGroup"
                  Write-Host "IsInherited       : $IsInHerit"
               }
            }## End of Get-Acl loop
         }## End of Exclude WindowsApps
      }## End of ForEach loop

   Write-Host "`n`nWeak Directory Permissions"
   Write-Host "--------------------------"
   If(-not($Count -gt 0) -or $Count -ieq $null){## Weak directorys permissions report banner
      Write-Host "None directorys found with '${UserGroup}:($param1)' permissions!" -ForegroundColor Red -BackgroundColor Black
   }Else{
      Write-Host "Found $Count directorys with '${UserGroup}:($param1)' permissions!"  -ForegroundColor Green -BackgroundColor Black
   }
   Write-Host "";Start-Sleep -Seconds 2
}

function Get-RegPaths {
[int]$Count = 0 ## Loop counter

   <#
   .SYNOPSIS
      Author: r00t-3xp10it
      Find Weak Services Registry Permissions (EoP)

   .EXAMPLE
      PS C:\> Get-RegPaths
      Find Weak Services Registry Permissions Everyone:(F)

   .EXAMPLE
      PS C:\> Get-RegPaths BUILTIN\Users
      Get-RegPaths arg accepts the Group Name (Everyone|BUILTIN\Users)
      REMARK: Use double quotes if Group Name contains any empty spaces in Name
   #>

   ## Var declarations
   $UserImput = $args[0]
   If(-not($UserImput)){$UserImput = "Everyone"}
   ## Escaping backslash's and quotes because of:
   # NT AUTHORITY\INTERACTIVE empty spaces in User Imputs
   If($UserImput -Match '"' -and $UserImput -Match '\\'){
      $UserGroup = "$UserImput" -replace '\\','\\' -replace '"',''
   }ElseIf($UserImput -Match '\\'){
      $UserGroup = "$UserImput" -replace '\\','\\'
   }ElseIf($UserImput -Match '"'){
      $UserGroup = "$UserImput" -replace '"',''
   }Else{## Group Name without backslash's
      $UserGroup = "$UserImput"  
   }
   
   ## Create Data Table for output
   $MajorVersion = [int]$OSVersion.split(".")[0]
   $mytable = New-Object System.Data.DataTable
   $mytable.Columns.Add("ModuleName")|Out-Null
   $mytable.Columns.Add("OS")|Out-Null
   $mytable.Columns.Add("Arch")|Out-Null
   $mytable.Columns.Add("SrvPermissions")|Out-Null
   $mytable.Columns.Add("GroupName")|Out-Null
   $mytable.Rows.Add("Sherlock",
                     "W$MajorVersion",
                     "$ProcessArchitecture",
                     "FullControl",
                     "$UserGroup")|Out-Null

   ## Display Data Table
   $mytable|Format-Table -AutoSize > $Env:TMP\MyTable.log
   Get-Content -Path "$Env:TMP\MyTable.log"
   Remove-Item -Path "$Env:TMP\MyTable.log" -Force


   Start-Sleep -Seconds 1
   ## Get ALL services under HKLM hive key
   $GetPath = (Get-Acl -Path "HKLM:\SYSTEM\CurrentControlSet\services\*" -EA SilentlyContinue).PSPath
   $ParseData = $GetPath -replace 'Microsoft.PowerShell.Core\\Registry::HKEY_LOCAL_MACHINE\\','HKLM:\'
   ForEach($Token in $ParseData){## Loop truth $ParseData services database List
      $IsInHerit = (Get-Acl -Path "$Token").Access.IsInherited|Select -First 1
      $CleanOutput = (Get-Acl -Path "$Token").Access|Where {## Search for Everyone:(F) registry service permissions (default)
         $_.IdentityReference -Match "$UserGroup" -and $_.RegistryRights -Match 'FullControl' -and $_.IsInherited -Match 'False'
      }
      If($CleanOutput){$Count++ ##  Write the Table 'IF' found any vulnerable permissions
         Write-Host "`nVulnId            : ${Count}::SRV"
         Write-Host "RegistryPath      : $Token" -ForegroundColor Yellow
         Write-Host "IdentityReference : $UserGroup"
         Write-Host "RegistryRights    : FullControl"
         Write-Host "AccessControlType : Allow"
         Write-Host "IsInherited       : $IsInHerit"
      }
   }

   Write-Host "`n`nWeak Services Registry Permissions"
   Write-Host "----------------------------------"
   If(-not($Count -gt 0) -or $Count -ieq $null){## Weak directorys permissions report banner
      Write-Host "None registry services found with '${UserGroup}:(FullControl)' permissions!" -ForegroundColor Red -BackgroundColor Black
   }Else{
      Write-Host "Found $Count registry services with '${UserGroup}:(FullControl)' permissions!" -ForegroundColor Green -BackgroundColor Black
   }
   Start-Sleep -Seconds 2;Write-Host ""
}

function Get-ModifiableRegPaths {


    <#
    .SYNOPSIS
       Author: @itm4n|@r00t-3xp10it
       Helper - Checks the permissions of a given registry key
       and returns the ones that the current user can modify.
    
    .DESCRIPTION
       Any registry path that the current user has modification rights
       on is returned in a custom object that contains the modifiable path,
       associated permission set, and the IdentityReference with the specified
       rights. The SID of the current user and any group he/she are a part of
       are used as the comparison set against the parsed path DACLs.
    
    .EXAMPLE
       PS C:\> Get-ModifiableRegPaths

    .OUTPUTS
       Name              : VulnService
       ImagePath         : C:\APPS\MyApp\service.exe
       User              : NT AUTHORITY\NetworkService
       ModifiablePath    : HKLM:\SYSTEM\CurrentControlSet\Services\VulnService
       IdentityReference : NT AUTHORITY\INTERACTIVE
       Permissions       : ReadControl, AppendData/AddSubdirectory, ReadExtendedAttributes, ReadData/ListDirectory
       Status            : Running
       UserCanStart      : True
       UserCanRestart    : False
    #>

    BEGIN {

    If($IsClientAdmin){## This module cant not run under admin privs
       write-host "[error] This module cant not run under administrator privs!" -ForegroundColor Red -BackgroundColor Black
       Write-Host "";Start-Sleep -Seconds 1

       ## Create Data Table for output
       $MajorVersion = [int]$OSVersion.split(".")[0]
       $mytable = New-Object System.Data.DataTable
       $mytable.Columns.Add("ModuleName")|Out-Null
       $mytable.Columns.Add("OS")|Out-Null
       $mytable.Columns.Add("Arch")|Out-Null
       $mytable.Columns.Add("SearchFor")|Out-Null
       $mytable.Rows.Add("Sherlock",
                         "W$MajorVersion",
                         "$ProcessArchitecture",
                         "ModifiableRegPaths")|Out-Null

       ## Display Data Table
       $mytable|Format-Table -AutoSize > $Env:TMP\MyTable.log
       Get-Content -Path "$Env:TMP\MyTable.log"
       Remove-Item -Path "$Env:TMP\MyTable.log" -Force

        # from http://stackoverflow.com/questions/28029872/retrieving-security-descriptor-and-getting-number-for-filesystemrights
        $AccessMask = @{
            [uint32]'0x80000000' = 'GenericRead'
            [uint32]'0x40000000' = 'GenericWrite'
            [uint32]'0x20000000' = 'GenericExecute'
            [uint32]'0x10000000' = 'GenericAll'
            [uint32]'0x02000000' = 'MaximumAllowed'
            [uint32]'0x01000000' = 'AccessSystemSecurity'
            [uint32]'0x00100000' = 'Synchronize'
            [uint32]'0x00080000' = 'WriteOwner'
            [uint32]'0x00040000' = 'WriteDAC'
            [uint32]'0x00020000' = 'ReadControl'
            [uint32]'0x00010000' = 'Delete'
            [uint32]'0x00000100' = 'WriteAttributes'
            [uint32]'0x00000080' = 'ReadAttributes'
            [uint32]'0x00000040' = 'DeleteChild'
            [uint32]'0x00000020' = 'Execute/Traverse'
            [uint32]'0x00000010' = 'WriteExtendedAttributes'
            [uint32]'0x00000008' = 'ReadExtendedAttributes'
            [uint32]'0x00000004' = 'AppendData/AddSubdirectory'
            [uint32]'0x00000002' = 'WriteData/AddFile'
            [uint32]'0x00000001' = 'ReadData/ListDirectory'
        }
        $UserIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $CurrentUserSids = $UserIdentity.Groups | Select-Object -ExpandProperty Value
        $CurrentUserSids += $UserIdentity.User.Value
        $TranslatedIdentityReferences = @{}
    }

    PROCESS {
        [string]$Path = "HKLM:\SYSTEM\CurrentControlSet\Services\*"
        $KeyAcl = Get-Acl -Path $Path -ErrorAction SilentlyContinue -ErrorVariable GetAclError
        If(-not $GetAclError){
            $KeyAcl|Select-Object -ExpandProperty Access|Where-Object {($_.AccessControlType -Match 'Allow')}|ForEach-Object {

                $RegistryRights = $_.RegistryRights.value__
                $Permissions = $AccessMask.Keys|Where-Object { $RegistryRights -band $_ }|ForEach-Object { $accessMask[$_] }
                # the set of permission types that allow for modification
                $Comparison = Compare-Object -ReferenceObject $Permissions -DifferenceObject @('GenericWrite', 'GenericAll', 'MaximumAllowed', 'WriteOwner', 'WriteDAC', 'WriteData/AddFile', 'AppendData/AddSubdirectory') -IncludeEqual -ExcludeDifferent
                If($Comparison){
                    If($_.IdentityReference -NotMatch '^S-1-5.*'){
                        If(-not($TranslatedIdentityReferences[$_.IdentityReference])){
                            # translate the IdentityReference if it's a username and not a SID
                            $IdentityUser = New-Object System.Security.Principal.NTAccount($_.IdentityReference)
                            $TranslatedIdentityReferences[$_.IdentityReference] = $IdentityUser.Translate([System.Security.Principal.SecurityIdentifier]) | Select-Object -ExpandProperty Value
                        }
                        $IdentitySID = $TranslatedIdentityReferences[$_.IdentityReference]
                    }Else{
                        $IdentitySID = $_.IdentityReference
                    }
                    If($CurrentUserSids -Contains $IdentitySID){
                       $State = $True ## Mark that we have found a vulnerable service
                       $ParseData = $Path -replace '{Microsoft.PowerShell.Core\\Registry::HKEY_LOCAL_MACHINE','HKLM:' -replace '}',''
                       $parsePerm = $Permissions -replace '{','' -replace '}',''
                        New-Object -TypeName PSObject -Property @{
                            ModifiablePath = $ParseData
                            IdentityReference = $_.IdentityReference
                            Permissions = $parsePerm
                        }
                    }
                }
            }
        }
        If(-not($State)){## None vuln Service registry found
           Write-Host "`n`nModifiable Registry Service Paths"
           Write-Host "---------------------------------"
           write-host "None Service Insecure Registry Permissions Found!" -ForegroundColor Red -BackgroundColor Black
        }
        Write-Host ""
    }
  }## This module cant not run under admin privs
}

function Get-Rotten {
[int]$Count = 0 ## Loop counter

   <#
   .SYNOPSIS
      Author: r00t-3xp10it
      Find Rotten Potato vulnerable settings (EoP)

   .NOTES
      Rotten Potato tests can 'NOT' run under Admin privs

   .EXAMPLE
      PS C:\> Get-Rotten
      Find Rotten Potato vuln privilege settings (EoP)
   #>

   ## Create Data Table for output
   $MajorVersion = [int]$OSVersion.split(".")[0]
   $mytable = New-Object System.Data.DataTable
   $mytable.Columns.Add("ModuleName")|Out-Null
   $mytable.Columns.Add("OS")|Out-Null
   $mytable.Columns.Add("Arch")|Out-Null
   $mytable.Columns.Add("SearchFor")|Out-Null
   $mytable.Rows.Add("Sherlock",
                     "W$MajorVersion",
                     "$ProcessArchitecture",
                     "RottenPotato")|Out-Null

   ## Display Data Table
   $mytable|Format-Table -AutoSize > $Env:TMP\MyTable.log
   Get-Content -Path "$Env:TMP\MyTable.log"
   Remove-Item -Path "$Env:TMP\MyTable.log" -Force

   ## Make sure we are NOT running tests under Administrator privs
   $IsClientAdmin = [bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -Match "S-1-5-32-544")
   If(-not($IsClientAdmin)){## Running tests Under UserLand Privileges => OK

      $ListPrivsDb = whoami /priv|findstr /V "PRIVILEGES INFORMATION -----"
      ## Display privileges List onscreen
      echo $ListPrivsDb > "$Env:TMP\ListPrivsDb.txt"
      Get-Content -Path "$Env:TMP\ListPrivsDb.txt"
      Remove-Item -Path "$Env:TMP\ListPrivsDb.txt" -Force

      ## Search for vulnerable settings in command output to build LogFile
      # MyLocalVulnTest: whoami /priv|findstr /C:"SeChangeNotifyPrivilege" > $Env:TMP\DCprivs.log
      whoami /priv|findstr /C:"SeImpersonatePrivilege" /C:"SeAssignPrimaryPrivilege" /C:"SeTcbPrivilege" /C:"SeBackupPrivilege" /C:"SeRestorePrivilege" /C:"SeCreateTokenPrivilege" /C:"SeLoadDriverPrivilege" /C:"SeTakeOwnershipPrivilege" /C:"SeDebugPrivileges" > $Env:TMP\DCprivs.log
      $CheckVulnSet = Get-Content -Path "$Env:TMP\DCprivs.log"|findstr /I /C:"Enabled"
      ForEach($Item in $CheckVulnSet){## Id every vulnerable settings found
         $Count++
      }

      Write-Host "`n`nRotten Potato Vulnerability"
      Write-Host "---------------------------";Start-Sleep -Seconds 1
      If($CheckVulnSet){## Check if there are vulnerable settings to report them
         Write-Host "Found $Count Rotten Potato Vulnerable Setting(s)" -ForegroundColor Green -BackgroundColor Black
         Write-Host "----------------------------- --------------------------------------------- --------"
         Get-Content "$Env:TMP\DCprivs.log"|findstr /I /C:"Enabled";remove-item "$Env:TMP\DCprivs.log" -Force
      }Else{
         Write-Host "None Rotten Potato vulnerable settings found under current system!" -ForegroundColor Red -BackgroundColor Black
      }

   }Else{## Rotten Potato can NOT run under Admin privs
      Write-Host "`n`nRotten Potato Vulnerability"
      Write-Host "---------------------------";Start-Sleep -Seconds 1
      Write-Host "Rotten Potato tests can NOT run under Administrator privileges!" -ForegroundColor Red -BackgroundColor Black
   }

   ## Clean old LogFiles
   If(Test-Path -Path "$Env:TMP\DCprivs.log"){remove-item "$Env:TMP\DCprivs.log" -Force}
   Start-Sleep -Seconds 2;Write-Host ""
}

function Get-HotFixs {
$KBDataEntrys = "null"
[int]$Count = 0 ## Loop counter

   <#
   .SYNOPSIS
      Author: r00t-3xp10it
      Find missing KB security packages

   .NOTES
      Sherlock KB tests will compare installed KB
      Id patches againts Sherlock $dATAbASE Id list
      Special thanks to @youhacker55 (W7 x64 database)
      Special thanks to @TroyDTaylor (W8 x64 database)

   .EXAMPLE
      PS C:\> Get-HotFixs
      Find missing security KB packages (HotFix Id)
   #>

   ## Variable declarations
   $MajorVersion = [int]$OSVersion.split(".")[0]
   $CPUArchitecture = (Get-WmiObject Win32_OperatingSystem).OSArchitecture

   ## Number of KB's entrys (db)
   If($MajorVersion -eq "vista"){
      $KBDataEntrys = "16"        ## Credits: @r00t-3xp10it (fully patch)
      $KB_dataBase = "23/12/2020" ## KB entrys database last update date
   }ElseIf($MajorVersion -eq '7' -and $CPUArchitecture -eq "64 bits"){
      $KBDataEntrys = "102"       ## Credits: @youhacker55 (fully patch)
      $KB_dataBase = "25/12/2020" ## KB entrys database last update date
   }ElseIf($MajorVersion -eq '7' -and $CPUArchitecture -eq "32 bits"){
      $KBDataEntrys = "16"        ## <-- TODO: confirm
      $KB_dataBase = "23/12/2020" ## KB entrys database last update date
   }ElseIf($MajorVersion -eq '8'){
      $KBDataEntrys = "44"        ## Credits: @TroyDTaylor (fully patch)
      $KB_dataBase = "06/01/2021" ## KB entrys database last update date
   }ElseIf($MajorVersion -eq '10' -and $CPUArchitecture -eq "64 bits"){
      $KBDataEntrys = "19"        ## Credits: @r00t-3xp10it (fully patch)
      $KB_dataBase = "13/01/2021" ## KB entrys database last update date
   }

   ## Create Data Table for output
   $mytable = New-Object System.Data.DataTable
   $mytable.Columns.Add("ModuleName")|Out-Null
   $mytable.Columns.Add("Entrys")|Out-Null
   $mytable.Columns.Add("OS")|Out-Null
   $mytable.Columns.Add("Arch")|Out-Null
   $mytable.Columns.Add("DataBase")|Out-Null
   $mytable.Rows.Add("Sherlock",
                     "$KBDataEntrys",
                     "W$MajorVersion",
                     "$ProcessArchitecture",
                     "$KB_dataBase")|Out-Null

   ## Display Data Table
   $mytable|Format-Table -AutoSize > $Env:TMP\MyTable.log
   Get-Content -Path "$Env:TMP\MyTable.log"
   Remove-Item -Path "$Env:TMP\MyTable.log" -Force

   ## Generates List of installed HotFixs
   $GetKBId = (Get-HotFix).HotFixID

   ## Sherlock $dATAbASE Lists
   # Supported versions: Windows (vista|7|8|8.1|10)
   If($MajorVersion -eq 10){## Windows 10
      If($CPUArchitecture -eq "64 bits" -or $ProcessArchitecture -eq "AMD64"){
         $dATAbASE = @(## Windows 10 x64 bits
            "KB4586878","KB4497165","KB4515383","KB4516115",
            "KB4517245","KB4521863","KB4524569","KB4528759",
            "KB4535680","KB4537759","KB4538674","KB4541338",
            "KB4552152","KB4559309","KB4560959","KB4561600",
            "KB4580325","KB4598479","KB4598229"#"KB3245007", ## Fake KB entry for debug
         )
      }Else{## Windows 10 x32 bits
         $dATAbASE = "Not supported under W$MajorVersion ($CPUArchitecture) architecture"
         $bypassTest = "True" ## Architecture 'NOT' supported by this test
      }
   }ElseIf($MajorVersion -eq 8){## Windows (8|8.1)
      If($CPUArchitecture -eq "64 bits" -or $ProcessArchitecture -eq "AMD64"){
         $dATAbASE = @(## Windows 8.1 x64 bits (@TroyDTaylor)
            "KB2920189","KB2931358","KB2931366","KB2949621","KB2961072","KB2976627",
            "KB2977629","KB2987107","KB3003057","KB3004545","KB3019978","KB3035126",
            "KB3045685","KB3045999","KB3046017","KB3046737","KB3059317","KB3061512",
            "KB3062760","KB3071756","KB3076949","KB3084135","KB3086255","KB3109103",
            "KB3109560","KB3110329","KB3126434","KB3126587","KB3138910","KB3138962",
            "KB3139398","KB3139914","KB3146723","KB3155784","KB3156059","KB3159398",
            "KB3161949","KB3172729","KB3175024","KB3178539","KB3187754","KB4566425",
            "KB4580325","KB4592484"
         )
      }Else{## Windows 8.1 x32 bits
         $dATAbASE = "Not supported under W$MajorVersion ($CPUArchitecture) architecture"
         $bypassTest = "True" ## Architecture 'NOT' supported by this test
      }
   }ElseIf($MajorVersion -eq 7){## Windows 7
      If($CPUArchitecture -eq "64 bits" -or $ProcessArchitecture -eq "AMD64"){
         $dATAbASE = @(## Windows 7 x64 bits (@youhacker55 KB List)
            "KB2479943","KB2491683","KB2506212","KB2560656","KB2564958","KB2579686",
            "KB2585542","KB2604115","KB2620704","KB2621440","KB2631813","KB2653956",
            "KB2654428","KB2656356","KB2667402","KB2685939","KB2690533","KB2698365",
            "KB2705219","KB2706045","KB2727528","KB2729452","KB2736422","KB2742599",
            "KB2758857","KB2770660","KB2789645","KB2807986","KB2813430","KB2840631",
            "KB2847927","KB2861698","KB2862330","KB2862335","KB2864202","KB2868038",
            "KB2871997","KB2884256","KB2893294","KB2894844","KB2900986","KB2911501",
            "KB2931356","KB2937610","KB2943357","KB2968294","KB2972100","KB2972211",
            "KB2973112","KB2973201","KB2977292","KB2978120","KB2978742","KB2984972",
            "KB2991963","KB2992611","KB3004375","KB3010788","KB3011780","KB3019978",
            "KB3021674","KB3023215","KB3030377","KB3031432","KB3035126","KB3037574",
            "KB3045685","KB3046017","KB3046269","KB3055642","KB3059317","KB3060716",
            "KB3067903","KB3071756","KB3072305","KB3074543","KB3075220","KB3086255",
            "KB3092601","KB3093513","KB3097989","KB3101722","KB3108371","KB3108664",
            "KB3109103","KB3109560","KB3110329","KB3115858","KB3122648","KB3124275",
            "KB3126587","KB3127220","KB3138910","KB3139398","KB3139914","KB3150220",
            "KB3155178","KB3156016","KB3159398","KB3161949","KB4474419","KB4054518"
         )
      }Else{
         $dATAbASE = @(## Windows 7 x32 bits
            "KB4033342","KB4078130","KB4074906",
            "KB3186497","KB4020513","KB4020507",
            "KB4020503","KB3216523","KB3196686",
            "KB3083186","KB3074233","KB3074230",
            "KB3037581","KB3035490","KB3023224",
            "KB2979578"
         )
      }
   }ElseIf($MajorVersion -eq "Vista"){
      $dATAbASE = @(## Windows Vista x32/x64 bits
         "KB3033890","KB3045171","KB3046002",
         "KB3050945","KB3051768","KB3055642",
         "KB3057839","KB3059317","KB3061518",
         "KB3063858","KB3065979","KB3067505",
         "KB3067903","KB3069392","KB3070102",
         "KB3072630"
      )
  }Else{
     $dATAbASE = "Not supported under W$MajorVersion ($CPUArchitecture) systems"
     $bypassTest = "True" ## Operative System Flavor 'NOT' supported by this test
  }

   ## Put Installed KB Id patches into an array list
   [System.Collections.ArrayList]$LocalKBLog = $GetKBId
   Write-Host "Id HotFixID   Status     VulnState"
   Write-Host "-- ---------  ---------  ---------"

   ## Compare the two KB Lists
   ForEach($KBkey in $dATAbASE){
      Start-Sleep -Milliseconds 500
      If(-not($LocalKBLog -Match $KBkey)){$Count++
         If($bypassTest -eq "True"){## Operative System OR Arch NOT supported output
            Write-Host "$Count  <$KBkey>" -ForeGroundColor Red -BackGroundColor Black
            Start-Sleep -Milliseconds 200
         }Else{## KB security Patch not found output (not patched)
            Write-Host "$Count  $KBkey  <Missing>  <NotFound>" -ForeGroundColor Red -BackGroundColor Black
            Start-Sleep -Milliseconds 200
         }
      }Else{## KB security Patch found output (patched)
         Write-Host "+  $KBkey  Installed  Patched" -ForeGroundColor Green
      }
   }
   Start-Sleep -Seconds 2;Write-Host ""
}

function Get-DllHijack {

   <#
   .SYNOPSIS
      Author: r00t-3xp10it|@Adam_Kramer
      Find service DLL's prone to Hijacking

   .NOTES
      dll_hijack_detect_x64.exe created by @Adam_Kramer
      https://github.com/adamkramer/dll_hijack_detect

   .EXAMPLE
      PS C:\> Get-DllHijack
      Find DLL's prone to hijacking (EoP).

   .EXAMPLE
      PS C:\> Get-DllHijack EnvPaths
      Checks if the current %PATH% has any directories
      that Migth be writeable (W) by the current user.
   #>

   Write-Host ""
   ## Create Data Table for output
   $MajorVersion = [int]$OSVersion.split(".")[0]
   $mytable = New-Object System.Data.DataTable
   $mytable.Columns.Add("ModuleName")|Out-Null
   $mytable.Columns.Add("OS")|Out-Null
   $mytable.Columns.Add("Arch")|Out-Null
   $mytable.Columns.Add("SearchFor")|Out-Null
   $mytable.Rows.Add("Sherlock",
                     "W$MajorVersion",
                     "$ProcessArchitecture",
                     "DLL-Hijack")|Out-Null

   ## Display Data Table
   $mytable|Format-Table -AutoSize > $Env:TMP\MyTable.log
   Get-Content -Path "$Env:TMP\MyTable.log"
   Remove-Item -Path "$Env:TMP\MyTable.log" -Force
   Start-sleep -Seconds 2


   ## User Imputs
   $ModuleSelection = $args[0]
   If($ModuleSelection -ieq "EnvPaths"){## Finds all %PATH% .DLL hijacking opportunities.

      <#
      .SYNOPSIS
         Phantom DLL hijacking
         Checks if the current %PATH% has any directories
         that are writeable (W) by the current user.

       .EXAMPLE
          PS C:\> Get-DllHijack EnvPaths
          Finds all %PATH% .DLL hijacking opportunities. 
      #>

      ## Variable declarations
      $OrigError = $ErrorActionPreference
      $ErrorActionPreference = "SilentlyContinue"
      $Paths = (Get-Item Env:Path).value.split(';')|Where-Object {$_ -ne ""}

      ForEach($Path in $Paths){
         $Path = $Path.Replace('"',"")
         If(-not $Path.EndsWith("\")){
            $Path = $Path + "\"
         }

      ## reference - http://stackoverflow.com/questions/9735449/how-to-verify-whether-the-share-has-write-access
      # This function writes a random file on $Path to test if user as 'Write (W)' privileges on $Path
      $TestPath = Join-Path $Path ([IO.Path]::GetRandomFileName())

      ## if the path doesn't exist
      # try to create the folder before testing it for write
      if(-not $(Test-Path -Path $Path)){
         try {
            ## try to create the folder
            $Null = New-Item -ItemType directory -Path $Path
            echo $Null > $TestPath
            $Out = New-Object PSObject
            $Out|Add-Member Noteproperty 'Permissions' 'Write'
            $Out|Add-Member Noteproperty 'HijackablePath' $Path
            $Out #|Format-Table -AutoSize
         }
         catch {}
         finally {
            ## remove the directory
            Remove-Item -Path $Path -Recurse -Force -ErrorAction SilentlyContinue
         }
      }
      Else{
         try {
            ## if the folder already exists
            echo $Null > $TestPath
            $Out = New-Object PSObject
            $Out|Add-Member Noteproperty 'Permissions' 'Write'
            $Out|Add-Member Noteproperty 'HijackablePath' $Path
            $Out #|Format-Table -AutoSize
         }
         catch {} 
         finally {
            ## Try to remove the item again just to be safe
            Remove-Item $TestPath -Force -ErrorAction SilentlyContinue
         }
      }
   }
   Start-Sleep -Seconds 2
    
   }Else{## dll_hijack_detect_x64.exe by @Adam_Kramer

      <#
      .SYNOPSIS
         Author: r00t-3xp10it
         Find service DLL's prone to Hijacking

      .NOTES
         dll_hijack_detect_x64.exe created by @Adam_Kramer
         https://github.com/adamkramer/dll_hijack_detect

      .EXAMPLE
         PS C:\> Get-DllHijack
         Find service DLL's prone to Hijacking (DLL-Hijack) 
      #>

      ## Variable declarations
      $Architecture = Get-Architecture
      $ArchBuildBits = $Architecture[0]
      If($ArchBuildBits -eq "64 bits"){## Download x64 binary
        $ArchiveName = "dll_hijack_detect_x64"
        $limmitKbytes = "26" ## Archive is: 26,9130859375/KB
      }Else{## Download x86 binary
        $ArchiveName = "dll_hijack_detect_x86"
        $limmitKbytes = "5" ## Archive is: 5,6396484375/KB
      }

      ## Download dll_hijack_detect.zip (x86|x64) archive from my GitHub repository
      # Repository: https://github.com/r00t-3xp10it/venom/blob/master/bin/dll_hijack_detect_x64.zip
      Start-BitsTransfer -priority foreground -Source https://raw.githubusercontent.com/r00t-3xp10it/venom/master/bin/${ArchiveName}.zip -Destination $Env:TMP\${ArchiveName}.zip -ErrorAction SilentlyContinue|Out-Null   
 
      ## Check for Failed/Corrupted archive download
      If(Test-Path -Path "$Env:TMP\${ArchiveName}.zip"){
         $SizeDump = ((Get-Item "$Env:TMP\${ArchiveName}.zip" -EA SilentlyContinue).length/1KB)
         If($SizeDump -lt $limmitKbytes){## Archive corrupted detected
            Write-Host "`n`nDll Hijacking"
            Write-Host "-------------";Start-Sleep -Seconds 1
            Write-Host "[corrupted] Fail to download '${ArchiveName}.zip' archive ($SizeDump/KB)" -ForegroundColor Red -BackgroundColor Black
            Start-Sleep -Seconds 1
         }Else{## Remote execute dll_hijack_detect.exe binary
            ## De-Compress dll_hijack_detect Archive into $Env:TMP remote directory
            Expand-Archive -LiteralPath "$Env:TMP\${ArchiveName}.zip" -DestinationPath "$Env:TMP" -Force

            <#
            .SYNOPSIS
               run an executable and display output on terminal console
               Credits: https://stackoverflow.com/questions/1673967/
               how-to-run-an-exe-file-in-powershell-with-parameters-with-spaces-and-quotes
            #>

            &"$Env:TMP\$ArchiveName.exe" /unsigned
            ## Remove Old files/binary from remote host
            Remove-Item -Path "$Env:TMP\${ArchiveName}.zip" -Force
            Remove-Item -Path "$Env:TMP\${ArchiveName}.exe" -Force
         }
      }Else{## Fail Archive download detected
         Write-Host "`n`nDll Hijacking"
         Write-Host "-------------";Start-Sleep -Seconds 1
         Write-Host "[Fail] Fail to download '${ArchiveName}.zip' archive" -ForegroundColor Red -BackgroundColor Black
         Start-Sleep -Seconds 1
      }## End of Check for Corrupted downloads
   }## End of EnvPaths argument
   Start-Sleep -Seconds 2;Write-Host ""
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

    ## r00t-3xp10it update (v1.3.4)
    $Global:ExploitTable.Rows.Add("ws2ifsl.sys Use After Free Elevation of Privileges","N/A","2019-1215","https://www.exploit-db.com/exploits/47935")
    $Global:ExploitTable.Rows.Add("Win32k Uninitialized Variable Elevation of Privileges","N/A","2019-1458","https://packetstormsecurity.com/files/159569/Microsoft-Windows-Uninitialized-Variable-Local-Privilege-Escalation.html")
    $Global:ExploitTable.Rows.Add("checkmk Local Elevation of Privileges","N/A","2020-005","https://tinyurl.com/ycrgjxec")
    $Global:ExploitTable.Rows.Add("Win32k Elevation of Privileges","MS13-036","2020-0624","https://tinyurl.com/ybpz7k6y")
    $Global:ExploitTable.Rows.Add("Win32k Elevation of Privileges","N/A","2020-0642","https://packetstormsecurity.com/files/158729/Microsoft-Windows-Win32k-Privilege-Escalation.html")
    $Global:ExploitTable.Rows.Add("Microsoft Spooler Local Elevation of Privileges","MS69-134","CVE-2020-1048","https://0day.today/exploit/34948")
    $Global:ExploitTable.Rows.Add("DrawIconEx Win32k Elevation of Privileges","N/A","2020-1054","https://packetstormsecurity.com/files/160515/Microsoft-Windows-DrawIconEx-Local-Privilege-Escalation.html")
    $Global:ExploitTable.Rows.Add("Druva inSync Local Elevation of Privileges","N/A","2020-5752","https://packetstormsecurity.com/files/160404/Druva-inSync-Windows-Client-6.6.3-Privilege-Escalation.html")
    $Global:ExploitTable.Rows.Add("Pulse Secure Client Local Elevation of Privileges","N/A","2020-13162","https://packetstormsecurity.com/files/158117/Pulse-Secure-Client-For-Windows-Local-Privilege-Escalation.html")
    $Global:ExploitTable.Rows.Add("MSI Ambient Link Driver Elevation of Privileges","N/A","2020-17382","https://www.exploit-db.com/exploits/48836")
    $Global:ExploitTable.Rows.Add("splWOW64 Local Elevation of Privileges","MS69-132","CVE-2020-17008","https://bugs.chromium.org/p/project-zero/issues/detail?id=2096")
    $Global:ExploitTable.Rows.Add("SUPREMO Local Elevation of Privileges","MS69-133","CVE-2020-25106","https://0day.today/exploit/35570")
    $Global:ExploitTable.Rows.Add("AppX Deployment Local Elevation of Privileges","MS69-134","CVE-2021-1642","https://shorturl.org/0qEkOtI")
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

   <#
   .SYNOPSIS
      Scan's for CVE's (EoP) using Sherlock $dATAbASE

   .NOTES
      Sherlock Currently looks for:
      MS10-015, MS10-092, MS13-053, MS13-081
      MS14-058, MS15-051, MS15-078, MS16-016
      MS16-032, MS16-034, MS16-135

      CVE-2017-7199, CVE-2019-1215, CVE-2019-1458
      CVE-2020-005, CVE-2020-0624, CVE-2020-0642
      CVE-2020-1048, CVE-2020-1054, CVE-2020-5752
      CVE-2020-13162, CVE-2020-17382, CVE-2020-17008
      CVE-2020-25106, CVE-2021-1642

   .EXAMPLE
      PS C:\> Find-AllVulns
   #>

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
        ## version 1.3 update
        Find-CVE20191215
        Find-CVE20191458
        Find-CVE20200624
        Find-CVE20200642
        Find-CVE20201054
        Find-CVE20205752
        Find-CVE202013162
        Find-CVE202017382
        Find-CVE2020005
        Find-CVE202017008
        Find-CVE202025106
        Find-CVE20201048
        Find-CVE20211642

        Get-Results
}

function Find-MS10015 {

    $MSBulletin = "MS10-015"
    $Architecture = Get-Architecture
    If($Architecture[0] -eq "64 bits"){
        $VulnStatus = "Not supported on 64 bits systems"
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
        $VulnStatus = "Not supported on 64 bits systems"
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
        $VulnStatus = "Not supported on 64 bits systems"
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
      $VulnStatus = "Not Vulnerable (not found)"
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
        $VulnStatus = "Not supported on 64 bits systems"
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
      Sherlock version v1.3.4 update

   .DESCRIPTION
      The next functions are related to new 2020 EOP CVE's

   .LINK
      https://www.exploit-db.com/
      https://0day.today/platforms/windows
      https://packetstormsecurity.com/files/os/windows/
   #>

# -------------------------------------------------------------------------------------------------------

function Find-CVE202025106 {

   <#
   .SYNOPSIS
      Author: r00t-3xp10it
      SUPREMO (rat) Local Privilege Escalation

   .DESCRIPTION
      CVE: 2020-25106
      MSBulletin: MS69-133
      Affected systems:
         Windows 10 (1901) x64 - 4.1.3.2348
   #>

    $CVEID = "2020-25106"
    $MSBulletin = "MS69-133"
    $Architecture = Get-Architecture
    $ArchBuildBits = $Architecture[0]
    $FilePath = ${Env:PROGRAMFILES(X86)} + "\Supremo\SupremoService.exe"

    ## Check for OS affected version/arch (Windows 10 x64 bits)
    $MajorVersion = [int]$OSVersion.split(".")[0]
    If(-not($MajorVersion -eq 10) -and $Architecture[0] -ne "64 bits"){
        $VulnStatus = "Not supported on Windows $MajorVersion ($ArchBuildBits) systems"
    }Else{
       
       $SoftwareVersion = (Get-Item "$FilePath" -EA SilentlyContinue).VersionInfo.ProductVersion
       If(-not($SoftwareVersion)){## SupremoService.exe appl not found
           $VulnStatus = "Not Vulnerable"
       }Else{

          ## Affected: =< 4.1.3.2348 Fixed: 4.2.0.2423
          $Major = [int]$SoftwareVersion.Split(".")[1]
          $Revision = $SoftwareVersion.Split(".")[3]

           switch($Major){
           1 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le 2348 ] }
           default { $VulnStatus = "Not Vulnerable" }
           }
       }
    }
    Set-ExploitTable $MSBulletin $VulnStatus
}

function Find-CVE2020005 {

   <#
   .SYNOPSIS
      Author: r00t-3xp10it
      Checkmk Local Privilege Escalation

   .DESCRIPTION
      CVE: 2020-005
      MSBulletin: N/A
      Affected systems:
         Windows 10 (1901) x64 - 1.6.0p16
   #>

    $MSBulletin = "N/A"
    $CVEID = "2020-005"
    $Architecture = Get-Architecture
    $ArchBuildBits = $Architecture[0]
    $FilePath = ${Env:PROGRAMFILES(X86)} + "\checkmk\service\Check_mk_agent.exe"

    ## Check for OS affected version/arch (Windows 10 x64 bits)
    $MajorVersion = [int]$OSVersion.split(".")[0]
    If(-not($MajorVersion -eq 10) -and $Architecture[0] -ne "64 bits"){
        $VulnStatus = "Not supported on Windows $MajorVersion ($ArchBuildBits) systems"
    }Else{
       
       $SoftwareVersion = (Get-Item "$FilePath" -EA SilentlyContinue).VersionInfo.ProductVersion
       If(-not($SoftwareVersion)){## Check_mk_agent.exe appl not found
           $VulnStatus = "Not Vulnerable"
       }Else{

          ## Affected: =< 1.6.0p16 (Windows 10 x64 bits)
          $Major = [int]$SoftwareVersion.Split(".")[1]
          $Revision = $SoftwareVersion.Split(".")[2]

           switch($Major){
           6 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le '0p16' ] }
           default { $VulnStatus = "Not Vulnerable" }
           }
       }
    }
    Set-ExploitTable $CVEID $VulnStatus
}

function Find-CVE20191215 {

   <#
   .SYNOPSIS
      Author: r00t-3xp10it
      ws2ifsl.sys Use After Free Local Privilege Escalation

   .DESCRIPTION
      CVE: 2019-1215
      MSBulletin: N/A
      Affected systems:
         Windows 10 (1901) x64 - 10.0.18362.295
   #>

    $MSBulletin = "N/A"
    $CVEID = "2019-1215"
    $Architecture = Get-Architecture
    $ArchBuildBits = $Architecture[0]
    $FilePath = $Env:WINDIR + "\System32\ntoskrnl.exe"

    ## Check for OS affected version/arch (Windows 10 x64 bits)
    $MajorVersion = [int]$OSVersion.split(".")[0]
    If(-not($MajorVersion -eq 10) -and $Architecture[0] -ne "64 bits"){
        $VulnStatus = "Not supported on Windows $MajorVersion ($ArchBuildBits) systems"
    }Else{
       
       $SoftwareVersion = (Get-Item "$FilePath" -EA SilentlyContinue).VersionInfo.ProductVersion
       If(-not($SoftwareVersion)){## ntoskrnl.exe appl not found
           $VulnStatus = "Not Vulnerable"
       }Else{

          ## Affected: =< 10.0.18362.295 (Windows 10 x64 bits)
          $Major = [int]$SoftwareVersion.Split(".")[2]
          $Revision = [int]$SoftwareVersion.Split(".")[3]

           switch($Major){
           18362 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le 295 ] }
           default { $VulnStatus = "Not Vulnerable" }
           }
       }
    }
    Set-ExploitTable $CVEID $VulnStatus
}

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
           $VulnStatus = "Not Vulnerable"
       }Else{

          ## Affected: < 10.0.14393.3383 (Windows 10)
          $Major = [int]$SoftwareVersion.Split(".")[2]
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
    $Architecture = Get-Architecture
    $ArchBuildBits = $Architecture[0]
    $FilePath = $Env:WINDIR + "\System32\Win32k.sys"

    ## Check for OS affected version (Windows 10)
    $MajorVersion = [int]$OSVersion.split(".")[0]
    If($MajorVersion -ne 10 -and $ArchBuildBits -ne "64 bits"){## Affected version number (Windows)
        $VulnStatus = "Not supported on Windows $MajorVersion ($ArchBuildBits) systems"
    }Else{

       $SoftwareVersion = (Get-Item "$FilePath" -EA SilentlyContinue).VersionInfo.ProductVersion
       If(-not($SoftwareVersion)){## Win32k.sys driver not found
           $VulnStatus = "Not Vulnerable"
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
           $VulnStatus = "Not Vulnerable"
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

function Find-CVE20201048 {
   <#
   .SYNOPSIS
      Author: r00t-3xp10it
      Microsoft Spooler Local Privilege Elevation Vulnerability

   .DESCRIPTION
      CVE: 2020-1048
      MSBulletin: MS69-134
      Affected systems:
         Windows 8 x64 bits - 6.2.9200.18363
   #>

    $CVEID = "2020-1048"
    $MSBulletin = "MS69-134"
    $Architecture = Get-Architecture
    $ArchBuildBits = $Architecture[0]
    $FilePath = $Env:WINDIR + "\System32\ualapi.dll"

    ## Check for OS affected version/arch (Windows 8 x64 bits)
    $MajorVersion = [int]$OSVersion.split(".")[0]
    If($MajorVersion -ne 8 -and $ArchBuildBits -ne "64 bits"){
        $VulnStatus = "Not supported on Windows $MajorVersion ($ArchBuildBits) systems"
    }Else{
       
       $SoftwareVersion = (Get-Item "$FilePath" -EA SilentlyContinue).VersionInfo.ProductVersion
       If(-not($SoftwareVersion)){## ualapi.dll appl not found
           $VulnStatus = "Not Vulnerable"
       }Else{

          ## Affected: =< 6.2.9200.18363
          $Major = [int]$SoftwareVersion.Split(".")[2]
          $Revision = $SoftwareVersion.Split(".")[3]

           switch($Major){
           9200 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le 18363 ] }
           default { $VulnStatus = "Not Vulnerable" }
           }
       }
    }
    Set-ExploitTable $MSBulletin $VulnStatus
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
           $VulnStatus = "Not Vulnerable"
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
    If(-not($MajorVersion -eq 10 -and $ArchBuildBits -eq "64 bits")){
        $VulnStatus = "Not supported on Windows $MajorVersion ($ArchBuildBits) systems"
    }Else{

       ## Bypassing AV detection
       $CardiacArrest = "$"+"Env"+":PROGRAM"+"FILES" -Join ''
       $FuckingNuts = "$"+"Env"+":LOCAL"+"APPD"+"ATA" -Join ''
       $ArteryBlocked = "$"+"{Env"+":PROGRA"+"MFILES(x86)}" -Join ''

       ## Find druva.exe absoluct install path
       $SearchFilePath = (Get-ChildItem -Path $ArteryBlocked\Druva\, $CardiacArrest\Druva\, $FuckingNuts\Programs\Druva\ -Filter druva.exe -Recurse -ErrorAction SilentlyContinue -Force).fullname
       If(-not($SearchFilepath)){## Add value to $FilePath or else 'Get-Item' pops up an error if $null
          $FilePath = "$ArteryBlocked" + "\inSync4\Fail.exe"
       }Else{
          $FilePath = $SearchFilePath[0]
       }
       
       $SoftwareVersion = (Get-Item "$FilePath" -EA SilentlyContinue).VersionInfo.ProductVersion
       If(-not($SoftwareVersion)){## Binary.exe appl not found
           $VulnStatus = "Not Vulnerable"
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
           $VulnStatus = "Not Vulnerable"
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

function Find-CVE202017382 {

   <#
   .SYNOPSIS
      Author: r00t-3xp10it
      MSI Ambient Link Driver Elevation of Privileges

   .DESCRIPTION
      CVE: 2020-17382
      MSBulletin: N/A
      Affected systems:
         Windows 10 x64 bits (1709)
   #>

    $MSBulletin = "N/A"
    $CVEID = "2020-17382"
    $Architecture = Get-Architecture
    $ArchBuildBits = $Architecture[0]
    $FilePath = ${Env:PROGRAMFILES(x86)} + "\MSI\AmbientLink\Ambient_Link\msio64.sys"

    ## Check for OS affected version/arch
    $MajorVersion = [int]$OSVersion.split(".")[0]
    If(-not($MajorVersion -eq 10 -and $Architecture[0] -eq "64 bits")){
        $VulnStatus = "Not supported on Windows $MajorVersion ($ArchBuildBits) systems"
    }Else{
       
       $SoftwareVersion = (Get-Item "$FilePath" -EA SilentlyContinue).VersionInfo.ProductVersion
       If(-not($SoftwareVersion)){## msio64.sys driver not found
           $VulnStatus = "Not Vulnerable"
       }Else{

          ## Affected: < 1.0.0.8 (Windows 10 x64 bits)
          $Major = [int]$SoftwareVersion.split(".")[0]
          $Revision = [int]$SoftwareVersion.Split(".")[3]

           switch($Major){
           1 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le 8 ] }
           default { $VulnStatus = "Not Vulnerable" }
           }
       }
    }
    Set-ExploitTable $CVEID $VulnStatus
}

function Find-CVE202017008 {

   <#
   .SYNOPSIS
      Author: r00t-3xp10it
      splWOW64 Local Elevation of Privileges

   .NOTES
      The company is currently aiming to address the bug in January 2021.

   .DESCRIPTION
      CVE: 2020-17008
      MSBulletin: MS69-132
      Affected systems:
         Windows 10 (1901) x64 - 10.0.18362.900

   .LINKS
      https://bugs.chromium.org/p/project-zero/issues/detail?id=2096
      https://www.securityweek.com/google-microsoft-improperly-patched-exploited-windows-vulnerability      
   #>

    $CVEID = "2020-17008"
    $MSBulletin = "MS69-132"
    $Architecture = Get-Architecture
    $ArchBuildBits = $Architecture[0]
    $FilePath = $Env:WINDIR + "\splwow64.exe"

    ## Check for OS affected version/arch (Windows 10 x64 bits)
    $MajorVersion = [int]$OSVersion.split(".")[0]
    If(-not($MajorVersion -eq 10) -and $Architecture[0] -ne "64 bits"){
        $VulnStatus = "Not supported on Windows $MajorVersion ($ArchBuildBits) systems"
    }Else{
       
       $SoftwareVersion = (Get-Item "$FilePath" -EA SilentlyContinue).VersionInfo.ProductVersion
       If(-not($SoftwareVersion)){## splwow64.exe appl not found
           $VulnStatus = "Not Vulnerable"
       }Else{

          <#
          .SYNOPSIS
             Affected: =< 10.0.18362.900 (Windows 10 x64 bits)

          .NOTES
             VulnVersion     Minor   Checks
             -----------     ------  ------
             10.0.18362.900  18362   =< 900
          #>

          $Major = [int]$SoftwareVersion.Split(".")[2]
          $Revision = [int]$SoftwareVersion.Split(".")[3]

           switch($Major){
           18362 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le 900 ] }
           default { $VulnStatus = "Not Vulnerable" }
           }
       }
    }
    Set-ExploitTable $MSBulletin $VulnStatus
}

function Find-CVE20211642 {

   <#
   .SYNOPSIS
      Disclosure: @404death
      CmdLet Author: r00t-3xp10it
      AppX Deployment Service Local Elevation of Privileges

   .NOTES
      The company is currently aiming to address the bug in January 13/01/2021.

   .DESCRIPTION
      CVE: 2021-1642
      MSBulletin: MS69-134
      Affected systems:
         Windows 8  x64 - < 8.0.18362.329
         Windows 10 x64 - < 10.0.18362.329

   .LINKS
      https://pastebin.com/raw/ZefAhP2L?fbclid=IwAR369XIAYhI2J_E6bv6fWQwX_Y6ry8vq5S2JF3xISQMjZOok5FPSvKSrsy0     
   #>

    $CVEID = "2021-1642"
    $MSBulletin = "MS69-134"
    $Architecture = Get-Architecture
    $ArchBuildBits = $Architecture[0]
    $FilePath = $Env:WINDIR + "\System32\AppXDeploymentServer.dll"

    ## Check for OS affected version/arch (Windows 8|10 x64 bits)
    $MajorVersion = [int]$OSVersion.split(".")[0]
    If(-not($MajorVersion -eq 10 -or $MajorVersion -eq 8)){
        $VulnStatus = "Not supported on Windows $MajorVersion systems"
    }Else{

       $SoftwareVersion = (Get-Item "$FilePath" -EA SilentlyContinue).VersionInfo.ProductVersion
       If(-not($SoftwareVersion)){## AppXDeploymentServer.dll not found
           $VulnStatus = "Not Vulnerable"
       }Else{

          <#
          .SYNOPSIS
             Affected: < 10.0.18362.329 (Windows 8|10 x64 bits)
             CreationTime: 13/01/2021

          .NOTES
             VulnVersion     Minor   Checks
             -----------     ------  ------
             10.0.18362.329  18362  < 329
          #>

          $Major = [int]$SoftwareVersion.Split(".")[2]
          $Revision = [int]$SoftwareVersion.Split(".")[3]

          switch($Major){
          18362 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -lt 329 ] }
          default { $VulnStatus = "Not Vulnerable" }
          }
       }
    }
    Set-ExploitTable $MSBulletin $VulnStatus
}
