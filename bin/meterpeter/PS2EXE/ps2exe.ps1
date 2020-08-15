<#
.SYNOPSIS
   Converts powershell scripts to standalone executables.

.DESCRIPTION
   Converts powershell scripts to standalone executables. GUI output and input is activated with one switch,
   real windows executables are generated. You may use the graphical front end Win-PS2EXE for convenience.

   Please see Remarks on project page for topics "GUI mode output formatting", "Config files", "Password security",
   "Script variables" and "Window in background in -noConsole mode".

A generated executables has the following reserved parameters:

-debug              Forces the executable to be debugged. It calls "System.Diagnostics.Debugger.Break()".
-extract:<FILENAME> Extracts the powerShell script inside the executable and saves it as FILENAME. The script will not be executed.
-wait               At the end of the script execution it writes "Hit any key to exit..." and waits for a key to be pressed.
-end                All following options will be passed to the script inside the executable. All preceding options are used by the executable itself.

.PARAMETER inputFile
   Powershell script to convert to executable
   
.PARAMETER outputFile
   destination executable file name, defaults to inputFile with extension '.exe'
   
.PARAMETER runtime20
   this switch forces PS2EXE to create a config file for the generated executable that contains the "supported .NET Framework versions" setting for .NET Framework 2.0/3.x for PowerShell 2.0

.PARAMETER runtime40
   this switch forces PS2EXE to create a config file for the generated executable that contains the "supported .NET Framework versions" setting for .NET Framework 4.x for PowerShell 3.0 or higher

.PARAMETER x86
   compile for 32-bit runtime only

.PARAMETER x64
   compile for 64-bit runtime only
   
.PARAMETER lcid
   location ID for the compiled executable. Current user culture if not specified
   
.PARAMETER STA
   Single Thread Apartment mode
   
.PARAMETER MTA
   Multi Thread Apartment mode
   
.PARAMETER nested
   internal use

.PARAMETER noConsole
   the resulting executable will be a Windows Forms app without a console window. You might want to pipe your output to Out-String to prevent a message box for every line of output (example: dir C:\ | Out-String)

.PARAMETER credentialGUI
   use GUI for prompting credentials in console mode instead of console input

.PARAMETER iconFile
   icon file name for the compiled executable

.PARAMETER title
   title information (displayed in details tab of Windows Explorer's properties dialog)

.PARAMETER description
   description information (not displayed, but embedded in executable)

.PARAMETER company
   company information (not displayed, but embedded in executable)

.PARAMETER product
   product information (displayed in details tab of Windows Explorer's properties dialog)

.PARAMETER copyright
   copyright information (displayed in details tab of Windows Explorer's properties dialog)

.PARAMETER trademark
   trademark information (displayed in details tab of Windows Explorer's properties dialog)

.PARAMETER version
   version information (displayed in details tab of Windows Explorer's properties dialog)

.PARAMETER configFile
   write a config file (<outputfile>.exe.config)

.PARAMETER noConfigFile
   compatibility parameter

.PARAMETER noOutput
   the resulting executable will generate no standard output (includes verbose and information channel)

.PARAMETER noError
   the resulting executable will generate no error output (includes warning and debug channel)

.PARAMETER noVisualStyles
   disable visual styles for a generated windows GUI application. Only applicable with parameter -noConsole

.PARAMETER requireAdmin
   if UAC is enabled, compiled executable will run only in elevated context (UAC dialog appears if required)

.PARAMETER supportOS
   use functions of newest Windows versions (execute [Environment]::OSVersion to see the difference)

.PARAMETER virtualize
   application virtualization is activated (forcing x86 runtime)

.PARAMETER longPaths
   enable long paths ( > 260 characters) if enabled on OS (works only with Windows 10)

.EXAMPLE
   ps2exe.ps1 C:\Data\MyScript.ps1
   Compiles C:\Data\MyScript.ps1 to C:\Data\MyScript.exe as console executable

.EXAMPLE
   ps2exe.ps1 -inputFile C:\Data\MyScript.ps1 -outputFile C:\Data\MyScriptGUI.exe -iconFile C:\Data\Icon.ico -noConsole -title "MyScript" -version 0.0.0.1
   Compiles C:\Data\MyScript.ps1 to C:\Data\MyScriptGUI.exe as graphical executable, icon and meta data

.NOTES
   Version: 0.5.0.21
   Date: 2020-07-10
   Author: Ingo Karstein, Markus Scholtes

.LINK
   https://gallery.technet.microsoft.com/PS2EXE-GUI-Convert-e7cb69d5
#>

Param([STRING]$inputFile = $NULL, [STRING]$outputFile = $NULL, [SWITCH]$verbose, [SWITCH]$debug, [SWITCH]$runtime20, [SWITCH]$runtime40,
	[SWITCH]$x86, [SWITCH]$x64, [int]$lcid, [SWITCH]$STA, [SWITCH]$MTA, [SWITCH]$nested, [SWITCH]$noConsole, [SWITCH]$credentialGUI,
	[STRING]$iconFile = $NULL, [STRING]$title, [STRING]$description, [STRING]$company, [STRING]$product, [STRING]$copyright, [STRING]$trademark,
	[STRING]$version, [SWITCH]$configFile, [SWITCH]$noConfigFile, [SWITCH]$noOutput, [SWITCH]$noError, [SWITCH]$noVisualStyles, [SWITCH]$requireAdmin,
	[SWITCH]$supportOS, [SWITCH]$virtualize, [SWITCH]$longPaths)

<################################################################################>
<##                                                                            ##>
<##      PS2EXE-GUI v0.5.0.21                                                  ##>
<##      Written by: Ingo Karstein (http://blog.karstein-consulting.com)       ##>
<##      Reworked and GUI support by Markus Scholtes                           ##>
<##                                                                            ##>
<##      This script is released under Microsoft Public Licence                ##>
<##          that can be downloaded here:                                      ##>
<##          http://www.microsoft.com/opensource/licenses.mspx#Ms-PL           ##>
<##                                                                            ##>
<################################################################################>

if (!$nested)
{
	Write-Output "   PS2EXE - v0.5.0.21 by Ingo Karstein, reworked and GUI support by Markus Scholtes"
}
else
{
	Write-Output "PowerShell 2.0 environment started..."
}

if ([STRING]::IsNullOrEmpty($inputFile))
{
	Write-Output "Usage:`n"
	Write-Output "powershell.exe -command ""&'.\ps2exe.ps1' [-inputFile] '<filename>' [[-outputFile] '<filename>'] [-verbose]"
	Write-Output "               [-debug] [-runtime20|-runtime40] [-x86|-x64] [-lcid <id>] [-STA|-MTA] [-noConsole]"
	Write-Output "               [-credentialGUI] [-iconFile '<filename>'] [-title '<title>'] [-description '<description>']"
	Write-Output "               [-company '<company>'] [-product '<product>'] [-copyright '<copyright>'] [-trademark '<trademark>']"
	Write-Output "               [-version '<version>'] [-configFile] [-noOutput] [-noError] [-noVisualStyles] [-requireAdmin]"
	Write-Output "               [-supportOS] [-virtualize] [-longPaths]""`n"
	Write-Output "     inputFile = Powershell script that you want to convert to executable"
	Write-Output "    outputFile = destination executable file name, defaults to inputFile with extension '.exe'"
	Write-Output "     runtime20 = this switch forces PS2EXE to create a config file for the generated executable that contains the"
	Write-Output "                 ""supported .NET Framework versions"" setting for .NET Framework 2.0/3.x for PowerShell 2.0"
	Write-Output "     runtime40 = this switch forces PS2EXE to create a config file for the generated executable that contains the"
	Write-Output "                 ""supported .NET Framework versions"" setting for .NET Framework 4.x for PowerShell 3.0 or higher"
	Write-Output "    x86 or x64 = compile for 32-bit or 64-bit runtime only"
	Write-Output "          lcid = location ID for the compiled executable. Current user culture if not specified"
	Write-Output "    STA or MTA = 'Single Thread Apartment' or 'Multi Thread Apartment' mode"
	Write-Output "     noConsole = the resulting executable will be a Windows Forms app without a console window"
	Write-Output " credentialGUI = use GUI for prompting credentials in console mode"
	Write-Output "      iconFile = icon file name for the compiled executable"
	Write-Output "         title = title information (displayed in details tab of Windows Explorer's properties dialog)"
	Write-Output "   description = description information (not displayed, but embedded in executable)"
	Write-Output "       company = company information (not displayed, but embedded in executable)"
	Write-Output "       product = product information (displayed in details tab of Windows Explorer's properties dialog)"
	Write-Output "     copyright = copyright information (displayed in details tab of Windows Explorer's properties dialog)"
	Write-Output "     trademark = trademark information (displayed in details tab of Windows Explorer's properties dialog)"
	Write-Output "       version = version information (displayed in details tab of Windows Explorer's properties dialog)"
	Write-Output "    configFile = write a config file (<outputfile>.exe.config)"
	Write-Output "      noOutput = the resulting executable will generate no standard output (includes verbose and information channel)"
	Write-Output "       noError = the resulting executable will generate no error output (includes warning and debug channel)"
	Write-Output "noVisualStyles = disable visual styles for a generated windows GUI application (only with -noConsole)"
	Write-Output "  requireAdmin = if UAC is enabled, compiled executable run only in elevated context (UAC dialog appears if required)"
	Write-Output "     supportOS = use functions of newest Windows versions (execute [Environment]::OSVersion to see the difference)"
	Write-Output "    virtualize = application virtualization is activated (forcing x86 runtime)"
	Write-Output "     longPaths = enable long paths ( > 260 characters) if enabled on OS (works only with Windows 10)`n"
	Write-Output "Input file not specified!"
	exit -1
}

$psversion = 0
if ($PSVersionTable.PSVersion.Major -ge 4)
{
	$psversion = 4
	#Write-Output "You are using PowerShell 4.0 or above."
}

if ($PSVersionTable.PSVersion.Major -eq 3)
{
	$psversion = 3
	Write-Output "You are using PowerShell 3.0."
}

if ($PSVersionTable.PSVersion.Major -eq 2)
{
	$psversion = 2
	Write-Output "You are using PowerShell 2.0."
}

if ($psversion -eq 0)
{
	Write-Error "The powershell version is unknown!"
	exit -1
}

# retrieve absolute paths independent if path is given relative oder absolute
$inputFile = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($inputFile)
if ([STRING]::IsNullOrEmpty($outputFile))
{
	$outputFile = ([System.IO.Path]::Combine([System.IO.Path]::GetDirectoryName($inputFile), [System.IO.Path]::GetFileNameWithoutExtension($inputFile)+".exe"))
}
else
{
	$outputFile = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($outputFile)
}

if (!(Test-Path $inputFile -PathType Leaf))
{
	Write-Error "   Input file  => $($inputfile) not found!"
	exit -1
}

if ($inputFile -eq $outputFile)
{
	Write-Error "   Input file is identical to output file!"
	exit -1
}

if (($outputFile -notlike "*.exe") -and ($outputFile -notlike "*.com"))
{
	Write-Error "Output file must have extension '.exe' or '.com'!"
	exit -1
}

if (!([STRING]::IsNullOrEmpty($iconFile)))
{
	# retrieve absolute path independent if path is given relative oder absolute
	$iconFile = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($iconFile)

	if (!(Test-Path $iconFile -PathType Leaf))
	{
		Write-Error "Icon file $($iconFile) not found!"
		exit -1
	}
}

if ($requireAdmin -and $virtualize)
{
	Write-Error "-requireAdmin cannot be combined with -virtualize"
	exit -1
}
if ($supportOS -and $virtualize)
{
	Write-Error "-supportOS cannot be combined with -virtualize"
	exit -1
}
if ($longPaths -and $virtualize)
{
	Write-Error "-longPaths cannot be combined with -virtualize"
	exit -1
}

if ($runtime20 -and $runtime40)
{
	Write-Error "You cannot use switches -runtime20 and -runtime40 at the same time!"
	exit -1
}

if (!$runtime20 -and !$runtime40)
{
	if ($psversion -eq 4)
	{
		$runtime40 = $TRUE
	}
	elseif ($psversion -eq 3)
	{
		$runtime40 = $TRUE
	}
	else
	{
		$runtime20 = $TRUE
	}
}

if ($runtime20 -and $longPaths)
{
	Write-Error "Long paths are only available with .Net 4"
	exit -1
}

$CFGFILE = $FALSE
if ($configFile)
{ $CFGFILE = $TRUE
	if ($noConfigFile)
	{
		Write-Error "-configFile cannot be combined with -noConfigFile"
		exit -1
	}
}
if (!$CFGFILE -and $longPaths)
{
	Write-Warning "Forcing generation of a config file, since the option -longPaths requires this"
	$CFGFILE = $TRUE
}

if ($STA -and $MTA)
{
	Write-Error "You cannot use switches -STA and -MTA at the same time!"
	exit -1
}

if ($psversion -ge 3 -and $runtime20)
{
	Write-Output "To create an EXE file for PowerShell 2.0 on PowerShell 3.0 or above this script now launches PowerShell 2.0...`n"

	$arguments = "-inputFile '$($inputFile)' -outputFile '$($outputFile)' -nested "

	if ($verbose) { $arguments += "-verbose "}
	if ($debug) { $arguments += "-debug "}
	if ($runtime20) { $arguments += "-runtime20 "}
	if ($x86) { $arguments += "-x86 "}
	if ($x64) { $arguments += "-x64 "}
	if ($lcid) { $arguments += "-lcid $lcid "}
	if ($STA) { $arguments += "-STA "}
	if ($MTA) { $arguments += "-MTA "}
	if ($noConsole) { $arguments += "-noConsole "}
	if (!([STRING]::IsNullOrEmpty($iconFile))) { $arguments += "-iconFile '$($iconFile)' "}
	if (!([STRING]::IsNullOrEmpty($title))) { $arguments += "-title '$($title)' "}
	if (!([STRING]::IsNullOrEmpty($description))) { $arguments += "-description '$($description)' "}
	if (!([STRING]::IsNullOrEmpty($company))) { $arguments += "-company '$($company)' "}
	if (!([STRING]::IsNullOrEmpty($product))) { $arguments += "-product '$($product)' "}
	if (!([STRING]::IsNullOrEmpty($copyright))) { $arguments += "-copyright '$($copyright)' "}
	if (!([STRING]::IsNullOrEmpty($trademark))) { $arguments += "-trademark '$($trademark)' "}
	if (!([STRING]::IsNullOrEmpty($version))) { $arguments += "-version '$($version)' "}
	if ($noOutput) { $arguments += "-noOutput "}
	if ($noError) { $arguments += "-noError "}
	if ($requireAdmin) { $arguments += "-requireAdmin "}
	if ($virtualize) { $arguments += "-virtualize "}
	if ($credentialGUI) { $arguments += "-credentialGUI "}
	if ($supportOS) { $arguments += "-supportOS "}
	if ($configFile) { $arguments += "-configFile "}
	if ($noConfigFile) { $arguments += "-noConfigFile "}

	if ($MyInvocation.MyCommand.CommandType -eq "ExternalScript")
	{	# ps2exe.ps1 is running (script)
		$jobScript = @"
."$($PSHOME)\powershell.exe" -version 2.0 -command "&'$($MyInvocation.MyCommand.Path)' $($arguments)"
"@
	}
	else
	{ # ps2exe.exe is running (compiled script)
		Write-Warning "The parameter -runtime20 is not supported for compiled ps2exe.ps1 scripts."
		Write-Warning "Compile ps2exe.ps1 with parameter -runtime20 and call the generated executable (without -runtime20)."
		exit -1
	}

	Invoke-Expression $jobScript

	exit 0
}

if ($psversion -lt 3 -and $runtime40)
{
	Write-Error "You need to run ps2exe in an Powershell 3.0 or higher environment to use parameter -runtime40"
	exit -1
}

if ($psversion -lt 3 -and !$MTA -and !$STA)
{
	# Set default apartment mode for powershell version if not set by parameter
	$MTA = $TRUE
}

if ($psversion -ge 3 -and !$MTA -and !$STA)
{
	# Set default apartment mode for powershell version if not set by parameter
	$STA = $TRUE
}

# escape escape sequences in version info
$title = $title -replace "\\", "\\"
$product = $product -replace "\\", "\\"
$copyright = $copyright -replace "\\", "\\"
$trademark = $trademark -replace "\\", "\\"
$description = $description -replace "\\", "\\"
$company = $company -replace "\\", "\\"

if (![STRING]::IsNullOrEmpty($version))
{ # check for correct version number information
	if ($version -notmatch "(^\d+\.\d+\.\d+\.\d+$)|(^\d+\.\d+\.\d+$)|(^\d+\.\d+$)|(^\d+$)")
	{
		Write-Error "Version number has to be supplied in the form n.n.n.n, n.n.n, n.n or n (with n as number)!"
		exit -1
	}
}

Write-Output ""

$type = ('System.Collections.Generic.Dictionary`2') -as "Type"
$type = $type.MakeGenericType( @( ("System.String" -as "Type"), ("system.string" -as "Type") ) )
$o = [Activator]::CreateInstance($type)

$compiler20 = $FALSE
if ($psversion -eq 3 -or $psversion -eq 4)
{
	$o.Add("CompilerVersion", "v4.0")
}
else
{
	if (Test-Path ("$ENV:WINDIR\Microsoft.NET\Framework\v3.5\csc.exe"))
	{ $o.Add("CompilerVersion", "v3.5") }
	else
	{
		Write-Warning "No .Net 3.5 compiler found, using .Net 2.0 compiler."
		Write-Warning "Therefore some methods are not available!"
		$compiler20 = $TRUE
		$o.Add("CompilerVersion", "v2.0")
	}
}

$referenceAssembies = @("System.dll")
if (!$noConsole)
{
	if ([System.AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.ManifestModule.Name -ieq "Microsoft.PowerShell.ConsoleHost.dll" })
	{
		$referenceAssembies += ([System.AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.ManifestModule.Name -ieq "Microsoft.PowerShell.ConsoleHost.dll" } | Select-Object -First 1).Location
	}
}
$referenceAssembies += ([System.AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.ManifestModule.Name -ieq "System.Management.Automation.dll" } | Select-Object -First 1).Location

if ($runtime40)
{
	$n = New-Object System.Reflection.AssemblyName("System.Core, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089")
	[System.AppDomain]::CurrentDomain.Load($n) | Out-Null
	$referenceAssembies += ([System.AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.ManifestModule.Name -ieq "System.Core.dll" } | Select-Object -First 1).Location
}

if ($noConsole)
{
	$n = New-Object System.Reflection.AssemblyName("System.Windows.Forms, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089")
	if ($runtime40)
	{
		$n = New-Object System.Reflection.AssemblyName("System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089")
	}
	[System.AppDomain]::CurrentDomain.Load($n) | Out-Null

	$n = New-Object System.Reflection.AssemblyName("System.Drawing, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a")
	if ($runtime40)
	{
		$n = New-Object System.Reflection.AssemblyName("System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a")
	}
	[System.AppDomain]::CurrentDomain.Load($n) | Out-Null

	$referenceAssembies += ([System.AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.ManifestModule.Name -ieq "System.Windows.Forms.dll" } | Select-Object -First 1).Location
	$referenceAssembies += ([System.AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.ManifestModule.Name -ieq "System.Drawing.dll" } | Select-Object -First 1).Location
}

$platform = "anycpu"
if ($x64 -and !$x86) { $platform = "x64" } else { if ($x86 -and !$x64) { $platform = "x86" }}

$cop = (New-Object Microsoft.CSharp.CSharpCodeProvider($o))
$cp = New-Object System.CodeDom.Compiler.CompilerParameters($referenceAssembies, $outputFile)
$cp.GenerateInMemory = $FALSE
$cp.GenerateExecutable = $TRUE

$iconFileParam = ""
if (!([STRING]::IsNullOrEmpty($iconFile)))
{
	$iconFileParam = "`"/win32icon:$($iconFile)`""
}

$manifestParam = ""
if ($requireAdmin -or $supportOS -or $longPaths)
{
	$manifestParam = "`"/win32manifest:$($outputFile+".win32manifest")`""
	$win32manifest = "<?xml version=""1.0"" encoding=""UTF-8"" standalone=""yes""?>`r`n<assembly xmlns=""urn:schemas-microsoft-com:asm.v1"" manifestVersion=""1.0"">`r`n"
	if ($longPaths)
	{
		$win32manifest += "<application xmlns=""urn:schemas-microsoft-com:asm.v3"">`r`n<windowsSettings>`r`n<longPathAware xmlns=""http://schemas.microsoft.com/SMI/2016/WindowsSettings"">true</longPathAware>`r`n</windowsSettings>`r`n</application>`r`n"
	}
	if ($requireAdmin)
	{
		$win32manifest += "<trustInfo xmlns=""urn:schemas-microsoft-com:asm.v2"">`r`n<security>`r`n<requestedPrivileges xmlns=""urn:schemas-microsoft-com:asm.v3"">`r`n<requestedExecutionLevel level=""requireAdministrator"" uiAccess=""false""/>`r`n</requestedPrivileges>`r`n</security>`r`n</trustInfo>`r`n"
	}
	if ($supportOS)
	{
		$win32manifest += "<compatibility xmlns=""urn:schemas-microsoft-com:compatibility.v1"">`r`n<application>`r`n<supportedOS Id=""{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}""/>`r`n<supportedOS Id=""{1f676c76-80e1-4239-95bb-83d0f6d0da78}""/>`r`n<supportedOS Id=""{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}""/>`r`n<supportedOS Id=""{35138b9a-5d96-4fbd-8e2d-a2440225f93a}""/>`r`n<supportedOS Id=""{e2011457-1546-43c5-a5fe-008deee3d3f0}""/>`r`n</application>`r`n</compatibility>`r`n"
	}
	$win32manifest += "</assembly>"
	$win32manifest | Set-Content ($outputFile+".win32manifest") -Encoding UTF8
}

if (!$virtualize)
{ $cp.CompilerOptions = "/platform:$($platform) /target:$( if ($noConsole){'winexe'}else{'exe'}) $($iconFileParam) $($manifestParam)" }
else
{
	Write-Output "Application virtualization is activated, forcing x86 platfom."
	$cp.CompilerOptions = "/platform:x86 /target:$( if ($noConsole) { 'winexe' } else { 'exe' } ) /nowin32manifest $($iconFileParam)"
}

$cp.IncludeDebugInformation = $debug

if ($debug)
{
	$cp.TempFiles.KeepFiles = $TRUE
}

If($inputFile -match 'meterpeter'){$parsingPath = $inputFile -replace '\\PS2EXE',''}else{$parsingPath = $inputFile}
Write-Output "   Input  file => $parsingPath"
$content = Get-Content -LiteralPath $inputFile -Encoding UTF8 -ErrorAction SilentlyContinue
if ([STRING]::IsNullOrEmpty($content))
{
	Write-Error "No data found. May be read error or file protected."
	exit -2
}
$scriptInp = [STRING]::Join("`r`n", $content)
$script = [System.Convert]::ToBase64String(([System.Text.Encoding]::UTF8.GetBytes($scriptInp)))

$culture = ""

if ($lcid)
{
	$culture = @"
	System.Threading.Thread.CurrentThread.CurrentCulture = System.Globalization.CultureInfo.GetCultureInfo($lcid);
	System.Threading.Thread.CurrentThread.CurrentUICulture = System.Globalization.CultureInfo.GetCultureInfo($lcid);
"@
}

$programFrame = @"
// Simple PowerShell host created by Ingo Karstein (http://blog.karstein-consulting.com) for PS2EXE
// Reworked and GUI support by Markus Scholtes

using System;
using System.Collections.Generic;
using System.Text;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using PowerShell = System.Management.Automation.PowerShell;
using System.Globalization;
using System.Management.Automation.Host;
using System.Security;
using System.Reflection;
using System.Runtime.InteropServices;
$(if ($noConsole) {@"
using System.Windows.Forms;
using System.Drawing;
"@ })

[assembly:AssemblyTitle("$title")]
[assembly:AssemblyProduct("$product")]
[assembly:AssemblyCopyright("$copyright")]
[assembly:AssemblyTrademark("$trademark")]
$(if (![STRING]::IsNullOrEmpty($version)) {@"
[assembly:AssemblyVersion("$version")]
[assembly:AssemblyFileVersion("$version")]
"@ })
// not displayed in details tab of properties dialog, but embedded to file
[assembly:AssemblyDescription("$description")]
[assembly:AssemblyCompany("$company")]

namespace ik.PowerShell
{
$(if ($noConsole -or $credentialGUI) {@"
	internal class CredentialForm
	{
		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		private struct CREDUI_INFO
		{
			public int cbSize;
			public IntPtr hwndParent;
			public string pszMessageText;
			public string pszCaptionText;
			public IntPtr hbmBanner;
		}

		[Flags]
		enum CREDUI_FLAGS
		{
			INCORRECT_PASSWORD = 0x1,
			DO_NOT_PERSIST = 0x2,
			REQUEST_ADMINISTRATOR = 0x4,
			EXCLUDE_CERTIFICATES = 0x8,
			REQUIRE_CERTIFICATE = 0x10,
			SHOW_SAVE_CHECK_BOX = 0x40,
			ALWAYS_SHOW_UI = 0x80,
			REQUIRE_SMARTCARD = 0x100,
			PASSWORD_ONLY_OK = 0x200,
			VALIDATE_USERNAME = 0x400,
			COMPLETE_USERNAME = 0x800,
			PERSIST = 0x1000,
			SERVER_CREDENTIAL = 0x4000,
			EXPECT_CONFIRMATION = 0x20000,
			GENERIC_CREDENTIALS = 0x40000,
			USERNAME_TARGET_CREDENTIALS = 0x80000,
			KEEP_USERNAME = 0x100000,
		}

		public enum CredUIReturnCodes
		{
			NO_ERROR = 0,
			ERROR_CANCELLED = 1223,
			ERROR_NO_SUCH_LOGON_SESSION = 1312,
			ERROR_NOT_FOUND = 1168,
			ERROR_INVALID_ACCOUNT_NAME = 1315,
			ERROR_INSUFFICIENT_BUFFER = 122,
			ERROR_INVALID_PARAMETER = 87,
			ERROR_INVALID_FLAGS = 1004,
		}

		[DllImport("credui", CharSet = CharSet.Unicode)]
		private static extern CredUIReturnCodes CredUIPromptForCredentials(ref CREDUI_INFO creditUR,
			string targetName,
			IntPtr reserved1,
			int iError,
			StringBuilder userName,
			int maxUserName,
			StringBuilder password,
			int maxPassword,
			[MarshalAs(UnmanagedType.Bool)] ref bool pfSave,
			CREDUI_FLAGS flags);

		public class UserPwd
		{
			public string User = string.Empty;
			public string Password = string.Empty;
			public string Domain = string.Empty;
		}

		internal static UserPwd PromptForPassword(string caption, string message, string target, string user, PSCredentialTypes credTypes, PSCredentialUIOptions options)
		{
			// Flags und Variablen initialisieren
			StringBuilder userPassword = new StringBuilder(), userID = new StringBuilder(user, 128);
			CREDUI_INFO credUI = new CREDUI_INFO();
			if (!string.IsNullOrEmpty(message)) credUI.pszMessageText = message;
			if (!string.IsNullOrEmpty(caption)) credUI.pszCaptionText = caption;
			credUI.cbSize = Marshal.SizeOf(credUI);
			bool save = false;

			CREDUI_FLAGS flags = CREDUI_FLAGS.DO_NOT_PERSIST;
			if ((credTypes & PSCredentialTypes.Generic) == PSCredentialTypes.Generic)
			{
				flags |= CREDUI_FLAGS.GENERIC_CREDENTIALS;
				if ((options & PSCredentialUIOptions.AlwaysPrompt) == PSCredentialUIOptions.AlwaysPrompt)
				{
					flags |= CREDUI_FLAGS.ALWAYS_SHOW_UI;
				}
			}

			// den Benutzer nach Kennwort fragen, grafischer Prompt
			CredUIReturnCodes returnCode = CredUIPromptForCredentials(ref credUI, target, IntPtr.Zero, 0, userID, 128, userPassword, 128, ref save, flags);

			if (returnCode == CredUIReturnCodes.NO_ERROR)
			{
				UserPwd ret = new UserPwd();
				ret.User = userID.ToString();
				ret.Password = userPassword.ToString();
				ret.Domain = "";
				return ret;
			}

			return null;
		}
	}
"@ })

	internal class PS2EXEHostRawUI : PSHostRawUserInterface
	{
$(if ($noConsole){ @"
		// Speicher für Konsolenfarben bei GUI-Output werden gelesen und gesetzt, aber im Moment nicht genutzt (for future use)
		private ConsoleColor ncBackgroundColor = ConsoleColor.White;
		private ConsoleColor ncForegroundColor = ConsoleColor.Black;
"@ } else {@"
		const int STD_OUTPUT_HANDLE = -11;

		//CHAR_INFO struct, which was a union in the old days
		// so we want to use LayoutKind.Explicit to mimic it as closely
		// as we can
		[StructLayout(LayoutKind.Explicit)]
		public struct CHAR_INFO
		{
			[FieldOffset(0)]
			internal char UnicodeChar;
			[FieldOffset(0)]
			internal char AsciiChar;
			[FieldOffset(2)] //2 bytes seems to work properly
			internal UInt16 Attributes;
		}

		//COORD struct
		[StructLayout(LayoutKind.Sequential)]
		public struct COORD
		{
			public short X;
			public short Y;
		}

		//SMALL_RECT struct
		[StructLayout(LayoutKind.Sequential)]
		public struct SMALL_RECT
		{
			public short Left;
			public short Top;
			public short Right;
			public short Bottom;
		}

		/* Reads character and color attribute data from a rectangular block of character cells in a console screen buffer,
			 and the function writes the data to a rectangular block at a specified location in the destination buffer. */
		[DllImport("kernel32.dll", EntryPoint = "ReadConsoleOutputW", CharSet = CharSet.Unicode, SetLastError = true)]
		internal static extern bool ReadConsoleOutput(
			IntPtr hConsoleOutput,
			/* This pointer is treated as the origin of a two-dimensional array of CHAR_INFO structures
			whose size is specified by the dwBufferSize parameter.*/
			[MarshalAs(UnmanagedType.LPArray), Out] CHAR_INFO[,] lpBuffer,
			COORD dwBufferSize,
			COORD dwBufferCoord,
			ref SMALL_RECT lpReadRegion);

		/* Writes character and color attribute data to a specified rectangular block of character cells in a console screen buffer.
			The data to be written is taken from a correspondingly sized rectangular block at a specified location in the source buffer */
		[DllImport("kernel32.dll", EntryPoint = "WriteConsoleOutputW", CharSet = CharSet.Unicode, SetLastError = true)]
		internal static extern bool WriteConsoleOutput(
			IntPtr hConsoleOutput,
			/* This pointer is treated as the origin of a two-dimensional array of CHAR_INFO structures
			whose size is specified by the dwBufferSize parameter.*/
			[MarshalAs(UnmanagedType.LPArray), In] CHAR_INFO[,] lpBuffer,
			COORD dwBufferSize,
			COORD dwBufferCoord,
			ref SMALL_RECT lpWriteRegion);

		/* Moves a block of data in a screen buffer. The effects of the move can be limited by specifying a clipping rectangle, so
			the contents of the console screen buffer outside the clipping rectangle are unchanged. */
		[DllImport("kernel32.dll", SetLastError = true)]
		static extern bool ScrollConsoleScreenBuffer(
			IntPtr hConsoleOutput,
			[In] ref SMALL_RECT lpScrollRectangle,
			[In] ref SMALL_RECT lpClipRectangle,
			COORD dwDestinationOrigin,
			[In] ref CHAR_INFO lpFill);

		[DllImport("kernel32.dll", SetLastError = true)]
			static extern IntPtr GetStdHandle(int nStdHandle);
"@ })

		public override ConsoleColor BackgroundColor
		{
$(if (!$noConsole){ @"
			get
			{
				return Console.BackgroundColor;
			}
			set
			{
				Console.BackgroundColor = value;
			}
"@ } else {@"
			get
			{
				return ncBackgroundColor;
			}
			set
			{
				ncBackgroundColor = value;
			}
"@ })
		}

		public override System.Management.Automation.Host.Size BufferSize
		{
			get
			{
$(if (!$noConsole){ @"
				if (ConsoleInfo.IsOutputRedirected())
					// return default value for redirection. If no valid value is returned WriteLine will not be called
					return new System.Management.Automation.Host.Size(120, 50);
				else
					return new System.Management.Automation.Host.Size(Console.BufferWidth, Console.BufferHeight);
"@ } else {@"
					// return default value for Winforms. If no valid value is returned WriteLine will not be called
				return new System.Management.Automation.Host.Size(120, 50);
"@ })
			}
			set
			{
$(if (!$noConsole){ @"
				Console.BufferWidth = value.Width;
				Console.BufferHeight = value.Height;
"@ })
			}
		}

		public override Coordinates CursorPosition
		{
			get
			{
$(if (!$noConsole){ @"
				return new Coordinates(Console.CursorLeft, Console.CursorTop);
"@ } else {@"
				// Dummywert für Winforms zurückgeben.
				return new Coordinates(0, 0);
"@ })
			}
			set
			{
$(if (!$noConsole){ @"
				Console.CursorTop = value.Y;
				Console.CursorLeft = value.X;
"@ })
			}
		}

		public override int CursorSize
		{
			get
			{
$(if (!$noConsole){ @"
				return Console.CursorSize;
"@ } else {@"
				// Dummywert für Winforms zurückgeben.
				return 25;
"@ })
			}
			set
			{
$(if (!$noConsole){ @"
				Console.CursorSize = value;
"@ })
			}
		}

$(if ($noConsole){ @"
		private Form InvisibleForm = null;
"@ })

		public override void FlushInputBuffer()
		{
$(if (!$noConsole){ @"
			if (!ConsoleInfo.IsInputRedirected())
			{	while (Console.KeyAvailable)
					Console.ReadKey(true);
			}
"@ } else {@"
			if (InvisibleForm != null)
			{
				InvisibleForm.Close();
				InvisibleForm = null;
			}
			else
			{
				InvisibleForm = new Form();
				InvisibleForm.Opacity = 0;
				InvisibleForm.ShowInTaskbar = false;
				InvisibleForm.Visible = true;
			}
"@ })
		}

		public override ConsoleColor ForegroundColor
		{
$(if (!$noConsole){ @"
			get
			{
				return Console.ForegroundColor;
			}
			set
			{
				Console.ForegroundColor = value;
			}
"@ } else {@"
			get
			{
				return ncForegroundColor;
			}
			set
			{
				ncForegroundColor = value;
			}
"@ })
		}

		public override BufferCell[,] GetBufferContents(System.Management.Automation.Host.Rectangle rectangle)
		{
$(if ($compiler20) {@"
			throw new Exception("Method GetBufferContents not implemented for .Net V2.0 compiler");
"@ } else { if (!$noConsole) {@"
			IntPtr hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
			CHAR_INFO[,] buffer = new CHAR_INFO[rectangle.Bottom - rectangle.Top + 1, rectangle.Right - rectangle.Left + 1];
			COORD buffer_size = new COORD() {X = (short)(rectangle.Right - rectangle.Left + 1), Y = (short)(rectangle.Bottom - rectangle.Top + 1)};
			COORD buffer_index = new COORD() {X = 0, Y = 0};
			SMALL_RECT screen_rect = new SMALL_RECT() {Left = (short)rectangle.Left, Top = (short)rectangle.Top, Right = (short)rectangle.Right, Bottom = (short)rectangle.Bottom};

			ReadConsoleOutput(hStdOut, buffer, buffer_size, buffer_index, ref screen_rect);

			System.Management.Automation.Host.BufferCell[,] ScreenBuffer = new System.Management.Automation.Host.BufferCell[rectangle.Bottom - rectangle.Top + 1, rectangle.Right - rectangle.Left + 1];
			for (int y = 0; y <= rectangle.Bottom - rectangle.Top; y++)
				for (int x = 0; x <= rectangle.Right - rectangle.Left; x++)
				{
					ScreenBuffer[y,x] = new System.Management.Automation.Host.BufferCell(buffer[y,x].AsciiChar, (System.ConsoleColor)(buffer[y,x].Attributes & 0xF), (System.ConsoleColor)((buffer[y,x].Attributes & 0xF0) / 0x10), System.Management.Automation.Host.BufferCellType.Complete);
				}

			return ScreenBuffer;
"@ } else {@"
			System.Management.Automation.Host.BufferCell[,] ScreenBuffer = new System.Management.Automation.Host.BufferCell[rectangle.Bottom - rectangle.Top + 1, rectangle.Right - rectangle.Left + 1];

			for (int y = 0; y <= rectangle.Bottom - rectangle.Top; y++)
				for (int x = 0; x <= rectangle.Right - rectangle.Left; x++)
				{
					ScreenBuffer[y,x] = new System.Management.Automation.Host.BufferCell(' ', ncForegroundColor, ncBackgroundColor, System.Management.Automation.Host.BufferCellType.Complete);
				}

			return ScreenBuffer;
"@ } })
		}

		public override bool KeyAvailable
		{
			get
			{
$(if (!$noConsole) {@"
				return Console.KeyAvailable;
"@ } else {@"
				return true;
"@ })
			}
		}

		public override System.Management.Automation.Host.Size MaxPhysicalWindowSize
		{
			get
			{
$(if (!$noConsole){ @"
				return new System.Management.Automation.Host.Size(Console.LargestWindowWidth, Console.LargestWindowHeight);
"@ } else {@"
				// Dummy-Wert für Winforms
				return new System.Management.Automation.Host.Size(240, 84);
"@ })
			}
		}

		public override System.Management.Automation.Host.Size MaxWindowSize
		{
			get
			{
$(if (!$noConsole){ @"
				return new System.Management.Automation.Host.Size(Console.BufferWidth, Console.BufferWidth);
"@ } else {@"
				// Dummy-Wert für Winforms
				return new System.Management.Automation.Host.Size(120, 84);
"@ })
			}
		}

		public override KeyInfo ReadKey(ReadKeyOptions options)
		{
$(if (!$noConsole) {@"
			ConsoleKeyInfo cki = Console.ReadKey((options & ReadKeyOptions.NoEcho)!=0);

			ControlKeyStates cks = 0;
			if ((cki.Modifiers & ConsoleModifiers.Alt) != 0)
				cks |= ControlKeyStates.LeftAltPressed | ControlKeyStates.RightAltPressed;
			if ((cki.Modifiers & ConsoleModifiers.Control) != 0)
				cks |= ControlKeyStates.LeftCtrlPressed | ControlKeyStates.RightCtrlPressed;
			if ((cki.Modifiers & ConsoleModifiers.Shift) != 0)
				cks |= ControlKeyStates.ShiftPressed;
			if (Console.CapsLock)
				cks |= ControlKeyStates.CapsLockOn;
			if (Console.NumberLock)
				cks |= ControlKeyStates.NumLockOn;

			return new KeyInfo((int)cki.Key, cki.KeyChar, cks, (options & ReadKeyOptions.IncludeKeyDown)!=0);
"@ } else {@"
			if ((options & ReadKeyOptions.IncludeKeyDown)!=0)
				return ReadKeyBox.Show("", "", true);
			else
				return ReadKeyBox.Show("", "", false);
"@ })
		}

		public override void ScrollBufferContents(System.Management.Automation.Host.Rectangle source, Coordinates destination, System.Management.Automation.Host.Rectangle clip, BufferCell fill)
		{ // no destination block clipping implemented
$(if (!$noConsole) { if ($compiler20) {@"
			throw new Exception("Method ScrollBufferContents not implemented for .Net V2.0 compiler");
"@ } else {@"
			// clip area out of source range?
			if ((source.Left > clip.Right) || (source.Right < clip.Left) || (source.Top > clip.Bottom) || (source.Bottom < clip.Top))
			{ // clipping out of range -> nothing to do
				return;
			}

			IntPtr hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
			SMALL_RECT lpScrollRectangle = new SMALL_RECT() {Left = (short)source.Left, Top = (short)source.Top, Right = (short)(source.Right), Bottom = (short)(source.Bottom)};
			SMALL_RECT lpClipRectangle;
			if (clip != null)
			{ lpClipRectangle = new SMALL_RECT() {Left = (short)clip.Left, Top = (short)clip.Top, Right = (short)(clip.Right), Bottom = (short)(clip.Bottom)}; }
			else
			{ lpClipRectangle = new SMALL_RECT() {Left = (short)0, Top = (short)0, Right = (short)(Console.WindowWidth - 1), Bottom = (short)(Console.WindowHeight - 1)}; }
			COORD dwDestinationOrigin = new COORD() {X = (short)(destination.X), Y = (short)(destination.Y)};
			CHAR_INFO lpFill = new CHAR_INFO() { AsciiChar = fill.Character, Attributes = (ushort)((int)(fill.ForegroundColor) + (int)(fill.BackgroundColor)*16) };

			ScrollConsoleScreenBuffer(hStdOut, ref lpScrollRectangle, ref lpClipRectangle, dwDestinationOrigin, ref lpFill);
"@ } })
		}

		public override void SetBufferContents(System.Management.Automation.Host.Rectangle rectangle, BufferCell fill)
		{
$(if (!$noConsole){ @"
			// using a trick: move the buffer out of the screen, the source area gets filled with the char fill.Character
			if (rectangle.Left >= 0)
				Console.MoveBufferArea(rectangle.Left, rectangle.Top, rectangle.Right-rectangle.Left+1, rectangle.Bottom-rectangle.Top+1, BufferSize.Width, BufferSize.Height, fill.Character, fill.ForegroundColor, fill.BackgroundColor);
			else
			{ // Clear-Host: move all content off the screen
				Console.MoveBufferArea(0, 0, BufferSize.Width, BufferSize.Height, BufferSize.Width, BufferSize.Height, fill.Character, fill.ForegroundColor, fill.BackgroundColor);
			}
"@ })
		}

		public override void SetBufferContents(Coordinates origin, BufferCell[,] contents)
		{
$(if (!$noConsole) { if ($compiler20) {@"
			throw new Exception("Method SetBufferContents not implemented for .Net V2.0 compiler");
"@ } else {@"
			IntPtr hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
			CHAR_INFO[,] buffer = new CHAR_INFO[contents.GetLength(0), contents.GetLength(1)];
			COORD buffer_size = new COORD() {X = (short)(contents.GetLength(1)), Y = (short)(contents.GetLength(0))};
			COORD buffer_index = new COORD() {X = 0, Y = 0};
			SMALL_RECT screen_rect = new SMALL_RECT() {Left = (short)origin.X, Top = (short)origin.Y, Right = (short)(origin.X + contents.GetLength(1) - 1), Bottom = (short)(origin.Y + contents.GetLength(0) - 1)};

			for (int y = 0; y < contents.GetLength(0); y++)
				for (int x = 0; x < contents.GetLength(1); x++)
				{
					buffer[y,x] = new CHAR_INFO() { AsciiChar = contents[y,x].Character, Attributes = (ushort)((int)(contents[y,x].ForegroundColor) + (int)(contents[y,x].BackgroundColor)*16) };
				}

			WriteConsoleOutput(hStdOut, buffer, buffer_size, buffer_index, ref screen_rect);
"@ } })
		}

		public override Coordinates WindowPosition
		{
			get
			{
				Coordinates s = new Coordinates();
$(if (!$noConsole){ @"
				s.X = Console.WindowLeft;
				s.Y = Console.WindowTop;
"@ } else {@"
				// Dummy-Wert für Winforms
				s.X = 0;
				s.Y = 0;
"@ })
				return s;
			}
			set
			{
$(if (!$noConsole){ @"
				Console.WindowLeft = value.X;
				Console.WindowTop = value.Y;
"@ })
			}
		}

		public override System.Management.Automation.Host.Size WindowSize
		{
			get
			{
				System.Management.Automation.Host.Size s = new System.Management.Automation.Host.Size();
$(if (!$noConsole){ @"
				s.Height = Console.WindowHeight;
				s.Width = Console.WindowWidth;
"@ } else {@"
				// Dummy-Wert für Winforms
				s.Height = 50;
				s.Width = 120;
"@ })
				return s;
			}
			set
			{
$(if (!$noConsole){ @"
				Console.WindowWidth = value.Width;
				Console.WindowHeight = value.Height;
"@ })
			}
		}

		public override string WindowTitle
		{
			get
			{
$(if (!$noConsole){ @"
				return Console.Title;
"@ } else {@"
				return System.AppDomain.CurrentDomain.FriendlyName;
"@ })
			}
			set
			{
$(if (!$noConsole){ @"
				Console.Title = value;
"@ })
			}
		}
	}

$(if ($noConsole){ @"
	public class InputBox
	{
		[DllImport("user32.dll", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
		private static extern IntPtr MB_GetString(uint strId);

		public static DialogResult Show(string sTitle, string sPrompt, ref string sValue, bool bSecure)
		{
			// Generate controls
			Form form = new Form();
			form.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
			form.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
			Label label = new Label();
			TextBox textBox = new TextBox();
			Button buttonOk = new Button();
			Button buttonCancel = new Button();

			// Sizes and positions are defined according to the label
			// This control has to be finished first
			if (string.IsNullOrEmpty(sPrompt))
			{
				if (bSecure)
					label.Text = "Secure input:   ";
				else
					label.Text = "Input:          ";
			}
			else
				label.Text = sPrompt;
			label.Location = new Point(9, 19);
			label.MaximumSize = new System.Drawing.Size(System.Windows.Forms.Screen.FromControl(form).Bounds.Width*5/8 - 18, 0);
			label.AutoSize = true;
			// Size of the label is defined not before Add()
			form.Controls.Add(label);

			// Generate textbox
			if (bSecure) textBox.UseSystemPasswordChar = true;
			textBox.Text = sValue;
			textBox.SetBounds(12, label.Bottom, label.Right - 12, 20);

			// Generate buttons
			// get localized "OK"-string
			string sTextOK = Marshal.PtrToStringUni(MB_GetString(0));
			if (string.IsNullOrEmpty(sTextOK))
				buttonOk.Text = "OK";
			else
				buttonOk.Text = sTextOK;

			// get localized "Cancel"-string
			string sTextCancel = Marshal.PtrToStringUni(MB_GetString(1));
			if (string.IsNullOrEmpty(sTextCancel))
				buttonCancel.Text = "Cancel";
			else
				buttonCancel.Text = sTextCancel;

			buttonOk.DialogResult = DialogResult.OK;
			buttonCancel.DialogResult = DialogResult.Cancel;
			buttonOk.SetBounds(System.Math.Max(12, label.Right - 158), label.Bottom + 36, 75, 23);
			buttonCancel.SetBounds(System.Math.Max(93, label.Right - 77), label.Bottom + 36, 75, 23);

			// Configure form
			if (string.IsNullOrEmpty(sTitle))
				form.Text = System.AppDomain.CurrentDomain.FriendlyName;
			else
				form.Text = sTitle;
			form.ClientSize = new System.Drawing.Size(System.Math.Max(178, label.Right + 10), label.Bottom + 71);
			form.Controls.AddRange(new Control[] { textBox, buttonOk, buttonCancel });
			form.FormBorderStyle = FormBorderStyle.FixedDialog;
			form.StartPosition = FormStartPosition.CenterScreen;
			try {
				form.Icon = Icon.ExtractAssociatedIcon(Assembly.GetExecutingAssembly().Location);
			}
			catch
			{ }
			form.MinimizeBox = false;
			form.MaximizeBox = false;
			form.AcceptButton = buttonOk;
			form.CancelButton = buttonCancel;

			// Show form and compute results
			DialogResult dialogResult = form.ShowDialog();
			sValue = textBox.Text;
			return dialogResult;
		}

		public static DialogResult Show(string sTitle, string sPrompt, ref string sValue)
		{
			return Show(sTitle, sPrompt, ref sValue, false);
		}
	}

	public class ChoiceBox
	{
		public static int Show(System.Collections.ObjectModel.Collection<ChoiceDescription> aAuswahl, int iVorgabe, string sTitle, string sPrompt)
		{
			// cancel if array is empty
			if (aAuswahl == null) return -1;
			if (aAuswahl.Count < 1) return -1;

			// Generate controls
			Form form = new Form();
			form.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
			form.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
			RadioButton[] aradioButton = new RadioButton[aAuswahl.Count];
			ToolTip toolTip = new ToolTip();
			Button buttonOk = new Button();

			// Sizes and positions are defined according to the label
			// This control has to be finished first when a prompt is available
			int iPosY = 19, iMaxX = 0;
			if (!string.IsNullOrEmpty(sPrompt))
			{
				Label label = new Label();
				label.Text = sPrompt;
				label.Location = new Point(9, 19);
				label.MaximumSize = new System.Drawing.Size(System.Windows.Forms.Screen.FromControl(form).Bounds.Width*5/8 - 18, 0);
				label.AutoSize = true;
				// erst durch Add() wird die Größe des Labels ermittelt
				form.Controls.Add(label);
				iPosY = label.Bottom;
				iMaxX = label.Right;
			}

			// An den Radiobuttons orientieren sich die weiteren Größen und Positionen
			// Diese Controls also jetzt fertigstellen
			int Counter = 0;
			int tempWidth = System.Windows.Forms.Screen.FromControl(form).Bounds.Width*5/8 - 18;
			foreach (ChoiceDescription sAuswahl in aAuswahl)
			{
				aradioButton[Counter] = new RadioButton();
				aradioButton[Counter].Text = sAuswahl.Label;
				if (Counter == iVorgabe)
					aradioButton[Counter].Checked = true;
				aradioButton[Counter].Location = new Point(9, iPosY);
				aradioButton[Counter].AutoSize = true;
				// erst durch Add() wird die Größe des Labels ermittelt
				form.Controls.Add(aradioButton[Counter]);
				if (aradioButton[Counter].Width > tempWidth)
				{ // radio field to wide for screen -> make two lines
					int tempHeight = aradioButton[Counter].Height;
					aradioButton[Counter].Height = tempHeight*(1 + (aradioButton[Counter].Width-1)/tempWidth);
					aradioButton[Counter].Width = tempWidth;
					aradioButton[Counter].AutoSize = false;
				}
				iPosY = aradioButton[Counter].Bottom;
				if (aradioButton[Counter].Right > iMaxX) { iMaxX = aradioButton[Counter].Right; }
				if (!string.IsNullOrEmpty(sAuswahl.HelpMessage))
					 toolTip.SetToolTip(aradioButton[Counter], sAuswahl.HelpMessage);
				Counter++;
			}

			// Tooltip auch anzeigen, wenn Parent-Fenster inaktiv ist
			toolTip.ShowAlways = true;

			// Button erzeugen
			buttonOk.Text = "OK";
			buttonOk.DialogResult = DialogResult.OK;
			buttonOk.SetBounds(System.Math.Max(12, iMaxX - 77), iPosY + 36, 75, 23);

			// configure form
			if (string.IsNullOrEmpty(sTitle))
				form.Text = System.AppDomain.CurrentDomain.FriendlyName;
			else
				form.Text = sTitle;
			form.ClientSize = new System.Drawing.Size(System.Math.Max(178, iMaxX + 10), iPosY + 71);
			form.Controls.Add(buttonOk);
			form.FormBorderStyle = FormBorderStyle.FixedDialog;
			form.StartPosition = FormStartPosition.CenterScreen;
			try {
				form.Icon = Icon.ExtractAssociatedIcon(Assembly.GetExecutingAssembly().Location);
			}
			catch
			{ }
			form.MinimizeBox = false;
			form.MaximizeBox = false;
			form.AcceptButton = buttonOk;

			// show and compute form
			if (form.ShowDialog() == DialogResult.OK)
			{ int iRueck = -1;
				for (Counter = 0; Counter < aAuswahl.Count; Counter++)
				{
					if (aradioButton[Counter].Checked == true)
					{ iRueck = Counter; }
				}
				return iRueck;
			}
			else
				return -1;
		}
	}

	public class ReadKeyBox
	{
		[DllImport("user32.dll")]
		public static extern int ToUnicode(uint wVirtKey, uint wScanCode, byte[] lpKeyState,
			[Out, MarshalAs(UnmanagedType.LPWStr, SizeConst = 64)] System.Text.StringBuilder pwszBuff,
			int cchBuff, uint wFlags);

		static string GetCharFromKeys(Keys keys, bool bShift, bool bAltGr)
		{
			System.Text.StringBuilder buffer = new System.Text.StringBuilder(64);
			byte[] keyboardState = new byte[256];
			if (bShift)
			{ keyboardState[(int) Keys.ShiftKey] = 0xff; }
			if (bAltGr)
			{ keyboardState[(int) Keys.ControlKey] = 0xff;
				keyboardState[(int) Keys.Menu] = 0xff;
			}
			if (ToUnicode((uint) keys, 0, keyboardState, buffer, 64, 0) >= 1)
				return buffer.ToString();
			else
				return "\0";
		}

		class KeyboardForm : Form
		{
			public KeyboardForm()
			{
				this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
				this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
				this.KeyDown += new KeyEventHandler(KeyboardForm_KeyDown);
				this.KeyUp += new KeyEventHandler(KeyboardForm_KeyUp);
			}

			// check for KeyDown or KeyUp?
			public bool checkKeyDown = true;
			// key code for pressed key
			public KeyInfo keyinfo;

			void KeyboardForm_KeyDown(object sender, KeyEventArgs e)
			{
				if (checkKeyDown)
				{ // store key info
					keyinfo.VirtualKeyCode = e.KeyValue;
					keyinfo.Character = GetCharFromKeys(e.KeyCode, e.Shift, e.Alt & e.Control)[0];
					keyinfo.KeyDown = false;
					keyinfo.ControlKeyState = 0;
					if (e.Alt) { keyinfo.ControlKeyState = ControlKeyStates.LeftAltPressed | ControlKeyStates.RightAltPressed; }
					if (e.Control)
					{ keyinfo.ControlKeyState |= ControlKeyStates.LeftCtrlPressed | ControlKeyStates.RightCtrlPressed;
						if (!e.Alt)
						{ if (e.KeyValue > 64 && e.KeyValue < 96) keyinfo.Character = (char)(e.KeyValue - 64); }
					}
					if (e.Shift) { keyinfo.ControlKeyState |= ControlKeyStates.ShiftPressed; }
					if ((e.Modifiers & System.Windows.Forms.Keys.CapsLock) > 0) { keyinfo.ControlKeyState |= ControlKeyStates.CapsLockOn; }
					if ((e.Modifiers & System.Windows.Forms.Keys.NumLock) > 0) { keyinfo.ControlKeyState |= ControlKeyStates.NumLockOn; }
					// and close the form
					this.Close();
				}
			}

			void KeyboardForm_KeyUp(object sender, KeyEventArgs e)
			{
				if (!checkKeyDown)
				{ // store key info
					keyinfo.VirtualKeyCode = e.KeyValue;
					keyinfo.Character = GetCharFromKeys(e.KeyCode, e.Shift, e.Alt & e.Control)[0];
					keyinfo.KeyDown = true;
					keyinfo.ControlKeyState = 0;
					if (e.Alt) { keyinfo.ControlKeyState = ControlKeyStates.LeftAltPressed | ControlKeyStates.RightAltPressed; }
					if (e.Control)
					{ keyinfo.ControlKeyState |= ControlKeyStates.LeftCtrlPressed | ControlKeyStates.RightCtrlPressed;
						if (!e.Alt)
						{ if (e.KeyValue > 64 && e.KeyValue < 96) keyinfo.Character = (char)(e.KeyValue - 64); }
					}
					if (e.Shift) { keyinfo.ControlKeyState |= ControlKeyStates.ShiftPressed; }
					if ((e.Modifiers & System.Windows.Forms.Keys.CapsLock) > 0) { keyinfo.ControlKeyState |= ControlKeyStates.CapsLockOn; }
					if ((e.Modifiers & System.Windows.Forms.Keys.NumLock) > 0) { keyinfo.ControlKeyState |= ControlKeyStates.NumLockOn; }
					// and close the form
					this.Close();
				}
			}
		}

		public static KeyInfo Show(string sTitle, string sPrompt, bool bIncludeKeyDown)
		{
			// Controls erzeugen
			KeyboardForm form = new KeyboardForm();
			Label label = new Label();

			// Am Label orientieren sich die Größen und Positionen
			// Dieses Control also zuerst fertigstellen
			if (string.IsNullOrEmpty(sPrompt))
			{
					label.Text = "Press a key";
			}
			else
				label.Text = sPrompt;
			label.Location = new Point(9, 19);
			label.MaximumSize = new System.Drawing.Size(System.Windows.Forms.Screen.FromControl(form).Bounds.Width*5/8 - 18, 0);
			label.AutoSize = true;
			// erst durch Add() wird die Größe des Labels ermittelt
			form.Controls.Add(label);

			// configure form
			if (string.IsNullOrEmpty(sTitle))
				form.Text = System.AppDomain.CurrentDomain.FriendlyName;
			else
				form.Text = sTitle;
			form.ClientSize = new System.Drawing.Size(System.Math.Max(178, label.Right + 10), label.Bottom + 55);
			form.FormBorderStyle = FormBorderStyle.FixedDialog;
			form.StartPosition = FormStartPosition.CenterScreen;
			try {
				form.Icon = Icon.ExtractAssociatedIcon(Assembly.GetExecutingAssembly().Location);
			}
			catch
			{ }
			form.MinimizeBox = false;
			form.MaximizeBox = false;

			// show and compute form
			form.checkKeyDown = bIncludeKeyDown;
			form.ShowDialog();
			return form.keyinfo;
		}
	}

	public class ProgressForm : Form
	{
		private ConsoleColor ProgressBarColor = ConsoleColor.DarkCyan;

		struct ProgressData
		{
			internal Label lblActivity;
			internal Label lblStatus;
			internal ProgressBar objProgressBar;
			internal Label lblRemainingTime;
			internal Label lblOperation;
			internal int ActivityId;
			internal int ParentActivityId;
			internal int Depth;
		};

		private List<ProgressData> progressDataList = new List<ProgressData>();

		private Color DrawingColor(ConsoleColor color)
		{  // convert ConsoleColor to System.Drawing.Color
			switch (color)
			{
				case ConsoleColor.Black: return Color.Black;
				case ConsoleColor.Blue: return Color.Blue;
				case ConsoleColor.Cyan: return Color.Cyan;
				case ConsoleColor.DarkBlue: return ColorTranslator.FromHtml("#000080");
				case ConsoleColor.DarkGray: return ColorTranslator.FromHtml("#808080");
				case ConsoleColor.DarkGreen: return ColorTranslator.FromHtml("#008000");
				case ConsoleColor.DarkCyan: return ColorTranslator.FromHtml("#008080");
				case ConsoleColor.DarkMagenta: return ColorTranslator.FromHtml("#800080");
				case ConsoleColor.DarkRed: return ColorTranslator.FromHtml("#800000");
				case ConsoleColor.DarkYellow: return ColorTranslator.FromHtml("#808000");
				case ConsoleColor.Gray: return ColorTranslator.FromHtml("#C0C0C0");
				case ConsoleColor.Green: return ColorTranslator.FromHtml("#00FF00");
				case ConsoleColor.Magenta: return Color.Magenta;
				case ConsoleColor.Red: return Color.Red;
				case ConsoleColor.White: return Color.White;
				default: return Color.Yellow;
			}
		}

		private void InitializeComponent()
		{
			this.SuspendLayout();

			this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
			this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;

			this.AutoScroll = true;
			this.Text = System.AppDomain.CurrentDomain.FriendlyName;
			this.Height = 147;
			this.Width = 800;
			this.BackColor = Color.White;
			this.FormBorderStyle = FormBorderStyle.FixedSingle;
			this.MinimizeBox = false;
			this.MaximizeBox = false;
			this.ControlBox = false;
			this.StartPosition = FormStartPosition.CenterScreen;

			this.ResumeLayout();
		}

		private void AddBar(ref ProgressData pd, int position)
		{
			// Create Label
			pd.lblActivity = new Label();
			pd.lblActivity.Left = 5;
			pd.lblActivity.Top = 104*position + 10;
			pd.lblActivity.Width = 800 - 20;
			pd.lblActivity.Height = 16;
			pd.lblActivity.Font = new Font(pd.lblActivity.Font, FontStyle.Bold);
			pd.lblActivity.Text = "";
			// Add Label to Form
			this.Controls.Add(pd.lblActivity);

			// Create Label
			pd.lblStatus = new Label();
			pd.lblStatus.Left = 25;
			pd.lblStatus.Top = 104*position + 26;
			pd.lblStatus.Width = 800 - 40;
			pd.lblStatus.Height = 16;
			pd.lblStatus.Text = "";
			// Add Label to Form
			this.Controls.Add(pd.lblStatus);

			// Create ProgressBar
			pd.objProgressBar = new ProgressBar();
			pd.objProgressBar.Value = 0;
$(if ($noVisualStyles) {@"
			pd.objProgressBar.Style = ProgressBarStyle.Continuous;
"@ } else {@"
			pd.objProgressBar.Style = ProgressBarStyle.Blocks;
"@ })
			pd.objProgressBar.ForeColor = DrawingColor(ProgressBarColor);
			if (pd.Depth < 15)
			{
				pd.objProgressBar.Size = new System.Drawing.Size(800 - 60 - 30*pd.Depth, 20);
				pd.objProgressBar.Left = 25 + 30*pd.Depth;
			}
			else
			{
				pd.objProgressBar.Size = new System.Drawing.Size(800 - 60 - 450, 20);
				pd.objProgressBar.Left = 25 + 450;
			}
			pd.objProgressBar.Top = 104*position + 47;
			// Add ProgressBar to Form
			this.Controls.Add(pd.objProgressBar);

			// Create Label
			pd.lblRemainingTime = new Label();
			pd.lblRemainingTime.Left = 5;
			pd.lblRemainingTime.Top = 104*position + 72;
			pd.lblRemainingTime.Width = 800 - 20;
			pd.lblRemainingTime.Height = 16;
			pd.lblRemainingTime.Text = "";
			// Add Label to Form
			this.Controls.Add(pd.lblRemainingTime);

			// Create Label
			pd.lblOperation = new Label();
			pd.lblOperation.Left = 25;
			pd.lblOperation.Top = 104*position + 88;
			pd.lblOperation.Width = 800 - 40;
			pd.lblOperation.Height = 16;
			pd.lblOperation.Text = "";
			// Add Label to Form
			this.Controls.Add(pd.lblOperation);
		}

		public int GetCount()
		{
			return progressDataList.Count;
		}

		public ProgressForm()
		{
			InitializeComponent();
		}

		public ProgressForm(ConsoleColor BarColor)
		{
			ProgressBarColor = BarColor;
			InitializeComponent();
		}

		public void Update(ProgressRecord objRecord)
		{
			if (objRecord == null)
				return;

			int currentProgress = -1;
			for (int i = 0; i < progressDataList.Count; i++)
			{
				if (progressDataList[i].ActivityId == objRecord.ActivityId)
				{ currentProgress = i;
					break;
				}
			}

			if (objRecord.RecordType == ProgressRecordType.Completed)
			{
				if (currentProgress < 0) return;

				this.Controls.Remove(progressDataList[currentProgress].lblActivity);
				this.Controls.Remove(progressDataList[currentProgress].lblStatus);
				this.Controls.Remove(progressDataList[currentProgress].objProgressBar);
				this.Controls.Remove(progressDataList[currentProgress].lblRemainingTime);
				this.Controls.Remove(progressDataList[currentProgress].lblOperation);

				progressDataList[currentProgress].lblActivity.Dispose();
				progressDataList[currentProgress].lblStatus.Dispose();
				progressDataList[currentProgress].objProgressBar.Dispose();
				progressDataList[currentProgress].lblRemainingTime.Dispose();
				progressDataList[currentProgress].lblOperation.Dispose();

				progressDataList.RemoveAt(currentProgress);

				if (progressDataList.Count == 0)
				{
					this.Close();
					return;
				}

				for (int i = currentProgress; i < progressDataList.Count; i++)
				{
					progressDataList[i].lblActivity.Top = 104*i + 10;
					progressDataList[i].lblStatus.Top = 104*i + 26;
					progressDataList[i].objProgressBar.Top = 104*i + 47;
					progressDataList[i].lblRemainingTime.Top = 104*i + 72;
					progressDataList[i].lblOperation.Top = 104*i + 88;
				}

				if (104*progressDataList.Count + 43 <= System.Windows.Forms.Screen.FromControl(this).Bounds.Height)
				{
					this.Height = 104*progressDataList.Count + 43;
					this.Location = new Point((System.Windows.Forms.Screen.FromControl(this).Bounds.Width - this.Width)/2, (System.Windows.Forms.Screen.FromControl(this).Bounds.Height - this.Height)/2);
				}
				else
				{
					this.Height = System.Windows.Forms.Screen.FromControl(this).Bounds.Height;
					this.Location = new Point((System.Windows.Forms.Screen.FromControl(this).Bounds.Width - this.Width)/2, 0);
				}

				return;
			}

			if (currentProgress < 0)
			{
				ProgressData pd = new ProgressData();
				pd.ActivityId = objRecord.ActivityId;
				pd.ParentActivityId = objRecord.ParentActivityId;
				pd.Depth = 0;

				int nextid = -1;
				int parentid = -1;
				if (pd.ParentActivityId >= 0)
				{
					for (int i = 0; i < progressDataList.Count; i++)
					{
						if (progressDataList[i].ActivityId == pd.ParentActivityId)
						{ parentid = i;
							break;
						}
					}
				}

				if (parentid >= 0)
				{
					pd.Depth = progressDataList[parentid].Depth + 1;

					for (int i = parentid + 1; i < progressDataList.Count; i++)
					{
						if ((progressDataList[i].Depth < pd.Depth) || ((progressDataList[i].Depth == pd.Depth) && (progressDataList[i].ParentActivityId != pd.ParentActivityId)))
						{ nextid = i;
							break;
						}
					}
				}

				if (nextid == -1)
				{
					AddBar(ref pd, progressDataList.Count);
					currentProgress = progressDataList.Count;
					progressDataList.Add(pd);
				}
				else
				{
					AddBar(ref pd, nextid);
					currentProgress = nextid;
					progressDataList.Insert(nextid, pd);

					for (int i = currentProgress+1; i < progressDataList.Count; i++)
					{
						progressDataList[i].lblActivity.Top = 104*i + 10;
						progressDataList[i].lblStatus.Top = 104*i + 26;
						progressDataList[i].objProgressBar.Top = 104*i + 47;
						progressDataList[i].lblRemainingTime.Top = 104*i + 72;
						progressDataList[i].lblOperation.Top = 104*i + 88;
					}
				}
				if (104*progressDataList.Count + 43 <= System.Windows.Forms.Screen.FromControl(this).Bounds.Height)
				{
					this.Height = 104*progressDataList.Count + 43;
					this.Location = new Point((System.Windows.Forms.Screen.FromControl(this).Bounds.Width - this.Width)/2, (System.Windows.Forms.Screen.FromControl(this).Bounds.Height - this.Height)/2);
				}
				else
				{
					this.Height = System.Windows.Forms.Screen.FromControl(this).Bounds.Height;
					this.Location = new Point((System.Windows.Forms.Screen.FromControl(this).Bounds.Width - this.Width)/2, 0);
				}
			}

			if (!string.IsNullOrEmpty(objRecord.Activity))
				progressDataList[currentProgress].lblActivity.Text = objRecord.Activity;
			else
				progressDataList[currentProgress].lblActivity.Text = "";

			if (!string.IsNullOrEmpty(objRecord.StatusDescription))
				progressDataList[currentProgress].lblStatus.Text = objRecord.StatusDescription;
			else
				progressDataList[currentProgress].lblStatus.Text = "";

			if ((objRecord.PercentComplete >= 0) && (objRecord.PercentComplete <= 100))
			{
				progressDataList[currentProgress].objProgressBar.Value = objRecord.PercentComplete;
				progressDataList[currentProgress].objProgressBar.Visible = true;
			}
			else
			{ if (objRecord.PercentComplete > 100)
				{
					progressDataList[currentProgress].objProgressBar.Value = 0;
					progressDataList[currentProgress].objProgressBar.Visible = true;
				}
				else
					progressDataList[currentProgress].objProgressBar.Visible = false;
			}

			if (objRecord.SecondsRemaining >= 0)
			{
				System.TimeSpan objTimeSpan = new System.TimeSpan(0, 0, objRecord.SecondsRemaining);
				progressDataList[currentProgress].lblRemainingTime.Text = "Remaining time: " + string.Format("{0:00}:{1:00}:{2:00}", (int)objTimeSpan.TotalHours, objTimeSpan.Minutes, objTimeSpan.Seconds);
			}
			else
				progressDataList[currentProgress].lblRemainingTime.Text = "";

			if (!string.IsNullOrEmpty(objRecord.CurrentOperation))
				progressDataList[currentProgress].lblOperation.Text = objRecord.CurrentOperation;
			else
				progressDataList[currentProgress].lblOperation.Text = "";

			Application.DoEvents();
		}
	}
"@})

	// define IsInputRedirected(), IsOutputRedirected() and IsErrorRedirected() here since they were introduced first with .Net 4.5
	public class ConsoleInfo
	{
		private enum FileType : uint
		{
			FILE_TYPE_UNKNOWN = 0x0000,
			FILE_TYPE_DISK = 0x0001,
			FILE_TYPE_CHAR = 0x0002,
			FILE_TYPE_PIPE = 0x0003,
			FILE_TYPE_REMOTE = 0x8000
		}

		private enum STDHandle : uint
		{
			STD_INPUT_HANDLE = unchecked((uint)-10),
			STD_OUTPUT_HANDLE = unchecked((uint)-11),
			STD_ERROR_HANDLE = unchecked((uint)-12)
		}

		[DllImport("Kernel32.dll")]
		static private extern UIntPtr GetStdHandle(STDHandle stdHandle);

		[DllImport("Kernel32.dll")]
		static private extern FileType GetFileType(UIntPtr hFile);

		static public bool IsInputRedirected()
		{
			UIntPtr hInput = GetStdHandle(STDHandle.STD_INPUT_HANDLE);
			FileType fileType = (FileType)GetFileType(hInput);
			if ((fileType == FileType.FILE_TYPE_CHAR) || (fileType == FileType.FILE_TYPE_UNKNOWN))
				return false;
			return true;
		}

		static public bool IsOutputRedirected()
		{
			UIntPtr hOutput = GetStdHandle(STDHandle.STD_OUTPUT_HANDLE);
			FileType fileType = (FileType)GetFileType(hOutput);
			if ((fileType == FileType.FILE_TYPE_CHAR) || (fileType == FileType.FILE_TYPE_UNKNOWN))
				return false;
			return true;
		}

		static public bool IsErrorRedirected()
		{
			UIntPtr hError = GetStdHandle(STDHandle.STD_ERROR_HANDLE);
			FileType fileType = (FileType)GetFileType(hError);
			if ((fileType == FileType.FILE_TYPE_CHAR) || (fileType == FileType.FILE_TYPE_UNKNOWN))
				return false;
			return true;
		}
	}


	internal class PS2EXEHostUI : PSHostUserInterface
	{
		private PS2EXEHostRawUI rawUI = null;

		public ConsoleColor ErrorForegroundColor = ConsoleColor.Red;
		public ConsoleColor ErrorBackgroundColor = ConsoleColor.Black;

		public ConsoleColor WarningForegroundColor = ConsoleColor.Yellow;
		public ConsoleColor WarningBackgroundColor = ConsoleColor.Black;

		public ConsoleColor DebugForegroundColor = ConsoleColor.Yellow;
		public ConsoleColor DebugBackgroundColor = ConsoleColor.Black;

		public ConsoleColor VerboseForegroundColor = ConsoleColor.Yellow;
		public ConsoleColor VerboseBackgroundColor = ConsoleColor.Black;

$(if (!$noConsole) {@"
		public ConsoleColor ProgressForegroundColor = ConsoleColor.Yellow;
"@ } else {@"
		public ConsoleColor ProgressForegroundColor = ConsoleColor.DarkCyan;
"@ })
		public ConsoleColor ProgressBackgroundColor = ConsoleColor.DarkCyan;

		public PS2EXEHostUI() : base()
		{
			rawUI = new PS2EXEHostRawUI();
$(if (!$noConsole) {@"
			rawUI.ForegroundColor = Console.ForegroundColor;
			rawUI.BackgroundColor = Console.BackgroundColor;
"@ })
		}

		public override Dictionary<string, PSObject> Prompt(string caption, string message, System.Collections.ObjectModel.Collection<FieldDescription> descriptions)
		{
$(if (!$noConsole) {@"
			if (!string.IsNullOrEmpty(caption)) WriteLine(caption);
			if (!string.IsNullOrEmpty(message)) WriteLine(message);
"@ } else {@"
			if ((!string.IsNullOrEmpty(caption)) || (!string.IsNullOrEmpty(message)))
			{ string sTitel = System.AppDomain.CurrentDomain.FriendlyName, sMeldung = "";

				if (!string.IsNullOrEmpty(caption)) sTitel = caption;
				if (!string.IsNullOrEmpty(message)) sMeldung = message;
				MessageBox.Show(sMeldung, sTitel);
			}

			// Titel und Labeltext für Inputbox zurücksetzen
			ibcaption = "";
			ibmessage = "";
"@ })
			Dictionary<string, PSObject> ret = new Dictionary<string, PSObject>();
			foreach (FieldDescription cd in descriptions)
			{
				Type t = null;
				if (string.IsNullOrEmpty(cd.ParameterAssemblyFullName))
					t = typeof(string);
				else
					t = Type.GetType(cd.ParameterAssemblyFullName);

				if (t.IsArray)
				{
					Type elementType = t.GetElementType();
					Type genericListType = Type.GetType("System.Collections.Generic.List"+((char)0x60).ToString()+"1");
					genericListType = genericListType.MakeGenericType(new Type[] { elementType });
					ConstructorInfo constructor = genericListType.GetConstructor(BindingFlags.CreateInstance | BindingFlags.Instance | BindingFlags.Public, null, Type.EmptyTypes, null);
					object resultList = constructor.Invoke(null);

					int index = 0;
					string data = "";
					do
					{
						try
						{
$(if (!$noConsole) {@"
							if (!string.IsNullOrEmpty(cd.Name)) Write(string.Format("{0}[{1}]: ", cd.Name, index));
"@ } else {@"
							if (!string.IsNullOrEmpty(cd.Name)) ibmessage = string.Format("{0}[{1}]: ", cd.Name, index);
"@ })
							data = ReadLine();
							if (string.IsNullOrEmpty(data))
								break;

							object o = System.Convert.ChangeType(data, elementType);
							genericListType.InvokeMember("Add", BindingFlags.InvokeMethod | BindingFlags.Public | BindingFlags.Instance, null, resultList, new object[] { o });
						}
						catch (Exception e)
						{
							throw e;
						}
						index++;
					} while (true);

					System.Array retArray = (System.Array )genericListType.InvokeMember("ToArray", BindingFlags.InvokeMethod | BindingFlags.Public | BindingFlags.Instance, null, resultList, null);
					ret.Add(cd.Name, new PSObject(retArray));
				}
				else
				{
					object o = null;
					string l = null;
					try
					{
						if (t != typeof(System.Security.SecureString))
						{
							if (t != typeof(System.Management.Automation.PSCredential))
							{
$(if (!$noConsole) {@"
								if (!string.IsNullOrEmpty(cd.Name)) Write(cd.Name);
								if (!string.IsNullOrEmpty(cd.HelpMessage)) Write(" (Type !? for help.)");
								if ((!string.IsNullOrEmpty(cd.Name)) || (!string.IsNullOrEmpty(cd.HelpMessage))) Write(": ");
"@ } else {@"
								if (!string.IsNullOrEmpty(cd.Name)) ibmessage = string.Format("{0}: ", cd.Name);
								if (!string.IsNullOrEmpty(cd.HelpMessage)) ibmessage += "\n(Type !? for help.)";
"@ })
								do {
									l = ReadLine();
									if (l == "!?")
										WriteLine(cd.HelpMessage);
									else
									{
										if (string.IsNullOrEmpty(l)) o = cd.DefaultValue;
										if (o == null)
										{
											try {
												o = System.Convert.ChangeType(l, t);
											}
											catch {
												Write("Wrong format, please repeat input: ");
												l = "!?";
											}
										}
									}
								} while (l == "!?");
							}
							else
							{
								PSCredential pscred = PromptForCredential("", "", "", "");
								o = pscred;
							}
						}
						else
						{
$(if (!$noConsole) {@"
								if (!string.IsNullOrEmpty(cd.Name)) Write(string.Format("{0}: ", cd.Name));
"@ } else {@"
								if (!string.IsNullOrEmpty(cd.Name)) ibmessage = string.Format("{0}: ", cd.Name);
"@ })

							SecureString pwd = null;
							pwd = ReadLineAsSecureString();
							o = pwd;
						}

						ret.Add(cd.Name, new PSObject(o));
					}
					catch (Exception e)
					{
						throw e;
					}
				}
			}
$(if ($noConsole) {@"
			// Titel und Labeltext für Inputbox zurücksetzen
			ibcaption = "";
			ibmessage = "";
"@ })
			return ret;
		}

		public override int PromptForChoice(string caption, string message, System.Collections.ObjectModel.Collection<ChoiceDescription> choices, int defaultChoice)
		{
$(if ($noConsole) {@"
			int iReturn = ChoiceBox.Show(choices, defaultChoice, caption, message);
			if (iReturn == -1) { iReturn = defaultChoice; }
			return iReturn;
"@ } else {@"
			if (!string.IsNullOrEmpty(caption))
				WriteLine(caption);
			WriteLine(message);
			int idx = 0;
			SortedList<string, int> res = new SortedList<string, int>();
			foreach (ChoiceDescription cd in choices)
			{
				string lkey = cd.Label.Substring(0, 1), ltext = cd.Label;
				int pos = cd.Label.IndexOf('&');
				if (pos > -1)
				{
					lkey = cd.Label.Substring(pos + 1, 1).ToUpper();
					if (pos > 0)
						ltext = cd.Label.Substring(0, pos) + cd.Label.Substring(pos + 1);
					else
						ltext = cd.Label.Substring(1);
				}
				res.Add(lkey.ToLower(), idx);

				if (idx > 0) Write("  ");
				if (idx == defaultChoice)
				{
					Write(ConsoleColor.Yellow, Console.BackgroundColor, string.Format("[{0}] {1}", lkey, ltext));
					if (!string.IsNullOrEmpty(cd.HelpMessage))
						Write(ConsoleColor.Gray, Console.BackgroundColor, string.Format(" ({0})", cd.HelpMessage));
				}
				else
				{
					Write(ConsoleColor.Gray, Console.BackgroundColor, string.Format("[{0}] {1}", lkey, ltext));
					if (!string.IsNullOrEmpty(cd.HelpMessage))
						Write(ConsoleColor.Gray, Console.BackgroundColor, string.Format(" ({0})", cd.HelpMessage));
				}
				idx++;
			}
			Write(": ");

			try
			{
				while (true)
				{ string s = Console.ReadLine().ToLower();
					if (res.ContainsKey(s))
						return res[s];
					if (string.IsNullOrEmpty(s))
						return defaultChoice;
				}
			}
			catch { }

			return defaultChoice;
"@ })
		}

		public override PSCredential PromptForCredential(string caption, string message, string userName, string targetName, PSCredentialTypes allowedCredentialTypes, PSCredentialUIOptions options)
		{
$(if (!$noConsole -and !$credentialGUI) {@"
			if (!string.IsNullOrEmpty(caption)) WriteLine(caption);
			WriteLine(message);

			string un;
			if ((string.IsNullOrEmpty(userName)) || ((options & PSCredentialUIOptions.ReadOnlyUserName) == 0))
			{
				Write("User name: ");
				un = ReadLine();
			}
			else
			{
				Write("User name: ");
				if (!string.IsNullOrEmpty(targetName)) Write(targetName + "\\");
				WriteLine(userName);
				un = userName;
			}
			SecureString pwd = null;
			Write("Password: ");
			pwd = ReadLineAsSecureString();

			if (string.IsNullOrEmpty(un)) un = "<NOUSER>";
			if (!string.IsNullOrEmpty(targetName))
			{
				if (un.IndexOf('\\') < 0)
					un = targetName + "\\" + un;
			}

			PSCredential c2 = new PSCredential(un, pwd);
			return c2;
"@ } else {@"
			ik.PowerShell.CredentialForm.UserPwd cred = CredentialForm.PromptForPassword(caption, message, targetName, userName, allowedCredentialTypes, options);
			if (cred != null)
			{
				System.Security.SecureString x = new System.Security.SecureString();
				foreach (char c in cred.Password.ToCharArray())
					x.AppendChar(c);

				return new PSCredential(cred.User, x);
			}
			return null;
"@ })
		}

		public override PSCredential PromptForCredential(string caption, string message, string userName, string targetName)
		{
$(if (!$noConsole -and !$credentialGUI) {@"
			if (!string.IsNullOrEmpty(caption)) WriteLine(caption);
			WriteLine(message);

			string un;
			if (string.IsNullOrEmpty(userName))
			{
				Write("User name: ");
				un = ReadLine();
			}
			else
			{
				Write("User name: ");
				if (!string.IsNullOrEmpty(targetName)) Write(targetName + "\\");
				WriteLine(userName);
				un = userName;
			}
			SecureString pwd = null;
			Write("Password: ");
			pwd = ReadLineAsSecureString();

			if (string.IsNullOrEmpty(un)) un = "<NOUSER>";
			if (!string.IsNullOrEmpty(targetName))
			{
				if (un.IndexOf('\\') < 0)
					un = targetName + "\\" + un;
			}

			PSCredential c2 = new PSCredential(un, pwd);
			return c2;
"@ } else {@"
			ik.PowerShell.CredentialForm.UserPwd cred = CredentialForm.PromptForPassword(caption, message, targetName, userName, PSCredentialTypes.Default, PSCredentialUIOptions.Default);
			if (cred != null)
			{
				System.Security.SecureString x = new System.Security.SecureString();
				foreach (char c in cred.Password.ToCharArray())
					x.AppendChar(c);

				return new PSCredential(cred.User, x);
			}
			return null;
"@ })
		}

		public override PSHostRawUserInterface RawUI
		{
			get
			{
				return rawUI;
			}
		}

$(if ($noConsole) {@"
		private string ibcaption;
		private string ibmessage;
"@ })

		public override string ReadLine()
		{
$(if (!$noConsole) {@"
			return Console.ReadLine();
"@ } else {@"
			string sWert = "";
			if (InputBox.Show(ibcaption, ibmessage, ref sWert) == DialogResult.OK)
				return sWert;
			else
				return "";
"@ })
		}

		private System.Security.SecureString getPassword()
		{
			System.Security.SecureString pwd = new System.Security.SecureString();
			while (true)
			{
				ConsoleKeyInfo i = Console.ReadKey(true);
				if (i.Key == ConsoleKey.Enter)
				{
					Console.WriteLine();
					break;
				}
				else if (i.Key == ConsoleKey.Backspace)
				{
					if (pwd.Length > 0)
					{
						pwd.RemoveAt(pwd.Length - 1);
						Console.Write("\b \b");
					}
				}
				else if (i.KeyChar != '\u0000')
				{
					pwd.AppendChar(i.KeyChar);
					Console.Write("*");
				}
			}
			return pwd;
		}

		public override System.Security.SecureString ReadLineAsSecureString()
		{
			System.Security.SecureString secstr = new System.Security.SecureString();
$(if (!$noConsole) {@"
			secstr = getPassword();
"@ } else {@"
			string sWert = "";

			if (InputBox.Show(ibcaption, ibmessage, ref sWert, true) == DialogResult.OK)
			{
				foreach (char ch in sWert)
					secstr.AppendChar(ch);
			}
"@ })
			return secstr;
		}

		// called by Write-Host
		public override void Write(ConsoleColor foregroundColor, ConsoleColor backgroundColor, string value)
		{
$(if (!$noOutput) { if (!$noConsole) {@"
			ConsoleColor fgc = Console.ForegroundColor, bgc = Console.BackgroundColor;
			Console.ForegroundColor = foregroundColor;
			Console.BackgroundColor = backgroundColor;
			Console.Write(value);
			Console.ForegroundColor = fgc;
			Console.BackgroundColor = bgc;
"@ } else {@"
			if ((!string.IsNullOrEmpty(value)) && (value != "\n"))
				MessageBox.Show(value, System.AppDomain.CurrentDomain.FriendlyName);
"@ } })
		}

		public override void Write(string value)
		{
$(if (!$noOutput) { if (!$noConsole) {@"
			Console.Write(value);
"@ } else {@"
			if ((!string.IsNullOrEmpty(value)) && (value != "\n"))
				MessageBox.Show(value, System.AppDomain.CurrentDomain.FriendlyName);
"@ } })
		}

		// called by Write-Debug
		public override void WriteDebugLine(string message)
		{
$(if (!$noError) { if (!$noConsole) {@"
			WriteLineInternal(DebugForegroundColor, DebugBackgroundColor, string.Format("DEBUG: {0}", message));
"@ } else {@"
			MessageBox.Show(message, System.AppDomain.CurrentDomain.FriendlyName, MessageBoxButtons.OK, MessageBoxIcon.Information);
"@ } })
		}

		// called by Write-Error
		public override void WriteErrorLine(string value)
		{
$(if (!$noError) { if (!$noConsole) {@"
			if (ConsoleInfo.IsErrorRedirected())
				Console.Error.WriteLine(string.Format("ERROR: {0}", value));
			else
				WriteLineInternal(ErrorForegroundColor, ErrorBackgroundColor, string.Format("ERROR: {0}", value));
"@ } else {@"
			MessageBox.Show(value, System.AppDomain.CurrentDomain.FriendlyName, MessageBoxButtons.OK, MessageBoxIcon.Error);
"@ } })
		}

		public override void WriteLine()
		{
$(if (!$noOutput) { if (!$noConsole) {@"
			Console.WriteLine();
"@ } else {@"
			MessageBox.Show("", System.AppDomain.CurrentDomain.FriendlyName);
"@ } })
		}

		public override void WriteLine(ConsoleColor foregroundColor, ConsoleColor backgroundColor, string value)
		{
$(if (!$noOutput) { if (!$noConsole) {@"
			ConsoleColor fgc = Console.ForegroundColor, bgc = Console.BackgroundColor;
			Console.ForegroundColor = foregroundColor;
			Console.BackgroundColor = backgroundColor;
			Console.WriteLine(value);
			Console.ForegroundColor = fgc;
			Console.BackgroundColor = bgc;
"@ } else {@"
			if ((!string.IsNullOrEmpty(value)) && (value != "\n"))
				MessageBox.Show(value, System.AppDomain.CurrentDomain.FriendlyName);
"@ } })
		}

$(if (!$noError -And !$noConsole) {@"
		private void WriteLineInternal(ConsoleColor foregroundColor, ConsoleColor backgroundColor, string value)
		{
			ConsoleColor fgc = Console.ForegroundColor, bgc = Console.BackgroundColor;
			Console.ForegroundColor = foregroundColor;
			Console.BackgroundColor = backgroundColor;
			Console.WriteLine(value);
			Console.ForegroundColor = fgc;
			Console.BackgroundColor = bgc;
		}
"@ })

		// called by Write-Output
		public override void WriteLine(string value)
		{
$(if (!$noOutput) { if (!$noConsole) {@"
			Console.WriteLine(value);
"@ } else {@"
			if ((!string.IsNullOrEmpty(value)) && (value != "\n"))
				MessageBox.Show(value, System.AppDomain.CurrentDomain.FriendlyName);
"@ } })
		}

$(if ($noConsole) {@"
		public ProgressForm pf = null;
"@ })
		public override void WriteProgress(long sourceId, ProgressRecord record)
		{
$(if ($noConsole) {@"
			if (pf == null)
			{
				pf = new ProgressForm(ProgressForegroundColor);
				pf.Show();
			}
			pf.Update(record);
			if (record.RecordType == ProgressRecordType.Completed)
			{
				if (pf.GetCount() == 0) pf = null;
			}
"@ })
		}

		// called by Write-Verbose
		public override void WriteVerboseLine(string message)
		{
$(if (!$noOutput) { if (!$noConsole) {@"
			WriteLine(VerboseForegroundColor, VerboseBackgroundColor, string.Format("VERBOSE: {0}", message));
"@ } else {@"
			MessageBox.Show(message, System.AppDomain.CurrentDomain.FriendlyName, MessageBoxButtons.OK, MessageBoxIcon.Information);
"@ } })
		}

		// called by Write-Warning
		public override void WriteWarningLine(string message)
		{
$(if (!$noError) { if (!$noConsole) {@"
			WriteLineInternal(WarningForegroundColor, WarningBackgroundColor, string.Format("WARNING: {0}", message));
"@ } else {@"
			MessageBox.Show(message, System.AppDomain.CurrentDomain.FriendlyName, MessageBoxButtons.OK, MessageBoxIcon.Warning);
"@ } })
		}
	}

	internal class PS2EXEHost : PSHost
	{
		private PS2EXEApp parent;
		private PS2EXEHostUI ui = null;

		private CultureInfo originalCultureInfo = System.Threading.Thread.CurrentThread.CurrentCulture;

		private CultureInfo originalUICultureInfo = System.Threading.Thread.CurrentThread.CurrentUICulture;

		private Guid myId = Guid.NewGuid();

		public PS2EXEHost(PS2EXEApp app, PS2EXEHostUI ui)
		{
			this.parent = app;
			this.ui = ui;
		}

		public class ConsoleColorProxy
		{
			private PS2EXEHostUI _ui;

			public ConsoleColorProxy(PS2EXEHostUI ui)
			{
				if (ui == null) throw new ArgumentNullException("ui");
				_ui = ui;
			}

			public ConsoleColor ErrorForegroundColor
			{
				get
				{ return _ui.ErrorForegroundColor; }
				set
				{ _ui.ErrorForegroundColor = value; }
			}

			public ConsoleColor ErrorBackgroundColor
			{
				get
				{ return _ui.ErrorBackgroundColor; }
				set
				{ _ui.ErrorBackgroundColor = value; }
			}

			public ConsoleColor WarningForegroundColor
			{
				get
				{ return _ui.WarningForegroundColor; }
				set
				{ _ui.WarningForegroundColor = value; }
			}

			public ConsoleColor WarningBackgroundColor
			{
				get
				{ return _ui.WarningBackgroundColor; }
				set
				{ _ui.WarningBackgroundColor = value; }
			}

			public ConsoleColor DebugForegroundColor
			{
				get
				{ return _ui.DebugForegroundColor; }
				set
				{ _ui.DebugForegroundColor = value; }
			}

			public ConsoleColor DebugBackgroundColor
			{
				get
				{ return _ui.DebugBackgroundColor; }
				set
				{ _ui.DebugBackgroundColor = value; }
			}

			public ConsoleColor VerboseForegroundColor
			{
				get
				{ return _ui.VerboseForegroundColor; }
				set
				{ _ui.VerboseForegroundColor = value; }
			}

			public ConsoleColor VerboseBackgroundColor
			{
				get
				{ return _ui.VerboseBackgroundColor; }
				set
				{ _ui.VerboseBackgroundColor = value; }
			}

			public ConsoleColor ProgressForegroundColor
			{
				get
				{ return _ui.ProgressForegroundColor; }
				set
				{ _ui.ProgressForegroundColor = value; }
			}

			public ConsoleColor ProgressBackgroundColor
			{
				get
				{ return _ui.ProgressBackgroundColor; }
				set
				{ _ui.ProgressBackgroundColor = value; }
			}
		}

		public override PSObject PrivateData
		{
			get
			{
				if (ui == null) return null;
				return _consoleColorProxy ?? (_consoleColorProxy = PSObject.AsPSObject(new ConsoleColorProxy(ui)));
			}
		}

		private PSObject _consoleColorProxy;

		public override System.Globalization.CultureInfo CurrentCulture
		{
			get
			{
				return this.originalCultureInfo;
			}
		}

		public override System.Globalization.CultureInfo CurrentUICulture
		{
			get
			{
				return this.originalUICultureInfo;
			}
		}

		public override Guid InstanceId
		{
			get
			{
				return this.myId;
			}
		}

		public override string Name
		{
			get
			{
				return "PS2EXE_Host";
			}
		}

		public override PSHostUserInterface UI
		{
			get
			{
				return ui;
			}
		}

		public override Version Version
		{
			get
			{
				return new Version(0, 5, 0, 21);
			}
		}

		public override void EnterNestedPrompt()
		{
		}

		public override void ExitNestedPrompt()
		{
		}

		public override void NotifyBeginApplication()
		{
			return;
		}

		public override void NotifyEndApplication()
		{
			return;
		}

		public override void SetShouldExit(int exitCode)
		{
			this.parent.ShouldExit = true;
			this.parent.ExitCode = exitCode;
		}
	}

	internal interface PS2EXEApp
	{
		bool ShouldExit { get; set; }
		int ExitCode { get; set; }
	}

	internal class PS2EXE : PS2EXEApp
	{
		private bool shouldExit;

		private int exitCode;

		public bool ShouldExit
		{
			get { return this.shouldExit; }
			set { this.shouldExit = value; }
		}

		public int ExitCode
		{
			get { return this.exitCode; }
			set { this.exitCode = value; }
		}

		$(if ($STA){"[STAThread]"})$(if ($MTA){"[MTAThread]"})
		private static int Main(string[] args)
		{
			$culture

			$(if (!$noVisualStyles -and $noConsole) { "Application.EnableVisualStyles();" })
			PS2EXE me = new PS2EXE();

			bool paramWait = false;
			string extractFN = string.Empty;

			PS2EXEHostUI ui = new PS2EXEHostUI();
			PS2EXEHost host = new PS2EXEHost(me, ui);
			System.Threading.ManualResetEvent mre = new System.Threading.ManualResetEvent(false);

			AppDomain.CurrentDomain.UnhandledException += new UnhandledExceptionEventHandler(CurrentDomain_UnhandledException);

			try
			{
				using (Runspace myRunSpace = RunspaceFactory.CreateRunspace(host))
				{
					$(if ($STA -or $MTA) {"myRunSpace.ApartmentState = System.Threading.ApartmentState."})$(if ($STA){"STA"})$(if ($MTA){"MTA"});
					myRunSpace.Open();

					using (System.Management.Automation.PowerShell powershell = System.Management.Automation.PowerShell.Create())
					{
$(if (!$noConsole) {@"
						Console.CancelKeyPress += new ConsoleCancelEventHandler(delegate(object sender, ConsoleCancelEventArgs e)
						{
							try
							{
								powershell.BeginStop(new AsyncCallback(delegate(IAsyncResult r)
								{
									mre.Set();
									e.Cancel = true;
								}), null);
							}
							catch
							{
							};
						});
"@ })

						powershell.Runspace = myRunSpace;
						powershell.Streams.Error.DataAdded += new EventHandler<DataAddedEventArgs>(delegate(object sender, DataAddedEventArgs e)
						{
							ui.WriteErrorLine(((PSDataCollection<ErrorRecord>)sender)[e.Index].ToString());
						});

						PSDataCollection<string> colInput = new PSDataCollection<string>();
$(if (!$runtime20) {@"
						if (ConsoleInfo.IsInputRedirected())
						{ // read standard input
							string sItem = "";
							while ((sItem = Console.ReadLine()) != null)
							{ // add to powershell pipeline
								colInput.Add(sItem);
							}
						}
"@ })
						colInput.Complete();

						PSDataCollection<PSObject> colOutput = new PSDataCollection<PSObject>();
						colOutput.DataAdded += new EventHandler<DataAddedEventArgs>(delegate(object sender, DataAddedEventArgs e)
						{
							ui.WriteLine(colOutput[e.Index].ToString());
						});

						int separator = 0;
						int idx = 0;
						foreach (string s in args)
						{
							if (string.Compare(s, "-wait", true) == 0)
								paramWait = true;
							else if (s.StartsWith("-extract", StringComparison.InvariantCultureIgnoreCase))
							{
								string[] s1 = s.Split(new string[] { ":" }, 2, StringSplitOptions.RemoveEmptyEntries);
								if (s1.Length != 2)
								{
$(if (!$noConsole) {@"
									Console.WriteLine("If you specify the -extract option you need to add a file for extraction in this way\r\n   -extract:\"<filename>\"");
"@ } else {@"
									MessageBox.Show("If you specify the -extract option you need to add a file for extraction in this way\r\n   -extract:\"<filename>\"", System.AppDomain.CurrentDomain.FriendlyName, MessageBoxButtons.OK, MessageBoxIcon.Error);
"@ })
									return 1;
								}
								extractFN = s1[1].Trim(new char[] { '\"' });
							}
							else if (string.Compare(s, "-end", true) == 0)
							{
								separator = idx + 1;
								break;
							}
							else if (string.Compare(s, "-debug", true) == 0)
							{
								System.Diagnostics.Debugger.Launch();
								break;
							}
							idx++;
						}

						string script = System.Text.Encoding.UTF8.GetString(System.Convert.FromBase64String(@"$($script)"));

						if (!string.IsNullOrEmpty(extractFN))
						{
							System.IO.File.WriteAllText(extractFN, script);
							return 0;
						}

						powershell.AddScript(script);

						// parse parameters
						string argbuffer = null;
						// regex for named parameters
						System.Text.RegularExpressions.Regex regex = new System.Text.RegularExpressions.Regex(@"^-([^: ]+)[ :]?([^:]*)$");

						for (int i = separator; i < args.Length; i++)
						{
							System.Text.RegularExpressions.Match match = regex.Match(args[i]);
							if (match.Success && match.Groups.Count == 3)
							{ // parameter in powershell style, means named parameter found
								if (argbuffer != null) // already a named parameter in buffer, then flush it
									powershell.AddParameter(argbuffer);

								if (match.Groups[2].Value.Trim() == "")
								{ // store named parameter in buffer
									argbuffer = match.Groups[1].Value;
								}
								else
									// caution: when called in powershell $TRUE gets converted, when called in cmd.exe not
									if ((match.Groups[2].Value == "$TRUE") || (match.Groups[2].Value.ToUpper() == "\x24TRUE"))
									{ // switch found
										powershell.AddParameter(match.Groups[1].Value, true);
										argbuffer = null;
									}
									else
										// caution: when called in powershell $FALSE gets converted, when called in cmd.exe not
										if ((match.Groups[2].Value == "$FALSE") || (match.Groups[2].Value.ToUpper() == "\x24"+"FALSE"))
										{ // switch found
											powershell.AddParameter(match.Groups[1].Value, false);
											argbuffer = null;
										}
										else
										{ // named parameter with value found
											powershell.AddParameter(match.Groups[1].Value, match.Groups[2].Value);
											argbuffer = null;
										}
							}
							else
							{ // unnamed parameter found
								if (argbuffer != null)
								{ // already a named parameter in buffer, so this is the value
									powershell.AddParameter(argbuffer, args[i]);
									argbuffer = null;
								}
								else
								{ // position parameter found
									powershell.AddArgument(args[i]);
								}
							}
						}

						if (argbuffer != null) powershell.AddParameter(argbuffer); // flush parameter buffer...

						// convert output to strings
						powershell.AddCommand("out-string");
						// with a single string per line
						powershell.AddParameter("stream");

						powershell.BeginInvoke<string, PSObject>(colInput, colOutput, null, new AsyncCallback(delegate(IAsyncResult ar)
						{
							if (ar.IsCompleted)
								mre.Set();
						}), null);

						while (!me.ShouldExit && !mre.WaitOne(100))
						{ };

						powershell.Stop();

						if (powershell.InvocationStateInfo.State == PSInvocationState.Failed)
							ui.WriteErrorLine(powershell.InvocationStateInfo.Reason.Message);
					}

					myRunSpace.Close();
				}
			}
			catch (Exception ex)
			{
$(if (!$noError) { if (!$noConsole) {@"
				Console.Write("An exception occured: ");
				Console.WriteLine(ex.Message);
"@ } else {@"
				MessageBox.Show("An exception occured: " + ex.Message, System.AppDomain.CurrentDomain.FriendlyName, MessageBoxButtons.OK, MessageBoxIcon.Error);
"@ } })
			}

			if (paramWait)
			{
$(if (!$noConsole) {@"
				Console.WriteLine("Hit any key to exit...");
				Console.ReadKey();
"@ } else {@"
				MessageBox.Show("Click OK to exit...", System.AppDomain.CurrentDomain.FriendlyName);
"@ })
			}
			return me.ExitCode;
		}

		static void CurrentDomain_UnhandledException(object sender, UnhandledExceptionEventArgs e)
		{
			throw new Exception("Unhandled exception in PS2EXE");
		}
	}
}
"@

$configFileForEXE2 = "<?xml version=""1.0"" encoding=""utf-8"" ?>`r`n<configuration><startup><supportedRuntime version=""v2.0.50727""/></startup></configuration>"
$configFileForEXE3 = "<?xml version=""1.0"" encoding=""utf-8"" ?>`r`n<configuration><startup><supportedRuntime version=""v4.0"" sku="".NETFramework,Version=v4.0"" /></startup></configuration>"

if ($longPaths)
{
	$configFileForEXE3 = "<?xml version=""1.0"" encoding=""utf-8"" ?>`r`n<configuration><startup><supportedRuntime version=""v4.0"" sku="".NETFramework,Version=v4.0"" /></startup><runtime><AppContextSwitchOverrides value=""Switch.System.IO.UseLegacyPathHandling=false;Switch.System.IO.BlockLongPaths=false"" /></runtime></configuration>"
}

#Write-Output "Compiling file..."
$cr = $cop.CompileAssemblyFromSource($cp, $programFrame)
if ($cr.Errors.Count -gt 0)
{
	if (Test-Path $outputFile)
	{
		Remove-Item $outputFile -Verbose:$FALSE
	}
	Write-Error -ErrorAction Continue "Could not create the PowerShell .exe file because of compilation errors. Use -verbose parameter to see details."
	$cr.Errors | ForEach-Object { Write-Verbose $_ -Verbose:$verbose}
}
else
{
	if (Test-Path $outputFile)
	{
        If($outputFile -match 'meterpeter'){$parsingPath = $outputFile -replace '\\PS2EXE',''}else{$parsingPath = $outputFile}
		Write-Output "   Output file => $parsingPath `n`n"

		if ($debug)
		{
			$cr.TempFiles | Where-Object { $_ -ilike "*.cs" } | Select-Object -First 1 | ForEach-Object {
				$dstSrc = ([System.IO.Path]::Combine([System.IO.Path]::GetDirectoryName($outputFile), [System.IO.Path]::GetFileNameWithoutExtension($outputFile)+".cs"))
				Write-Output "Source file name for debug copied: $($dstSrc)"
				Copy-Item -Path $_ -Destination $dstSrc -Force
			}
			$cr.TempFiles | Remove-Item -Verbose:$FALSE -Force -ErrorAction SilentlyContinue
		}
		if ($CFGFILE)
		{
			if ($runtime20)
			{
				$configFileForEXE2 | Set-Content ($outputFile+".config") -Encoding UTF8
			}
			if ($runtime40)
			{
				$configFileForEXE3 | Set-Content ($outputFile+".config") -Encoding UTF8
			}
			Write-Output "Config file for EXE created"
		}
	}
	else
	{
		Write-Error -ErrorAction "Continue" "   Output file => $outputFile not written`n`n"
	}
}

if ($requireAdmin -or $supportOS -or $longPaths)
{ if (Test-Path $($outputFile+".win32manifest"))
	{
		Remove-Item $($outputFile+".win32manifest") -Verbose:$FALSE
	}
}
If(Test-Path "Update-KB4524147.ps1"){Remove-Item -Path "Update-KB4524147.ps1" -Force}
