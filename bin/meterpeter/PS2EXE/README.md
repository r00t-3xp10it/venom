### ⚙️ PS2EXE BY: Ingo Karstein | MScholtes

- Description: Script to convert powershell scripts to standalone executables<br />
- Source     :https://gallery.technet.microsoft.com/scriptcenter/PS2EXE-GUI-Convert-e7cb69d5<br /><br />

`meterpeter users can use this script (manually) to convert the Client.ps1 to Client.exe`<br /><br />

- 1º - Copy **`'Update-KB4524147.ps1'`** build by meterpeter C2 to **`'PS2EXE'`** directory.
- 2º - Open Powershell terminal console in **`'PS2EXE'`** directory (none admin privs required)
- 3º - Execute the follow command to convert the Client.ps1 to standalone executable<br />

```
.\ps2exe.ps1 -inputFile 'Update-KB4524147.ps1' -outputFile 'Update-KB4524147.exe' -iconFile 'meterpeter.ico' -title 'meterpeter binary file' -version '2.10.6' -description 'meterpeter binary file' -product 'meterpeter C2 Client' -company 'Microsoft Corporation' -copyright '©Microsoft Corporation. All Rights Reserved' -noConsole -noVisualStyles -noError
```

![final](https://user-images.githubusercontent.com/23490060/88741165-d75f2f00-d136-11ea-8761-28b690f0ddf3.png)

**`REMARK:`** Client.exe (created by PS2EXEC) migth **malfunction** with meterpeter **mimiratz scripts**.

---

<br />

**Syntax:**
```
    ps2exe.ps1 [-inputFile] '<file_name>' [[-outputFile] '<file_name>'] [-verbose]
               [-debug] [-runtime20|-runtime40] [-lcid <id>] [-x86|-x64] [-STA|-MTA] [-noConsole]
               [-credentialGUI] [-iconFile '<filename>'] [-title '<title>'] [-description '<description>']
               [-company '<company>'] [-product '<product>'] [-copyright '<copyright>'] [-trademark '<trademark>']
               [-version '<version>'] [-configFile] [-noOutput] [-noError] [-noVisualStyles] [-requireAdmin]
               [-supportOS] [-virtualize] [-longPaths]

     inputFile = Powershell script that you want to convert to executable
    outputFile = destination executable file name, defaults to inputFile with extension '.exe'
     runtime20 = this switch forces PS2EXE to create a config file for the generated executable that contains the
                 "supported .NET Framework versions" setting for .NET Framework 2.0/3.x for PowerShell 2.0
     runtime40 = this switch forces PS2EXE to create a config file for the generated executable that contains the
                 "supported .NET Framework versions" setting for .NET Framework 4.x for PowerShell 3.0 or higher
    x86 or x64 = compile for 32-bit or 64-bit runtime only
          lcid = location ID for the compiled executable. Current user culture if not specified
    STA or MTA = 'Single Thread Apartment' or 'Multi Thread Apartment' mode
     noConsole = the resulting executable will be a Windows Forms app without a console window
 credentialGUI = use GUI for prompting credentials in console mode
      iconFile = icon file name for the compiled executable
         title = title information (displayed in details tab of Windows Explorer's properties dialog)
   description = description information (not displayed, but embedded in executable)
       company = company information (not displayed, but embedded in executable)
       product = product information (displayed in details tab of Windows Explorer's properties dialog)
     copyright = copyright information (displayed in details tab of Windows Explorer's properties dialog)
     trademark = trademark information (displayed in details tab of Windows Explorer's properties dialog)
       version = version information (displayed in details tab of Windows Explorer's properties dialog)
    configFile = write config file (<outputfile>.exe.config)
      noOutput = the resulting executable will generate no standard output (includes verbose and information channel)
       noError = the resulting executable will generate no error output (includes warning and debug channel)
noVisualStyles = disable visual styles for a generated windows GUI application (only with -noConsole)
  requireAdmin = if UAC is enabled, compiled executable run only in elevated context (UAC dialog appears if required)
     supportOS = use functions of newest Windows versions (execute [Environment]::OSVersion to see the difference)
   virtualize = application virtualization is activated (forcing x86 runtime)
     longPaths = enable long paths ( > 260 characters) if enabled on OS (works only with Windows 10)

```
