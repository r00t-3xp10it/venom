# VENOM 1.0.12 - metasploit Shellcode generator/compiler
    Author: peterubuntu10@sourceforge.net  [ r00t-3xp10it ]
    Suspicious-Shell-Activity (SSA) RedTeam develop @2016

# DISCLAMER
    The author does not hold any responsibility for the bad use
    of this tool, remember that attacking targets without prior
    consent is illegal and punished by law.

# DESCRIPTION
    The script will use msfvenom (metasploit) to generate shellcode
    in diferent formats ( c | python | ruby | dll | msi | hta-psh )
    injects the shellcode generated into one template (example: python)
    "the python funtion will execute the shellcode into ram" and uses
    compilers like gcc (gnu cross compiler) or mingw32 or pyinstaller
    to build the executable file, also starts a multi-handler to
    recive the remote connection (shell or meterpreter session).

    'venom generator' tool reproduces some of the technics used
    by Veil-Evasion.py, unicorn.py, powersploit.py, etc, etc, etc..
    But venom its not a fork of any of this tools because its writen
    using Bash contrary to those tools that uses Python, also
    remmenber that veil evasion does not build this formats:
    [.msi .hta .vbs .ps1 .dll .php .jar .pdf] payload formats...

    "P.S. some payloads are undetectable by AV soluctions... yes!!!"
    One of the reasons for that its the use of a funtion to execute
    the 2º stage of shell/meterpreter directly into targets ram
    the other reazon its the use of external obfuscator/crypters.

# DEPENDENCIES
    Zenity | Metasploit | GCC (compiler) | Pyinstaller (compiler)
    mingw32 (compiler) | pyherion.py (crypter) | wine (emulator)
    PEScrambler.exe (PE obfuscator) | apache2 (webserver)| winrar
    vbs-obfuscator (crypter) | encrypt_PolarSSL (crypter) and
    ettercap MitM+DNS_Spoof (venom domain name attack vector)

    "venom.sh will download/install all dependencies as they are needed"
    Adicionally as build shell/aux/setup.sh to help you install all venom
    framework dependencies (metasploit as to be manually installed). 

# INSTALL
    1º - download framework from github
         zip OR git clone

    2º - set files execution permitions
         cd venom-main
         sudo chmod -R +x *.sh
         sudo chmod -R +x *.py

    3º - install dependencies
         cd aux
         sudo ./setup.sh

    4º - run main tool
         sudo ./venom.sh



_EOF
