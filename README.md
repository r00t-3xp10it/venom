[![Version](https://img.shields.io/badge/VENOM-1.0.14-brightgreen.svg?maxAge=259200)]()
[![Stage](https://img.shields.io/badge/Release-Beta-brightgreen.svg)]()
[![Build](https://img.shields.io/badge/Supported_OS-Linux-orange.svg)]()
[![AUR](https://img.shields.io/aur/license/yaourt.svg)]()

## VENOM 1.0.14 - metasploit Shellcode generator/compiller
    Version release : v1.0.14
    Author : pedro ubuntu  [ r00t-3xp10it ]
    Codename: Pandora's box (pithos)
    Distros Supported : Linux Ubuntu, Kali, Mint, Parrot OS
    Suspicious-Shell-Activity (SSA) RedTeam develop @2017


## LEGAL DISCLAMER
    The author does not hold any responsibility for the bad use
    of this tool, remember that attacking targets without prior
    consent is illegal and punished by law.



## FRAMEWORK DESCRIPTION
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


## HOW DO I DELIVER MY PAYLOADS TO TARGET HOST ?
    venom 1.0.11 (malicious_server) was build to take advantage of
    apache2 webserver to deliver payloads (LAN) using a fake webpage
    writen in html that takes advantage of <iframe> <meta-http-equiv>
    or "<form>" tags to be hable to trigger payload downloads, the
    user just needs to send the link provided to target host.

    ATTACK VECTOR: http://192.168.1.69

    "Apache2 (malicious url) will copy all files needed to your webroot"
       Just run venom-main/aux/setup.sh to config framework settings.



## DEPENDENCIES
    Zenity | Metasploit | GCC (compiler) | Pyinstaller (compiler)
    mingw32 (compiler) | pyherion.py (crypter) | wine (emulator)
    PEScrambler.exe (PE obfuscator) | apache2 (webserver)| winrar
    vbs-obfuscator (obfuscator) | encrypt_PolarSSL (crypter) and
    ettercap MitM+DNS_Spoof (venom domain name attack vector)

    "venom.sh will download/install all dependencies as they are needed"
    Adicionally as build venom-main/aux/setup.sh to help you install all
    venom framework dependencies (metasploit as to be manually installed). 


## DOWNLOAD/INSTALL
    1º - Download framework from github
         tar.gz OR zip OR git clone

    2º - Set files execution permitions
         cd venom-main
         sudo chmod -R +x *.sh
         sudo chmod -R +x *.py

    3º - Install dependencies
         cd aux
         sudo ./setup.sh

    4º - Run main tool
         sudo ./venom.sh

## Framework Banner
![venom shellcode v1.0.13](http://4.1m.yt/zNRgR8N.png)
## Framework Main Menu
![venom shellcode v1.0.13](http://1.1m.yt/5GUpWxf.png)
## [ build 4 ] python/pyinstaller - osiris.exe
    Build 4 Work floow: Build shellcode in C language, embebbed into
    one python template and compiled to exe by pyinstaller = osiris.exe
![venom shellcode v1.0.13-Beta](http://1.1m.yt/K3Vd4x.png)


## video tutorial [build 23 - Invoke-Phant0m]
![venom shellcode v1.0.13](http://i.cubeupload.com/oBrL13.gif)

<br />


### Special thanks: @Chaitanya Haritash (MDPC-kimi.py debian agent)
Suspicious-Shell-Activity© (SSA) RedTeam develop @2017


_EOF


