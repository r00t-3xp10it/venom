<p align="center">
  <a href="https://github.com/r00t-3xp10it//github-readme-stats">
    <img
      align="center"
      height="165"
      src="https://github-readme-stats.vercel.app/api?username=r00t-3xp10it&count_private=true&show_icons=true&custom_title=Github%20Status&hide=issues&theme=radical"
    />
  </a>
</p>

[![Version](https://img.shields.io/badge/VENOM-1.0.17-brightgreen.svg?maxAge=259200)]()
[![Stage](https://img.shields.io/badge/Release-Stable-brightgreen.svg)]()
[![Build](https://img.shields.io/badge/Supported_OS-Linux-orange.svg)]()
![licence](https://img.shields.io/badge/license-GPLv3-brightgreen.svg)
![lastupdated](https://img.shields.io/aur/last-modified/venom)
![languages](https://img.shields.io/github/languages/count/r00t-3xp10it/venom)
![Open issues](https://img.shields.io/github/issues/r00t-3xp10it/venom?color=red&label=open%20issues)



## VENOM 1.0.17 - metasploit Shellcode generator/compiller
    Version release : v1.0.17
    Author : pedro ubuntu  [ r00t-3xp10it ]
    Codename: Aconite (Aconitum napellus)
    Distros Supported : Linux Ubuntu, Kali, Mint, Parrot OS
    Suspicious-Shell-Activity (SSA) RedTeam develop @2019

![banner](https://user-images.githubusercontent.com/23490060/71019038-8cd1fa80-20f1-11ea-9cb3-795020d24481.png)


#### LEGAL DISCLAMER
    The author does not hold any responsibility for the bad use of this tool, remember that attacking
    targets without prior consent is illegal and punished by law. So use this tool responsibly.



#### FRAMEWORK DESCRIPTION
    The script will use msfvenom (metasploit) to generate shellcode in diferent formats ( C# | python
    | ruby | dll | msi | hta-psh | docm | apk | macho | elf | deb | mp4 | etc ) injects the shellcode
    generated into one template (example: python) "the python funtion will execute the shellcode into
    ram" and uses compilers like gcc (gnu cross compiler) or mingw32 or pyinstaller to build the
    executable file. It also starts an handler to recive the remote connection (shell or meterpreter)

    'venom' reproduces some of the technics used by Veil-Evasion.py, unicorn.py, powersploit.py, etc..


#### HOW DO I DELIVER MY PAYLOADS TO TARGET HOST ?
    venom 1.0.11 (malicious_server) was build to take advantage of apache2 webserver to deliver payloads
    (LAN) using a fake webpage writen in html that takes advantage of <iframe> or <form> to be hable to
    trigger payload downloads, the user just needs to send the link provided to target host.

    "Apache2 (malicious url) will copy all files needed to your webroot, and starts apache for you."

![venom shellcode v1.0.17](http://i.cubeupload.com/nvmSq3.png)


#### DEPENDENCIES
    Zenity|Metasploit|GCC (compiler)|Pyinstaller (compiler)|mingw32 (compiler)|pyherion.py (crypter)
    wine (emulator)|PEScrambler.exe (PE obfuscator)|apache2 (webserver)|winrar (wine)|shellter (KyRecon)
    vbs-obfuscator (obfuscator)|avet (Daniel Sauder)|ettercap (MitM + DNS_Spoofing)|icmpsh (ICMP shell)
    openssl (build SSL certs)|CarbonCopy (sign exe binarys)|ResourceHacker (wine)|NXcrypt(python crypter)

    "venom will download/install all dependencies as they are needed". Adicionally was build the script
    venom-main/aux/setup.sh to help you install all framework dependencies fast and easy.We just need to
    install first the most importante dependencies before trigger setup.sh = zenity, metasploit, ettercap


#### DOWNLOAD/INSTALL

**1º - Download framework from github**<br />
`git clone https://github.com/r00t-3xp10it/venom.git`

**2º - Set execution permissions**<br />
`cd venom`<br />
`sudo find ./ -name "*.sh" -exec chmod +x {} \;`<br />
`sudo find ./ -name "*.py" -exec chmod +x {} \;`<br />

**3º - Install all dependencies**<br />
`cd aux && sudo ./setup.sh`

**4º - Run main tool**<br />
`sudo ./venom.sh`

**Update venom instalation** (compare local version againts github oficial version)<br />
`sudo ./venom.sh -u`


#### Framework Main Menu
![banner](https://user-images.githubusercontent.com/23490060/71019038-8cd1fa80-20f1-11ea-9cb3-795020d24481.png)
![venom shellcode v1.0.17](http://i.cubeupload.com/cVldOV.png)


<br />

Detailed info about release 1.0.17: https://github.com/r00t-3xp10it/venom/releases<br />
Suspicious-Shell-Activity© (SSA) RedTeam develop @2019

_EOF




