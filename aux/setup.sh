#!/bin/sh
# --------------------------------------------------------
# setup.sh | Author: r00t-3xp10it
# Install all dependencies nedded by venom to work
# and config/build venom.conf configuration file
# also builds or delete apache2 domain name attack vector
# --------------------------------------------------------





# ---------------------
# check if user is root
# ---------------------
if [ $(id -u) != "0" ]; then
echo "[☠] we need to be root to run this script..."
echo "[☠] execute [ sudo ./setup.sh ] on terminal"
exit
else
echo "root user" > /dev/null 2>&1
fi





# ----------------------
# variable declarations
# ----------------------
OS=`uname` # grab OS
ver="1.0.13"
H0m3=`echo ~` # grab home path
user=`who | cut -d' ' -f1 | sort | uniq` # grab username
DiStRo=`awk '{print $1}' /etc/issue` # grab distribution -  Ubuntu or Kali
inter=`netstat -r | grep "default" | awk {'print $8'}` # grab interface in use
IP=`ifconfig $InT3R | egrep -w "inet" | cut -d ':' -f2 | cut -d 'B' -f1` # grab ip (lhost)
IPATH=`pwd` # grab setup.sh install path (home/username/shell/aux)





case $DiStRo in
    Kali) IP=`ifconfig $inter | egrep -w "inet" | awk '{print $2}'`;;
    Debian) IP=`ifconfig $inter | egrep -w "inet" | awk '{print $2}'`;;
    Ubuntu) IP=`ifconfig $inter | egrep -w "inet" | cut -d ':' -f2 | cut -d 'B' -f1`;;
    Parrot) IP=`ifconfig $inter | egrep -w "inet" | cut -d ':' -f2 | cut -d 'B' -f1`;;
    BackBox) IP=`ifconfig $inter | egrep -w "inet" | cut -d ':' -f2 | cut -d 'B' -f1`;;
    *) IP=`zenity --title="☠ Input your IP addr ☠" --text "example: 192.168.1.68" --entry --width 300`;;
  esac
clear



# -------------------
# BANNER DISPLAY
# -------------------
clear
cat << !

    __    _ ______  ____   _  _____  ____    __  
   \  \  //|   ___||    \ | |/     \|    \  /  |
    \  \// |   ___||     \| ||     ||     \/   |
     \__/  |______||__/\____|\_____/|__/\__/|__|
   +-------------------------------------------+
   |    "setup.sh - configuration script"      |
   |                                           |
   |   Use this script to configure venom.sh   |
   | internal settings, like the installation  |
   | of dependencies, mega-upload domain name  |
   | path to apache2 webroot, wine install...  |
   |                                           |
   +-------------------------------------------+
   |_ OS:$OS  DISTRO:$DiStRo  VERSION:$ver


!
sleep 3
lhost=$(zenity --title="☠ Enter LHOST ☠" --text "example: $IP" --entry --width 330) > /dev/null 2>&1




# -----------------------------
# check venom tool dependencies
# -----------------------------
# check if zenity its installed
zen=`which zenity`
if [ "$?" -eq "0" ]; then
echo "[✔] zenity............................[ found ]"
sleep 2
else
echo ""
echo "[☠] zenity -> not found!                      ]"
echo "[☠] This script requires zenity               ]"
sleep 2
echo "[☠] Please download zenity                    ]"
su $user -c "xdg-open http://www.tecmint.com/zenity-creates-graphical-gtk-dialog-boxes-in-command-line-and-shell-scripts/" > /dev/null 2>&1
fi





# check if msfconsole its installed
imp=`which msfconsole`
if [ "$?" -eq "0" ]; then
echo "[✔] msfconsole........................[ found ]"
sleep 2
else
echo ""
echo "[☠] msfconsole -> not found                   ]"
echo "[☠] This script requires msfconsole           ]"
sleep 2
exit
fi





# check if gcc exists
c0m=`which gcc`> /dev/null 2>&1
if [ "$?" -eq "0" ]; then
echo "[✔] gcc compiler......................[ found ]"
sleep 2 
else
echo "[☠] gcc compiler      -> not found            ]"
echo "[☠] Download compiler -> apt-get install gcc  ]"
xterm -T "☠ INSTALL GCC COMPILLER ☠" -geometry 110x23 -e "sudo apt-get install gcc"
sleep 2
fi





# check if mingw32 exists
c0m=`which i586-mingw32msvc-gcc`> /dev/null 2>&1
if [ "$?" -eq "0" ]; then
echo "[✔] mingw32 compiler..................[ found ]"
sleep 2
else
echo "[☠] mingw32 compiler  -> not found            ]"
echo "[☠] Download compiler -> apt-get install mingw32"
xterm -T "☠ INSTALL MINGW32 COMPILLER ☠" -geometry 110x23 -e "sudo apt-get install mingw32"
sleep 2
fi





cd ..
# check if pyherion exists
if [ -e obfuscate/pyherion.py ]; then
echo "[✔] pyherion crypter..................[ found ]"
sleep 2
cd $IPATH
else
echo "[☠] pyherion crypter -> not found             ]"
sleep 2
echo "[☠] please wait      -> updating              ]"
sleep 2
echo ""
git pull
echo ""
sleep 2
cd $IPATH
fi





cd ..
# check if vbs-obfuscator exists
if [ -e obfuscate/vbs-obfuscator.py ]; then
echo "[✔] vbs-obfuscator....................[ found ]"
sleep 2
cd $IPATH
else
echo "[☠] vbs-obfuscator -> not found               ]"
sleep 2
echo "[☠] please wait    -> updating                ]"
sleep 2
echo ""
git pull
echo ""
sleep 2
cd $IPATH
fi





# check if apache2 exists
ch3=`which apache2`
if [ "$?" -eq "0" ]; then
echo "[✔] apache2 webserver.................[ found ]"
sleep 2
else
echo ""
echo "[☠] apache2 webserver -> not found            ]"
echo "[☠] Download apache2  -> apt-get install apache2"
xterm -T "☠ INSTALL APACHE2 WEBSERVER ☠" -geometry 110x23 -e "sudo apt-get install apache2"
sleep 2
fi





# ------------------------------------------------
# grab apache2 webroot path and config domain name
# http://192.168.1.208 OR http://mega-Upload
# ------------------------------------------------
# Input apache2 webroot path
ApAcHe=$(zenity --title="☠ Enter APACHE2 WEBROOT PATH ☠" --text "example: /var/www/html" --entry --width 330) > /dev/null 2>&1
QuE=$(zenity --list --title "APACHE2 DOMAIN NAME CONFIGURATION" --text "\nChose option:" --radiolist --column "Pick" --column "Option" TRUE "Skipp Domain configuration" FALSE "Use Venom domain name" FALSE "Delete Venom domain name" --width 350 --height 220) > /dev/null 2>&1
D3F="$ApAcHe"

if [ "$QuE" = "Use Venom domain name" ]; then
  dsrr="YES"
  # check if running Apache/2.2 or Apache/2.4
  apache2 -v | grep "Server version" | cut -d ':' -f2 | cut -d '(' -f1 >> version.log
  sed -i "s/ //g" version.log
  un=`cat version.log`
  rm version.log > /dev/null 2>&1

     echo ""
     if [ "$un" = "Apache/2.2.22" ]; then
       # build mega-upload.conf apache 2.2
       echo "[☆] Building       -> venom mega-upload.conf"
       echo "<VirtualHost *:80>" > /etc/apache2/sites-available/mega-upload.conf
       echo "   ServerName mega-upload.com" >> /etc/apache2/sites-available/mega-upload.conf
       echo "   DocumentRoot $IPATH/public_html/mega-upload.com" >> /etc/apache2/sites-available/mega-upload.conf
       echo "</VirtualHost>" >> /etc/apache2/sites-available/mega-upload.conf
       sleep 2
     else
       # build mega-upload.conf apache 2.4
       echo "[☆] Building       -> venom mega-upload.conf"
       echo "<VirtualHost *:80>" > /etc/apache2/sites-available/mega-upload.conf
       echo "   ServerName mega-upload.com" >> /etc/apache2/sites-available/mega-upload.conf
       echo "   DocumentRoot $IPATH/public_html/mega-upload.com" >> /etc/apache2/sites-available/mega-upload.conf
       echo "   <Directory $IPATH/public_html/mega-upload.com/>" >> /etc/apache2/sites-available/mega-upload.conf
       echo "      Require all granted" >> /etc/apache2/sites-available/mega-upload.conf
       echo "   </Directory>" >> /etc/apache2/sites-available/mega-upload.conf
       echo "</VirtualHost>" >> /etc/apache2/sites-available/mega-upload.conf
       sleep 2
     fi


  # build directorys needed by mega-upload domain
  echo "[☆] Building       -> venom domain directory"
  mkdir -p $IPATH/public_html/mega-upload.com
  echo "<html><H1>VENOM DOMAIN WORKING ....</H1></html>" > $IPATH/public_html/mega-upload.com/index.html
  sudo chmod -R g+rw $IPATH/public_html/mega-upload.com
  sleep 2

  # config hosts file (DNS record - DNS_SPOOFING)
  P0Is0N=$(zenity --title="☠ Enter etter.dns FULL PATH ☠" --text "example: /usr/share/ettercap" --entry --width 330) > /dev/null 2>&1
  echo "[☆] Added          -> DNS record to etter.dns"
  cp $P0Is0N/etter.dns $P0Is0N/etter[bak].dns > /dev/null 2>&1
  sed "s|IpAdDr|$IP|g" etter.dns > etter.filter
  mv etter.filter $P0Is0N/etter.dns > /dev/null 2>&1
  sleep 2

  # display configs to user
  ApAcHe="$IPATH/public_html/mega-upload.com"
  echo "[☆] DOMAIN_NAME    -> mega-upload.com"
  echo "[☆] ATTACK_VECTOR  -> http://mega-upload.com"
  echo "[☆] APACHE_WEBROOT -> $ApAcHe"
  echo ""
  sleep 2
  # enable new site
  sddf="domain"
  a2ensite mega-upload.conf
  /etc/init.d/apache2 restart | zenity --progress --pulsate --title "☠ PLEASE WAIT ☠" --text="restart apache2 webserver" --percentage=0 --auto-close --width 300 > /dev/null 2>&1
  echo ""


elif [ "$QuE" = "Delete Venom domain name" ]; then
    dsrr="NO"
  # use venom default configuration
  P0Is0N=$(zenity --title="☠ Enter etter.dns FULL PATH ☠" --text "example: /usr/share/ettercap" --entry --width 330) > /dev/null 2>&1
  echo ""
  # display config to user
  echo "[☆] DOMAIN_NAME    -> localhost"
  echo "[☆] ATTACK_VECTOR  -> http://$lhost"
  echo "[☆] APACHE_WEBROOT -> $ApAcHe"
  echo ""
  sleep 2
  mv $P0Is0N/etter[bak].dns $P0Is0N/etter.dns > /dev/null 2>&1
  rm /etc/apache2/sites-available/mega-upload.conf > /dev/null 2>&1
  rm /etc/apache2/sites-enabled/mega-upload.conf > /dev/null 2>&1
  rm -r $IPATH/public_html > /dev/null 2>&1
  /etc/init.d/apache2 restart | zenity --progress --pulsate --title "☠ PLEASE WAIT ☠" --text="restart apache2 webserver" --percentage=0 --auto-close --width 300 > /dev/null 2>&1
  echo ""

else

  echo "[☆] Venom Domain name Configuration...[ skipp ]"
  dsrr="NO"

fi





# -------------------------------------------------
# ETTERCAP DNS SPOOFING - APACHE2 VENOM DOMAIN NAME
# ------------------------------------------------- 
if [ "$sddf" = "domain" ]; then

# venom domain name settings found...
Pr0T0=$(zenity --list --title "☠ ETTERCAP IPV6 SETTINGS ☠" --text "\nchose to use ettercap IPv6 or IPv4 arp poison." --radiolist --column "Pick" --column "Option" TRUE "IPv4 (old operative systems)" FALSE "IPv6 (new operative systems)" --width 350 --height 190) > /dev/null 2>&1


   # use 'SED' to replace settings in venom.sh file...
   # like the use of ettercap IPV4 or IPV6 settings to run
   # everytime apache2 attack vector its trigger...
   if [ "$Pr0T0" = "IPv4 (old operative systems)" ]; then

     cd ..
     echo "[✔] ettercap settings.................[  IPv4 ]"
     sed "s|-M ARP /// ///|-M ARP // //|g" venom.sh > test.bak
     mv test.bak venom.sh > /dev/null 2>&1
     chmod +x venom.sh > /dev/null 2>&1
     cd $IPATH
     fd3d="IPv4"
     sleep 2

   else

     cd ..
     echo "[✔] ettercap settings.................[  IPv6 ]"
     sed "s|-M ARP // //|-M ARP /// ///|g" venom.sh > test.bak
     mv test.bak venom.sh > /dev/null 2>&1
     chmod +x venom.sh > /dev/null 2>&1
     cd $IPATH
     fd3d="IPv6"
     sleep 2

   fi

else

cd ..
# DONT USE VENOM DOMAIN NAME ATTACK VECTOR SETTINGS
# DEFAULT SETTINGS IN VENOM.SH ETTERCAP COMMANDS TO DEFAULT.
echo "[✔] ettercap settings.................[  IPv4 ]"
sed "s|-M ARP /// ///|-M ARP // //|g" venom.sh > test.bak
mv test.bak venom.sh > /dev/null 2>&1
chmod +x venom.sh > /dev/null 2>&1
cd $IPATH
fd3d="IPv4"
echo "null" > /dev/null 2>&1
sleep 2
fi




# --------------------------------------------------
# chose in post-exploitation (apache2 attack vector)
# to auto-migrate to what process in target machine
# -----------------------------------------------------
CsT=`cat fast_migrate.rc | grep "migrate" | awk {'print $4'}`
echo "[✔] post-exploitation.................[ found ]"
sleep 2
# enter process name to were migrate after a succesfully exloitation
M1G=$(zenity --title="☠ AUTO MIGRATE SETTINGS ☠" --text "\nPost-exploitation 'fast-migrate.rc' module by default\nwill auto-migrate the session to 'wininit.exe' process.\n[ when using apache2 attack vector module ]\n\nInput the process name to were auto-migrate\nexample: explorer.exe" --entry --width 330) > /dev/null 2>&1
# rebuild 'fast_migrate.rc' with new settings
echo "getsystem" > fast_migrate.rc 
echo "run migrate -n $M1G" >> fast_migrate.rc
echo "sysinfo" >> fast_migrate.rc
echo "getuid" >> fast_migrate.rc





# --------------------
# check if wine exists
# --------------------
c0m=`which wine`> /dev/null 2>&1
if [ "$?" -eq "0" ]; then
echo "[✔] wine..............................[ found ]"
sleep 2
# input wine drive_c path
DrIvC=$(zenity --title="☠ Enter .wine folder PATH ☠" --text "example: $H0m3/.wine" --entry --width 330) > /dev/null 2>&1
sleep 2
else
echo "[☠] wine     -> not found                     ]"
echo "[☠] Download -> apt-get install wine          ]"
xterm -T "☠ INSTALL WINE ☠" -geometry 110x23 -e "sudo apt-get install wine"
sleep 2
fi





# ------------------------
# configure WINE settings
# ------------------------
if [ -d $DrIvC ]; then
  echo "[✔] wine folder.......................[ found ]"
  sleep 2

else

  echo "[☠] wine folder -> not found                  ]"
  echo "[☠] Please wait -> running winecfg            ]"
  sleep 2

    if [ "$DiStRo" = "Kali" ]; then
      winecfg > /dev/null 2>&1
    else
      su $user -c "winecfg > /dev/null 2>&1"
    sleep 2
    fi

fi





# install WinRAR under WINE
if [ $(uname -m) = "i686" ]; then

  echo "[✔] arch sellected....................[ 32bit ]"
  sleep 2
  cd .. && cd bin
  # copy winRAR to wine
  if [ "$DiStRo" = "Kali" ]; then

       if [ -d "$DrIvC/drive_c/Program Files/WinRAR" ]; then
       echo "[✔] WinRAR.exe........................[ found ]"
       sleep 2
       else
       echo "[☠] WinRAR.exe -> not found                   ]"
       sleep 2
       echo ""
       wine install_winrar_wine32.exe
       echo ""
       cd $IPATH
       fi

  else

       if [ -d "$DrIvC/drive_c/Program Files/WinRAR" ]; then
       echo "[✔] WinRAR.exe........................[ found ]"
       sleep 2
       else
       echo "[☠] WinRAR.exe -> not found                   ]"
       sleep 2
       echo ""
       su $user -c "wine install_winrar_wine32.exe"
       echo ""
       cd $IPATH
       fi
  fi

else

   echo "[✔] arch sellected....................[ 64bit ]"
   sleep 2
  cd .. && cd bin
  # copy winRAR to wine
  if [ "$DiStRo" = "Kali" ]; then

       if [ -d "$DrIvC/drive_c/Program Files/WinRAR" ]; then
       echo "[✔] WinRAR.exe........................[ found ]"
       sleep 2
       else
       echo "[☠] WinRAR.exe....................[ not found ]"
       sleep 2
       echo ""
       wine64 install_winrar_wine64.exe
       echo ""
       cd $IPATH
       fi

  else

       if [ -d "$DrIvC/drive_c/Program Files/WinRAR" ]; then
       echo "[✔] WinRAR.exe........................[ found ]"
       sleep 2
       else
       echo "[☠] WinRAR.exe....................[ not found ]"
       sleep 2
       echo ""
       su $user -c "wine64 install_winrar_wine64.exe"
       echo ""
       cd $IPATH
       fi
  fi

fi







# pyinstaller wine dependencies checks
if [ $(uname -m) = "i686" ]; then

    # check if pyinstaller its on wine directory
    if [ -d "$DrIvC/drive_c/pyinstaller-2.0" ]; then
      echo "[✔] pyinstaller.......................[ found ]"
      sleep 2
    else
      # copy pyinstaller to wine
      echo "[☠] pyinstaller -> not found                  ]"
      echo ""
      sleep 2
      cd $IPATH
      cd ..
      cd obfuscate
      tar -xf pyinstaller.tar.gz
      cd pyinstaller

        if [ "$DiStRo" = "Kali" ]; then
          echo "[☠] copy to     -> $DrIvC/drive_c/pyinstaller-2.0"
          sleep 2
          mv pyinstaller-2.0 $DrIvC/drive_c/pyinstaller-2.0 > /dev/null 2>&1
          echo "[☠] install     -> python 2.6.6               ]"
          sleep 2
          echo ""
          wine msiexec /i python-2.6.6.msi
          echo ""
          echo "[☠] install     -> pywin32-220                ]"
          sleep 2
          wine pywin32-220.win32-py2.6.exe
          echo ""
          cd ..
          rm -R pyinstaller
          sleep 2
          cd $IPATH
        else
          echo "[☠] copy to     -> $DrIvC/drive_c/pyinstaller-2.0"
          sleep 2
          su $user -c "mv pyinstaller-2.0 $DrIvC/drive_c/pyinstaller-2.0" > /dev/null 2>&1
          echo "[☠] install     -> python 2.6.6               ]"
          sleep 2
          echo ""
          su $user -c "wine msiexec /i python-2.6.6.msi"
          echo ""
          echo "[☠] install     -> pywin32-220                ]"
          sleep 2
          su $user -c "wine pywin32-220.win32-py2.6.exe"
          echo ""
          cd ..
          rm -R pyinstaller
          sleep 2
          cd $IPATH
        fi
    fi


else


    # check if pyinstaller its on wine directory
    if [ -d "$DrIvC/drive_c/pyinstaller-2.0" ]; then
      echo "[✔] pyinstaller.......................[ found ]"
      sleep 2
    else
      # copy pyinstaller to wine
      echo "[☠] pyinstaller -> not found                  ]"
      echo ""
      sleep 2
      cd $IPATH
      cd ..
      cd obfuscate
      tar -xf pyinstaller.tar.gz
      cd pyinstaller

        if [ "$DiStRo" = "Kali" ]; then
          echo "[☠] copy to     -> $DrIvC/drive_c/pyinstaller-2.0"
          sleep 2
          mv pyinstaller-2.0 $DrIvC/drive_c/pyinstaller-2.0 > /dev/null 2>&1
          echo "[☠] install     -> python 2.6.6               ]"
          sleep 2
          echo ""
          wine64 msiexec /i python-2.6.6.amd64.msi
          echo ""
          echo "[☠] install     -> pywin32-220                ]"
          sleep 2
          wine64 pywin32-220.win-amd64-py3.5.exe
          echo ""
          cd ..
          rm -R pyinstaller
          sleep 2
          cd $IPATH
        else
          echo "[☠] copy to     -> $DrIvC/drive_c/pyinstaller-2.0"
          sleep 2
          su $user -c "mv pyinstaller-2.0 $DrIvC/drive_c/pyinstaller-2.0" > /dev/null 2>&1
          echo "[☠] install     -> python 2.6.6               ]"
          sleep 2
          echo ""
          su $user -c "wine64 msiexec /i python-2.6.6.amd64.msi"
          echo ""
          echo "[☠] install     -> pywin32-220                ]"
          sleep 2
          su $user -c "wine64 pywin32-220.win-amd64-py3.5.exe"
          echo ""
          cd ..
          rm -R pyinstaller > /dev/null 2>&1
          cd $IPATH
        fi
    fi
fi





# ---------------------
# build venom.conf file
# ---------------------

# change to rigth directory structure
cd ..
# store values in variables
ApDe=`cat settings | egrep -m 1 "APACHE_DEFAULT" | cut -d '=' -f2` > /dev/null 2>&1
ApWR=`cat settings | egrep -m 1 "APACHE_WEBROOT" | cut -d '=' -f2` > /dev/null 2>&1
DTuR=`cat settings | egrep -m 1 "MEGAUPLOAD_DOMAIN" | cut -d '=' -f2` > /dev/null 2>&1
WdPa=`cat settings | egrep -m 1 "WINE_DRIVEC" | cut -d '=' -f2` > /dev/null 2>&1
DnLh=`cat settings | egrep -m 1 "LOCAL_HOST" | cut -d '=' -f2` > /dev/null 2>&1
ArP=`cat settings | egrep -m 1 "ARP_SETTINGS" | cut -d '=' -f2` > /dev/null 2>&1
DnAm=`cat settings | egrep -m 1 "DOMAIN_NAME" | cut -d '=' -f2` > /dev/null 2>&1
AtVe=`cat settings | egrep -m 1 "ATTACK_VECTOR" | cut -d '=' -f2` > /dev/null 2>&1
EdNp=`cat settings | egrep -m 1 "ETTER_DNS_PATH" | cut -d '=' -f2` > /dev/null 2>&1
# config settings file
if [ "$sddf" = "domain" ]; then
Df="mega-upload.com"
Af="http://mega-upload.com"
Ps="$P0Is0N"
else
Df="localhost"
Af="http://$lhost"
Ps="/etc/ettercap"
fi
# change setting file configurations
sed -i "s|$ApDe|$D3F|" settings
sed -i "s|$ApWR|$ApAcHe|" settings
sed -i "s|$DTuR|$dsrr|" settings
sed -i "s|$WdPa|$DrIvC/drive_c|" settings
sed -i "s|$DnLh|$lhost|" settings
sed -i "s|$ArP|$fd3d|" settings
sed -i "s|$DnAm|$Df|" settings
sed -i "s|$AtVe|$Af|" settings
sed -i "s|$EdNp|$Ps/etter.dns|" settings
cd aux



# exit setup.sh script
echo ""
echo "[✔] All checks completed..............[   OK  ]"
sleep 1
cd $IPATH/
cd .. && cd ..
sudo chown -hR $user shell > /dev/null 2>&1
sleep 1
exit
