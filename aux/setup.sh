#!/bin/sh
# --------------------------------------------------------
# setup.sh | Author: r00t-3xp10it
# Install all dependencies nedded by venom to work
# and config/build venom.conf configuration file
# also builds or delete apache2 domain name attack vector
# --------------------------------------------------------
resize -s 24 89 > /dev/null



#
# check if user is root
#
if [ $(id -u) != "0" ]; then
echo "[x] we need to be root to run this script..."
echo "[x] execute [ sudo ./setup.sh ] on terminal"
exit
fi



#
# variable declarations _________________________________
#                                                        |
OS=`uname`                                               # grab OS
ver="1.0.15"                                             # toolkit version
H0m3=`echo ~`                                            # grab home path
user=`who | awk {'print $1'}`                            # grab username
DiStRo=`awk '{print $1}' /etc/issue`                     # grab distribution -  Ubuntu or Kali
inter=`netstat -r | grep "default" | awk {'print $8'}`   # grab interface in use
IPATH=`pwd`                                              # grab setup.sh install path
# _______________________________________________________|




#
# select the arch to use in setup.sh installs
#
uN=`uname -m`
if [ "$uN" = "i686" ]; then
legit="x86"
else
legit="x64"
fi
ARCHSELECTED=$(zenity --list --title "☠ venom - arch sellection ☠" --text "Your system identify itself as: $legit [ arch ]\nDo you wish setup.sh to use this arch to install backend applications?\nRemmenber: venom.sh will also use the arch sellected here to work." --radiolist --column "Pick" --column "Option" TRUE "x86" FALSE "x64" --width 350 --height 220) > /dev/null 2>&1
  if [ "$ARCHSELECTED" = "x86" ]; then
    echo "[✔] arch sellected to install backend appl: x86"
    sleep 3
    Dftt="x86"
    arch="wine"
  elif [ "$ARCHSELECTED" = "x64" ]; then
    echo "[✔] arch sellected to install backend appl: x64"
    sleep 3
    Dftt="x64"
    arch="wine64"
  else
    echo "[x] Script execution aborted .."
    sleep 3
    exit
  fi



#
# store local ip adress ..
#
case $DiStRo in
    Kali) lhost=`ifconfig $inter | egrep -w "inet" | awk '{print $2}'`;;
    Debian) lhost=`ifconfig $inter | egrep -w "inet" | awk '{print $2}'`;;
    Linux) lhost=`ifconfig $inter | egrep -w "inet" | awk '{print $2}' | cut -d ':' -f2`;; # Mint strange bug
    Ubuntu) lhost=`ifconfig $inter | egrep -w "inet" | awk '{print $2}'`;;
    Parrot) lhost=`ifconfig $inter | egrep -w "inet" | awk '{print $2}'`;;
    *) lhost=`zenity --title="☠ Input your IP addr ☠" --text "example: 192.168.1.68" --entry --width 300`;;
  esac
clear



#
# BANNER DISPLAY
#
clear
cat << !

    __    _ ______  ____   _  _____  ____    __
   \  \  //|   ___||    \ | |/     \|    \  /  |
    \  \// |   ___||     \| ||     ||     \/   |
     \__/  |______||__/\____|\_____/|__/\__/|__|
   ╔───────────────────────────────────────────╗
   |    "setup.sh - configuration script"      |
   |                                           |
   |   Use this script to configure venom.sh   |
   | internal settings, like the installation  |
   | of dependencies, mega-upload domain name  |
   | path to apache2 webroot, wine install...  |
   |                                           |
   ╠───────────────────────────────────────────╝
   |  OS:$OS DISTRO:$DiStRo($legit) VERSION:$ver
   |_ BROADCAST:$inter IP_ADDR:$lhost


!
sleep 1
QuE=$(zenity --question --title="☠ venom - installation ☠" --text "Run install script?\nAuthor: r00t-3xp10it" --width 200) > /dev/null 2>&1
if [ "$?" -eq "0" ]; then


# updating local repository (apt-get update)
sudo apt-get update | zenity --progress --pulsate --title "☠ PLEASE WAIT ☠" --text="Updating system (apt-get) .." --percentage=0 --auto-close --width 300 > /dev/null 2>&1
echo ""


#
# check venom tool dependencies (backend appl)
#
# check if zenity its installed
zen=`which zenity`
if [ "$?" -eq "0" ]; then
  echo "[✔] zenity............................[ found ]"
  sleep 2
else
  echo "[x] zenity                        [ not found ]"
  sleep 1
  echo ""
  sudo apt-get install zenity
  echo ""

      sleep 1
      again=`which zenity` > /dev/null 2>&1
      if [ "$?" -eq "0" ]; then
        echo "[✔] zenity........................[ installed ]"
      else
        echo ""
        echo "    WARNING: Unable to locate package zenity"
        echo "    To solve this issue make sure you have the right repositories in sources.list"
        echo "    With the right repositories in sources.list, you need to run apt-get update"
        echo "    and then run the installation command for the zenity package again."
        echo "    http://www.tecmint.com/zenity-creates-graphical-gtk-dialog-boxes-in-command-line-and-shell-scripts/"
        echo ""
        sleep 2
        exit
      fi
fi



#
# check if msfconsole its installed
#
imp=`which msfconsole`
if [ "$?" -eq "0" ]; then
  echo "[✔] msfconsole........................[ found ]"
  sleep 2
  MSFDATA=$(zenity --title="☠ Enter METASPLOIT FULL PATH ☠" --text "example: /usr/share/metasploit-framework" --entry --width 330) > /dev/null 2>&1
    # check for non-accepted empty inputs
    if [ -z "$MSFDATA" ]; then
      echo ""
      echo "    ERROR: Empty inputs are not accepted .."
      echo ""
      exit
    fi
    if [ -d $MSFDATA ]; then
      :
    else
      echo ""
      echo "    ERROR: Metasploit path not found: $MSFDATA"
      echo ""
      MSFDATA=$(zenity --title="☠ Enter METASPLOIT FULL PATH ☠" --text "example: /usr/share/metasploit-framework" --entry --width 330) > /dev/null 2>&1
    fi
else
  echo "[x] msfconsole                    [ not found ]"
  sleep 1
  echo ""
  echo "    Please Download/Install metasploit-framework .."
  echo "    https://www.rapid7.com/products/metasploit/download/"
  echo ""
  sleep 2
  exit
fi



#
# check if gcc compiler exists ..
#
c0m=`which gcc` > /dev/null 2>&1
if [ "$?" -eq "0" ]; then
  echo "[✔] gcc compiler......................[ found ]"
  sleep 2
else
  echo "[x] gcc compiler                  [ not found ]"
  sleep 1
  echo ""
  sudo apt-get install gcc
  echo ""

  sleep 1
  again=`which gcc` > /dev/null 2>&1
  if [ "$?" -eq "0" ]; then
    echo "[✔] gcc compiler..................[ installed ]"
    sleep 2
  else
    echo ""
    echo "    WARNING: Unable to locate package gcc"
    echo "    To solve this issue make sure you have the right repositories in sources.list"
    echo "    With the right repositories in sources.list, you need to run apt-get update"
    echo "    and then run the installation command for the gcc package again."
    echo "    KALI: https://docs.kali.org/general-use/kali-linux-sources-list-repositories"
    echo ""
    sleep 2
  fi
fi



#
# check correct mingw-gcc install (x86/x64)..
#
if [ "$Dftt" = "x86" ]; then
  # check if mingw32 exists
  c0m=`which i586-mingw32msvc-gcc` > /dev/null 2>&1
  if [ "$?" -eq "0" ]; then
    echo "[✔] mingw32 compiler..................[ found ]"
    sleep 2
  else
    echo "[x] mingw32 compiler              [ not found ]"
    sleep 1
    echo ""
    sudo apt-get install mingw32
    echo ""

      sleep 1
      again=`which i586-mingw32msvc-gcc` > /dev/null 2>&1
      if [ "$?" -eq "0" ]; then
        echo "[✔] mingw32 compiler..................[ installed ]"
        sleep 2
      else
        echo ""
        echo "    WARNING: Unable to locate package i586-mingw32msvc-gcc"
        echo "    To solve this issue make sure you have the right repositories in sources.list"
        echo "    With the right repositories in sources.list, you need to run apt-get update"
        echo "    and then run the installation command for the Mingw32 package again."
        echo "    HINT: Add kali-sana (old repo) to your sources.list and apt-get update"
        echo "    KALI: https://docs.kali.org/general-use/kali-linux-sources-list-repositories"
        echo ""
        sleep 2
      fi
  fi

else

  # check if mingw64 exists
  c0m=`which i686-w64-mingw32-gcc` > /dev/null 2>&1
  if [ "$?" -eq "0" ]; then
    echo "[✔] mingw64 compiler..................[ found ]"
    sleep 2
  else
    echo "[x] mingw64 compiler              [ not found ]"
    sleep 1
    echo ""
    sudo apt-get install mingw-w64
    echo ""

      sleep 1
      again=`which i686-w64-mingw32-gcc` > /dev/null 2>&1
      if [ "$?" -eq "0" ]; then
        echo "[✔] mingw64 compiler..................[ installed ]"
        sleep 2
      else
        echo ""
        echo "    WARNING: Unable to locate package i686-w64-mingw32-gcc"
        echo "    To solve this issue make sure you have the right repositories in sources.list"
        echo "    With the right repositories in sources.list, you need to run apt-get update"
        echo "    and then run the installation command for the mingw-w64 package again."
        echo "    KALI: https://docs.kali.org/general-use/kali-linux-sources-list-repositories"
        echo ""
        sleep 2
      fi
  fi
fi



#
# check if pyherion exists
#
cd ..
if [ -e obfuscate/pyherion.py ]; then
  echo "[✔] pyherion crypter..................[ found ]"
  sleep 2
  cd $IPATH
else
  echo "[x] pyherion crypter              [ not found ]"
  sleep 1
  echo ""
  echo "    WARNING: Unable to locate pyherion.py"
  echo "    Please Download pytherion crypter to: venom-main/obfuscate"
  echo "    https://github.com/r00t-3xp10it/venom/blob/master/obfuscate/pyherion.py"
  echo ""
  sleep 2
  cd $IPATH
fi




#
# check if vbs-obfuscator exists
#
cd ..
if [ -e obfuscate/vbs-obfuscator.py ]; then
  echo "[✔] vbs-obfuscator....................[ found ]"
  sleep 2
  cd $IPATH
else
  echo "[x] vbs-obfuscator                [ not found ]"
  sleep 1
  echo ""
  echo "    WARNING: Unable to locate vbs-obfuscator.py"
  echo "    Please Download vbs-obfuscator.py to: venom-main/obfuscate"
  echo "    https://github.com/r00t-3xp10it/venom/blob/master/obfuscate/vbs-obfuscator.py"
  echo ""
  sleep 2
  cd $IPATH
fi




#
# check if apache2 exists
#
ch3=`which apache2`
if [ "$?" -eq "0" ]; then
  echo "[✔] apache2 webserver.................[ found ]"
  sleep 2
else
  echo "[x] apache2 webserver             [ not found ]"
  sleep 1
  echo ""
  sudo apt-get install apache2
  echo ""

    sleep 1
    again=`which apache2`
    if [ "$?" -eq "0" ]; then
      echo "[✔] apache2 webserver.............[ installed ]"
      sleep 2
    else
      echo ""
      echo "    WARNING: Unable to locate package apache2"
      echo "    To solve this issue make sure you have the right repositories in sources.list"
      echo "    With the right repositories in sources.list, you need to run apt-get update"
      echo "    and then run the installation command for the apache2 package again."
      echo "    KALI: https://docs.kali.org/general-use/kali-linux-sources-list-repositories"
      echo ""
      sleep 2
    fi
fi




# ------------------------------------------------
# grab apache2 webroot path and config domain name
# http://192.168.1.208 OR http://mega-Upload
# ------------------------------------------------
# Input apache2 webroot path
ApAcHe=$(zenity --title="☠ Enter APACHE2 WEBROOT PATH ☠" --text "example: /var/www/html" --entry --width 330) > /dev/null 2>&1

    # check for non-accepted empty inputs
    if [ -z "$ApAcHe" ]; then
      echo ""
      echo "    ERROR: Empty inputs are not accepted .."
      echo ""
      exit
    fi

if [ -d $ApAcHe ]; then
  :
else
  echo ""
  echo "    ERROR: Apache2 path not found: $ApAcHe"
  echo ""
  ApAcHe=$(zenity --title="☠ Enter APACHE2 WEBROOT PATH ☠" --text "example: /var/www/html" --entry --width 330) > /dev/null 2>&1
fi


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
  P0Is0N=$(zenity --title="☠ Enter ettercap FULL PATH ☠" --text "example: /usr/share/ettercap" --entry --width 330) > /dev/null 2>&1

    # check for non-accepted empty inputs
    if [ -z "$P0Is0N" ]; then
      echo ""
      echo "    ERROR: Empty inputs are not accepted .."
      echo ""
      exit
    fi

    if [ -d $P0Is0N ]; then
      :
    else
      echo ""
      echo "    ERROR: ettercap path not found: $P0Is0N"
      echo ""
      P0Is0N=$(zenity --title="☠ Enter ettercap FULL PATH ☠" --text "example: /usr/share/ettercap" --entry --width 330) > /dev/null 2>&1
    fi

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
  P0Is0N=$(zenity --title="☠ Enter ettercap FULL PATH ☠" --text "example: /usr/share/ettercap" --entry --width 330) > /dev/null 2>&1

    # check for non-accepted empty inputs
    if [ -z "$P0Is0N" ]; then
      echo ""
      echo "    ERROR: Empty inputs are not accepted .."
      echo ""
      exit
    fi

    if [ -d $P0Is0N ]; then
      :
    else
      echo ""
      echo "    ERROR: ettercap path not found: $P0Is0N"
      echo ""
      P0Is0N=$(zenity --title="☠ Enter ettercap FULL PATH ☠" --text "example: /usr/share/ettercap" --entry --width 330) > /dev/null 2>&1
    fi

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

  echo "[!] Venom Domain name Configuration...[ skipp ]"
  dsrr="NO"

fi





#
# ETTERCAP DNS SPOOFING - APACHE2 VENOM DOMAIN NAME
#
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







#
# check if wine exists
#
c0m=`which $arch` > /dev/null 2>&1
if [ "$?" -eq "0" ]; then
    echo "[✔] wine..............................[ found ]"
    sleep 2
    DrIvC=$(zenity --title="☠ Enter .wine folder PATH ☠" --text "example: $H0m3/.wine" --entry --width 330) > /dev/null 2>&1

      # check for non-accepted empty inputs
      if [ -z "$DrIvC" ]; then
        echo ""
        echo "    ERROR: Empty inputs are not accepted .."
        echo ""
        exit
      fi

      if [ -d $DrIvC ]; then
        :
      else
        echo ""
        echo "    ERROR: .wine path not found: $DrIvC"
        echo ""
        DrIvC=$(zenity --title="☠ Enter .wine folder PATH ☠" --text "example: $H0m3/.wine" --entry --width 330) > /dev/null 2>&1
      fi

else
    echo "[x] wine64                        [ not found ]"
    sleep 1
    echo ""
    sudo apt-get install $arch
    echo ""

    # test again
    again=`which $arch` > /dev/null 2>&1
    if [ "$?" -eq "0" ]; then
      echo "[✔] $arch ........................[ installed ]"
      sleep 2
    else
      echo ""
      echo "    WARNING: Unable to locate package $arch"
      echo "    To solve this issue make sure you have the right repositories in sources.list"
      echo "    With the right repositories in sources.list, you need to run apt-get update"
      echo "    and then run the installation command for the $arch package again."
      echo "    KALI: https://docs.kali.org/general-use/kali-linux-sources-list-repositories"
      echo "    https://devilzlinux.blogspot.pt/2016/11/how-to-install-wine-on-kali-linux.html"
      echo ""
      sleep 2
      DrIvC="$H0m3/.wine"
    fi
fi



#
# configure WINE settings
#
if [ -d $DrIvC ]; then
  echo "[✔] wine folder.......................[ found ]"
  sleep 2

else

  echo "[x] wine folder                   [ not found ]"
  echo "    Please wait, running winecfg .."
  sleep 1

    if [ "$DiStRo" = "Kali" ]; then
      winecfg > /dev/null 2>&1
    else
      su $user -c "winecfg" > /dev/null 2>&1
    fi

  # check again
  if [ -d $DrIvC ]; then
    echo "[✔] wine folder...................[ installed ]"
    sleep 2
  else
    echo ""
    echo "    WARNING: Unable to locate wine folder"
    echo "    Please Download/Install wine before runing setup.sh .."
    echo "    https://devilzlinux.blogspot.pt/2016/11/how-to-install-wine-on-kali-linux.html"
    echo ""
    sleep 2
  fi
fi



#
# install WinRAR under WINE
#
if [ "$Dftt" = "x86" ]; then

  echo "[✔] arch sellected....................[ 32bit ]"
  sleep 2
  cd .. && cd bin
  # copy winRAR to wine
  if [ "$DiStRo" = "Kali" ]; then

       if [ -d "$DrIvC/drive_c/Program Files/WinRAR" ]; then
         echo "[✔] WinRAR.exe........................[ found ]"
         sleep 2
       else
         echo "[x] WinRAR.exe                    [ not found ]"
         sleep 1
         echo ""
         $arch install_winrar_wine32.exe
         echo ""
         cd $IPATH

           sleep 1
           # check again
           if [ -d "$DrIvC/drive_c/Program Files/WinRAR" ]; then
             echo "[✔] WinRAR.exe....................[ installed ]"
             sleep 2
           else
             echo ""
             echo "    WARNING: Unable to locate WinRAR"
             echo "    Please Download WinRAR to: venom-main/bin"
             echo "    https://github.com/r00t-3xp10it/venom/blob/master/bin/install_winrar_wine32.exe"
             echo ""
             sleep 2
             cd $IPATH
           fi
       fi

  else

       if [ -d "$DrIvC/drive_c/Program Files/WinRAR" ]; then
         echo "[✔] WinRAR.exe........................[ found ]"
         sleep 2
       else
         echo "[x] WinRAR.exe                    [ not found ]"
         sleep 1
         echo ""
         su $user -c "$arch install_winrar_wine32.exe"
         echo ""
         cd $IPATH

           sleep 1
           # check again
           if [ -d "$DrIvC/drive_c/Program Files/WinRAR" ]; then
             echo "[✔] WinRAR.exe....................[ installed ]"
             sleep 2
           else
             echo ""
             echo "    WARNING: Unable to locate WinRAR"
             echo "    Please Download WinRAR to: venom-main/bin"
             echo "    https://github.com/r00t-3xp10it/venom/blob/master/bin/install_winrar_wine32.exe"
             echo ""
             cd $IPATH
             sleep 2
           fi
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
         echo "[x] WinRAR.exe                    [ not found ]"
         sleep 1
         echo ""
         $arch install_winrar_wine64.exe
         echo ""
         cd $IPATH

           sleep 1
           # check again
           if [ -d "$DrIvC/drive_c/Program Files/WinRAR" ]; then
             echo "[✔] WinRAR.exe....................[ installed ]"
             sleep 2
           else
             echo ""
             echo "    WARNING: Unable to locate WinRAR"
             echo "    Please Download WinRAR to: venom-main/bin"
             echo "    https://github.com/r00t-3xp10it/venom/blob/master/bin/install_winrar_wine64.exe"
             echo ""
             sleep 2
             cd $IPATH
           fi
       fi

  else

       if [ -d "$DrIvC/drive_c/Program Files/WinRAR" ]; then
         echo "[✔] WinRAR.exe........................[ found ]"
         sleep 2
       else
         echo "[x] WinRAR.exe                    [ not found ]"
         sleep 1
         echo ""
         su $user -c "$arch install_winrar_wine64.exe"
         echo ""
         cd $IPATH

           sleep 1
           # check again
           if [ -d "$DrIvC/drive_c/Program Files/WinRAR" ]; then
             echo "[✔] WinRAR.exe....................[ installed ]"
             sleep 2
           else
             echo ""
             echo "    WARNING: Unable to locate WinRAR"
             echo "    Please Download WinRAR to: venom-main/bin"
             echo "    https://github.com/r00t-3xp10it/venom/blob/master/bin/install_winrar_wine64.exe"
             echo ""
             sleep 2
             cd $IPATH
           fi
       fi
  fi

fi



#
# pyinstaller wine dependencies checks
#
if [ "$Dftt" = "x86" ]; then

    # check if pyinstaller its on wine directory
    if [ -d "$DrIvC/drive_c/pyinstaller-2.0" ]; then
      echo "[✔] pyinstaller.......................[ found ]"
      sleep 2
    else
      # copy pyinstaller to wine
      echo "[x] pyinstaller                   [ not found ]"
      sleep 1
      cd $IPATH
      cd ..
      cd obfuscate
      tar -xf pyinstaller.tar.gz
      cd pyinstaller

        if [ "$DiStRo" = "Kali" ]; then
          echo "    Copy to: $DrIvC/drive_c/pyinstaller-2.0"
          sleep 1
          mv pyinstaller-2.0 $DrIvC/drive_c/pyinstaller-2.0 > /dev/null 2>&1
          cd ..
          rm -R pyinstaller
          cd $IPATH
        else
          echo "    Copy to: $DrIvC/drive_c/pyinstaller-2.0"
          sleep 1
          su $user -c "mv pyinstaller-2.0 $DrIvC/drive_c/pyinstaller-2.0" > /dev/null 2>&1
          cd ..
          rm -R pyinstaller
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
      echo "[x] pyinstaller                   [ not found ]"
      sleep 1
      cd $IPATH
      cd ..
      cd obfuscate
      tar -xf pyinstaller.tar.gz
      cd pyinstaller

        if [ "$DiStRo" = "Kali" ]; then
          echo "    Copy to: $DrIvC/drive_c/pyinstaller-2.0"
          sleep 1
          mv pyinstaller-2.0 $DrIvC/drive_c/pyinstaller-2.0 > /dev/null 2>&1
          cd ..
          rm -R pyinstaller
          cd $IPATH
        else
          echo "    Copy to: $DrIvC/drive_c/pyinstaller-2.0"
          sleep 1
          su $user -c "mv pyinstaller-2.0 $DrIvC/drive_c/pyinstaller-2.0" > /dev/null 2>&1
          cd ..
          rm -R pyinstaller > /dev/null 2>&1
          cd $IPATH
        fi
    fi
fi




#
# check if pywin32-220 its installed ..
#
if [ "$Dftt" = "x86" ]; then

    #
    # check if pywin32-220 its on wine directory
    #
    if [ -e "$DrIvC/drive_c/Python26/pywin32-wininst.log" ]; then
      echo "[✔] pywin32-220.......................[ found ]"
      sleep 2
    else
      # copy pywin32 to wine
      echo "[x] pywin32-220                   [ not found ]"
      sleep 1
      cd $IPATH
      cd ..
      cd obfuscate
      tar -xf pyinstaller.tar.gz
      cd pyinstaller

        if [ "$DiStRo" = "Kali" ]; then
          echo ""
          echo "Install: python 2.6.6.msi"
          echo ""
          sleep 1
          $arch msiexec /i python-2.6.6.msi
          echo ""
          echo "Install: pywin32-220.win32-py2.6.exe"
          echo ""
          sleep 1
          $arch pywin32-220.win32-py2.6.exe
          echo ""
          cd ..
          rm -R pyinstaller

            sleep 1
            # check again
            if [ -e "$DrIvC/drive_c/Python26/pywin32-wininst.log" ]; then
              echo "[✔] pywin32-220...................[ installed ]"
              sleep 2
            else
              echo ""
              echo "    WARNING: Unable to locate pywin32-220 (x86)"
              echo "    Please Download/Install the follow packets"
              echo "    python-2.6.6.msi"
              echo "    pywin32-220.win32-py2.6.exe"
              echo ""
              sleep 2
            fi
            cd $IPATH

        else

          echo ""
          echo "Install: python 2.6.6.msi"
          echo ""
          sleep 1
          su $user -c "$arch msiexec /i python-2.6.6.msi"
          echo ""
          echo "Install: pywin32-220.win32-py2.6.exe"
          echo ""
          sleep 1
          su $user -c "$arch pywin32-220.win32-py2.6.exe"
          echo ""
          cd ..
          rm -R pyinstaller

            sleep 1
            # check again
            if [ -e "$DrIvC/drive_c/Python26/pywin32-wininst.log" ]; then
              echo "[✔] pywin32-220...................[ installed ]"
              sleep 2
            else
              echo ""
              echo "    WARNING: Unable to locate pywin32-220 (x86)"
              echo "    Please Download/Install the follow packets"
              echo "    python-2.6.6.msi"
              echo "    pywin32-220.win32-py2.6.exe"
              echo ""
              sleep 2
            fi
        fi
    fi
    cd $IPATH


else


    # check if pywin32 its on wine directory
    if [ -e "$DrIvC/drive_c/Python26/pywin32-wininst.log" ]; then
      echo "[✔] pywin32-220.......................[ found ]"
      sleep 2
    else
      # copy pywin32 to wine
      echo "[x] pywin32-220                   [ not found ]"
      sleep 1
      cd $IPATH
      cd ..
      cd obfuscate
      tar -xf pyinstaller.tar.gz
      cd pyinstaller

        if [ "$DiStRo" = "Kali" ]; then
          echo ""
          echo "Install: python-2.6.6.amd64.msi"
          echo ""
          sleep 1
          $arch msiexec /i python-2.6.6.amd64.msi
          echo ""
          echo "Install: pywin32-220.win-amd64-py2.6.exe"
          echo ""
          sleep 1
          $arch pywin32-220.win-amd64-py2.6.exe
          echo ""
          cd ..
          rm -R pyinstaller

            sleep 1
            # check again
            if [ -e "$DrIvC/drive_c/Python26/pywin32-wininst.log" ]; then
              echo "[✔] pywin32-220...................[ installed ]"
              sleep 2
            else
             echo ""
             echo "    WARNING: Unable to locate pywin32-220 (x64)"
             echo "    Please Download/Install the follow packets"
             echo "    python-2.6.6.amd64.msi"
             echo "    pywin32-220.win-amd64-py2.6.exe"
             echo ""
             sleep 2
            fi
            cd $IPATH

        else

          echo ""
          echo "Install: python-2.6.6.amd64.msi"
          echo ""
          sleep 1
          su $user -c "$arch msiexec /i python-2.6.6.amd64.msi"
          echo ""
          echo "Install: pywin32-220.win-amd64-py2.6.exe"
          echo ""
          sleep 1
          su $user -c "$arch pywin32-220.win-amd64-py2.6.exe"
          echo ""
          cd ..
          rm -R pyinstaller > /dev/null 2>&1

            sleep 1
            # check again
            if [ -e "$DrIvC/drive_c/Python26/pywin32-wininst.log" ]; then
              echo "[✔] pywin32-220...................[ installed ]"
              sleep 2
            else
              echo ""
              echo "    WARNING: Unable to locate pywin32-220 (x64)"
              echo "    Please Download/Install the follow packets"
              echo "    python-2.6.6.amd64.msi"
              echo "    pywin32-220.win-amd64-py2.6.exe"
              echo ""
              sleep 2
            fi
        fi
    fi
    cd $IPATH
fi



#
# rebuild settings file ..
#
echo "[✔] Rebuild toolkit settings file.....[  done ]"
sleep 2
# change to rigth directory structure
cd ..
# store settings file values in variables
ApWR=`cat settings | egrep -m 1 "APACHE_WEBROOT" | cut -d '=' -f2` > /dev/null 2>&1
DTuR=`cat settings | egrep -m 1 "MEGAUPLOAD_DOMAIN" | cut -d '=' -f2` > /dev/null 2>&1
WdPa=`cat settings | egrep -m 1 "WINE_DRIVEC" | cut -d '=' -f2` > /dev/null 2>&1
ArP=`cat settings | egrep -m 1 "ARP_SETTINGS" | cut -d '=' -f2` > /dev/null 2>&1
EdNp=`cat settings | egrep -m 1 "ETTER_DNS_PATH" | cut -d '=' -f2` > /dev/null 2>&1
EPAUA=`cat settings | egrep -m 1 "SYSTEM_ARCH" | cut -d '=' -f2` > /dev/null 2>&1
# config venom auxiliry modules install paths
POSTPATH=`cat settings | egrep -m 1 "POST_EXPLOIT_DIR" | cut -d '=' -f2` > /dev/null 2>&1
MSF_RANDOM_STAGER=`cat settings | egrep -m 1 "METERPRETER_STAGER" | cut -d '=' -f2` > /dev/null 2>&1


# config settings file
if [ "$sddf" = "domain" ]; then
Ps="$P0Is0N/etter.dns"
else
Ps="/etc/ettercap/etter.dns"
fi
# change setting file configurations
sed -i "s|$ApWR|$ApAcHe|" settings
sed -i "s|$DTuR|$dsrr|" settings
sed -i "s|$WdPa|$DrIvC/drive_c|" settings
sed -i "s|$ArP|$fd3d|" settings
sed -i "s|$EdNp|$Ps|" settings
sed -i "s|$EPAUA|$Dftt|" settings
sed -i "s|$POSTPATH|$MSFDATA/modules|" settings
sed -i "s|$MSF_RANDOM_STAGER|$MSFDATA/lib/msf/core/payload/windows|" settings
cd $IPATH/




#
# exit setup.sh script
#
echo "[✔] All checks completed..............[  done ]"
sleep 2
echo ""
echo "    Report-Bugs: https://github.com/r00t-3xp10it/venom/issues"
echo ""
sleep 1
cd $IPATH/
exit


#
# aborted setup.sh execution
#
else


  echo "[x] Script execution aborted .."
  sleep 2
  echo "    Report-Bugs: https://github.com/r00t-3xp10it/venom/issues"
  echo ""
  sleep 1
exit
fi

