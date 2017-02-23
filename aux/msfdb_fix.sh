#!/bin/bash
# resize terminal windows
resize -s 22 94 > /dev/null



# banner display
cat << !


    postgresql metasploit database connection fix

!

# testings
echo "[*] start postgresql service .."
service postgresql start
sleep 4



echo "[*] checking port 5432 .."
check=`ss -ant | grep 5432 | awk {'print $4'}`
dis=`ss -ant | grep 5432`
if [ "$check" != "127.0.0.1:5432" ]; then

echo "[*] port 5432 (postgresql) its not active .."
sleep 2

# rebuild msf database
echo "[*] rebuilding msf database .."
echo ""
msfdb delete
msfdb init
echo ""
sleep 4
echo "[*] checking port 5432 .."
dis=`ss -ant | grep 5432`
echo "    $dis"

else
echo ""
echo "    $dis"
echo ""
fi

echo "[*] checking msfdb connection status .."
msfconsole -q -x 'db_status; exit -y'
# echo "[*] stoping postgresql service .."
# service postgresql stop
