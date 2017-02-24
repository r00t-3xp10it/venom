#!/bin/bash
# resize terminal windows
resize -s 22 94 > /dev/null



# banner display
cat << !

    ╔─────────────────────────────────────────────────╗
    |  postgresql metasploit database connection fix  |
    ╚─────────────────────────────────────────────────╝

!

# testings
echo "[*] Starting postgresql service .."
service postgresql start
sleep 4


  #
  # check for postgresql port active
  #
  echo "[*] Checking port 5432 connection .."
  check=`ss -ant | grep 5432 | awk {'print $4'}`
  dis=`ss -ant | grep 5432`

    if [ "$check" != "127.0.0.1:5432" ]; then
      echo "[*] Port 5432 (postgresql): NOT active .."
      sleep 2
      echo "[*] Please wait, rebuilding msf database .."
      # rebuild msf database (database.yml)
      echo ""
      msfdb delete
      msfdb init
      echo ""
      sleep 6
      echo "[*] rechecking port 5432 connection .."
      dis=`ss -ant | grep 5432`
      echo "    $dis"

    else

      #
      # port 5432 active, no need to rebuild msfdb
      #
      echo ""
      echo "    $dis"
      echo ""
      echo "[*] Port 5432 (postgresql): active .."
    fi


  #
  # start msfconsole to check postgresql connection status
  #
  echo "[*] Checking msfdb connection status .."
  msfconsole -q -x 'db_status; exit -y'
  # echo "[*] stoping postgresql service .."
  # service postgresql stop
  sleep 1


  # start venom framework
  echo -n "[*] Start venom framework? (y/n):"
  read question

if [ "$question" = "y" ]; then
echo "[*] Please wait, executing framework .."
cd ..
./venom.sh
fi

