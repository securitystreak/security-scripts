#bruteforce file names
import sys
import urllib
import urllib2

if len(sys.argv) !=4:
    print "usage: %s url wordlist fileextension\n" % (sys.argv[0])
    sys.exit(0)

base_url = str(sys.argv[1])
wordlist= str(sys.argv[2])
extension=str(sys.argv[3])
filelist = open(wordlist,'r')
foundfiles = []

for file in filelist:
	file=file.strip("\n")
	extension=extension.rstrip()
	url=base_url+file+"."+str(extension.strip("."))
	try:
		request = urllib2.urlopen(url)
		if(request.getcode()==200):
			foundfiles.append(file+"."+extension.strip("."))
		request.close()
	except urllib2.HTTPError, e:
		pass

if len(foundfiles)>0:
	print "The following files exist:\n"
	for filename in foundfiles:
		print filename+"\n"
else:
	print "No files found\n"
