import requests
import re
from bs4 import BeautifulSoup
import sys

scripts = []

if len(sys.argv) != 2:
	print "usage: %s url" % (sys.argv[0])
	sys.exit(0)

tarurl = sys.argv[1]
url = requests.get(tarurl)
soup = BeautifulSoup(url.text)
for line in soup.find_all('script'):
	newline = line.get('src')
	scripts.append(newline)
	
for script in scripts:
	if "jquery.min" in str(script).lower():
		print script
		url = requests.get(script)
		comments = re.findall(r'\d[0-9a-zA-Z._:-]+',url.text)
		if comments[0] == "2.1.1" or comments[0] == "1.12.1":
			print "Up to date"
		else:
			print "Out of date"
			print "Version detected: "+comments[0]

	#try:
	#	if newline[:4] == "http":
	#		if tarurl in newline:
	#			urls.append(str(newline))
	#	elif newline[:1] == "/":
	#		combline = tarurl+newline 
	#		urls.append(str(combline)) 
	#except:
	#	pass
	#	print "failed"
#for uurl in urls:
#	if "jquery" in url:
#		