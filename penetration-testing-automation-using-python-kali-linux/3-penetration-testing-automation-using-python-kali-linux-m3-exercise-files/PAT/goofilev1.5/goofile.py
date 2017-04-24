#!/usr/bin/env python
# Goofile v1.5
# My Website: http://www.g13net.com
# Project Page: http://code.google.com/p/goofile
#
# TheHarvester used for inspiration
# A many thanks to the Edge-Security team!           
# 

import string
import httplib
import sys
import re
import getopt

print "\n-------------------------------------"
print "|Goofile v1.5	                    |"
print "|Coded by Thomas (G13) Richards     |"
print "|www.g13net.com                     |"
print "|code.google.com/p/goofile          |"
print "-------------------------------------\n\n"

global result
result =[]

def usage():
 print "Goofile 1.5\n"
 print "usage: goofile options \n"
 print "       -d: domain to search\n"
 print "       -f: filetype (ex. pdf)\n"
 print "example:./goofile.py -d test.com -f txt\n" 
 sys.exit()

def run(dmn,file):

	h = httplib.HTTP('www.google.com')
	h.putrequest('GET',"/search?num=500&q=site:"+dmn+"+filetype:"+file)
	h.putheader('Host', 'www.google.com')
	h.putheader('User-agent', 'Internet Explorer 6.0 ')
	h.putheader('Referrer', 'www.g13net.com')
	h.endheaders()
	returncode, returnmsg, headers = h.getreply()
	data=h.getfile().read()
	data=re.sub('<b>','',data)
        for e in ('>','=','<','\\','(',')','"','http',':','//'):
		data = string.replace(data,e,' ')
	r1 = re.compile('[-_.a-zA-Z0-9.-_]*'+'\.'+file)	
	res = r1.findall(data) 
	return res 
	

def search(argv):
	global limit
	limit = 100
	if len(sys.argv) < 2: 
		usage() 
	try :
	      opts, args = getopt.getopt(argv,"d:f:")
 
	except getopt.GetoptError:
  	     	usage()
		sys.exit()
	
	for opt,arg in opts :
    	   	if opt == '-f' :
			file=arg
		elif opt == '-d':
			dmn=arg
	
	print "Searching in "+dmn+" for "+ file
	print "========================================"


	cant = 0

	while cant < limit:
		res = run(dmn,file)
		for x in res:
			if result.count(x) == 0:
        			result.append(x)
		cant+=100
			

	print "\nFiles found:"
	print "====================\n"
	t=0
	if result==[]:
		print "No results were found"
	else:
		for x in result:
			x= re.sub('<li class="first">','',x)
			x= re.sub('</li>','',x)
			print x
			t+=1
	print "====================\n"
	

if __name__ == "__main__":
        try: search(sys.argv[1:])
	except KeyboardInterrupt:
		print "Search interrupted by user.."
	except:
		sys.exit()
