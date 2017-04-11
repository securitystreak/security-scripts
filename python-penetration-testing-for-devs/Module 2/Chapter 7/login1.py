import httplib
import shelve
url = raw_input("Enter the full URL ")
url1 =url.replace("http://","")
url2= url1.replace("/","")
s = shelve.open("mohit.raj",writeback=True)

for u in s['php']:
	a = "/"
	url_n = url2+a+u
	print url_n
	http_r = httplib.HTTPConnection(url2)
	u=a+u
	http_r.request("GET",u)
	reply = http_r.getresponse()
	
	if reply.status == 200:
		print "\n URL found ---- ", url_n
		ch = raw_input("Press c for continue : ")
		if ch == "c" or ch == "C" :
			continue 
		else :
			break
	
s.close()