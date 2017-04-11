import requests
import sys
from bs4 import BeautifulSoup, SoupStrainer
url = "http://127.0.0.1/xss/medium/guestbook2.php"
url2 = "http://127.0.0.1/xss/medium/addguestbook2.php"
url3 = "http://127.0.0.1/xss/medium/viewguestbook2.php"

f =  open("/home/cam/Downloads/fuzzdb-1.09/attack-payloads/all-attacks/interesting-metacharacters.txt")
o = open("results.txt", 'a')
d = {}
sets = []

print "Fuzzing begins!"

initial = requests.get(url)
for payload in f.readlines():
	for field in BeautifulSoup(initial.text, parse_only=SoupStrainer('input')):
	        if field.has_attr('name'):
	        	if field['name'].lower() == "submit":
	        		d[field['name']] = "submit"
	        	else:
	        		d[field['name']] = payload
	sets.append(d)
	req = requests.post(url2, data=d)
	response = requests.get(url3)

	o.write("Payload: "+ payload +"\r\n")
	o.write(response.text+"\r\n")


	d = {}

print "Fuzzing has ended"