import requests

url = 'http://www.packtpub.com/'
req = requests.get(url)

print req.cookies
cookies = dict(admin='True')

cookie_req = requests.get(url, cookies=cookies)
print cookie_req.text