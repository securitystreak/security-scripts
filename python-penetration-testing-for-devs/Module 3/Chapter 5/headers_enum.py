import requests

req = requests.get('http://google.com')
headers = ['Server', 'Date', 'Via', 'X-Powered-By']

for header in headers:
    try:
	result = req.headers[header]
        print '%s: %s' % (header, result)
    except Exception, error:
        pass