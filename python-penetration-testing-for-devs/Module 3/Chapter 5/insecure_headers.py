import requests
from ghost import Ghost
import logging
import os

url = 'http://www.realvnc.com'
req = requests.get(url)

def clickjack(url):
	html = '''
<html>
<body>
<iframe src="'''+url+'''"></iframe>
</body>
</html>'''
	 
	html_file = 'clickjack.html'
	log_file = 'test.log'
	 
	f = open(html_file, 'w+')
	f.write(html)
	f.close()
	 
	logging.basicConfig(filename=log_file)
	logger = logging.getLogger('ghost')
	logger.propagate = False
	 
	ghost = Ghost(log_level=logging.INFO)
	page, resources = ghost.open(html_file)
	ghost.exit()
	 
	l = open(log_file, 'r')
	if 'forbidden by X-Frame-Options.' in l.read():
	    print 'Clickjacking mitigated'
	else:
		print 'Clickjacking successful'
		print os.getcwd()
	 
	l.close()


try:
	xframe = req.headers['x-frame-options']
	print 'X-FRAME-OPTIONS:', xframe , 'present, clickjacking not likely possible'
except:
	print 'X-FRAME-OPTIONS missing'
print 'attempting clickjacking...'
clickjack(url)

try:
	xssprotect = req.headers['X-XSS-Protection']
	if 1 not in 'xssprotect':
		print 'X-XSS-Protection not set properly, XSS may be possible'
except:
	print 'X-XSS-Protection not set, XSS may be possible'

try:
	hsts = req.headers['Strict-Transport-Security']
except:
	print 'HSTS header not set, MITM should be possible via HTTP'