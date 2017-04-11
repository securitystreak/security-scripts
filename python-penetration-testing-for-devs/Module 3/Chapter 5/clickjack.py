import requests
from ghost import Ghost
import logging
import os

#<iframe src="http://usabledesigns.com/demo/iframe-test"></iframe>

URL = 'http://usabledesigns.com/demo/iframe-test'
URL = 'https://support.realvnc.com'
URL = 'https://evaluation.realvnc.com'
#def clickjack(URL):


req = requests.get(URL)

try:
    xframe = req.headers['x-frame-options']
    print 'X-FRAME-OPTIONS:', xframe , 'present, clickjacking not likely possible'
except:
    print 'X-FRAME-OPTIONS missing'

print 'Attempting clickjacking...'
#clickjack(URL)

html = '''
<html>
<body>
<iframe src="'''+URL+'''" height='600px' width='800px'></iframe>
</body>
</html>'''
  
html_filename = 'clickjack.html'
log_filename = 'test.log'
  
f = open(html_filename, 'w+')
f.write(html)
f.close()

fh = logging.FileHandler(log_filename)
ghost = Ghost(log_level=logging.INFO, log_handler=fh)
page, resources = ghost.open(html_filename)
  
l = open(log_filename, 'r')
if 'forbidden by X-Frame-Options.' in l.read():
    print 'Clickjacking mitigated via X-FRAME-OPTIONS'
else:
    href = ghost.evaluate('document.location.href')[0]
    if html_filename not in href:
        print 'Frame busting detected'
    else:
        print 'Frame busting not detected, page is likely vulnerable to clickjacking'
l.close()

logging.getLogger('ghost').handlers[0].close()
os.unlink(log_filename)
os.unlink(html_filename)