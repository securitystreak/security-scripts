import requests
import time

def check_httponly(c):
	if 'httponly' in c._rest.keys():
		return True
	else:
		return '\x1b[31mFalse\x1b[39;49m'

#req = requests.get('http://www.realvnc.com/support')
values = []
for i in xrange(0,5):
	req = requests.get('http://www.google.com')
	for cookie in req.cookies:
		print 'Name:', cookie.name
		print 'Value:', cookie.value
		values.append(cookie.value)
		if not cookie.secure:
			cookie.secure = '\x1b[31mFalse\x1b[39;49m'
		print 'HTTPOnly:', check_httponly(cookie), '\n'
	time.sleep(2)

print set(values)