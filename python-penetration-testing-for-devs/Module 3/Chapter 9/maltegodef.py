print"<MaltegoMessage>"
print"<MaltegoTransformResponseMessage>"
print"	<Entities>"


def maltego(entity, value, addvalues):
	print"		<Entity Type=\"maltego."+entity+"\">"
	print"			<Value>"+value+"</Value>"
	print"			<AdditionalFields>"
	for value, item in addvalues.iteritems():
		print"			<Field Name=\""+value+"\" DisplayName=\""+value+"\" MatchingRule=\"strict\">"+item+"</Field>"
	print"			</AdditionalFields>"
	print"		</Entity>"


maltego("ip", "127.0.0.1", {"domain": "google.com"})



print"	</Entities>"
print"</MaltegoTransformResponseMessage>"
print"</MaltegoMessage>"
