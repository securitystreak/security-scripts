from ctypes import *

class case(Union):
	_fields_ = [
	("evidence_long", c_long),
	("evidence_int", c_int),
	("evidence_char", c_char * 4),
	]

value = raw_input("Enter new evidence number:")
new_evidence = case(int(value))
print "Evidence number as a long: %ld" % new_evidence.evidence_long
print "Evidence number as a int: %d" % new_evidence.evidence_int
print "Evidence number as a char: %s" % new_evidence.evidence_char
