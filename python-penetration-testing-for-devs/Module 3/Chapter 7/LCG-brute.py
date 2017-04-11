#Linear Conruential Generator reverse from known mod, multiplier and increment + final 2 chars of each random value
#Replace hardcode numbers with known numbers

print "Starting attempt to brute"

for i in range(100000, 99999999):
	a = str((1664525 * int(str(i)+'00') + 1013904223) % 2**31)
	if a[-2:] == "47":
		b = str((1664525 * int(a) + 1013904223) % 2**31)
		if b[-2:] == "46":
			c = str((1664525 * int(b) + 1013904223) % 2**31)
			if c[-2:] == "57":
				d = str((1664525 * int(c) + 1013904223) % 2**31)
				if d[-2:] == "56":
					e = str((1664525 * int(d) + 1013904223) % 2**31)
					if e[-2:] == "07":
						f = str((1664525 * int(e) + 1013904223) % 2**31)
						if f[-2:] == "38":
							g = str((1664525 * int(f) + 1013904223) % 2**31)
							if g[-2:] == "81":
								h = str((1664525 * int(g) + 1013904223) % 2**31)
								if h[-2:] == "32":
									j = str((1664525 * int(h) + 1013904223) % 2**31)
									if j[-2:] == "19":
										k = str((1664525 * int(j) + 1013904223) % 2**31)
										if k[-2:] == "70":
											l = str((1664525 * int(k) + 1013904223) % 2**31)
											if l[-2:] == "53":
												print "potential number found: "+l
print "next 9 values are:"
for i in range(1, 10):
	l = str((1664525 * int(l) + 1013904223) % 2**31)
	print l[-2:]							