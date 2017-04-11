import scapy, GeoIP
from scapy import *

gi = GeoIP.new(GeoIP.GEOIP_MEMORY_CACHE)
def locatePackage(pkg):
	src=pkg.getlayer(IP).src
	dst=pkg.getlayer(IP).dst
	srcCountry = gi.country_code_by_addr(src)
	dstCountry = gi.country_code_by_addr(dst)
	print srcCountry+">>"+dstCountry

try:
	while True:
		sniff(filter="ip",prn=locatePackage,store=0)
except KeyboardInterrupt:
	print "\nScan Aborted!\n"
