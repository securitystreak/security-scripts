import time, dpkt
import plotly.plotly as py
from plotly.graph_objs import *
from datetime import datetime

filename = 'hbot.pcap'

full_datetime_list = []
dates = []

for ts, pkt in dpkt.pcap.Reader(open(filename,'rb')):
    eth=dpkt.ethernet.Ethernet(pkt) 
    if eth.type!=dpkt.ethernet.ETH_TYPE_IP:
        continue

    ip = eth.data
    tcp=ip.data
    
    if ip.p not in (dpkt.ip.IP_PROTO_TCP, dpkt.ip.IP_PROTO_UDP):
        continue

    if tcp.dport == 21 or tcp.sport == 21:
        full_datetime_list.append((ts, str(time.ctime(ts))))
 

for t,d in full_datetime_list:
    if d not in dates:
        dates.append(d)
    
dates.sort(key=lambda date: datetime.strptime(date, "%a %b %d %H:%M:%S %Y"))

datecount = []

for d in dates:
    counter = 0
    for d1 in full_datetime_list:
        if d1[1] == d:
            counter += 1

    datecount.append(counter)


data = Data([
    Scatter(
        x=dates,
        y=datecount
    )
])
plot_url = py.plot(data, filename='FTP Requests')
