#!./env/bin/python

""" fping

    A replacement for the fping tool because it is broken on osx. This
    takes the ip addresses or ip subnet given and pings them to see if
    they are alive.

    Don't be a moron, please don't use this for something illegal.

    Usage:
        fping.py list <ips>... [--threads=<threads>]/
        fping.py subnet <subnet> [--threads=<threads>]
        fping.py (-h|--help)
        fping.py --version

    Options:
        --threads=<threads> number of threads, defaults to four
        -h, --help          Display this message
        --version           Display the version of this program

    Examples:
        ./fping.py list 10.0.0.1 10.0.0.2
        ./fping.py list 10.0.0.1 10.0.0.2 --threads=8
        ./fping.py subnet 10.0.0.1/24
        ./fping.py subnet 10.0.0.1/24 --threads=8
"""

from docopt import docopt
from threading import Thread
import subprocess
from netaddr import IPNetwork
from Queue import Queue

if __name__ == '__main__':
    arguments = docopt(__doc__)

    if arguments['list']:
        ips = arguments['<ips>']
    elif arguments['subnet']:
        ips = list(IPNetwork(arguments['<subnet>']))

    if arguments['--threads']:
        num_threads = int(arguments['--threads'])
    else:
        num_threads = 4

    queue = Queue()


#wraps system ping command
def pinger(i, q):
    """Pings subnet"""
    while True:
        ip = q.get()
        ret = subprocess.call("ping -o -t 1 %s" % ip,
                              shell=True,
                              stdout=open('/dev/null', 'w'),
                              stderr=subprocess.STDOUT)
        if ret == 0:
            print ip
        q.task_done()
#Spawn thread pool
for i in range(num_threads):

    worker = Thread(target=pinger, args=(i, queue))
    worker.setDaemon(True)
    worker.start()

#Place work in queue
for ip in ips:
    queue.put(ip)

#Wait until worker threads are done to exit
queue.join()
