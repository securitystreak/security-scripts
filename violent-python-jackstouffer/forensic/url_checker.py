#!./env/bin/python

""" Url Checker

    This program brute forces a url pattern, with words from a provided
    file, to detect anything that does not throw a 404 error. Useful for
    finding hidden directories and files. A good number of wordlists have
    been included in this distribution for your convenience.

    Don't be a moron, please don't use this for something illegal.

    Usage:
        url_checker.py <url> <password_file> [(-a|--async) --verbose]
        url_checker.py <url> <password_file>
        url_checker.py (-h|--help)
        url_checker.py --version

    Options:
        -h, --help          Display this message
        --version           Display the version of this program
        -a, --async         Send requests asynchronously (faster but straining on server)

    Examples:
        ./url_checker.py http://www.example.com/\{\} wordlist.txt
        ./url_checker.py http://www.example.com/\{\}.php wordlist.txt  --async
        ./url_checker.py http://www.example.com/file.php?argument=\{\} wordlist.txt
"""

import requests
import time
import grequests
from docopt import docopt
from colorama import Fore, init


def file_len(fname):
    with open(fname) as f:
        for i, l in enumerate(f):
            pass
    return i + 1


def main(file, url, async, verbose):
    f = open(file, 'r')
    num_lines = file_len(file)
    start_time = time.time()
    count = 0

    if verbose:
        print "[+] Checking {} different urls, this may take a while.".format(num_lines)

    urls = []
    for line in f:
        line = line.rstrip('\n')
        formated_url = url.format(line)
        urls.append(formated_url)

    if async:
        rs = (grequests.get(u) for u in urls)
        responses = grequests.map(rs)
        for response in responses:
            if response.status_code != 404:
                print response.url + " : " + str(response.status_code)
                count += 1
    else:
        for url in urls:
            r = requests.get(url, verify=False)
            if r.status_code != 404:
                print Fore.GREEN + "[*] " + r.url + " : " + str(r.status_code) + Fore.RESET
                count += 1

    if verbose:
        if count == 0:
            print Fore.RED + "[-] No urls where found!" + Fore.RESET
        else:
            print "Found {} urls".format(count)

        print "Checked {} different urls in {} seconds\n".format(num_lines, time.time() - start_time)


if __name__ == '__main__':
    init()
    arguments = docopt(__doc__, version="1.0")
    main(arguments['<password_file>'], arguments['<url>'], arguments['--async'], arguments['--verbose'])
