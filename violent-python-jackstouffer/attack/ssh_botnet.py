#!./env/bin/python

""" SSH Botnet

    This script logs into several different machines with ssh and sends
    commands to each of them in tandem

    Don't be a moron, please don't use this for something illegal.

    Usage:
        ssh_botnet.py
        ssh_botnet.py (-h | --help)
        ssh_botnet.py (-v | --version)

    Options:
        -h --help       Show this screen.
        --version       Show version
"""

import pxssh
from docopt import docopt
from colorama import Fore, init


class Client:
    def __init__(self, host, user, password):
        self.host = host
        self.user = user
        self.password = password
        self.session = self.connect()

    def connect(self):
        try:
            ssh = pxssh.pxssh()
            ssh.login(self.host, self.user, self.password)

            return ssh
        except Exception, e:
            print Fore.RED + '[-] Error Connecting' + Fore.RESET
            print e

    def send_command(self, cmd):
        self.session.sendline(cmd)
        self.session.prompt()

        return self.session.before


def botnet_command(command, botnet):
    for client in botnet:
        output = client.send_command(command)
        print Fore.GREEN + '[*] Output from ' + client.host + Fore.RESET
        print '[+] ' + output + '\n'


def add_client(host, user, password, botnet):
    client = Client(host, user, password)
    botnet.append(client)


def main():
    botnet = []

    add_client('10.10.10.110', 'root', 'toor', botnet)
    add_client('10.10.10.120', 'root', 'toor', botnet)
    add_client('10.10.10.130', 'root', 'toor', botnet)
    botnet_command('uname -v', botnet)


if __name__ == '__main__':
    init()
    docopt(__doc__, version=0.1)
    main()
