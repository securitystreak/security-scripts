#!/usr/bin/python
#
# Copyright (C) 2015 Michael Spreitzenbarth (research@spreitzenbarth.de)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import os, sys, subprocess


def get_kc(ip, backup_dir):
    
    # dumping the keychain
    print "Dumping the keychain ..."
    
    kc = subprocess.Popen(['scp', 'root@' + ip + ':/private/var/Keychains/keychain-2.db', backup_dir], 
        stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
    kc.communicate()


def push_kcd(ip):
    
    # dumping the keychain
    print "Pushing the Keychain Dumper to the device ..."
    
    kcd = subprocess.Popen(['scp', 'keychain_dumper' 'root@' + ip + ':~/'], 
        stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
    kcd.communicate()


def exec_kcd(ip, backup_dir):

    # pretty print keychain
    kcc = subprocess.Popen(['ssh', 'root@' + ip, './keychain_dumper'], 
        stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
    kcc.communicate()
    kcc.stdout


if __name__ == '__main__':

    # starting to create the output directory
    backup_dir = sys.argv[1]

    try:
        os.stat(backup_dir)
    except:
        os.mkdir(backup_dir)

    # get the IP of the iDevice from user input
    ip = sys.argv[2]

    get_kc(ip, backup_dir)
    push_kcd(ip)
    exec_kcd(ip, backup_dir)