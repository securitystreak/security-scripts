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

import os, sys, subprocess, binascii, struct
import sqlite3 as lite


def get_sha1hash(backup_dir):

    # dumping the password/pin from the device
    print "Dumping PIN/Password hash ..."
    password = subprocess.Popen(['adb', 'pull', '/data/system/password.key', backup_dir], 
        stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
    password.wait()

    # cutting the HASH within password.key
    sha1hash = open(backup_dir + '/password.key', 'r').readline()[:40]
    print "HASH: \033[0;32m" + sha1hash + "\033[m"
    
    return sha1hash


def get_salt(backup_dir):

    # dumping the system DB containing the SALT
    print "Dumping locksettings.db ..."
    saltdb = subprocess.Popen(['adb', 'pull', '/data/system/locksettings.db', backup_dir], 
        stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
    saltdb.wait()
    saltdb2 = subprocess.Popen(['adb', 'pull', '/data/system/locksettings.db-wal', backup_dir], 
        stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
    saltdb2.wait()
    saltdb3 = subprocess.Popen(['adb', 'pull', '/data/system/locksettings.db-shm', backup_dir], 
        stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
    saltdb3.wait()

    # extract the SALT
    con = lite.connect(backup_dir + '/locksettings.db')
    cur = con.cursor()    
    cur.execute("SELECT value FROM locksettings WHERE name='lockscreen.password_salt'")
    salt = cur.fetchone()[0]
    con.close()

    # convert SALT to Hex
    returnedsalt =  binascii.hexlify(struct.pack('>q', int(salt) ))
    print "SALT: \033[0;32m" + returnedsalt + "\033[m"

    return returnedsalt


def write_crack(salt, sha1hash, backup_dir):

    crack = open(backup_dir + '/crack.hash', 'a+')
    
    # write HASH and SALT to cracking file
    hash_salt = sha1hash + ':' + salt
    crack.write(hash_salt)
    crack.close()

    
if __name__ == '__main__':

    # check if device is connected and adb is running as root
    if subprocess.Popen(['adb', 'get-state'], stdout=subprocess.PIPE).communicate(0)[0].split("\n")[0] == "unknown":
        print "no device connected - exiting..."
        sys.exit(2)

    # starting to create the output directory and the crack file used for hashcat
    backup_dir = sys.argv[1]

    try:
        os.stat(backup_dir)
    except:
        os.mkdir(backup_dir)
    
    sha1hash = get_sha1hash(backup_dir)
    salt = get_salt(backup_dir)
    write_crack(salt, sha1hash, backup_dir)

    print "crack.hash can now be used to feed hashcat"
    print "\033[0;32m-> hashcat -a 3 -m 110 " + backup_dir + "/crack.hash -1 ?d ?1?1?1?1\033[m (just add ?1 for echt additional digit to crack)"