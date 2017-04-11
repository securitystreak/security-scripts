#!/usr/bin/python

import uuid
import hashlib
 
def hash(password):
    salt = uuid.uuid4().hex
    return hashlib.sha512(salt.encode() + password.encode()).hexdigest() + ':' + salt
    
def check(hashed, p2):
    password, salt = hashed.split(':')
    return password == hashlib.sha512(salt.encode() + p2.encode()).hexdigest()
 
password = raw_input('Please enter a password: ')

hashed = hash(password)

print('The string to store in the db is: ' + hashed)

re = raw_input('Please re-enter your password: ')

if check(hashed, re):
    print('Password Match')
else:
    print('Password Mismatch')