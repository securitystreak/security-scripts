#!/usr/bin/python
# -*- coding: utf-8 -*-

import hashlib

message = raw_input("Enter the string you would like to hash: ")
md5 = hashlib.md5(message.encode())

print (md5.hexdigest())
