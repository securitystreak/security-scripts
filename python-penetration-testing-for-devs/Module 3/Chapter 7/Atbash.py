#!/usr/bin/python
import string

input = raw_input("Please enter the value you would like to Atbash Ciper: ")

transform = string.maketrans(
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
"ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba")

final = string.translate(input, transform)

print final