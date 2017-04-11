#!/usr/bin/python
import hashlib

target = raw_input("Please enter your hash here: ")
dictionary = raw_input("Please enter the file name of your dictionary: ")


def main():
    with open(dictionary) as fileobj:
        for line in fileobj:
            line = line.strip()
            if hashlib.md5(line).hexdigest() == target:
                print "Hash was successfully cracked %s: The value is %s" % (target, line)
                return ""
    print "Failed to crack the file."

if __name__ == "__main__":
    main()
