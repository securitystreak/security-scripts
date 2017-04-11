#!/usr/bin/env python
'''
Author: Christopher S. Duffy
Date: March 2015
Name: username_generator.py
Purpose: To generate a username list from the US Census Top 1000 surnames and other lists

Copyright (c) 2015, Christopher Duffy All rights reserved.

Redistribution and use in source and binary forms, with or without modification, 
are permitted provided that the following conditions are met: * Redistributions 
of source code must retain the above copyright notice, this list of conditions and 
the following disclaimer. * Redistributions in binary form must reproduce the above 
copyright notice, this list of conditions and the following disclaimer in the 
documentation and/or other materials provided with the distribution. * Neither the 
name of the nor the names of its contributors may be used to endorse or promote 
products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, 
THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 
DISCLAIMED. IN NO EVENT SHALL CHRISTOPHER DUFFY BE LIABLE FOR ANY DIRECT, INDIRECT, 
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, 
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT 
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE 
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
'''
import sys
from collections import namedtuple
import string
import argparse
import os
try:
    import xlrd
except:
    sys.exit("[!] Please install the xlrd library: pip install xlrd")

def unique_list(list_sort, verbose):
    noted = []
    if verbose > 0:
        print("[*] Removing duplicates while maintaining order")
    [noted.append(item) for item in list_sort if not noted.count(item)] # List comprehension
    return noted


def census_parser(filename, verbose):
    # Create the named tuple
    CensusTuple = namedtuple('Census', 'name, rank, count, prop100k, cum_prop100k, pctwhite, pctblack, pctapi, pctaian, pct2prace, pcthispanic')

    # Define the location of the file and worksheet till arguments are developed
    worksheet_name = "top1000"

    #Define work book and work sheet variables
    workbook = xlrd.open_workbook(filename)
    spreadsheet = workbook.sheet_by_name(worksheet_name)
    total_rows = spreadsheet.nrows - 1
    current_row = -1

    # Define holder for details
    username_dict = {}
    surname_dict = {}
    alphabet = list(string.ascii_lowercase)

    while current_row < total_rows:
        row = spreadsheet.row(current_row)
        current_row += 1
        entry = CensusTuple(*tuple(row)) #Passing the values of the row as a tuple into the namedtuple
        surname_dict[entry.rank] = entry
        cellname = entry.name
        cellrank = entry.rank
        for letter in alphabet:
            if "." not in str(cellrank.value):
                if verbose > 1:
                    print("[-] Eliminating table headers")
                break
            username = letter + str(cellname.value.lower())
            rank = str(cellrank.value)
            username_dict[username] = rank
    username_list = sorted(username_dict, key=lambda key: username_dict[key])

    return(surname_dict, username_dict, username_list)

def username_file_parser(prepend_file, append_file, verbose):
    if prepend_file:
        put_where = "begin"
        filename = prepend_file
    elif append_file:
        put_where = "end"
        filename = append_file
    else:
        sys.exit("[!] There was an error in processing the supplemental username list!")
    with open(filename) as file:
        lines = [line.rstrip('\n') for line in file]
    if verbose > 1:
        if "end" in put_where:
            print("[*] Appending %d entries to the username list") % (len(lines))
        else:
            print("[*] Prepending %d entries to the username list") % (len(lines))
    return(lines, put_where)

def combine_usernames(supplemental_list, put_where, username_list, verbose):
    if "begin" in put_where:
        username_list[:0] = supplemental_list #Prepend with a slice
    if "end" in put_where:
        username_list.extend(supplemental_list)
    username_list = unique_list(username_list, verbose)
    return(username_list)

def write_username_file(username_list, filename, domain, verbose):
    open(filename, 'w').close() #Delete contents of file name
    if domain:
        domain_filename = filename + "_" + domain
        email_list = []
        open(domain_filename, 'w').close()
    if verbose > 1:
        print("[*] Writing to %s") % (filename)
    with open(filename, 'w') as file:
        file.write('\n'.join(username_list))
    if domain:
        if verbose > 1:
            print("[*] Writing domain supported list to %s") % (domain_filename)
        for line in username_list:
            email_address = line + "@" + domain
            email_list.append(email_address)
        with open(domain_filename, 'w') as file:
            file.write('\n'.join(email_list))
    return


if __name__ == '__main__':
    # If script is executed at the CLI
    usage = '''usage: %(prog)s [-c census.xlsx] [-f output_filename] [-a append_filename] [-p prepend_filename] [-d domain_name] -q -v -vv -vvv'''
    parser = argparse.ArgumentParser(usage=usage)
    parser.add_argument("-c", "--census", type=str, help="The census file that will be used to create usernames, this can be retrieved like so:\n wget http://www2.census.gov/topics/genealogy/2000surnames/Top1000.xls", action="store", dest="census_file")
    parser.add_argument("-f", "--filename", type=str, help="Filename for output the usernames", action="store", dest="filename")
    parser.add_argument("-a","--append", type=str, action="store", help="A username list to append to the list generated from the census", dest="append_file")
    parser.add_argument("-p","--prepend", type=str, action="store", help="A username list to prepend to the list generated from the census", dest="prepend_file")
    parser.add_argument("-d","--domain", type=str, action="store", help="The domain to append to usernames", dest="domain_name")
    parser.add_argument("-v", action="count", dest="verbose", default=1, help="Verbosity level, defaults to one, this outputs each command and result")
    parser.add_argument("-q", action="store_const", dest="verbose", const=0, help="Sets the results to be quiet")
    parser.add_argument('--version', action='version', version='%(prog)s 0.42b')
    args = parser.parse_args()

    # Set Constructors
    census_file = args.census_file   # Census
    filename = args.filename         # Filename for outputs
    verbose = args.verbose           # Verbosity level
    append_file = args.append_file   # Filename for the appending usernames to the output file
    prepend_file = args.prepend_file # Filename to prepend to the usernames to the output file
    domain_name = args.domain_name   # The name of the domain to be appended to the username list
    dir = os.getcwd()                # Get current working directory
		
    # Argument Validator
    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)
    if append_file and prepend_file:
        sys.exit("[!] Please select either prepend or append for a file not both")
	
    if not filename:
        if os.name != "nt":
             filename = dir + "/census_username_list"
        else:
             filename = dir + "\\census_username_list"
    else:
        if filename:
            if "\\" or "/" in filename:
                if verbose > 1:
                    print("[*] Using filename: %s") % (filename)
        else:
            if os.name != "nt":
                filename = dir + "/" + filename
            else:
                filename = dir + "\\" + filename
                if verbose > 1:
                    print("[*] Using filename: %s") % (filename)

    # Define working variables
    sur_dict = {}
    user_dict = {}
    user_list = []
    sup_username = []
    target = []
    combined_users = []

    # Process census file
    if not census_file:
        sys.exit("[!] You did not provide a census file!")
    else:
        sur_dict, user_dict, user_list = census_parser(census_file, verbose)

    # Process supplemental username file
    if append_file or prepend_file:
        sup_username, target = username_file_parser(prepend_file, append_file, verbose)
        combined_users = combine_usernames(sup_username, target, user_list, verbose)
    else:
        combined_users = user_list

    write_username_file(combined_users, filename, domain_name, verbose)
