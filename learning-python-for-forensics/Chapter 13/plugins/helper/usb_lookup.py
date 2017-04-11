import urllib2
import sys

__author__ = 'Preston Miller and Chapin Bryce'
__date__ = '20160401'
__version__ = 0.02
__description__ = """Reads Linux-usb.org's USB.ids file and parses into usable data for parsing VID/PIDs"""


def main():
    ids = get_ids()
    usb_file = get_usb_file()
    usbs = parse_file(usb_file)
    search_key(usbs, ids)


def get_ids():
    if len(sys.argv) >= 3:
        return sys.argv[1], sys.argv[2]
    else:
        print 'Please provide the vendor Id and product Id separated by spaces. on the command line'
        sys.exit(1)


def get_usb_file():
    url = 'http://www.linux-usb.org/usb.ids'
    return urllib2.urlopen(url)


def parse_file(usb_file):
    usbs = {}
    curr_id = ''
    for line in usb_file:
        if line.startswith('#') or line == '\n':
            pass
        else:
            if not(line.startswith('\t')) and (line[0].isdigit() or line[0].islower()):
                usb_id, name = getRecord(line.strip())
                curr_id = usb_id
                usbs[usb_id] = [name, {}]
            elif line.startswith('\t') and line.count('\t') == 1:
                usb_id, name = getRecord(line.strip())
                usbs[curr_id][1][usb_id] = name

    return usbs


def getRecord(record_line):
    split = record_line.find(' ')
    record_id = record_line[:split]
    record_name = record_line[split + 1:]
    return record_id, record_name


def search_key(usb_dict, ids):
    vendor_key = ids[0]
    product_key = ids[1]

    try:
        vendor = usb_dict[vendor_key][0]
    except KeyError:
        vendor = 'Unknown'
    try:
        product = usb_dict[vendor_key][1][product_key]
    except KeyError:
        product = 'Unknown'
    return vendor, product
