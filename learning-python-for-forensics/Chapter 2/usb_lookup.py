import urllib2
import sys

__author__ = 'Preston Miller and Chapin Bryce'
__date__ = '20150825'
__version__ = '0.01'

def main():
    url = 'http://www.linux-usb.org/usb.ids'
    usbs = {}
    usb_file = urllib2.urlopen(url)
    curr_id = ''

    for line in usb_file:
        if line.startswith('#') or line == '\n':
            pass
        else:
            if not(line.startswith('\t')) and (line[0].isdigit() or line[0].islower()):
                id, name = getRecord(line.strip())
                curr_id = id
                usbs[id] = [name, {}]
            elif line.startswith('\t') and line.count('\t') == 1:
                id, name = getRecord(line.strip())
                usbs[curr_id][1][id] = name

    search_key(usbs)


def getRecord(record_line):
    split = record_line.find(' ')
    record_id = record_line[:split]
    record_name = record_line[split + 1:]
    return record_id, record_name


def search_key(usb_dict):

    try:
        vendor_key = sys.argv[1]
        product_key = sys.argv[2]
    except IndexError:
        print 'Please provide the vendor Id and product Id separated by spaces.'
        sys.exit(1)

    try:
        vendor = usb_dict[vendor_key][0]
    except KeyError:
        print 'Vendor Id not found.'
        sys.exit(0)
    try:
        product = usb_dict[vendor_key][1][product_key]
    except KeyError:
        print 'Vendor: {}\nProduct Id not found.'.format(vendor)
        sys.exit(0)
    print 'Vendor: {}\nProduct: {}'.format(vendor, product)


if __name__ == '__main__':
    main()