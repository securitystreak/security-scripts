import urllib2
import sys

__author__ = 'Preston Miller and Chapin Bryce'
__date__ = '20160401'
__version__ = 0.02
__description__ = """Reads Linux-usb.org's USB.ids file and parses into usable data for parsing VID/PIDs"""


def main():
    """
    Main function to control operation. Requires arguments passed as VID PID
    on the command line. If discovered in data set, the common names will be
    printed to stdout
    :return: None
    """
    ids = getIds()
    usb_file = getUSBFile()
    usbs = parseFile(usb_file)
    results = searchKey(usbs, ids)
    print "Vendor: {}\nProduct: {}".format(results[0],results[1])


def getIds():
    """
    Retrieves vid and pid from arguments in the format of VID PID.
    ie: python usb_lookup.py 0123 4567
    """
    if len(sys.argv) >= 3:
        return sys.argv[1], sys.argv[2]
    else:
        print """Please provide the vendor Id and product Id separated by
                 spaces at the command line. ie: python usb_lookup.py 0123 4567
        """
        sys.exit(1)


def getUSBFile():
    """
    Retrieves USB.ids database from the web.
    """
    url = 'http://www.linux-usb.org/usb.ids'
    return urllib2.urlopen(url)


def parseFile(usb_file):
    """
    Parses the USB.ids file. If this is run offline, please download the USB.ids
    and pass the open file to this function.
    ie: parseFile(open('path/to/USB.ids', 'r'))
    :return: dictionary of entires for querying
    """
    usbs = {}
    curr_id = ''
    for line in usb_file:
        if line.startswith('#') or line == '\n':
            pass
        else:
            if not line.startswith('\t') and (line[0].isdigit() or line[0].islower()):
                id, name = getRecord(line.strip())
                curr_id = id
                usbs[id] = [name, {}]
            elif line.startswith('\t') and line.count('\t') == 1:
                id, name = getRecord(line.strip())
                usbs[curr_id][1][id] = name
    return usbs


def getRecord(record_line):
    """
    Split records out by dynamic position. By finding the space, we can determine the
    location to split the record for extraction. To learn more about this,
    uncomment the print statements and see what the code is doing behind the
    scenes!
    """
    # print "Line: ",
    # print record_line
    split = record_line.find(' ')
    # print "Split: ",
    # print split
    record_id = record_line[:split]
    # print "Record ID: ",
    # print record_id
    record_name = record_line[split + 1:]
    # print "Record Name: ",
    # print record_name
    return record_id, record_name


def searchKey(usb_dict, ids):
    """
    Compare provided IDs to the built USB dictionary. If found, it will return
    the common name, otherwise returns the string "Unknown"
    """

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


if __name__ == '__main__':
    main()
