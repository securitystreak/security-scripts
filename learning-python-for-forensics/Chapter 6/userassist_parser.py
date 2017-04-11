import argparse
import struct
import sys
import logging
import os
from Writers import xlsx_writer, csv_writer
from Registry import Registry

__author__ = 'Preston Miller & Chapin Bryce'
__date__ = '20160401'
__version__ = 0.04
__description__ = 'This scripts parses the UserAssist Key from NTUSER.DAT.'

# KEYS will contain sub-lists of each parsed UserAssist (UA) key
KEYS = []


def main(registry, out_file):
    """
    The main function handles main logic of script.
    :param registry: Registry Hive to process
    :param out_file: The output path and file
    :return: Nothing.
    """
    if os.path.basename(registry).lower() != 'ntuser.dat':
        print '[-] {} filename is incorrect (Should be ntuser.dat)'.format(registry)
        logging.error('Incorrect file detected based on name')
        sys.exit(1)
    # Create dictionary of ROT-13 decoded UA key and its value
    apps = createDictionary(registry)
    ua_type = parseValues(apps)

    if ua_type == 0:
        logging.info('Detected XP-based Userassist values.')

    else:
        logging.info('Detected Win7-based Userassist values. Contains Focus values.')

    # Use .endswith string function to determine output type
    if out_file.lower().endswith('.xlsx'):
        xlsx_writer.excelWriter(KEYS, out_file)
    elif out_file.lower().endswith('.csv'):
        csv_writer.csvWriter(KEYS, out_file)
    else:
        print '[-] CSV or XLSX extension not detected in output. Writing CSV to current directory.'
        logging.warning('.csv or .xlsx output not detected. Writing CSV file to current directory.')
        csv_writer.csvWriter(KEYS, 'Userassist_parser.csv')


def createDictionary(registry):
    """
    The createDictionary function creates a list of dictionaries where keys are the ROT-13
    decoded app names and values are the raw hex data of said app.
    :param registry: Registry Hive to process
    :return: apps_list, A list containing dictionaries for each app
    """
    try:
        # Open the registry file to be parsed
        reg = Registry.Registry(registry)
    except (IOError, Registry.RegistryParse.ParseException) as e:
        msg = 'Invalid NTUSER.DAT path or Registry ID.'
        print '[-]', msg
        logging.error(msg)
        sys.exit(2)
    try:
        # Navigate to the UserAssist key
        ua_key = reg.open('SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist')
    except Registry.RegistryKeyNotFoundException:
        msg = 'UserAssist Key not found in Registry file.'
        print '[-]', msg
        logging.error(msg)
        sys.exit(3)
    apps_list = []
    # Loop through each subkey in the UserAssist key
    for ua_subkey in ua_key.subkeys():
        # For each subkey in the UserAssist key, detect if there is a subkey called
        # Count and that it has more than 0 values to parse.
        if ua_subkey.subkey('Count') and ua_subkey.subkey('Count').values_number() > 0:
            apps = {}
            for v in ua_subkey.subkey('Count').values():
                apps[v.name().decode('rot-13')] = v.raw_data()
            apps_list.append(apps)
    return apps_list


def parseValues(data):
    """
    The parseValues function uses struct to unpack the raw value data from the UA key
    :param data: A list containing dictionaries of UA application data
    :return: ua_type, based on the size of the raw data from the dictionary values.
    """
    ua_type = -1
    msg = 'Parsing UserAssist values.'
    print '[+]', msg
    logging.info(msg)

    for dictionary in data:
        for v in dictionary.keys():
            # WinXP based UA keys are 16 bytes
            if len(dictionary[v]) == 16:
                raw = struct.unpack('<2iq', dictionary[v])
                ua_type = 0
                KEYS.append({'Name': getName(v), 'Path': v, 'Session ID': raw[0], 'Count': raw[1],
                             'Last Used Date (UTC)': raw[2], 'Focus Time (ms)': '', 'Focus Count': ''})
            # Win7 based UA keys are 72 bytes
            elif len(dictionary[v]) == 72:
                raw = struct.unpack('<4i44xq4x', dictionary[v])
                ua_type = 1
                KEYS.append({'Name': getName(v), 'Path': v, 'Session ID': raw[0], 'Count': raw[1],
                             'Last Used Date (UTC)': raw[4], 'Focus Time (ms)': raw[3], 'Focus Count': raw[2]})
            else:
                # If the key is not WinXP or Win7 based -- ignore.
                msg = 'Ignoring ' + str(v) + ' value that is ' + str(len(dictionary[v])) + ' bytes.'
                print '[-]', msg
                logging.info(msg)
                continue
    return ua_type


def getName(full_name):
    """
    the getName function splits the name of the application returning the executable name and
    ignoring the path details.
    :param full_name: the path and executable name
    :return: the executable name
    """
    # Determine if '\\' and ':' are within the full_name
    if ':' in full_name and '\\' in full_name:
        # Find if ':' comes before '\\'
        if full_name.rindex(':') > full_name.rindex('\\'):
            # Split on ':' and return the last element (the executable)
            return full_name.split(':')[-1]
        else:
            # Otherwise split on '\\'
            return full_name.split('\\')[-1]
    # When just ':' or '\\' is in the full_name, split on that item and return
    # the last element (the executable)
    elif ':' in full_name:
        return full_name.split(':')[-1]
    else:
        return full_name.split('\\')[-1]


if __name__ == '__main__':
    parser = argparse.ArgumentParser(version=str(__version__), description=__description__,
                                     epilog='Developed by ' + __author__ + ' on ' + __date__)
    parser.add_argument('REGISTRY', help='NTUSER Registry Hive.')
    parser.add_argument('OUTPUT', help='Output file (.csv or .xlsx)')
    parser.add_argument('-l', help='File path of log file.')

    args = parser.parse_args()

    if args.l:
        if not os.path.exists(args.l):
            os.makedirs(args.l)
        log_path = os.path.join(args.l, 'userassist_parser.log')
    else:
        log_path = 'userassist_parser.log'
    logging.basicConfig(filename=log_path, level=logging.DEBUG,
                        format='%(asctime)s | %(levelname)s | %(message)s', filemode='a')

    logging.info('Starting UserAssist_Parser v.' + str(__version__))
    logging.debug('System ' + sys.platform)
    logging.debug('Version ' + sys.version)
    main(args.REGISTRY, args.OUTPUT)
