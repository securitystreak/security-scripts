import struct
import logging

from helper import utility

from Registry import Registry


__author__ = 'Preston Miller & Chapin Bryce'
__date__ = '20160401'
__version__ = 0.04
__description__ = 'This scripts parses the UserAssist Key from NTUSER.DAT.'

# KEYS will contain sub-lists of each parsed UserAssist (UA) key
KEYS = []


def main(registry, **kwargs):
    """
    The main function handles main logic of script.
    :param registry: Registry hive to process
    :return: Nothing.
    """
    if utility.checkHeader(registry, ['72656766'], 4) is not True:
        logging.error('Incorrect file detected based on name')
        raise TypeError
    # Create dictionary of ROT-13 decoded UA key and its value
    apps = createDictionary(registry)
    ua_type = parseValues(apps)

    if ua_type == 0:
        logging.info('Detected XP based Userassist values.')

    else:
        logging.info('Detected Win7 based Userassist values.')

    headers = ['Name', 'Path', 'Session ID', 'Count', 'Last Used Date (UTC)', 'Focus Time (ms)', 'Focus Count']
    return KEYS, headers


def createDictionary(registry):
    """
    The createDictionary function creates a list of dictionaries where keys are the ROT-13
    decoded app names and values are the raw hex data of said app.
    :param registry: Registry Hive to process
    :return: tmp, A list containing dictionaries for each app
    """
    try:
        # Open the registry file to be parsed
        reg = Registry.Registry(registry)
    except (IOError, Registry.RegistryParse.ParseException) as e:
        msg = 'Invalid NTUSER.DAT path or Registry ID.'
        print '[-]', msg
        logging.error(msg)
        raise TypeError
    try:
        # Navigate to the UserAssist key
        ua_key = reg.open('SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist')
    except Registry.RegistryKeyNotFoundException:
        msg = 'UserAssist Key not found in Registry file.'
        print '[-]', msg
        logging.error(msg)
        raise TypeError
    tmp = []
    # Loop through each subkey in the UserAssist key
    for subkey in ua_key.subkeys():
        # For each subkey in the UserAssist key, detect if there is a subkey called
        # Count and that it has more than 0 values to parse.
        if subkey.subkey('Count') and subkey.subkey('Count').values_number() > 0:
            apps = {}
            for v in subkey.subkey('Count').values():
                apps[v.name().decode('rot-13')] = v.raw_data()
            tmp.append(apps)
    return tmp


def parseValues(data):
    """
    The parseValues function uses struct to unpack the raw value data from the UA key
    :param data: A list containing dictionaries of UA application data
    :return: ua_type, based on the size of the raw data from the dictionary values.
    """
    ua_type = -1

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
