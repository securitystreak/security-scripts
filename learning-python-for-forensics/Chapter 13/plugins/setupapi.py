from helper import usb_lookup

__author__ = 'Preston Miller & Chapin Bryce'
__date__ = '20160401'
__version__ = 0.03
__description__ = 'This scripts reads a Windows 7 Setup API log and prints USB Devices to the user'


def main(in_file):
    """
    Main function to handle operation
    :param in_file: Str - Path to setupapi log to analyze
    :return: list of USB data and list of headers for output
    """
    headers = ['Vendor ID', 'Vendor Name', 'Product ID', 'Product Name', 'Revision', 'UID', 'First Installation Date']
    data = []

    device_information = parseSetupapi(in_file)
    usb_ids = prepUSBLookup()
    for device in device_information:
        parsed_info = parseDeviceInfo(device)
        if isinstance(parsed_info, dict):
            parsed_info = getDeviceNames(usb_ids, parsed_info)
            data.append(parsed_info)
        else:
            data.append({'Vendor ID': parsed_info})
    return data, headers


def parseSetupapi(setup_log):
    """
    Read data from provided file for Device Install Events for USB Devices
    :param setup_log: str - Path to valid setup api log
    :return: tuple of str - Device name and date
    """
    device_list = list()
    unique_list = set()
    with open(setup_log) as infile:
        for line in infile:
            tmp = line.lower()
            # if 'Device Install (Hardware initiated)' in line:
            if 'device install (hardware initiated)' in tmp and ('vid' in tmp or 'ven' in tmp):
                device_name = line.split('-')[1].strip()
                date = next(infile).split('start')[1].strip()
                if device_name not in unique_list:
                    device_list.append((device_name, date))
                    unique_list.add(device_name)

    return device_list


def parseDeviceInfo(device_info):
    """
    Parses Vendor, Product, Revision and UID from a Setup API entry
    :param device_info: string of device information to parse
    :return: dictionary of parsed information or original string if error
    """
    # Initialize variables
    vid = ''
    pid = ''
    rev = ''
    uid = ''

    # Split string into segments on \\
    segments = device_info[0].lower().split('\\')
    for segment in segments:
        for item in segment.split('&'):
            if 'ven' in item or 'vid' in item:
                vid = item.split('_')[-1]
            elif 'dev' in item or 'pid' in item:
                pid = item.split('_')[-1]
            elif 'rev' in item or 'mi' in item:
                rev = item.split('_')[-1]

        if len(segments) >= 3:
            uid = segments[2].strip(']')

        if vid != '' or pid != '':
            return {'Vendor ID': vid, 'Product ID': pid, 'Revision': rev, 'UID': uid,
                    'First Installation Date': device_info[1]}
        else:
            continue

    # Unable to parse data, returning whole string
    return device_info


def prepUSBLookup():
    """
    Prepare the lookup of USB devices through accessing the most recent copy
    of the database at http://linux-usb.org/usb.ids and parsing it into a
    queriable dictionary format.
    """
    usb_file = usb_lookup.get_usb_file()
    return usb_lookup.parse_file(usb_file)


def getDeviceNames(usb_dict, device_info):
    """
    Query `usb_lookup.py` for device information based on VID/PID.
    :param usb_dict: Dictionary from usb_lookup.py of known devices.
    :param device_info: Dictionary containing 'Vendor ID' and 'Product ID' keys and values.
    :return: original dictionary with 'Vendor Name' and 'Product Name' keys and values
    """
    device_names = usb_lookup.search_key(usb_dict, [device_info['Vendor ID'], device_info['Product ID']])

    if len(device_names) >= 1:
        device_info['Vendor Name'] = device_names[0]
    if len(device_names) >= 2:
        device_info['Product Name'] = device_names[1]

    return device_info
