import argparse
import os
import sys

__author__ = 'Preston Miller & Chapin Bryce'
__date__ = '20160401'
__version__ = 0.02
__description__ = 'This scripts reads a Windows 7 Setup API log and prints USB Devices to the user'

def main(in_file):
    """
    Main function to handle operation
    :param in_file: string path to Windows 7 setupapi.dev.log
    :return: None
    """

    if os.path.isfile(in_file):
        print '{:=^22}'.format('')
        print '{} {}'.format('SetupAPI Parser, ', __version__)
        print '{:=^22} \n'.format('')
        device_information = parseSetupapi(in_file)
        for device in device_information:
            printOutput(device[0], device[1])
    else:
        print 'Input is not a file.'
        sys.exit(1)


def parseSetupapi(setup_log):
    """
    Read data from provided file for Device Install Events for USB Devices
    :param setup_log: str - Path to valid setup api log
    :return: list of tuples - Tuples contain device name and date in that order
    """
    device_list = list()
    with open(setup_log) as in_file:
        for line in in_file:
            lower_line = line.lower()
            # if 'Device Install (Hardware initiated)' in line:
            if 'device install (hardware initiated)' in lower_line and ('ven' in lower_line or 'vid' in lower_line):
                device_name = line.split('-')[1].strip()

                if 'usb' not in device_name.split('\\')[0].lower():
                    continue  # Remove most non-USB devices

                date = next(in_file).split('start')[1].strip()
                device_list.append((device_name, date))

    return device_list


def printOutput(usb_name, usb_date):
    """
    Print formatted information about USB Device
    :param usb_name:
    :param usb_date:
    :return:
    """
    print 'Device: {}'.format(usb_name)
    print 'First Install: {}\n'.format(usb_date)


if __name__ == '__main__':
    # Run this code if the script is run from the command line.
    parser = argparse.ArgumentParser(description='SetupAPI Parser', version=__version__,
                                     epilog='Developed by ' + __author__ + ' on ' + __date__)
    parser.add_argument('IN_FILE', help='Windows 7 SetupAPI file')
    args = parser.parse_args()

    # Run main program
    main(args.IN_FILE)
