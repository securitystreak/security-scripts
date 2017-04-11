__author__ = 'Preston Miller & Chapin Bryce'
__date__ = '20160401'
__version__ = 0.01
__description__ = 'This scripts reads a Windows 7 Setup API log and prints USB Devices to the user'


def main():
    """
    Run the program
    :return: None
    """
    # Insert your own path to your sample setupapi.dev.log here.
    file_path = 'setupapi.dev.log'

    # Print version information when the script is run
    print '='*22
    print 'SetupAPI Parser, ', __version__
    print '='*22

    parseSetupapi(file_path)


def parseSetupapi(setup_file):
    """
    Interpret the file
    :param setup_file: path to the setupapi.dev.log
    :return: None
    """
    in_file = open(setup_file)
    data = in_file.readlines()

    for i,line in enumerate(data):
        if 'device install (hardware initiated)' in line.lower():
            device_name = data[i].split('-')[1].strip()
            date = data[i+1].split('start')[1].strip()
            printOutput(device_name, date)

    in_file.close()


def printOutput(usb_name, usb_date):
    """
    Print the information discovered
    :param usb_name: String USB Name to print
    :param usb_date: String USB Date to print
    :return: None
    """

    print 'Device: {}'.format(usb_name)
    print 'First Install: {}'.format(usb_date)


if __name__ == '__main__':
    # Run the program
    main()
