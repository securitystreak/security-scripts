
import datetime

__author__ = 'Preston Miller & Chapin Bryce'
__date__ = '20150815'
__version__ = '0.01'
__description__ = "Convert unix formatted timestamps (seconds since Epoch [1970-01-01 00:00:00]) to human readable"

def main():
    unix_ts = int(raw_input('Unix timestamp to convert:\n>> '))
    print unix_converter(unix_ts)

def unix_converter(timestamp):
    date_ts = datetime.datetime.utcfromtimestamp(timestamp)
    return date_ts.strftime('%m/%d/%Y %I:%M:%S %p UTC')

if __name__ == '__main__':
    main()
