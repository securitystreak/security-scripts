import csv
from datetime import datetime, timedelta
import logging

__author__ = 'Preston Miller & Chapin Bryce'
__date__ = '20160401'
__version__ = 0.04
__description__ = 'This scripts parses the UserAssist Key from NTUSER.DAT.'


def csvWriter(data, out_file):
    """
    The csvWriter function writes the parsed UA data to a csv file
    :param data: the list of lists containing parsed UA data
    :param out_file: the desired output directory and filename for the csv file
    :return: Nothing
    """
    print '[+] Writing CSV output.'
    logging.info('Writing CSV to ' + out_file + '.')
    headers = ['ID', 'Name', 'Path', 'Session ID', 'Count', 'Last Used Date (UTC)', 'Focus Time (ms)', 'Focus Count']

    with open(out_file, 'wb') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=headers, extrasaction='ignore')
        # Writes the header from list supplied to fieldnames keyword argument
        writer.writeheader()

        for i, dictionary in enumerate(data):
            # Insert the 'ID' value to each dictionary in the list. Add 1 to start ID at 1 instead of 0.
            dictionary['ID'] = i + 1
            # Convert the FILETIME object in the fourth index to human readable value
            dictionary['Last Used Date (UTC)'] = fileTime(dictionary['Last Used Date (UTC)'])
            writer.writerow(dictionary)

        csvfile.flush()
        csvfile.close()
        msg = 'Completed writing CSV file. Program exiting successfully.'
        print '[*]', msg
        logging.info(msg)


def fileTime(ft):
    """
    The fileTime function converts Windows FILETIME objects into human readable value
    :param ft: the FILETIME to convert
    :return: date_str, the human readable datetime value
    """
    return datetime(1601, 1, 1) + timedelta(microseconds=ft / 10)
