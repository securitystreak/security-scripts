import csv
import os
import logging

__author__ = 'Preston Miller & Chapin Bryce'
__date__ = '20160401'
__version__ = 0.01

def csvWriter(output_data, headers, output_dir, output_name):
    """
    The csvWriter function uses the csv.DictWriter module to write the list of dictionaries. The
    DictWriter can take a fieldnames argument, as a list, which represents the desired order of columns.
    :param output_data: The list of dictionaries containing embedded metadata.
    :param headers: A list of keys in the dictionary that represent the desired order of columns in the output.
    :param output_dir: The folder to write the output CSV to.
    :param output_name: The name of the output CSV.
    :return:
    """
    msg = 'Writing ' + output_name + ' CSV output.'
    print '[+]', msg
    logging.info(msg)

    with open(os.path.join(output_dir, output_name), 'wb') as outfile:
        # We use DictWriter instead of Writer to write dictionaries to CSV.
        writer = csv.DictWriter(outfile, fieldnames=headers)

        # Writerheader writes the header based on the supplied headers object
        writer.writeheader()
        for dictionary in output_data:
            if dictionary:
                writer.writerow(dictionary)
