import unicodecsv as csv

__author__ = 'Preston Miller & Chapin Bryce'
__date__ = '20160401'
__version__ = 0.01
__description__ = 'CSV Writer for the framework'


def writer(output, headers, output_data, **kwargs):
    """
    The writer function uses the csv.DictWriter module to write list(s) of dictionaries. The
    DictWriter can take a fieldnames argument, as a list, which represents the desired order of columns.
    :param output: The name of the output CSV.
    :param headers: A list of keys in the dictionary that represent the desired order of columns in the output.
    :param output_data: The list of dictionaries containing embedded metadata.
    :return: None
    """
    with open(output, 'wb') as outfile:
        # We use DictWriter instead of writer to write dictionaries to CSV.
        w = csv.DictWriter(outfile, fieldnames=headers,extrasaction='ignore')

        # Writerheader writes the header based on the supplied headers object
        try:
            w.writeheader()
        except TypeError:
            print '[-] Received empty headers...\n[-] Skipping writing output.'
            return

        if 'recursion' in kwargs.keys():
            for l in output_data:
                for data in l:
                    if data:
                        w.writerow(data)
        else:
            for data in output_data:
                if data:
                    w.writerow(data)
