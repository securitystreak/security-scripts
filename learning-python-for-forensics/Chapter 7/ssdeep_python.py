import os
import sys
import csv
import argparse
import logging
import progressbar
import ssdeep

__author__ = 'Preston Miller & Chapin Bryce'
__date__ = 20160401
__version__ = 0.1
__description__ = 'Compare known file to another file or files in a directory using ssdeep. Results will output as CSV'


def main(known, comparison, output):
    """
    The main function handles the main operations of the script
    :param known: str path to the known file
    :param comparison: str path to the comparison file or directory
    :param output: open output file object to write to
    :return: None
    """

    if os.path.isdir(comparison):
        fuzzy_hashes = dict()
        fuzzy_hashes['results'] = directoryController(known, comparison)
    elif os.path.isfile(comparison):
        fuzzy_hashes = fileController(known, comparison)
    else:
        logging.error("Error - comparison location not found")
        sys.exit(1)

    fuzzy_hashes['output_path'] = output
    writer(fuzzy_hashes)


def fileController(known, comparison):
    """
    The fileController function fuzzy hashes and compares a file
    :param known: path to known file to use for comparison
    :param comparison: list of hashes from the comparison file
    :return: dictionary of file_path and similarity for output
    """

    logging.info('Processing File')

    known_hash = ssdeep.hash_from_file(known)
    comparison_hash = ssdeep.hash_from_file(comparison)
    hash_comparison = ssdeep.compare(known_hash, comparison_hash)

    return {'file_path': os.path.abspath(comparison), 'similarity': hash_comparison}


def directoryController(known, comparison):
    """
    The directoryController function processes a directory and hands each file to the fileController
    :param known: str path to the known file
    :param comparison: str path to the comparison directory
    :return: list of dictionaries containing comparison results
    """

    logging.info('Processing Directory')

    known_hash = ssdeep.hash_from_file(known)

    # Prepare progressbar
    files_to_process = list()
    for root, directories, files in os.walk(comparison):
        for file_entry in files:
            file_entry_path = os.path.abspath(os.path.join(root, file_entry))
            files_to_process.append(file_entry_path)

    pb_widgets = [progressbar.Bar(), ' ', progressbar.SimpleProgress(), ' ', progressbar.ETA()]
    pbar = progressbar.ProgressBar(widgets=pb_widgets, maxval=len(files_to_process))

    pbar.start()
    compared_hashes = []
    for count, file_path in enumerate(files_to_process):
        try:
            comparison_hash = ssdeep.hash_from_file(file_path)
        except IOError as e:
            logging.error('Could not open ' + file_path + ' | ' + str(e))
            pbar.update(count)
            continue

        hash_comparison = ssdeep.compare(known_hash, comparison_hash)
        compared_hashes.append({'file_path': file_path, 'similarity': hash_comparison})
        pbar.update(count)

    pbar.finish()
    return compared_hashes


def writer(results):
    """
    The writer function writes the raw hash information to a CSV file
    :param results: dictionary of values to write
    :return: None
    """

    logging.info('Writing Output')
    is_list = type(results.get('results', '')) == list

    headers = ['file_path', 'similarity']
    dict_writer = csv.DictWriter(results['output_path'], headers, extrasaction="ignore")
    dict_writer.writeheader()

    if is_list:
        dict_writer.writerows(results['results'])
    else:
        dict_writer.writerow(results)
    results['output_path'].close()

    logging.info('Writing Completed')

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__description__, version=str(__version__),
                                     epilog='Developed by ' + __author__ + ' on ' + str(__date__))
    parser.add_argument('KNOWN', help='Path to known file to use to compare for similarity')
    parser.add_argument('COMPARISON', help='Path to file or directory to look for similarities. '
                                           'Will recurse through all sub directories')
    parser.add_argument('OUTPUT', help='Path to output CSV file. Existing files will be overwritten',
                        type=argparse.FileType('wb'))
    parser.add_argument('-l', help='specify logging file')

    args = parser.parse_args()

    if args.l:
        if not os.path.exists(args.l):
            os.makedirs(args.l)
        log_path = os.path.join(args.l, 'ssdeep_python.log')
    else:
        log_path = 'ssdeep_python.log'
    logging.basicConfig(filename=log_path, level=logging.DEBUG,
                        format='%(asctime)s | %(levelname)s | %(message)s', filemode='a')

    logging.info('Starting SSDeep Python v.' + str(__version__))
    logging.debug('System ' + sys.platform)
    logging.debug('Version ' + sys.version)

    logging.info('Script Starting')
    main(args.KNOWN, args.COMPARISON, args.OUTPUT)
    logging.info('Script Completed')
