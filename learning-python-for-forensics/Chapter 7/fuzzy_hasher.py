import os
import sys
import csv
import logging
import argparse
import progressbar
import rabinkarp as rk

__author__ = 'Preston Miller & Chapin Bryce'
__date__ = 20160401
__version__ = 0.01
__description__ = 'Compare known file to another file or files in a directory using a rolling hash. Results will output as CSV'


def main(known, comparison, chunk_size, output_path):
    """
    The main function handles the main operations of the script
    :param known: open known file for comparison
    :param comparison: path to file or directory of files to compare
    :param chunk_size: integer size of bytes to read per chunk
    :param output_path: open file for output
    :return: None
    """

    if os.path.isdir(comparison):
        fuzzy_hashes = dict()
        fuzzy_hashes['results'] = directoryController(known, comparison, chunk_size)
    elif os.path.isfile(comparison):
        fuzzy_hashes = fileController(known, comparison, chunk_size)
    else:
        logging.error("Error - comparison location not found")
        sys.exit(1)

    fuzzy_hashes['output_path'] = output_path

    writer(fuzzy_hashes)


def fileController(known_file, comparison, chunk_size):
    """
    The fileController function fuzzy hashes and compares a file
    :param known_file: open known file for comparison
    :param comparison: path to file or directory of files to compare
    :param chunk_size: integer size of bytes to read per chunk
    :return: dictionary containing information about the comparison
    """

    logging.info('Processing File')

    known_hashes = fuzzFile(known_file, chunk_size)

    comparison_file = open(comparison, 'rb')
    comparison_hashes = fuzzFile(comparison_file, chunk_size)

    fuzzy_dict = compareFuzzies(known_hashes, comparison_hashes)
    fuzzy_dict['file_path'] = os.path.abspath(comparison)
    fuzzy_dict['comparison_total_segments'] = len(comparison_hashes)
    return fuzzy_dict


def directoryController(known_file, comparison, chunk_size):
    """
    The directoryController function processes a directory and hands each file to the fileController
    :param known_file: path to known file for comparison
    :param comparison: path to file or directory of files to compare
    :param chunk_size: integer size of bytes to read per chunk
    :return: list of dictionaries containing information about each comparison
    """

    logging.info('Processing Directory')

    # Calculate the hashes of the known file before iteration
    known_hashes = fuzzFile(known_file, chunk_size)

    # Prepare progressbar
    files_to_process = list()
    for root, directories, files in os.walk(comparison):
        for file_entry in files:
            file_entry_path = os.path.abspath(os.path.join(root,file_entry))
            files_to_process.append(file_entry_path)

    pb_widgets = [progressbar.Bar(), ' ', progressbar.SimpleProgress(), ' ', progressbar.ETA()]
    pbar = progressbar.ProgressBar(widgets=pb_widgets, maxval=len(files_to_process))

    # Begin recurring through the discovered files
    fuzzy_list = []
    pbar.start()
    for count, file_path in enumerate(files_to_process):
        try:
            file_obj = open(file_path, 'rb')
        except IOError, e:
            logging.error('Could not open ' + file_path + ' | ' + str(e))
            pbar.update(count)
            continue

        comparison_hashes = fuzzFile(file_obj, chunk_size)
        fuzzy_dict = compareFuzzies(known_hashes, comparison_hashes)
        fuzzy_dict['file_path'] = file_path
        fuzzy_dict['comparison_total_segments'] = len(comparison_hashes)
        fuzzy_list.append(fuzzy_dict)
        pbar.update(count)

    pbar.finish()
    return fuzzy_list


def fuzzFile(file_obj, chunk_size):
    """
    The fuzzFile function creates a fuzzy hash of a file
    :param file_obj: open file object to read. must be able to call `.read()`
    :param chunk_size: integer size of bytes to read per chunk
    :return: set of hashes for comparison
    """

    hash_set = set()
    const_num = 7
    complete_file = bytearray(file_obj.read())

    chunk = complete_file[0:chunk_size]
    ha = rk.hash(chunk, const_num)
    hash_set.add(ha)
    try:
        old_byte = chunk[0]
    except IndexError, e:
        logging.warning("File is 0-bytes. Skipping...")
        return set()

    for new_byte in complete_file[chunk_size:]:
        ha = rk.update(ha, const_num, chunk_size, old_byte, new_byte)
        hash_set.add(ha)
        chunk = chunk[1:]
        chunk.append(new_byte)
        old_byte = chunk[0]

    return hash_set


def compareFuzzies(known_fuzz, comparison_fuzz):
    """
    The compareFuzzies function compares Fuzzy Hashes
    :param known_fuzz: list of hashes from the known file
    :param comparison_fuzz: list of hashes from the comparison file
    :return: dictionary of formatted results for output
    """

    matches = known_fuzz.intersection(comparison_fuzz)

    if len(comparison_fuzz):
        similarity = (float(len(matches))/len(known_fuzz))*100
    else:
        logging.error('Comparison file not fuzzed. Please check file size and permissions')
        similarity = 0

    return {'similarity': similarity, 'matching_segments': len(matches),
        'known_file_total_segments': len(known_fuzz)}


def writer(results):
    """
    The writer function writes the raw hash information to a CSV file
    :param results: dictionary of keyword arguments
    :return: None
    """

    logging.info('Writing Output')

    is_list = isinstance(results.get('results', ''), list)

    headers = ['file_path', 'similarity', 'matching_segments',
               'known_file_total_segments', 'comparison_total_segments']
    dict_writer = csv.DictWriter(results['output_path'],
        headers, extrasaction="ignore")
    dict_writer.writeheader()

    if is_list:
        dict_writer.writerows(results['results'])
    else:
        dict_writer.writerow(results)

    results['output_path'].close()

    logging.info('Writing Completed')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description=__description__, version=str(__version__),
        epilog='Developed by ' + __author__ + ' on ' + str(__date__))
    parser.add_argument('KNOWN',
        help='Path to known file to use to compare for similarity',
        type=argparse.FileType('rb'))
    parser.add_argument('COMPARISON',
        help='Path to file or directory to look for similarities. '
             'Will recurse through all sub directories')
    parser.add_argument('OUTPUT',
        help='Path to output CSV file. Existing files will be overwritten',
        type=argparse.FileType('wb'))
    parser.add_argument('--chunk-size',
        help='Chunk Size (in bytes) to hash at a time. Modifies granularity of'
             ' matches. Default 8 Bytes',
        type=int, default=8)
    parser.add_argument('-l', help='specify logging file')

    args = parser.parse_args()

    if args.l:
        if not os.path.exists(args.l):
            os.makedirs(args.l)
        log_path = os.path.join(args.l, 'fuzzy_hasher.log')
    else:
        log_path = 'fuzzy_hasher.log'
    logging.basicConfig(filename=log_path, level=logging.DEBUG,
        format='%(asctime)s | %(levelname)s | %(message)s', filemode='a')

    logging.info('Starting Fuzzy Hasher v.' + str(__version__))
    logging.debug('System ' + sys.platform)
    logging.debug('Version ' + sys.version)

    logging.info('Script Starting')
    main(args.KNOWN, args.COMPARISON, args.chunk_size, args.OUTPUT)
    logging.info('Script Completed')
