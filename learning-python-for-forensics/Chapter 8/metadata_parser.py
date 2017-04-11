import argparse
import os
import sys
import logging

import plugins
import writers

__author__ = 'Preston Miller & Chapin Bryce'
__date__ = '20160401'
__version__ = 0.01
__description__ = 'This scripts handles processing and output of various embedded metadata  files'


def main(input_dir, output_dir):
    """
    The main function generates a file listing, sends files to be processed, and output written.
    :param input_dir: The input directory to scan for suported embedded metadata containing files
    :param output_dir: The output directory to write metadata reports to
    :return: Nothing.
    """
    # Create lists to store each supported embedded metadata before writing to output
    exif_metadata = []
    office_metadata = []
    id3_metadata = []

    # Walk through list of files
    msg = 'Generating file listing and running plugins.'
    print '[+]', msg
    logging.info(msg)
    for root, subdir, files in os.walk(input_dir, topdown=True):
        for file_name in files:
            current_file = os.path.join(root, file_name)
            ext = os.path.splitext(current_file)[1].lower()

            # PLUGINS
            if ext == '.jpeg' or ext == '.jpg':
                try:
                    ex_metadata, exif_headers = plugins.exif_parser.exifParser(current_file)
                    exif_metadata.append(ex_metadata)
                except TypeError:
                    print '[-] File signature mismatch. Continuing to next file.'
                    logging.error(('JPG & TIFF File Signature check failed for ' + current_file))
                    continue

            elif ext == '.docx' or ext == '.pptx' or ext == '.xlsx':
                try:
                    of_metadata, office_headers = plugins.office_parser.officeParser(current_file)
                    office_metadata.append(of_metadata)
                except TypeError:
                    print '[-] File signature mismatch. Continuing to next file.'
                    logging.error(('DOCX, XLSX, & PPTX File Signature check failed for ' + current_file))
                    continue

            elif ext == '.mp3':
                try:
                    id_metadata, id3_headers = plugins.id3_parser.id3Parser(current_file)
                    id3_metadata.append(id_metadata)
                except TypeError:
                    print '[-] File signature mismatch. Continuing to next file.'
                    logging.error(('MP3 File Signature check failed for ' + current_file))
                    continue

    # WRITERS
    msg = 'Writing output to ' + output_dir
    print '[+]', msg
    logging.info(msg)

    if len(exif_metadata) > 0:
        writers.kml_writer.kmlWriter(exif_metadata, output_dir, 'exif_metadata.kml')
        writers.csv_writer.csvWriter(exif_metadata, exif_headers, output_dir, 'exif_metadata.csv')

    if len(office_metadata) > 0:
        writers.csv_writer.csvWriter(office_metadata, office_headers, output_dir, 'office_metadata.csv')

    if len(id3_metadata) > 0:
        writers.csv_writer.csvWriter(id3_metadata, id3_headers, output_dir, 'id3_metadata.csv')

    msg = 'Program completed successfully -- exiting..'
    print '[*]', msg
    logging.info(msg)

if __name__ == '__main__':

    parser = argparse.ArgumentParser(version=str(__version__), description=__description__,
                                     epilog='Developed by ' + __author__ + ' on ' + __date__)
    parser.add_argument('INPUT_DIR', help='Input Directory')
    parser.add_argument('OUTPUT_DIR', help='Output Directory')
    parser.add_argument('-l', help='File path of log file.')
    args = parser.parse_args()

    if args.l:
        if not os.path.exists(args.l):
            os.makedirs(args.l)
        log_path = os.path.join(args.l, 'metadata_parser.log')
    else:
        log_path = 'metadata_parser.log'
    logging.basicConfig(filename=log_path, level=logging.DEBUG,
                        format='%(asctime)s | %(levelname)s | %(message)s', filemode='a')

    logging.info('Starting Metadata_Parser v.' + str(__version__))
    logging.debug('System ' + sys.platform)
    logging.debug('Version ' + sys.version)

    if not os.path.exists(args.OUTPUT_DIR):
        os.makedirs(args.OUTPUT_DIR)

    if os.path.exists(args.INPUT_DIR) and os.path.isdir(args.INPUT_DIR):
        main(args.INPUT_DIR, args.OUTPUT_DIR)
    else:
        msg = 'Supplied input directory does not exist or is not a directory'
        print '[-]', msg
        logging.error(msg)
        sys.exit(1)