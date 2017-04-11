#!./env/bin/python

""" PDF Metadata Extractor

    Takes a pdf and prints the embedded metadata in the file

    Don't be a moron, please don't use this for something illegal.

    Usage:
        pdf_metadata.py <file>
        pdf_metadata.py -h | --help
        pdf_metadata.py --version

    Options:
        -h, --help      Display this message
        --version       Display the version of this program
"""

from pyPdf import PdfFileReader
from docopt import docopt
from colorama import Style, Back, init


def print_meta(file_name):
    pdf = PdfFileReader(file(file_name, 'rb'))
    info = pdf.getDocumentInfo()
    print Style.BRIGHT + Back.GREEN + 'PDF MetaData For: ' + str(file_name) + Style.RESET_ALL

    for metaItem in info:
        print '[+] ' + metaItem + ':' + info[metaItem]


def main():
    init()
    arguments = docopt(__doc__, version=0.1)

    print_meta(arguments['<file>'])

if __name__ == '__main__':
    main()
