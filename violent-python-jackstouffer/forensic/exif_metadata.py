#!./env/bin/python

""" EXIF Metadata Extractor

    Takes an image and prints the embedded metadata in the file

    Don't be a moron, please don't use this for something illegal.

    Usage:
        exif_metadata.py <file>
        exif_metadata.py -h | --help
        exif_metadata.py --version

    Options:
        -h, --help      Display this message
        --version       Display the version of this program
"""
import pprint

from docopt import docopt
from colorama import init, Fore, Style
from PIL import Image
from PIL.ExifTags import TAGS


def get_exif(imgFileName):
    pp = pprint.PrettyPrinter(indent=4)

    try:
        exifData = {}
        imgFile = Image.open(imgFileName)
        info = imgFile._getexif()

        if info:
            for (tag, value) in info.items():
                decoded = TAGS.get(tag, tag)
                exifData[decoded] = value

            for key, value in exifData.iteritems():
                if key == 'GPSInfo':
                    print Style.BRIGHT + Fore.GREEN + "GPS Info:" + Style.RESET_ALL
                    pp.pprint(value)

                if key == 'Manufacturer':
                    print Style.BRIGHT + Fore.GREEN + "Manufacturer:" + Style.RESET_ALL
                    print value

                if key == 'Model':
                    print Style.BRIGHT + Fore.GREEN + "Model:" + Style.RESET_ALL
                    print value

                if key == 'Make':
                    print Style.BRIGHT + Fore.GREEN + "Make:" + Style.RESET_ALL
                    print value

                if key == 'Software':
                    print Style.BRIGHT + Fore.GREEN + "Software:" + Style.RESET_ALL
                    print value

                if key == 'DateTimeOriginal':
                    print Style.BRIGHT + Fore.GREEN + "Date Created:" + Style.RESET_ALL
                    print value

                if key == 'Creating Application':
                    print Style.BRIGHT + Fore.GREEN + "Creating Application:" + Style.RESET_ALL
                    print value
        else:
            pass
    except:
        pass


def main():
    init()
    arguments = docopt(__doc__, version=0.1)

    get_exif(arguments['<file>'])


if __name__ == '__main__':
    main()
