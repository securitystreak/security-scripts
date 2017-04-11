from datetime import datetime
import os
from time import gmtime, strftime

from PIL import Image

import processors

__author__ = 'Preston Miller & Chapin Bryce'
__date__ = '20160401'
__version__ = 0.01
__description__ = 'This scripts parses embedded EXIF metadata from compatible objects'

def exifParser(filename):
    """
    The exifParser function confirms the file type and sends it to be processed.
    :param filename: name of the file potentially containing EXIF metadata.
    :return: A dictionary from getTags, containing the embedded EXIF metadata.
    """

    # JPEG signatures
    signatures = ['ffd8ffdb','ffd8ffe0', 'ffd8ffe1', 'ffd8ffe2', 'ffd8ffe3',
                  'ffd8ffe8']
    if processors.utility.checkHeader(filename, signatures, 4) == True:
        return getTags(filename)
    else:
        print 'File signature does not match known JPEG signatures.'
        raise TypeError('File signature does not match JPEG object.')

def getTags(filename):
    """
    The getTags function extracts the EXIF metadata from the data object.
    :param filename: the path and name to the data object.
    :return: tags and headers, tags is a dictionary containing EXIF metadata and headers are the
             order of keys for the CSV output.
    """
    # Set up CSV headers
    headers = ['Path', 'Name', 'Size', 'Filesystem CTime', 'Filesystem MTime', 'Original Date', 'Digitized Date',
               'Make', 'Model', 'Software', 'Latitude', 'Latitude Reference', 'Longitude', 'Longitude Reference',
               'Exif Version', 'Height', 'Width', 'Flash', 'Scene Type']
    image = Image.open(filename)

    # Detects if the file is corrupt without decoding the data
    image.verify()

    # Descriptions and values of EXIF tags: http://www.exiv2.org/tags.html
    exif = image._getexif()

    tags = {}
    tags['Path'] = filename
    tags['Name'] = os.path.basename(filename)
    tags['Size'] = processors.utility.convertSize(os.path.getsize(filename))
    tags['Filesystem CTime'] = strftime('%m/%d/%Y %H:%M:%S', gmtime(os.path.getctime(filename)))
    tags['Filesystem MTime'] = strftime('%m/%d/%Y %H:%M:%S', gmtime(os.path.getmtime(filename)))
    if exif:
        for tag in exif.keys():
            if tag == 36864:
                tags['Exif Version'] = exif[tag]
            elif tag == 36867:
                dt = datetime.strptime(exif[tag], '%Y:%m:%d %H:%M:%S')
                tags['Original Date'] = dt.strftime('%m/%d/%Y %H:%M:%S')
            elif tag == 36868:
                dt = datetime.strptime(exif[tag], '%Y:%m:%d %H:%M:%S')
                tags['Digitized Date'] = dt.strftime('%m/%d/%Y %H:%M:%S')
            elif tag == 41990:
                # Scene tags: http://www.awaresystems.be/imaging/tiff/tifftags/privateifd/exif/scenecapturetype.html
                scenes = {0: 'Standard', 1: 'Landscape', 2: 'Portrait', 3: 'Night Scene'}
                if exif[tag] in scenes:
                    tags['Scene Type'] = scenes[exif[tag]]
                else:
                    pass
            elif tag == 37385:
                # Flash tags: http://www.awaresystems.be/imaging/tiff/tifftags/privateifd/exif/flash.html
                flash = {0: 'Flash did not fire', 1: 'Flash fired', 5: 'Strobe return light not detected',
                         7: 'Strobe return light detected', 9: 'Flash fired, compulsory flash mode',
                         13: 'Flash fired, compulsory flash mode, return light not detected',
                         15: 'Flash fired, compulsory flash mode, return light detected',
                         16: 'Flash did not fire, compulsory flash mode', 24: 'Flash did not fire, auto mode',
                         25: 'Flash fired, auto mode', 29: 'Flash fired, auto mode, return light not detected',
                         31: 'Flash fired, auto mode, return light detected', 32: 'No flash function',
                         65: 'Flash fired, red-eye reduction mode',
                         69: 'Flash fired, red-eye reduction mode, return light not detected',
                         71: 'Flash fired, red-eye reduction mode, return light detected',
                         73: 'Flash fired, compulsory flash mode, red-eye reduction mode',
                         77: 'Flash fired, compulsory flash mode, red-eye reduction mode, return light not detected',
                         79: 'Flash fired, compulsory flash mode, red-eye reduction mode, return light detected',
                         89: 'Flash fired, auto mode, red-eye reduction mode',
                         93: 'Flash fired, auto mode, return light not detected, red-eye reduction mode',
                         95: 'Flash fired, auto mode, return light detected, red-eye reduction mode'}
                if exif[tag] in flash:
                    tags['Flash'] = flash[exif[tag]]
            elif tag == 271:
                tags['Make'] = exif[tag]
            elif tag == 272:
                tags['Model'] = exif[tag]
            elif tag == 305:
                tags['Software'] = exif[tag]
            elif tag == 40962:
                tags['Width'] = exif[tag]
            elif tag == 40963:
                tags['Height'] = exif[tag]
            elif tag == 34853:
                for gps in exif[tag]:
                    if gps == 1:
                        tags['Latitude Reference'] = exif[tag][gps]
                    elif gps == 2:
                        tags['Latitude'] = dmsToDecimal(exif[tag][gps])
                    elif gps == 3:
                        tags['Longitude Reference'] = exif[tag][gps]
                    elif gps == 4:
                        tags['Longitude'] = dmsToDecimal(exif[tag][gps])
            else:
                pass
    return tags, headers

# http://resources.arcgis.com/EN/HELP/MAIN/10.1/index.html#//003r00000005000000
def dmsToDecimal(dms):
    """
    Converts GPS Degree Minute Seconds format to Decimal format.
    :param dms: The GPS data in Degree Minute Seconds format.
    :return: The decimal formatted GPS coordinate.
    """
    deg, min, sec = [x[0] for x in dms]
    if deg > 0:
        return "{0:.5f}".format(deg + (min / 60.) + (sec / 3600000.))
    else:
        return "{0:.5f}".format(deg - (min / 60.) - (sec / 3600000.))
