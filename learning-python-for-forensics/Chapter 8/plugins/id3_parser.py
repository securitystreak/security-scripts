import os
from time import gmtime, strftime

from mutagen import mp3, id3

import processors

__author__ = 'Preston Miller & Chapin Bryce'
__date__ = '20160401'
__version__ = 0.01
__description__ = 'This scripts parses embedded ID3 metadata from compatible objects'


def id3Parser(filename):
    """
    The id3Parser function confirms the file type and sends it to be processed.
    :param filename: name of the file potentially containing exif metadata.
    :return: A dictionary from getTags, containing the embedded EXIF metadata.
    """

    # MP3 signatures
    signatures = ['494433']
    if processors.utility.checkHeader(filename, signatures, 3) == True:
        return getTags(filename)
    else:
        print 'File signature does not match known MP3 signatures.'
        raise TypeError('File signature does not match MP3.')

def getTags(filename):
    """
    The getTags function extracts the ID3 metadata from the data object.
    :param filename: the path and name to the data object.
    :return: tags and headers, tags is a dictionary containing ID3 metadata and headers are the
             order of keys for the CSV output.
    """

    # Set up CSV headers
    header = ['Path', 'Name', 'Size', 'Filesystem CTime', 'Filesystem MTime', 'Title', 'Subtitle', 'Artist', 'Album',
              'Album/Artist', 'Length (Sec)', 'Year', 'Category', 'Track Number', 'Comments', 'Publisher', 'Bitrate',
              'Sample Rate', 'Encoding', 'Channels', 'Audio Layer']
    tags = {}
    tags['Path'] = filename
    tags['Name'] = os.path.basename(filename)
    tags['Size'] = processors.utility.convertSize(os.path.getsize(filename))
    tags['Filesystem CTime'] = strftime('%m/%d/%Y %H:%M:%S', gmtime(os.path.getctime(filename)))
    tags['Filesystem MTime'] = strftime('%m/%d/%Y %H:%M:%S', gmtime(os.path.getmtime(filename)))

    # MP3 Specific metadata
    audio = mp3.MP3(filename)
    if 'TENC' in audio.keys():
        tags['Encoding'] = audio['TENC'][0]
    tags['Bitrate'] = audio.info.bitrate
    tags['Channels'] = audio.info.channels
    tags['Audio Layer'] = audio.info.layer
    tags['Length (Sec)'] = audio.info.length
    tags['Sample Rate'] = audio.info.sample_rate

    # ID3 embedded metadata tags
    id = id3.ID3(filename)
    if 'TPE1' in id.keys():
        tags['Artist'] = id['TPE1'][0]
    if 'TRCK' in id.keys():
        tags['Track Number'] = id['TRCK'][0]
    if 'TIT3' in id.keys():
        tags['Subtitle'] = id['TIT3'][0]
    if 'COMM::eng' in id.keys():
        tags['Comments'] = id['COMM::eng'][0]
    if 'TDRC' in id.keys():
        tags['Year'] = id['TDRC'][0]
    if 'TALB' in id.keys():
        tags['Album'] = id['TALB'][0]
    if 'TIT2' in id.keys():
        tags['Title'] = id['TIT2'][0]
    if 'TCON' in id.keys():
        tags['Category'] = id['TCON'][0]
    if 'TPE2' in id.keys():
        tags['Album/Artist'] = id['TPE2'][0]
    if 'TPUB' in id.keys():
        tags['Publisher'] = id['TPUB'][0]

    return tags, header