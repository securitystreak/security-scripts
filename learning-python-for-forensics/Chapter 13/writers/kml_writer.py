__author__ = 'Preston Miller & Chapin Bryce'
__date__ = '20151107'
__version__ = 0.01
__description__ = 'KML Writer'

import os
import simplekml


def writer(output, output_name, output_data):
    """
    The writer function writes JPEG and TIFF EXIF GPS data to a Google Earth KML file. This file can be opened
    in Google Earth and will use the GPS coordinates to create 'pins' on the map of the taken photo's location.
    :param output: The output directory to write the KML file.
    :param output_name: The name of the output KML file.
    :param output_data: The embedded EXIF metadata to be written
    :return:
    """

    kml = simplekml.Kml(name=output_name)
    for exif in output_data:
        if 'Latitude' in exif.keys() and 'Latitude Reference' in exif.keys() and 'Longitude Reference' in exif.keys() and 'Longitude' in exif.keys():

            if 'Original Date' in exif.keys():
                dt = exif['Original Date']
            else:
                dt = 'N/A'

            if exif['Latitude Reference'] == 'S':
                latitude = '-' + exif['Latitude']
            else:
                latitude = exif['Latitude']

            if exif['Longitude Reference'] == 'W':
                longitude = '-' + exif['Longitude']
            else:
                longitude = exif['Longitude']

            kml.newpoint(name=exif['Name'], description='Originally Created: ' + dt,
                         coords=[(longitude, latitude)])
        else:
            pass
    kml.save(os.path.join(output, output_name))
