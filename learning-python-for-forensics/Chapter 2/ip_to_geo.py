__author__ = 'Preston Miller & Chapin Bryce'
__version__ = '20150822'
__date__ = '0.01'

import urllib
import ast


class IPtoGeo(object):

    def __init__(self, ip_address):
        # Initialize objects to store
        self.latitude = ''
        self.longitude = ''
        self.country = ''
        self.city = ''

        self.ip_address = ip_address

        self._get_location()

    def _get_location(self):
        """
        Retrieve initial location data (contry, city, lat/long) from hostip.info
        :return:
        """
        request = urllib.urlopen('http://api.hostip.info/get_json.php?ip=%s&position=true' % self.ip_address).read()
        json_request = ast.literal_eval(request)

        self.country = json_request['country_name']
        self.country_code = json_request['country_code']
        self.city = json_request['city']
        self.latitude = json_request['lat']
        self.longitude = json_request['lng']

if __name__ == '__main__':
    ip1 = IPtoGeo('8.8.8.8')
    ip2 = IPtoGeo('12.215.42.19')
    print ip1.__dict__
    print ip2.__dict__