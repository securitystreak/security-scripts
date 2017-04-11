#!/usr/bin/python
#
# Copyright (C) 2015 Michael Spreitzenbarth (research@spreitzenbarth.de)
# Copyright (C) 2015 Daniel Arp (darp@gwdg.de)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


import re, urllib
from os.path import basename
from urlparse import urlparse
import numpy as np
from misc import get_file_hash
from xml.dom.minidom import parseString
from androguard.core.bytecodes import apk, dvm
from androguard.core.analysis.analysis import VMAnalysis


class StaticAPKAnalyzer():
    
    # performs static analysis on given apk file
    def __init__(self, output_format=None):
        self._apk_data = dict()
        self._a = None
        self._d = None
        self._dx = None
        self._cm = None
        self._strings = None

        # set output parameters
        categories = ['files',
                      'features',
                      'intent_filters',
                      'activities',
                      'req_permissions',
                      'used_permissions',
                      'api_calls',
                      'crypto_calls',
                      'net_calls',
                      'telephony_calls',
                      'suspicious_calls',
                      'dynamic_calls',
                      'native_calls',
                      'reflection_calls',
                      'urls',
                      'providers',
                      'receivers',
                      'services',
                      'libraries']

        self._out = {'format': output_format,
                     'feat_len': 80,
                     'categories': categories}


    def analyze(self, apk_file):
        self._apk_data = dict()
        self.__init_androguard_objects(apk_file)
        self.__extract_features(apk_file)


    def set_max_output_feat_len(self, feat_len):

        # set maximal length of feature strings
        self._out['feat_len'] = feat_len


    def set_output_categories(self, categories):

        # specify feature categories that should be printed, by default, all extracted features are written to output.
        self._out['categories'] = categories


    def __init_androguard_objects(self, apk_file):
        self._a = apk.APK(apk_file)
        self._d = dvm.DalvikVMFormat(self._a.get_dex())
        self._dx = VMAnalysis(self._d)
        self._cm = self._d.get_class_manager()
        self._strings = self._d.get_strings()


    def __extract_features(self, apk_file):
        self.__calc_hashes(apk_file)
        self.__extract_apk_obj_features()

        # extract features from vm analysis object
        used_perms_dict = self._dx.get_permissions([])
        self._apk_data['used_permissions'] = used_perms_dict.keys()

        for paths in used_perms_dict.values():
            self.__extract_dx_features('api_calls', paths)
        
        paths = self._dx.tainted_packages.search_crypto_packages()
        self.__extract_dx_features('crypto_calls', paths)
        paths = self._dx.tainted_packages.search_net_packages()
        self.__extract_dx_features('net_calls', paths)
        paths = self._dx.tainted_packages.search_telephony_packages()
        self.__extract_dx_features('telephony_calls', paths)
        paths = self._dx.get_tainted_packages().search_methods("Ldalvik/system/DexClassLoader;", ".", ".")
        self.__extract_dx_features('dynamic_calls', paths)
        paths = self._dx.get_tainted_packages().search_methods("Ljava/lang/reflect/Method;", ".", ".")
        self.__extract_dx_features('reflection_calls', paths)

        self.__extract_native_calls()
        self.__extract_urls()
        self.__extract_suspicious_calls()


    def __calc_hashes(self, apk_file):
        self._apk_data['md5'] = get_file_hash('md5', apk_file)
        self._apk_data['sha256'] = get_file_hash('sha256', apk_file)


    def __extract_apk_obj_features(self):
        self._apk_data['apk_name'] = str(basename(self._a.get_filename()))
        self._apk_data['package_name'] = str(self._a.get_package())
        self._apk_data['sdk_version'] = str(self._a.get_min_sdk_version())
        self._apk_data['features'] = self._a.get_elements('uses-feature', 'android:name')
        self._apk_data['files'] = self._a.get_files()
        self._apk_data['activities'] = self._a.get_activities()
        self._apk_data['providers'] = self._a.get_providers()
        self._apk_data['req_permissions'] = self._a.get_permissions()
        self._apk_data['receivers'] = self._a.get_receivers()
        self._apk_data['services'] = self._a.get_services()
        self._apk_data['libraries'] = self._a.get_libraries()
        self._apk_data['intent_filters'] = self._a.get_elements('action', 'android:name') + self._a.get_elements('category', 'android:name')


    def __extract_dx_features(self, category, paths):
        self._apk_data[category] = dict()
        for path in paths:
            class_name = path.get_dst(self._cm)[0]
            method_name = path.get_dst(self._cm)[1]
            if method_name.find('init') > 0:
                method_name = 'init'
            method_name = class_name[1:] + '->' + method_name
            self._apk_data[category][method_name] = 1


    def __extract_native_calls(self):
        self._apk_data['native_calls'] = dict()
        for method in self._d.get_methods():

            # this condition is copied from show_NativeCalls()
            if method.get_access_flags() & 0x100:
                class_name = method.get_class_name()
                method_name = method.get_name()
                if method_name.find('init') > 0:
                    method_name = 'init'
                method_name = class_name[1:] + '->' + method_name
                self._apk_data['native_calls'][method_name] = 1


    def __extract_urls(self):

        # get urls
        ip_regex = '(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})'
        url_regex = 'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|\
                    (?:%[0-9a-fA-F][0-9a-fA-F]))+'

        self._apk_data['urls'] = dict()

        for string in self._strings:
            # search for ip addresses
            ip = re.search(ip_regex, string)
            if None != ip:
                ip = ip.group()
                self._apk_data['urls'][ip] = 1

            # search for urls	
            url = re.search(url_regex, string)
            if None != url:
                url = urllib.quote(url.group(), '>:/?')
                self._apk_data['urls'][url] = 1
                # add hostname
                o = urlparse(url)
                hostname = o.netloc
                self._apk_data['urls'][hostname] = 1


    def __extract_suspicious_calls(self):
        sus_calls = ['Ljava/net/HttpURLconnection;->setRequestMethod',
                     'Ljava/net/HttpURLconnection',
                     'getExternalStorageDirectory',
                     'getSimCountryIso',
                     'execHttpRequest',
                     'sendTextMessage',
                     'Lorg/apache/http/client/methods/HttpPost',
                     'getSubscriberId',
                     'Landroid/telephony/SmsMessage;->getMessageBody',
                     'getDeviceId',
                     'getPackageInfo',
                     'getSystemService',
                     'getWifiState',
                     'system/bin/su',
                     'system/xbin/su',
                     'setWifiEnabled',
                     'setWifiDisabled',
                     'Cipher',
                     'Ljava/io/IOException;->printStackTrace',
                     'android/os/Exec',
                     'Ljava/lang/Runtime;->exec']

        sus_calls = dict(zip(sus_calls, np.ones(len(sus_calls))))
        self._apk_data['suspicious_calls'] = dict()

        for string in self._strings:
            for sc in sus_calls:
                if string.find(sc) >= 0:
                    self._apk_data['suspicious_calls'][string] = 1

        sus_tuples = [('java/net/HttpURLconnection', 'setRequestMethod'),
                      ('android/telephony/SmsMessage', 'getMessageBody'),
                      ('java/io/IOException', 'printStackTrace'),
                      ('java/lang/Runtime', 'exec')]

        for tpl in sus_tuples:
            class_name = tpl[0][1:]
            name = tpl[1]
            paths = self._dx.tainted_packages.search_methods(class_name, name, '')
            for path in paths:
                method = path.get_dst(self._cm)
                method_full = method[0] + '->' + method[1]
                self._apk_data['suspicious_calls'][method_full] = 1


    def __str__(self):
        if self._out['format'] == 'xml':
            out_str = self.__create_xml_string()
        else:
            out_str = self.__get_feature_strings()
        return out_str


    def __get_feature_strings(self):
        feat_str = ''
        for category in self._out['categories']:
            if category not in self._apk_data:
                continue

            for item in self._apk_data[category]:
                feat_str += '\n{0}::{1}'\
                    .format(category, item[:self._out['feat_len']])
        return feat_str[1:]


    def __create_xml_string(self):
        xml_str = '<static>'
        xml_str += self.__get_info_string()
        for category in self._out['categories']:
            xml_str += self.__get_category_string(category)
        xml_str += '\n</static>'

        doc = parseString("" + xml_str + "")
        xml = doc.toxml().replace('<static>', '\n<static>')
        return xml


    def __get_info_string(self):
        istr = '\n\t<info>'
        istr += '\n\t\t<sha256>' + str(self._apk_data['sha256']) + '</sha256>'
        istr += '\n\t\t<md5>' + str(self._apk_data['md5']) + '</md5>'
        istr += '\n\t\t<apk_name>' + self._apk_data['apk_name'] + '</apk_name>'
        istr += '\n\t\t<package_name>' + self._apk_data['package_name'] + '</package_name>'
        istr += '\n\t\t<sdk_version>' + self._apk_data['sdk_version'] + '</sdk_version>'
        istr += '\n\t</info>'
        return istr


    def __get_category_string(self, category):
        cat_str = '\n\t<{}>'.format(category)
        for item in self._apk_data[category]:
            field = self.__get_field_name(category)
            cat_str += '\n\t\t<{0}>{1}</{0}>'\
                .format(field, item[:self._out['feat_len']])
        cat_str += '\n\t</{}>'.format(category)
        return cat_str


    @staticmethod
    def __get_field_name(category):
        if category.endswith('ies'):
            return category[:-3] + 'y'
        else:
            return category[:-1]