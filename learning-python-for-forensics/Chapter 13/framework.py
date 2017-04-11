import os
import sys
import logging
import argparse
import plugins
import writers
import colorama
from datetime import datetime
from pyfiglet import Figlet

colorama.init()

__author__ = 'Preston Miller & Chapin Bryce'
__date__ = '20160401'
__version__ = 0.01
__description__ = 'This script is our framework controller and handles each plugin'


class Framework(object):
    
    def __init__(self, input_directory, output_directory, log, **kwargs):
        self.input = input_directory
        self.output = output_directory
        logging.basicConfig(filename=log, level=logging.DEBUG,
                            format='%(asctime)s | %(levelname)s | %(message)s', filemode='a')
        self.log = logging.getLogger(log)
        self.kwargs = kwargs

    def run(self):
        msg = 'Initializing framework v' + str(__version__)
        print '[+]', msg
        self.log.info(msg)
        f = Figlet(font='doom')
        print f.renderText('Framework')
        self.log.debug('System ' + sys.platform)
        self.log.debug('Version ' + sys.version)
        if not os.path.exists(self.output):
            os.makedirs(self.output)
        self._list_files()
        self._run_plugins()

    def _list_files(self):
        msg = 'Indexing {}'.format(self.input)
        print '[+]', msg
        logging.info(msg)

        self.wal_files = []
        self.setupapi_files = []
        self.userassist_files = []
        self.exif_metadata = []
        self.office_metadata = []
        self.id3_metadata = []
        self.pst_files = []

        for root, subdir, files in os.walk(self.input, topdown=True):
            for file_name in files:
                current_file = os.path.join(root, file_name)
                current_file = current_file.decode('utf-8').lower()
                if not os.path.isfile(current_file):
                    logging.warning(u"Could not parse file {}... Skipping...".format((current_file)))
                    continue
                ext = os.path.splitext(current_file)[1]
                if current_file.endswith('ntuser.dat'):
                    self.userassist_files.append(current_file)
                elif 'setupapi.dev.log' in current_file:
                    self.setupapi_files.append(current_file)
                elif ext == '.jpeg' or ext == '.jpg':
                    self.exif_metadata.append(current_file)
                elif ext == '.docx' or ext == '.pptx' or ext == '.xlsx':
                    self.office_metadata.append(current_file)
                elif ext == '.mp3':
                    self.id3_metadata.append(current_file)
                elif ext == '.pst':
                    self.pst_files.append(current_file)
                elif ext.endswith('-wal'):
                    self.wal_files.append(current_file)
                else:
                    continue

    def _run_plugins(self):
        # Run Wal Crawler
        if len(self.wal_files) > 0:
            wal_plugin = Framework.Plugin('wal_crawler', self.wal_files, self.log)
            wal_output = os.path.join(self.output, 'wal')
            wal_plugin.run(plugins.wal_crawler.main)
            if self.kwargs['excel'] is True:
                wal_plugin.write(wal_output, recursion=1, excel=1)
            else:
                wal_plugin.write(wal_output, recursion=1)

        # Run Setupapi Parser
        if len(self.setupapi_files) > 0:
            setupapi_plugin = Framework.Plugin('setupapi', self.setupapi_files, self.log)
            setupapi_output = os.path.join(self.output, 'setupapi')
            setupapi_plugin.run(plugins.setupapi.main)
            if self.kwargs['excel'] is True:
                setupapi_plugin.write(setupapi_output, recursion=1, excel=1)
            else:
                setupapi_plugin.write(setupapi_output, recursion=1)

        # Run Userassist Parser
        if len(self.userassist_files) > 0:
            userassist_plugin = Framework.Plugin('userassist', self.userassist_files, self.log)
            userassist_output = os.path.join(self.output, 'userassist')
            userassist_plugin.run(plugins.userassist.main)
            if self.kwargs['excel'] is True:
                userassist_plugin.write(userassist_output, recursion=1, excel=1)
            else:
                userassist_plugin.write(userassist_output, recursion=1)

        # Run EXIF metadata parser
        if len(self.exif_metadata) > 0:
            exif_metadata_plugin = Framework.Plugin('exif_metadata', self.exif_metadata, self.log)
            exif_metadata_output = os.path.join(self.output, 'metadata')
            exif_metadata_plugin.run(plugins.exif.main)
            if self.kwargs['excel'] is True:
                exif_metadata_plugin.write(exif_metadata_output, excel=1)
            else:
                exif_metadata_plugin.write(exif_metadata_output)

        # Run office metadata parser
        if len(self.office_metadata) > 0:
            office_metadata_plugin = Framework.Plugin('office_metadata', self.office_metadata, self.log)
            office_metadata_output = os.path.join(self.output, 'metadata')
            office_metadata_plugin.run(plugins.office.main)
            if self.kwargs['excel'] is True:
                office_metadata_plugin.write(office_metadata_output, excel=1)
            else:
                office_metadata_plugin.write(office_metadata_output)

        # Run ID3 metadata parser
        if len(self.id3_metadata) > 0:
            id3_metadata_plugin = Framework.Plugin('id3_metadata', self.id3_metadata, self.log)
            id3_metadata_output = os.path.join(self.output, 'metadata')
            id3_metadata_plugin.run(plugins.id3.main)
            if self.kwargs['excel'] is True:
                id3_metadata_plugin.write(id3_metadata_output, excel=1)
            else:
                id3_metadata_plugin.write(id3_metadata_output)

        # Run PST parser
        if len(self.pst_files) > 0:
            pst_plugin = Framework.Plugin('pst', self.pst_files, self.log)
            pst_output = os.path.join(self.output, 'pst')
            pst_plugin.run(plugins.pst_indexer.main)
            if self.kwargs['excel'] is True:
                pst_plugin.write(pst_output, recursion=1, excel=1)
            else:
                pst_plugin.write(pst_output, recursion=1)

    class Plugin(object):

        def __init__(self, plugin, files, log):
            self.plugin = plugin
            self.files = files
            self.log = log
            self.results = {'data': [], 'headers': None}

        def run(self, function):
            msg = 'Executing {} plugin'.format(self.plugin)
            print colorama.Fore.RESET + '[+]', msg
            self.log.info(msg)

            for f in self.files:
                try:
                    data, headers = function(f)
                    self.results['data'].append(data)
                    self.results['headers'] = headers

                except TypeError:
                    self.log.error('Issue processing {}. Skipping...'.format(f))
                    continue

            msg = 'Plugin {} completed at {}'.format(self.plugin, datetime.now().strftime('%m/%d/%Y %H:%M:%S'))
            print colorama.Fore.GREEN + '[*]', msg
            self.log.info(msg)

        def write(self, output, **kwargs):
            msg = 'Writing results of {} plugin'.format(self.plugin)
            print colorama.Fore.RESET + '[+]', msg
            self.log.info(msg)
            if not os.path.exists(output):
                os.makedirs(output)
            if 'excel' in kwargs.keys():
                Framework.Writer(writers.xlsx_writer.writer, output, self.plugin + '.xlsx', self.results['headers'],
                                 self.results['data'], **kwargs)
            else:
                Framework.Writer(writers.csv_writer.writer, output, self.plugin + '.csv', self.results['headers'],
                                 self.results['data'], **kwargs)
            if self.plugin == 'exif_metadata':
                Framework.Writer(writers.kml_writer.writer, output, '', self.plugin + '.kml', self.results['data'])

    class Writer(object):

        def __init__(self, writer, output, name, header, data, **kwargs):
            self.writer = writer
            self.output = os.path.join(output, name)
            self.header = header
            self.data = data
            self.recursion = None
            if 'recursion' in kwargs.keys():
                self.recursion = kwargs['recursion']
            self.run()

        def run(self):
            if self.recursion:
                self.writer(self.output, self.header, self.data, recursion=self.recursion)
            else:
                self.writer(self.output, self.header, self.data)


if __name__ == '__main__':

    parser = argparse.ArgumentParser(version=str(__version__), description=__description__,
                                     epilog='Developed by ' + __author__ + ' on ' + __date__)
    parser.add_argument('INPUT_DIR', help='Base directory to process.')
    parser.add_argument('OUTPUT_DIR', help='Output directory.')
    parser.add_argument('-x', help='Excel output (Default CSV)', action='store_true')
    parser.add_argument('-l', help='File path and name of log file.')
    args = parser.parse_args()

    if os.path.isfile(args.INPUT_DIR) or os.path.isfile(args.OUTPUT_DIR):
        msg = 'Input and Output arguments must be directories.'
        print colorama.Fore.RED + '[-]', msg
        sys.exit(1)

    if args.l:
        if not os.path.exists(args.l):
            os.makedirs(args.l)  # create log directory path
        log_path = os.path.join(args.l, 'framework.log')
    else:
        log_path = 'framework.log'

    framework = Framework(args.INPUT_DIR, args.OUTPUT_DIR, log_path, excel=args.x)
    framework.run()
