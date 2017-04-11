from Tkinter import *
import ttk
from dateutil import parser as duparser
import datetime
import logging

__author__ = 'Preston Miller & Chapin Bryce'
__date__ = '20160401'
__version__ = 0.01
__description__ = 'This script uses a GUI to show date values interpreted by common timestamp formats'


class DateDecoder(object):
    """
    The DateDecoder class handles the construction of the GUI and the processing of date & time values
    """
    def __init__(self):
        """
        The __init__ method initializes the root GUI window and variable used in the script
        """
        # Init root window
        self.root = Tk()
        self.root.geometry("500x180+40+40")
        self.root.config(background = '#ECECEC')
        self.root.title('Date Decoder')

        # Init time values
        self.processed_unix_seconds = None
        self.processed_windows_filetime_64 = None
        self.processed_chrome_time = None

        # Set Constant Epoch Offset
        self.epoch_1601 = 11644473600000000
        self.epoch_1970 = datetime.datetime(1970,1,1)

    def run(self):
        """
        The run method calls appropriate methods to build the GUI and set's the event listener loop.
        """
        logging.info('Launching GUI')
        self.buildInputFrame()
        self.buildOutputFrame()
        self.root.mainloop()

    def buildInputFrame(self):
        """
        The buildInputFrame method builds the interface for the input frame
        """
        # Frame Init
        self.input_frame = ttk.Frame(self.root)
        self.input_frame.config(padding = (30,0))
        self.input_frame.pack()

        # Input Value
        ttk.Label(self.input_frame, text="Enter Time Value").grid(row=0, column=0)

        self.input_time = StringVar()
        ttk.Entry(self.input_frame, textvariable=self.input_time, width=25).grid(row=0, column=1, padx=5)

        # Radiobuttons
        self.time_type = StringVar()
        self.time_type.set('raw')

        ttk.Radiobutton(self.input_frame, text="Raw Value", variable=self.time_type, value="raw").grid(row=1, column=0, padx=5)

        ttk.Radiobutton(self.input_frame, text="Formatted Value", variable=self.time_type, value="formatted").grid(row=1, column=1, padx=5)

        # Button
        ttk.Button(self.input_frame, text="Run", command=self.convert).grid(row=2, columnspan=2, pady=5)

    def buildOutputFrame(self):
        """
        The buildOutputFrame method builds the interface for the output frame
        """
        # Output Frame Init
        self.output_frame = ttk.Frame(self.root)
        self.output_frame.config(height=300, width=500)
        self.output_frame.pack()

        # Output Area
        ## Label for area
        self.output_label = ttk.Label(self.output_frame, text="Conversion Results (UTC)")
        self.output_label.config(font=("", 16))
        self.output_label.pack(fill=X)

        ## For Unix Seconds Timestamps
        self.unix_sec = ttk.Label(self.output_frame, text="Unix Seconds: N/A")
        self.unix_sec.pack(fill=X)

        ## For Windows FILETIME 64 Timestamps
        self.win_ft_64 = ttk.Label(self.output_frame, text="Windows FILETIME 64: N/A")
        self.win_ft_64.pack(fill=X)

        ## For Chrome Timestamps
        self.google_chrome = ttk.Label(self.output_frame, text="Google Chrome: N/A")
        self.google_chrome.pack(fill=X)

    def convert(self):
        """
        The convert method handles the event when the button is pushed.
        It calls to the converters and updates the labels with new output.
        """
        logging.info('Processing Timestamp: ' + self.input_time.get())
        logging.info('Input Time Format: ' + self.time_type.get())

        # Init values every instance
        self.processed_unix_seconds = 'N/A'
        self.processed_windows_filetime_64 = 'N/A'
        self.processed_chrome_time = 'N/A'

        # Use this to call converters
        self.convertUnixSeconds()
        self.convertWindowsFiletime_64()
        self.convertChromeTimestamps()

        # Update labels
        self.output()

    def convertUnixSeconds(self):
        """
        The convertUnixSeconds method handles the conversion of timestamps per the UNIX seconds format
        """
        if self.time_type.get() == 'raw':
            try:
                self.processed_unix_seconds = datetime.datetime.fromtimestamp(float(self.input_time.get())).strftime('%Y-%m-%d %H:%M:%S')
            except Exception, e:
                logging.error(str(type(e)) + "," + str(e))
                self.processed_unix_seconds = str(type(e).__name__)

        elif self.time_type.get() == 'formatted':
            try:
                converted_time = duparser.parse(self.input_time.get())
                self.processed_unix_seconds = str((converted_time - self.epoch_1970).total_seconds())
            except Exception, e:
                logging.error(str(type(e)) + "," + str(e))
                self.processed_unix_seconds = str(type(e).__name__)

    def convertWindowsFiletime_64(self):
        """
        The convertWindowsFiletime_64 method handles the conversion of timestamps per the Windows FILETIME format
        """
        if self.time_type.get() == 'raw':
            try:
                base10_microseconds = int(self.input_time.get(), 16) / 10
                datetime_obj = datetime.datetime(1601,1,1) + datetime.timedelta(microseconds=base10_microseconds)
                self.processed_windows_filetime_64 = datetime_obj.strftime('%Y-%m-%d %H:%M:%S.%f')
            except Exception, e:
                logging.error(str(type(e)) + "," + str(e))
                self.processed_windows_filetime_64 = str(type(e).__name__)

        elif self.time_type.get() == 'formatted':
            try:
                converted_time = duparser.parse(self.input_time.get())
                minus_epoch = converted_time - datetime.datetime(1601,1,1)
                calculated_time = minus_epoch.microseconds + (minus_epoch.seconds * 1000000) + (minus_epoch.days * 86400000000)
                self.processed_windows_filetime_64 = str(hex(int(calculated_time)*10))
            except Exception, e:
                logging.error(str(type(e)) + "," + str(e))
                self.processed_windows_filetime_64 = str(type(e).__name__)

    def convertChromeTimestamps(self):
        """
        The convertChromeTimestamps method handles the conversion of timestamps per the Google Chrome timestamp format
        """
        # Run Conversion
        if self.time_type.get() == 'raw':
            try:
                converted_time = datetime.datetime.fromtimestamp((float(self.input_time.get())-self.epoch_1601)/1000000)
                self.processed_chrome_time = converted_time.strftime('%Y-%m-%d %H:%M:%S.%f')
            except Exception, e:
                logging.error(str(type(e)) + "," + str(e))
                self.processed_chrome_time = str(type(e).__name__)

        elif self.time_type.get() == 'formatted':
            try:
                converted_time = duparser.parse(self.input_time.get())
                chrome_time = (converted_time - self.epoch_1970).total_seconds()*1000000 + self.epoch_1601
                self.processed_chrome_time = str(int(chrome_time))
            except Exception, e:
                logging.error(str(type(e)) + "," + str(e))
                self.processed_chrome_time = str(type(e).__name__)

    def output(self):
        """
        The output method updates the output frame with the latest value.
        """
        if isinstance(self.processed_unix_seconds, str):
            self.unix_sec['text'] = "Unix Seconds: " + self.processed_unix_seconds

        if isinstance(self.processed_windows_filetime_64, str):
            self.win_ft_64['text'] = "Windows FILETIME 64: " + self.processed_windows_filetime_64

        if isinstance(self.processed_chrome_time, str):
            self.google_chrome['text'] = "Google Chrome: " + self.processed_chrome_time


if __name__ == '__main__':
    """
    This statement is used to initialize the GUI. No arguments needed as it is a graphic interface
    """
    # Initialize Logging
    log_path = 'date_decoder.log'
    logging.basicConfig(filename=log_path, level=logging.DEBUG,
                           format='%(asctime)s | %(levelname)s | %(message)s', filemode='a')

    logging.info('Starting Date Decoder v.' + str(__version__))
    logging.debug('System ' + sys.platform)
    logging.debug('Version ' + sys.version)

    # Create Instance and run the GUI
    dd = DateDecoder()
    dd.run()
