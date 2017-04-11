import os
import sys
import argparse
import logging
import jinja2

import pypff
import unicodecsv as csv
from collections import Counter

__author__ = 'Preston Miller & Chapin Bryce'
__date__ = '20160401'
__version__ = 0.01
__description__ = 'This scripts handles processing and output of PST Email Containers'


output_directory = ""
date_dict = {x:0 for x in xrange(1, 25)}
date_list = [date_dict.copy() for x in xrange(7)]


def main(pst_file, report_name):
    """
    The main function opens a PST and calls functions to parse and report data from the PST
    :param pst_file: A string representing the path to the PST file to analyze
    :param report_name: Name of the report title (if supplied by the user)
    :return: None
    """
    logging.debug("Opening PST for processing...")
    pst_name = os.path.split(pst_file)[1]
    opst = pypff.open(pst_file)
    root = opst.get_root_folder()

    logging.debug("Starting traverse of PST structure...")
    folderTraverse(root)

    logging.debug("Generating Reports...")
    top_word_list = wordStats()
    top_sender_list = senderReport()
    dateReport()

    HTMLReport(report_name, pst_name, top_word_list, top_sender_list)


def makePath(file_name):
    """
    The makePath function provides an absolute path between the output_directory and a file
    :param file_name: A string representing a file name
    :return: A string representing the path to a specified file
    """
    return os.path.abspath(os.path.join(output_directory, file_name))


def folderTraverse(base):
    """
    The folderTraverse function walks through the base of the folder and scans for sub-folders and messages
    :param base: Base folder to scan for new items within the folder.
    :return: None
    """
    for folder in base.sub_folders:
        if folder.number_of_sub_folders:
            folderTraverse(folder) # Call new folder to traverse:
        checkForMessages(folder)


def checkForMessages(folder):
    """
    The checkForMessages function reads folder messages if present and passes them to the report function
    :param folder: pypff.Folder object
    :return: None
    """
    logging.debug("Processing Folder: " + folder.name)
    message_list = []
    for message in folder.sub_messages:
        message_dict = processMessage(message)
        message_list.append(message_dict)
    folderReport(message_list, folder.name)


def processMessage(message):
    """
    The processMessage function processes multi-field messages to simplify collection of information
    :param message: pypff.Message object
    :return: A dictionary with message fields (values) and their data (keys)
    """
    return {
        "subject": message.subject,
        "sender": message.sender_name,
        "header": message.transport_headers,
        "body": message.plain_text_body,
        "creation_time": message.creation_time,
        "submit_time": message.client_submit_time,
        "delivery_time": message.delivery_time,
        "attachment_count": message.number_of_attachments,
    }


def folderReport(message_list, folder_name):
    """
    The folderReport function generates a report per PST folder
    :param message_list: A list of messages discovered during scans
    :folder_name: The name of an Outlook folder within a PST
    :return: None
    """
    if not len(message_list):
        logging.warning("Empty message not processed")
        return

    # CSV Report
    fout_path = makePath("folder_report_" + folder_name + ".csv")
    fout = open(fout_path, 'wb')
    header = ['creation_time', 'submit_time', 'delivery_time',
              'sender', 'subject', 'attachment_count']
    csv_fout = csv.DictWriter(fout, fieldnames=header, extrasaction='ignore')
    csv_fout.writeheader()
    csv_fout.writerows(message_list)
    fout.close()

    # HTML Report Prep
    global date_list  # Allow access to edit global variable
    body_out = open(makePath("message_body.txt"), 'a')
    senders_out = open(makePath("senders_names.txt"), 'a')
    for m in message_list:
        if m['body']:
            body_out.write(m['body'] + "\n\n")
        if m['sender']:
            senders_out.write(m['sender'] + '\n')
        # Creation Time
        day_of_week = m['creation_time'].weekday()
        hour_of_day = m['creation_time'].hour + 1
        date_list[day_of_week][hour_of_day] += 1
        # Submit Time
        day_of_week = m['submit_time'].weekday()
        hour_of_day = m['submit_time'].hour + 1
        date_list[day_of_week][hour_of_day] += 1
        # Delivery Time
        day_of_week = m['delivery_time'].weekday()
        hour_of_day = m['delivery_time'].hour + 1
        date_list[day_of_week][hour_of_day] += 1
    body_out.close()
    senders_out.close()


def wordStats(raw_file="message_body.txt"):
    """
    The wordStats function reads and counts words from a file
    :param raw_file: The path to a file to read
    :return: A list of word frequency counts
    """
    word_list = Counter()
    for line in open(makePath(raw_file), 'r').readlines():
        for word in line.split():
            # Prevent too many false positives/common words
            if word.isalnum() and len(word) > 4:
                word_list[word] += 1
    return wordReport(word_list)


def wordReport(word_list):
    """
    The wordReport function counts a list of words and returns results in a CSV format
    :param word_list: A list of words to iterate through
    :return: None or html_report_list, a list of word frequency counts
    """
    if not word_list:
        logging.debug('Message body statistics not available')
        return

    fout = open(makePath("frequent_words.csv"), 'wb')
    fout.write("Count,Word\n")
    for e in word_list.most_common():
        if len(e) > 1:
            fout.write(str(e[1]) + "," + str(e[0]) + "\n")
    fout.close()

    html_report_list = []
    for e in word_list.most_common(10):
        html_report_list.append({"word": str(e[0]), "count": str(e[1])})

    return html_report_list


def senderReport(raw_file="senders_names.txt"):
    """
    The senderReport function reports the most frequent_senders
    :param raw_file: The file to read raw information
    :return: html_report_list, a list of the most frequent senders
    """
    sender_list = Counter(open(makePath(raw_file), 'r').readlines())

    fout = open(makePath("frequent_senders.csv"), 'wb')
    fout.write("Count,Sender\n")
    for e in sender_list.most_common():
        if len(e) > 1:
            fout.write(str(e[1]) + "," + str(e[0]))
    fout.close()

    html_report_list = []
    for e in sender_list.most_common(5):
        html_report_list.append({"label": str(e[0]), "count": str(e[1])})

    return html_report_list


def dateReport():
    """
    The dateReport function writes date information in a TSV report. No input args as the filename
    is static within the HTML dashboard
    :return: None
    """
    csv_out = open(makePath("heatmap.tsv"), 'w')
    csv_out.write("day\thour\tvalue\n")
    for date, hours_list in enumerate(date_list):
        for hour, count in hours_list.items():
            to_write = str(date+1) + "\t" + str(hour) + "\t" + str(count) + "\n"
            csv_out.write(to_write)
        csv_out.flush()
    csv_out.close()


def HTMLReport(report_title, pst_name, top_words, top_senders):
    """
    The HTMLReport function generates the HTML report from a Jinja2 Template
    :param report_title: A string representing the title of the report
    :param pst_name: A string representing the file name of the PST
    :param top_words: A list of the top 10 words
    :param top_senders: A list of the top 10 senders
    :return: None
    """
    open_template = open("stats_template.html", 'r').read()
    html_template = jinja2.Template(open_template)

    context = {"report_title": report_title, "pst_name": pst_name,
               "word_frequency": top_words, "percentage_by_sender": top_senders}
    new_html = html_template.render(context)

    html_report_file = open(makePath(report_title+".html"), 'w')
    html_report_file.write(new_html)
    html_report_file.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(version=str(__version__), description=__description__,
                                     epilog='Developed by ' + __author__ + ' on ' + __date__)
    parser.add_argument('PST_FILE', help="PST File Format from Microsoft Outlook")
    parser.add_argument('OUTPUT_DIR', help="Directory of output for temporary and report files.")
    parser.add_argument('--title', help='Title of the HTML Report. (default=PST Report)',
                        default="PST Report")
    parser.add_argument('-l', help='File path of log file.')
    args = parser.parse_args()

    output_directory = os.path.abspath(args.OUTPUT_DIR)

    if not os.path.exists(output_directory):
        os.makedirs(output_directory)

    if args.l:
        if not os.path.exists(args.l):
            os.makedirs(args.l)
        log_path = os.path.join(args.l, 'pst_indexer.log')
    else:
        log_path = 'pst_indexer.log'
    logging.basicConfig(filename=log_path, level=logging.DEBUG,
                        format='%(asctime)s | %(levelname)s | %(message)s', filemode='a')

    logging.info('Starting PST_Indexer v.' + str(__version__))
    logging.debug('System ' + sys.platform)
    logging.debug('Version ' + sys.version)

    logging.info('Starting Script...')
    main(args.PST_FILE, args.title)
    logging.info('Script Complete')
