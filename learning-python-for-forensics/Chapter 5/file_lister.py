import os
import sys
import logging
import csv
import sqlite3
import argparse
import datetime

__author__ = 'Preston Miller & Chapin Bryce'
__date__ = '20160401'
__version__ = 0.01
__description__ = 'This script uses a database to ingest and report meta data information about active entries in directories'


def main(custodian, source, db):
    """
    The main function creates the database or table, logs execution status, and handles errors
    :param custodian: The name of the custodian
    :param source: tuple containing the mode 'input' or 'output' as the first elemnet and its arguments as the second
    :param db: The filepath for the database
    :return: None
    """
    logging.info('Initiating SQLite database: ' + db)
    conn = initDB(db)
    cur = conn.cursor()
    logging.info('Initialization Successful')
    logging.info('Retrieving or adding custodian: ' + custodian)
    custodian_id = getOrAddCustodian(cur, custodian)
    while not custodian_id:
        custodian_id = getOrAddCustodian(cur, custodian)
    logging.info('Custodian Retrieved')
    if source[0] == 'input':
        logging.info('Ingesting base input directory: ' + source[1])
        ingestDirectory(cur, source[1], custodian_id)
        conn.commit()
        logging.info('Ingest Complete')
    elif source[0] == 'output':
        logging.info('Preparing to write output: ' + source[1])
        writeOutput(cur, source[1], custodian)
    else:
        raise argparse.ArgumentError('Could not interpret run time arguments')

    cur.close()
    conn.close()
    logging.info('Script Completed')


def initDB(db_path):
    """
    The initDB function opens or creates the database
    :param db_path: The filepath for the database
    :return: conn, the sqlite3 database connection
    """
    if os.path.exists(db_path):
        logging.info('Found Existing Database')
        return sqlite3.connect(db_path)
    else:
        logging.info('Existing database not found. Initializing new database')
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()

        sql = 'CREATE TABLE Custodians (id INTEGER PRIMARY KEY, name TEXT);'
        cur.execute(sql)
        cur.execute('PRAGMA foreign_keys = 1;')
        sql = "CREATE TABLE Files(id INTEGER PRIMARY KEY, custodian INTEGER REFERENCES Custodians(id)," \
              "file_name TEXT, file_path TEXT, extension TEXT, file_size INTEGER,  " \
              "mtime TEXT, ctime TEXT, atime TEXT, mode INTEGER, inode INTEGER);"
        cur.execute(sql)
        return conn


def getOrAddCustodian(cur, custodian):
    """
    The getOrAddCustodian function checks the database for a custodian and returns the ID if present;
    Or otherwise creates the custodian
    :param cur: The sqlite3 database cursor object
    :param custodian: The name of the custodian
    :return: The custodian ID or None
    """
    id = getCustodian(cur, custodian)

    if id:
        return id[0]
    else:
        sql = "INSERT INTO Custodians (id, name) VALUES (null, '" + custodian + "') ;"
        cur.execute(sql)
        return None


def getCustodian(cur, custodian):
    """
    The getCustodian function checks the database for a custodian and returns the ID if present
    :param cur: The sqlite3 database cursor object
    :param custodian: The name of the custodian
    :return: The custodian ID
    """
    sql = "SELECT id FROM Custodians WHERE name='{}';".format(custodian)
    cur.execute(sql)
    data = cur.fetchone()
    return data


def ingestDirectory(cur, source, custodian_id):
    """
    The ingestDirectory function reads file metadata and stores it in the database
    :param cur: The sqlite3 database cursor object
    :param source: The path for the root directory to recursively walk
    :param custodian_id: The custodian ID
    :return: None
    """
    count = 0
    for root, folders, files in os.walk(source):
        for file_name in files:
            meta_data = dict()
            try:
                meta_data['file_name'] = file_name
                meta_data['file_path'] = os.path.join(root, file_name)
                meta_data['extension'] = os.path.splitext(file_name)[-1]

                file_stats = os.stat(meta_data['file_path'])
                meta_data['mode'] = oct(file_stats.st_mode)
                meta_data['inode'] = int(file_stats.st_ino)
                meta_data['file_size'] = int(file_stats.st_size)
                meta_data['atime'] = formatTimestamp(file_stats.st_atime)
                meta_data['mtime'] = formatTimestamp(file_stats.st_mtime)
                meta_data['ctime'] = formatTimestamp(file_stats.st_ctime)
            except Exception as e:
                logging.error('Could not gather data for file: ' + meta_data['file_path'] + e.__str__())
            meta_data['custodian'] = custodian_id
            columns = '","'.join(meta_data.keys())
            values = '","'.join(str(x).encode('string_escape') for x in meta_data.values())
            sql = 'INSERT INTO Files ("' + columns + '") VALUES ("' + values + '")'
            cur.execute(sql)
            count += 1

    logging.info('Stored meta data for ' + str(count) + ' files.')


def formatTimestamp(ts):
    """
    The formatTimestamp function formats an integer to a string timestamp
    :param ts: An integer timestamp
    :return: ts_format, a formatted (YYYY-MM-DD HH:MM:SS) string
    """
    ts_datetime = datetime.datetime.fromtimestamp(ts)
    ts_format = ts_datetime.strftime('%Y-%m-%d %H:%M:%S')
    return ts_format


def writeOutput(cur, source, custodian):
    """
    The writeOutput function handles writing either the CSV or HTML reports
    :param cur: The sqlite3 database cursor object
    :param source: The output filepath
    :param custodian: Name of the custodian
    :return: None
    """
    custodian_id = getCustodian(cur, custodian)

    if custodian_id:
        custodian_id = custodian_id[0]
        sql = "SELECT COUNT(id) FROM Files where custodian = '" + str(custodian_id) + "'"
        cur.execute(sql)
        count = cur.fetchone()
    else:
        logging.error('Could not find custodian in database. '
                      'Please check the input of the custodian name and database path')

    if not count or not count[0] > 0:
        logging.error('Files not found for custodian')
    elif source.endswith('.csv'):
        writeCSV(cur, source, custodian_id)
    elif source.endswith('.html'):
        writeHTML(cur, source, custodian_id, custodian)
    elif not (source.endswith('.html')or source.endswith('.csv')):
        logging.error('Could not determine file type')
    else:
        logging.error('Unknown Error Occurred')


def writeCSV(cur, source, custodian_id):
    """
    The writeCSV function generates a CSV report from the Files table
    :param cur: The Sqlite3 database cursor object
    :param source: The output filepath
    :param custodian_id: The custodian ID
    :return: None
    """
    sql = "SELECT * FROM Files where custodian = '" + str(custodian_id) + "'"
    cur.execute(sql)

    column_names = [description[0] for description in cur.description]
    logging.info('Writing CSV report')
    with open(source, 'w') as csv_file:
        csv_writer = csv.writer(csv_file)
        csv_writer.writerow(column_names)

        for entry in cur.fetchall():
            csv_writer.writerow(entry)
        csv_file.flush()
    logging.info('CSV report completed: ' + source)


def writeHTML(cur, source, custodian_id, custodian_name):
    """
    The writeHTML function generates an HTML report from the Files table
    :param cur: The sqlite3 database cursor object
    :param source: The output filepath
    :param custodian_id: The custodian ID
    :return: None
    """
    sql = "SELECT * FROM Files where custodian = '" + str(custodian_id) + "'"
    cur.execute(sql)

    column_names = [description[0] for description in cur.description]
    table_header = '</th><th>'.join(column_names)
    table_header = '<tr><th>' + table_header + '</th></tr>'

    logging.info('Writing HTML report')

    with open(source, 'w') as html_file:
        html_string = "<html><body>\n"
        html_string += '<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.5/css/bootstrap.min.css">\n'
        html_string += "<h1>File Listing for Custodian ID: " + str(custodian_id) + ", " + custodian_name + "</h1>\n"
        html_string += "<table class='table table-hover table-striped'>\n"
        html_file.write(html_string)
        html_file.write(table_header)

        for entry in cur.fetchall():
            row_data = "</td><td>".join([str(x).encode('utf-8') for x in entry])
            html_string = "\n<tr><td>" + row_data + "</td></tr>"
            html_file.write(html_string)
            html_file.flush()
        html_string = "\n</table>\n</body></html>"
        html_file.write(html_string)
    logging.info('HTML Report completed: ' + source)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(version=str(__version__), description=__description__,
                                     epilog='Developed by ' + __author__ + ' on ' + __date__)
    parser.add_argument('CUSTODIAN', help='Name of custodian collection is of.')
    parser.add_argument('DB_PATH', help='File path and name of database file to create/append.')
    parser.add_argument('--input', help='Base directory to scan.')
    parser.add_argument('--output', help='Output file to write to. use `.csv` extension for CSV and `.html` for HTML')
    parser.add_argument('-l', help='File path and name of log file.')
    args = parser.parse_args()

    if args.input:
        source = ('input', args.input)
    elif args.output:
        source = ('output', args.output)
    else:
        raise argparse.ArgumentError('Please specify input or output')

    if args.l:
        if not os.path.exists(args.l):
            os.makedirs(args.l)  # create log directory path
        log_path = os.path.join(args.l, 'file_lister.log')
    else:
        log_path = 'file_lister.log'
    logging.basicConfig(filename=log_path, level=logging.DEBUG,
                        format='%(asctime)s | %(levelname)s | %(message)s', filemode='a')

    logging.info('Starting File Lister v.' + str(__version__))
    logging.debug('System ' + sys.platform)
    logging.debug('Version ' + sys.version)

    args_dict = {'custodian': args.CUSTODIAN, 'source': source, 'db': args.DB_PATH}
    main(**args_dict)