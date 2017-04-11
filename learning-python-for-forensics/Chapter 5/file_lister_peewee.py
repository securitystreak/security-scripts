import os
import sys
import logging
import unicodecsv as csv
import argparse
import datetime

try:
    import peewee
except ImportError, e:
    raise ImportError(e)

try:
    import jinja2
except ImportError, e:
    raise ImportError(e)

__author__ = 'Preston Miller & Chapin Bryce'
__date__ = '20160401'
__version__ = 0.02
__description__ = 'This script uses a database to ingest and report meta data information about active entries in directories'

database_proxy = peewee.Proxy()


class BaseModel(peewee.Model):
    class Meta:
        database = database_proxy


class Custodians(BaseModel):
    name = peewee.TextField(unique=True)


class Files(BaseModel):
    id = peewee.PrimaryKeyField(unique=True, primary_key=True)
    custodian = peewee.ForeignKeyField(Custodians)
    file_name = peewee.TextField()
    file_path = peewee.TextField()
    extension = peewee.TextField()
    file_size = peewee.IntegerField()
    atime = peewee.DateTimeField()
    mtime = peewee.DateTimeField()
    ctime = peewee.DateTimeField()
    mode = peewee.IntegerField()
    inode = peewee.IntegerField()


def getTemplate():
    """
    The getTemplate function returns a basic template for our HTML report
    :return: Jinja2 Template
    """
    html_string = """<html>\n<head>\n
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.5/css/bootstrap.min.css"></head>\n
    <body>\n<h1>File Listing for Custodian {{ custodian.id }}, {{ custodian.name }}</h1>\n

    <table class="table table-hover table-striped">\n

    <tr>\n
    {% for header in table_headers %}
        <th>{{ header }}</th>
    {% endfor %}
    </tr>\n

    {% for entry in file_listing %}
        <tr>
            <td>{{ entry.id }}</td>
            <td>{{ entry.custodian.name }}</td>
            <td>{{ entry.file_name }}</td></td>
            <td>{{ entry.file_path }}</td>
            <td>{{ entry.extension }}</td>
            <td>{{ entry.file_size }}</td>
            <td>{{ entry.atime }}</td>
            <td>{{ entry.mtime }}</td>
            <td>{{ entry.ctime }}</td>
            <td>{{ entry.mode }}</td>
            <td>{{ entry.inode }}</td>
        </tr>\n
    {% endfor %}

    </table>\n
    </body>\n
    </html\n\n
     """
    return jinja2.Template(html_string)


def main(custodian, source, db):
    """
    The main function creates the database or table, logs execution status, and handles errors
    :param custodian: The name of the custodian
    :param source: tuple containing the mode 'input' or 'output' as the first elemnet and its arguments as the second
    :param db: The filepath for the database
    :return: None
    """
    logging.info('Initializing Database')
    initDB(db)
    logging.info('Initialization Successful')
    logging.info('Retrieving or adding custodian: ' + custodian)
    custodian_model = getOrAddCustodian(custodian)
    logging.info('Custodian Retrieved')
    if source[0] == 'input':
        logging.info('Ingesting base input directory: ' + source[1])
        ingestDirectory(source[1], custodian_model)
        logging.info('Ingesting Complete')
    elif source[0] == 'output':
        logging.info('Preparing to write output for custodian: ' + source[1])
        writeOutput(source[1], custodian_model)
        logging.info('Output Complete')
    else:
        logging.error('Could not interpret run time arguments')

    logging.info('Script Complete')


def initDB(db):
    """
    The initDB function opens or creates the database
    :param db_path: The filepath for the database
    :return: conn, the sqlite3 database connection
    """
    database = peewee.SqliteDatabase(db)
    database_proxy.initialize(database)
    database.create_tables([Custodians, Files], True)  # Need to update with any new tables


def getOrAddCustodian(custodian):
    """
    The getOrAddCustodian function gets the custodian or adds it to the table
    :param custodian: The name of the custodian
    :return: custodian_model, custodian peewee model instance
    """
    custodian_model, created = Custodians.get_or_create(name=custodian)
    return custodian_model


def ingestDirectory(source, custodian_model):
    """
    The ingestDirectory function reads file metadata and stores it in the database
    :param source: The path for the root directory to recursively walk
    :param custodian_model: Peewee model instance for the custodian
    :return: None
    """
    file_data = []
    for root, folders, files in os.walk(source):
        for file_name in files:
            meta_data = dict()
            try:
                meta_data['file_name'] = os.path.join(file_name)
                meta_data['file_path'] = os.path.join(root, file_name)
                meta_data['extension'] = os.path.splitext(file_name)[-1]

                file_stats = os.stat(meta_data['file_path'])
                meta_data['mode'] = str(oct(file_stats.st_mode))
                meta_data['inode'] = str(file_stats.st_ino)
                meta_data['file_size'] = str(file_stats.st_size)
                meta_data['atime'] = formatTimestamp(file_stats.st_atime)
                meta_data['mtime'] = formatTimestamp(file_stats.st_mtime)
                meta_data['ctime'] = formatTimestamp(file_stats.st_ctime)
                meta_data['custodian'] = custodian_model
            except Exception:
                logging.error('Could not gather data for file: ' + meta_data['file_path'])
            file_data.append(meta_data)
    
    for x in xrange(0, len(file_data), 50):
        task = Files.insert_many(file_data[x:x+50])
        task.execute()
    logging.info('Stored meta data for ' + str(len(file_data)) + ' files.')


def formatTimestamp(ts):
    """
    The formatTimestamp function converts an integer into a datetime object
    :param ts: An integer timestamp
    :return: A datetime object
    """
    return datetime.datetime.fromtimestamp(ts)


def writeOutput(source, custodian_model):
    """
    The writeOutput function handles writing either the CSV or HTML reports
    :param source: The output filepath
    :param custodian_model: Peewee model instance for the custodian
    :return: None
    """
    count = Files.select().where(Files.custodian == custodian_model.id).count()

    if not count:
        logging.error('Files not found for custodian')
    elif source.endswith('.csv'):
        writeCSV(source, custodian_model)
    elif source.endswith('.html'):
        writeHTML(source, custodian_model)
    elif not (source.endswith('.html') or source.endswith('.csv')):
        logging.error('Could not determine file type')
    else:
        logging.error('Unknown Error Occurred')


def writeCSV(source, custodian_model):
    """
    The writeCSV function generates a CSV report from the Files table
    :param source: The output filepath
    :param custodian_model: Peewee model instance for the custodian
    :return: None
    """
    file_data = [entry for entry in Files.select().where(Files.custodian == custodian_model.id).dicts()]
    logging.info('Writing CSV report')

    with open(source, 'w') as csv_file:
        csv_writer = csv.DictWriter(csv_file, ['id', 'custodian', 'file_name', 'file_path', 'extension',
                                               'file_size', 'ctime', 'mtime', 'atime',
                                               'mode', 'inode'])
        csv_writer.writeheader()
        csv_writer.writerows(file_data)

    logging.info('CSV Report completed: ' + source)


def writeHTML(source, custodian_model):
    """
    The writeHTML function generates an HTML report from the Files table
    :param source: The output filepath
    :param custodian_model: Peewee model instance for the custodian
    :return: None
    """
    template = getTemplate()
    table_headers = ['Id', 'Custodian', 'File Name', 'File Path', 'File Extension', 'File Size', 'Created Time',
                     'Modified Time', 'Accessed Time', 'Mode', 'Inode']
    file_data = [entry for entry in Files.select().where(Files.custodian == custodian_model.id)]

    template_dict = {'custodian': custodian_model, 'table_headers': table_headers, 'file_listing': file_data}

    logging.info('Writing HTML report')

    with open(source, 'w') as html_file:
        html_file.write(template.render(**template_dict))

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