import argparse
import csv
import json
import logging
import sys
import os
import urllib2
import unix_converter as unix

__author__ = 'Preston Miller & Chapin Bryce'
__date__ = '20150920'
__version__ = 0.03
__description__ = 'This scripts downloads address transactions using blockchain.info public APIs'


def main(address, output_dir):
    """
    The main function handles coordinating logic
    :param address: The Bitcoin Address to lookup
    :param output_dir: The output directory to write the CSV results
    :return: Nothing
    """
    logging.info('Initiated program for {} address'.format(address))
    logging.info('Obtaining JSON structured data from blockchain.info')
    raw_account = getAddress(address)
    account = json.loads(raw_account.read())
    printHeader(account)
    parseTransactions(account, output_dir)


def getAddress(address):
    """
    The getAddress function uses the blockchain.info Data API to pull
    pull down account information and transactions for address of interest
    :param address: The Bitcoin Address to lookup
    :return: The response of the url request
    """
    url = 'https://blockchain.info/address/{}?format=json'.format(address)
    try:
        return urllib2.urlopen(url)
    except urllib2.URLError, e:
        logging.error('URL Error for {}'.format(url))
        if hasattr(e, 'code') and hasattr(e, 'headers'):
            logging.debug('{}: {}'.format(e.code, e.reason))
            logging.debug('{}'.format(e.headers))
        print 'Received URL Error for {}'.format(url)
        logging.info('Program exiting...')
        sys.exit(1)


def parseTransactions(account, output_dir):
    """
    The parseTransactions function appends transaction data into a
    nested list structure so it can be successfully used by the csvWriter function.
    :param account: The JSON decoded account and transaction data
    :param output_dir: The output directory to write the CSV results
    :return: Nothing
    """
    msg = 'Parsing transactions...'
    logging.info(msg)
    print msg
    transactions = []
    for i, tx in enumerate(account['txs']):
        transaction = []
        outputs = {}
        inputs = getInputs(tx)
        transaction.append(i)
        transaction.append(unix.unixConverter(tx['time']))
        transaction.append(tx['hash'])
        transaction.append(inputs)
        for output in tx['out']:
            outputs[output['addr']] = output['value'] * 10**-8
        transaction.append('\n'.join(outputs.keys()))
        transaction.append('\n'.join(str(v) for v in outputs.values()))
        transaction.append('{:.8f}'.format(sum(outputs.values())))
        transactions.append(transaction)
    csvWriter(transactions, output_dir)


def printHeader(account):
    """
    The printHeader function prints overall header information
    containing basic address information.
    :param account: The JSON decoded account and transaction data
    :return: Nothing
    """
    print 'Address:', account['address']
    print 'Current Balance: {:.8f} BTC'.format(account['final_balance'] * 10**-8)
    print 'Total Sent: {:.8f} BTC'.format(account['total_sent'] * 10**-8)
    print 'Total Received: {:.8f} BTC'.format(account['total_received'] * 10**-8)
    print 'Number of Transactions:', account['n_tx']
    print '{:=^22}\n'.format('')


def getInputs(tx):
    """
    The getInputs function is a small helper function that returns
    input addresses for a given transaction
    :param tx: A single instance of a Bitcoin transaction
    :return: inputs, a list of inputs
    """
    inputs = []
    for input_addr in tx['inputs']:
            inputs.append(input_addr['prev_out']['addr'])
    if len(inputs) > 1:
        input_string = '\n'.join(inputs)
    else:
        input_string = ''.join(inputs)
    return input_string


def csvWriter(data, output_dir):
    """
    The csvWriter function writes transaction data into a CSV file
    :param data: The parsed transaction data in nested list
    :param output_dir: The output directory to write the CSV results
    :return: Nothing
    """
    logging.info('Writing output to {}'.format(output_dir))
    print 'Writing output.'
    headers = ['Index', 'Date', 'Transaction Hash', 'Inputs', 'Outputs', 'Values', 'Total']
    try:
        with open(output_dir, 'wb') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(headers)
            for transaction in data:
                writer.writerow(transaction)
            csvfile.flush()
            csvfile.close()
    except IOError, e:
        logging.error('Error writing output to {}.\nGenerated message: {}.'.format(e.filename, e.strerror))
        print 'Error writing to CSV file. Please check output argument {}'.format(e.filename)
        logging.info('Program exiting.')
        sys.exit(1)
    logging.info('Program exiting.')
    print 'Program exiting.'
    sys.exit(0)

if __name__ == '__main__':
    # Run this code if the script is run from the command line.
    parser = argparse.ArgumentParser(description='BTC Address Lookup', version=str(__version__),
                                     epilog='Developed by ' + __author__ + ' on ' + __date__)

    parser.add_argument('ADDR', help='Bitcoin Address')
    parser.add_argument('OUTPUT', help='Output CSV file')
    parser.add_argument('-l', help='Specify log directory. Defaults to current working directory.')

    args = parser.parse_args()

    # Set up Log
    if args.l:
        if not os.path.exists(args.l):
            os.makedirs(args.l)  # create log directory path
        log_path = os.path.join(args.l, 'btc_addr_lookup.log')
    else:
        log_path = 'btc_addr_lookup.log'
    logging.basicConfig(filename=log_path, level=logging.DEBUG,
                        format='%(asctime)s | %(levelname)s | %(message)s', filemode='w')

    logging.info('Starting Bitcoin Address Lookup v.' + str(__version__))
    logging.debug('System ' + sys.platform)
    logging.debug('Version ' + sys.version)

    # Print Script Information
    print '{:=^22}'.format('')
    print '{} {}'.format('Bitcoin Address Lookup, ', __version__)
    print '{:=^22} \n'.format('')

    # Run main program
    main(args.ADDR, args.OUTPUT)
