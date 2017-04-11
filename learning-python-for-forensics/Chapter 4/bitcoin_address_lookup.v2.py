import argparse
import json
import logging
import sys
import os
import urllib2
import unix_converter as unix

__author__ = 'Preston Miller & Chapin Bryce'
__date__ = '20150920'
__version__ = 0.02
__description__ = 'This scripts downloads address transactions using blockchain.info public APIs'


def main(address):
    """
    The main function handles coordinating logic
    :param address: The Bitcoin Address to lookup
    :return: Nothing
    """
    logging.info('Initiated program for {} address'.format(address))
    logging.info('Obtaining JSON structured data from blockchain.info')
    raw_account = getAddress(address)
    account = json.loads(raw_account.read())
    printTransactions(account)


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


def printTransactions(account):
    """
    The print_transaction function is responsible for presenting transaction details to end user.
    :param account: The JSON decoded account and transaction data
    :return: Nothing
    """
    logging.info('Printing account and transaction data to console.')
    printHeader(account)
    print 'Transactions'
    for i, tx in enumerate(account['txs']):
        print 'Transaction #{}'.format(i)
        print 'Transaction Hash:', tx['hash']
        print 'Transaction Date: {}'.format(unix.unixConverter(tx['time']))
        for output in tx['out']:
            inputs = getInputs(tx)
            if len(inputs) > 1:
                print '{} --> {} ({:.8f} BTC)'.format(' & '.join(inputs), output['addr'], output['value'] * 10**-8)
            elif len(inputs) == 1:
                print '{} --> {} ({:.8f} BTC)'.format(''.join(inputs), output['addr'], output['value'] * 10**-8)
            else:
                logging.warn('Detected 0 inputs for transaction {}').format(tx['hash'])
                print 'Detected 0 inputs for transaction.'

        print '{:=^22}\n'.format('')


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
    return inputs

if __name__ == '__main__':
    # Run this code if the script is run from the command line.
    parser = argparse.ArgumentParser(description='BTC Address Lookup', version=str(__version__),
                                     epilog='Developed by ' + __author__ + ' on ' + __date__)

    parser.add_argument('ADDR', help='Bitcoin Address')
    parser.add_argument('-l', help='Specify log directory. Defaults to current working directory.')

    args = parser.parse_args()

    # Set up Log
    if args.l:
        if not os.path.exists(args.l):
            os.makedirs(args.l)
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
    main(args.ADDR)
