import argparse
import json
import urllib2
import unix_converter as unix
import sys

__author__ = 'Preston Miller & Chapin Bryce'
__date__ = '20150920'
__version__ = 0.01
__description__ = 'This scripts downloads address transactions using blockchain.info public APIs'


def main(address):
    """
    The main function handles coordinating logic
    :param address: The Bitcoin Address to lookup
    :return: Nothing
    """
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
    except urllib2.URLError:
        print 'Received URL Error for {}'.format(url)
        sys.exit(1)


def printTransactions(account):
    """
    The print_transaction function is responsible for presenting transaction details to end user.
    :param account: The JSON decoded account and transaction data
    :return:
    """
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
            else:
                print '{} --> {} ({:.8f} BTC)'.format(''.join(inputs), output['addr'], output['value'] * 10**-8)

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

    args = parser.parse_args()

    # Print Script Information
    print '{:=^22}'.format('')
    print '{} {}'.format('Bitcoin Address Lookup, ', __version__)
    print '{:=^22} \n'.format('')

    # Run main program
    main(args.ADDR)
