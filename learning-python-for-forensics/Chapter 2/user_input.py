import sys 


def main():
    """
    The main function uses sys.argv list to print any user supplied input.
    :return: Nothing.
    """
    args = sys.argv
    print 'Script:', args[0]
    args.pop(0)
    for i, argument in enumerate(sys.argv):
        print 'Argument {}: {}'.format(i, argument)
        print 'Type: {}'.format(type(argument))

if __name__ == '__main__':
    main()