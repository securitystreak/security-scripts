# Simple Substitution Cipher Editor, http://inventwithpython.com/hacking (BSD Licensed)

import textwrap, string, pyperclip

myMessage = ''
SYMBOLS = ''


def main(useText=None, useMapping=None):
    print('Simple Substitution Cipher Editor')

    while True:
        # Get the text to start editing:
        if useText == None:
            # start editing a new cipher
            print('Enter the cipher text you want to decrypt (or "quit"):')

            # Handle if the user wants to quit:
            ciphertext = input('> ').upper()
            if ciphertext == 'QUIT':
                return
        else:
            ciphertext = useText

        if useMapping == None:
            mapping = getBlankMapping() # start with a new, blank mapping.
        else:
            mapping = useMapping


        while True:
            # On each iteration of this loop, display the current translation
            # and let the user type in a command to perform.

            # Display the current translation:
            print('\n\n\n')
            printMessage(ciphertext, mapping)
            printMapping(mapping)
            print('COMMANDS: Enter ciphertext letter to substitute, or "quit", "clear",')
            print('"copy message", "copy key", "enter key", or "new":')

            # Get a command from the user and perform it:
            command = input('> ').upper()
            if command == 'QUIT':
                return
            elif command == 'CLEAR':
                # reset the mapping to a new, blank mapping
                mapping = getBlankMapping()
            elif command == 'NEW':
                print('\n' * 25) # print a huge gap
                break # break out of the inner loop
            elif command == 'COPY MESSAGE':
                pyperclip.copy(getTranslation(ciphertext, mapping))
                print('Copied the translated text to the clipboard.')
            elif command == 'COPY KEY':
                key = ''
                for letter in string.ascii_uppercase:
                    key += mapping[letter]
                pyperclip.copy(key)
                print('Copied the key to the clipboard.')
            elif command == 'ENTER KEY':
                pass # TODO
            else:
                # Assume the user is trying to suggest a ciphertext replacement:

                # get the ciphertext letter
                if len(command) != 1 or command not in string.ascii_uppercase:
                    print('Invalid character. Please specify a single letter.')
                    continue

                # get the letter that will replace this ciphertext letter
                print('Enter letter that %s should map to:' % command)
                mapToLetter = input('> ').upper()
                if mapToLetter == '':
                    # entering nothing means the user wants to reset that ciphertext letter
                    mapToLetter = '_'
                if len(mapToLetter) != 1 or mapToLetter not in string.ascii_uppercase + '_':
                    print('Invalid character. Please specify a single letter.')
                    continue

                # add this replacement letter to the current mapping
                mapping[command] = mapToLetter.lower()


def getTranslation(ciphertext, mapping):
    # Returns a string of the translation of ciphertext. Each character
    # in ciphertext is used as a key in mapping, and the returned
    # string uses the character that is the value for that key.
    result = ''
    for letter in ciphertext:
        if letter not in string.ascii_uppercase:
            result += letter
        else:
            result += mapping[letter]
    return result


def getBlankMapping():
    # Returns a dict with keys of the uppercase letters and values of
    # the string '_'.
    mapping = {}
    for letter in string.ascii_uppercase:
        mapping[letter] = '_'
    return mapping


def printMessage(ciphertext, mapping):
    # Print the cipher text, along with the translation according to the
    # current mapping. The text will never go past 80 characters in length
    # per line.

    # Split up the cipher text into lines of at most 80 characters in length,
    # and then put them in a list of these lines.
    wrappedText = textwrap.fill(ciphertext)
    lines = wrappedText.split('\n')

    for line in lines:
        # Print each line of ciphertext, followed by its translation.
        print(line)
        print(getTranslation(line, mapping))
        print()


def printMapping(mapping):
    # Print the mapping in a user-friendly format.
    print('Current Key:')
    print('    ' + ' '.join(list(string.ascii_uppercase)))

    print('    ', end='')
    for letter in string.ascii_uppercase:
        print(mapping[letter] + ' ', end='')
    print()


if __name__ == '__main__':
    main()
