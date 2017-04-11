import argparse


def main(args):
	"""
	The main function prints the the args input to the console.
	:param args: The parsed arguments namespace created by the argparse module.
	:return: Nothing.
	"""
	print args


if __name__ == '__main__':
	description = 'Argparse: Command-Line Parser Sample' # Description of the Program to display with help
	epilog = 'Built by Preston Miller & Chapin Bryce'  # Displayed after help, usually Authorship and License
	
	# Define initial information for argument parser
	parser = argparse.ArgumentParser(description=description, epilog=epilog)
	
	# Add arguments
	parser.add_argument('timezone', help='timezone to apply') # Required variable (no `-` character)
	parser.add_argument('--source', help='source information', required=True) # Optional argument, forced to be required
	parser.add_argument('-c', '--csv', help='Output to csv') # Optional argument using -c or --csv 
	
	# Using actions
	parser.add_argument('--no-email', help='disable emails', action="store_false") # Assign `False` to value if present.
	parser.add_argument('--send-email', help='enable emails', action="store_true") # Assign `True` to value if present.
	parser.add_argument('--emails', help='email addresses to notify', action="append") # Append values for each call. i.e. --emails a@example.com --emails b@example.com
	parser.add_argument('-v', help='add verbosity', action='count') # Count the number of instances. i.e. -vvv
	
	# Defaults
	parser.add_argument('--length', default=55, type=int)
	parser.add_argument('--name', default='Alfred', type=str)	
	
	# Handling Files
	parser.add_argument('input_file', type=argparse.FileType('r')) # Open specified file for reading
	parser.add_argument('output_file', type=argparse.FileType('w')) # Open specified file for writing
	
	# Choices
	parser.add_argument('--file-type', choices=['E01', 'DD/001', 'Ex01'])  # Allow only specified choices
	
	# Parsing arguments into objects
	arguments = parser.parse_args() 
	main(arguments)
	