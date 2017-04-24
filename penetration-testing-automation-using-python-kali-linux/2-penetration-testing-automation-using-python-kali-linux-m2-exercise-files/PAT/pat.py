#!/usr/bin/python
# This is version 0.3
import webbrowser
import time
import os
import subprocess
import argparse

class Utilities:
	# Common seperator line for the application
	seperator_single_line = '------------------------------------------------------------'
	seperator_double_line = '============================================================'
	
	#Static values
	reports_folder_name = "Reports"
	reconnaissance_category = 'Reconnaissance'
	red_color = '\033[31m'
	blue_color = '\033[34m'
	purple_color = '\033[35m'
	
	def __init__(self):
		self.name = 'static class'

class Core:
	def __init__(self,company_domain_name,utilities):
		self.company_domain_name = company_domain_name
		self.utilities = utilities

	# Description: Save the results to a file
	# Return: (void)
	def _save_results(self,results,folder_name,file_name):
		try:
			# Create a directory for the category e.g reconnaissance or external scanning ...
			if not os.path.isdir(folder_name):
				os.mkdir(folder_name)
				
			# Save the results to a file
			file_name = folder_name + '/'+ file_name
			file_to_save = open(file_name,'w')
			file_to_save.write(results)
			print self.utilities.blue_color + "[+] Report saved to: " + file_name
			print self.utilities.blue_color + self.utilities.seperator_double_line
			file_to_save.close()
		except Exception,e:
			print self.utilities.red_color + '[!] Error: Cannot save the results to a file!'

	# Description: Open and execute Linux Terminal command
	# Return: (string) return the results output after executing the command		
	def _get_terminal_output(self,app_name,cmd):
		output = '[+] Executing ' + str(app_name) + '...\r\n'
		try:
			output += subprocess.check_output(cmd,shell=True,stderr=subprocess.STDOUT)
			output += '\r\n'
		except Exception,e:
			output += str(e)
			print self.utilities.red_color + "[!] Error executing the command: " + cmd
		output +=  self.utilities.seperator_single_line + '\r\n'
		return output
	
	# Description: Iterate each command then open and execute Linux Terminal command
	# Return: (string) return the results output after executing all the commands
	def _execute_commands(self,commands):
		#Execute commands in terminal
		results = ''
		for key,val in commands.items():
			output = self._get_terminal_output(key,val)
			results += output
		return results
	
	# Description: Iterate each website then open the web browser
	# Return: (void) 
	def _open_websites(self,websites):
		# Open websites in browser
		for website in websites:
			try:
				webbrowser.open_new_tab(website)
				# It's better to have a delay of 2 seconds between each new tab execution
				time.sleep(2)
			except Exception,e:
				print self.utilities.red_color + '[!] cannot open the browser for the website: ' + website				
	# Description: Start PenTest
	# Return: (void)	
	def _start(self,commands,websites,folder_name,file_name):
		# If both lists are null then we stop here
		if commands == {} and websites == []:
			print self.utilities.red_color + '[!] No commands available! for: ' + folder_name + '/' + file_name 
			return
		
		# Execute and save terminal commands
		if commands != {}:
			results = self._execute_commands(commands)
			print results
			self._save_results(results,folder_name,file_name)
		
		# Open websites
		if websites != []:
			self._open_websites(websites)
	
	# Description: Create a directory by Client Domain Name
	# Return: (void)			
	def _create_client_domain_folder(self):
		# e.g root_folder_path = 'Report/domainname.com'
		root_folder_path = self.utilities.reports_folder_name + '/' + self.company_domain_name
		if not os.path.isdir(root_folder_path):
			os.mkdir(root_folder_path)
	
	# Description: Get/Load the terminal commands from file if needed
	# Return: (dictionary list) return the list of commands			
	def _get_commands_from_file(self,action_name):
		commands = {}
		# e.g commands_file_path = 'Reconnaissance/dns_commands.txt'
		commands_file_path = self.utilities.reconnaissance_category + '/' + action_name + '_commands.txt'
	
		if os.path.isfile(commands_file_path):
			commands_file = open(commands_file_path,'r')
	
			for command_line in commands_file.readlines():
				try:
					command_line_splitted = command_line.split(':')
					commands[command_line_splitted[0]] = command_line_splitted[1]
				except Exception,e:
						print self.utilities.red_color + '[!] Error: The file' + commands_file_path + ' is corrupted!'			
				
		return commands
	
	# Description: Get/Load the websites from file if needed
	# Return: (array) return the list of websites				
	def _get_websites_from_file(self,action_name):
		websites = []
		# e.g websites_file_path= 'Reconnaissance/dns_websites.txt'
		websites_file_path = self.utilities.reconnaissance_category + '/' + action_name + '_websites.txt'
	
		if os.path.isfile(websites_file_path):
			websites_file = open(websites_file_path,'r')
			for website_line in websites_file.readlines():
				websites.append(website_line.strip('\r').strip('\n'))
				
		return websites
	
	# Description: Start penetration testing			
	def pen_test(self,action_name,category_name):
		# Create the Client Root directory
		self._create_client_domain_folder()
		
		# get commands from file
		commands = self._get_commands_from_file(action_name)
		
		#get websites from file
		websites = self._get_websites_from_file(action_name)
				
		#e.g folder_name = 'Reports/test.com/reconnaissance'
		folder_name = self.utilities.reports_folder_name + '/' + self.company_domain_name + '/' + category_name
		#e.g file_name = 'dns_report.txt'
		file_name = action_name + '_report.txt'

		self._start(commands,websites,folder_name,file_name)

class Main:
	def __init__(self,utilities):
		self.utilities = utilities
	
	# Description: Print a help banner to show how to use the application and exit the application
	# Return: (void)		
	def _usage(self):
		print 'Pentester Automation Tool'
		print self.utilities.seperator_single_line
		print 'Arguments:'
		print '-c\t --company\t Your Client Company Domain Name'
		print 
		print 
		print "Example:"
		print "pat.py --company yourclientdomain.com"
		print
		#exit the application
		exit(0)	
		
	# Description: Print a welcome banner
	# Return: (void)		
	def _print_banner(self,company_domain_name):
		# Print Banner
		print 'Pentesting Client Domain Name: ' + company_domain_name
		print self.utilities.seperator_single_line
		print		
	
	# Description: Process the terminal arguments
	# Return: (void)	
	def _process_arguments(self,args,core):
		if args.dns_test:
			core.pen_test('dns',self.utilities.reconnaissance_category)
	
	# Description: Initialize the terminal arguments
	# Return: (void)	
	def _initialize_arguments(self):
		# Arguments
		parser = argparse.ArgumentParser('Pentester Automation Tool')
		parser.add_argument("-c","--company",type=str,help="Your Client Company Domain Name")
		parser.add_argument("-dns","--dns_test",help="Check/Test the DNS security",action="store_true")
	
		# Parse the arguments
		args= parser.parse_args()
	
		# Do not proceed further if the company domain name is null
		if args.company == None:
			self._usage()		
		
		return args
	
	# Description: Start the application
	# Return: (void)	
	def start(self):
		# Terminal arguments
		args = self._initialize_arguments()
		
		# Initialize the Core class	
		core = Core(args.company,self.utilities)
		
		# Print application banner
		self._print_banner(args.company)
		
		# Process the initilaized arguments
		self._process_arguments(args,core)

if __name__ == '__main__':
	# Initialize the Utilities class
	utilities = Utilities()	
	
	main = Main(utilities)
	main.start()
		



