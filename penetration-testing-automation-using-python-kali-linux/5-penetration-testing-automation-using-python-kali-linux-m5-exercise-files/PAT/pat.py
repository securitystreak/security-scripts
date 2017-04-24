#!/usr/bin/python
# Pentester Automation Tool version 0.8
# Author: Gus Khawaja
import webbrowser
import time
import os
import subprocess
import argparse
from netaddr import IPNetwork,IPAddress,IPRange
import re

LIVE_HOSTS = {}
EXPLOITS_COMMANDS={}
BRUTEFORCE_COMMANDS={}

class Utilities:
	# Common seperator line for the application
	seperator_single_line = '------------------------------------------------------------'
	seperator_double_line = '============================================================'
	
	#Static values
	reports_folder_name = "Reports"
	reconnaissance_category = 'Reconnaissance'
	internal_scanning_category = 'InternalScanning'
	attack_category = "Attack"
	red_color = '\033[31m'
	blue_color = '\033[34m'
	purple_color = '\033[35m'
	end_color = '\033[0m'
	
	#Port Numbers
	port_numbers={'13':'Daytime','21':'FTP','22':'SSH','23':'Telnet','25':'SMTP','37':'Time','53':'DNS','67':'DHCP','70':'Gopher','79':'Finger','110':'POP3','NFS':'111',
	              '123':'NTP','137':'NetBios','139':'SMB','143':'IMAP','161':'SNMP','389':'LDAP','445':'SMB','500':'Ike','523':'Db2','524':'Novel Netware','548':'AFP','554':'RTSP',
	              '631':'CUPS','636':'LDAP/S','873':'Rsync','993':'IMAP/S','995':'POP3/S','1050':'COBRA','1080':'SOCKS','1099':'RMI Registry','1344':'ICAP','1352':'Lotus Domino',
	              '1433':'MS-SQL','1434':'MS-SQL/UDP','1521':'Oracle','1604':'Citrix','1723':'PPTP','2202':'ACARS','2302':'Freelancer','2628':'DICT','2947':'GPS','3031':'Apple Remote Event',
	              '3260':'iSCSI','3306':'MySQL','3389':'Remote Desktop','3478':'STUN','3632':'Compiler Deaemon','4369':'Erlang Port Mapper','5019':'Versant','5060':'SIP',
	              '5353':'DNS Service Discovery','5666':'Nagios','5672':'AMQP','5850':'Open Lookup','5900':'VNC','5984':'CouchDb','6000':'X11','6379':'Redis','6481':'Sun Service Tag',
	              '6666':'Voldemort','7210':'MaxDb','7634':'HD Info','8000':'QNX QCONN','8009':'AJP','8081':'McAfee ePO','8091':'CoucheBase Web Administration','8332':'Bitcoin','8333':'Bitcoin',
	              '9100':'Lexmark','9160':'Cassandra','9999':'Java Debug Wire Protocol','10000':'Network Data Management','11211':'Memory Object Caching','1200':'CCCAM','12345':'NetBus',
	              '17185':'VxWorks','19150':'GKRe11M','27017':'MongoDb','31337':'BackOrifice','35871':'Flume','50000':'DRDA','50030':'Hadoop','50060':'Hadoop','50070':'Hadoop',
	              '50075':'Hadoop','50090':'Hadoop','60010':'Apache HBase','60030':'Apache HBase'}
	
	def get_application_service_name(self,port_number):
		if(self.port_numbers.has_key(port_number)):
			return self.port_numbers[port_number]
		
		return 'Port Number ' + port_number
		
	
	def print_color(self,text,color):
		if color == 'red':
			print self.red_color + text + self.end_color
		if color == 'blue':
			print self.blue_color + text + self.end_color
		if color == 'purple':
			print self.purple_color + text + self.end_color
	def extract_company_name(self,company_domain_name):
		return company_domain_name.split('.')[0]		
	
	def __init__(self):
		self.name = 'static class'

class Core:
	ip_address = ''
	current_test = ''
	
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
			
			#if this an ip address then you need to create a subfolder per IP Address
			if self.ip_address != '':
				ip_folder_name = folder_name + '/'+ self.ip_address
	
				if not os.path.isdir(ip_folder_name):
					os.mkdir(ip_folder_name)
				
				folder_name = ip_folder_name
				
			# Save the results to a file
			file_name = folder_name + '/'+ file_name
			file_to_save = open(file_name,'w')
			file_to_save.write(results)
			self.utilities.print_color("[+] Report saved to: " + file_name,'purple')
			self.utilities.print_color(self.utilities.seperator_double_line,'purple')
			file_to_save.close()
		except Exception,e:
			self.utilities.print_color('[!] Error: Cannot save the results to a file!','red')

	# Description: Open and execute Linux Terminal command
	# Return: (string) return the results output after executing the command		
	def _get_terminal_output(self,app_name,cmd):
		banner = '[+] Executing ' + str(app_name) + '...\r\n'
		print banner
		output = ''
	
		try:
			cmd = cmd.rstrip()
			output += subprocess.check_output(cmd,shell=True,stderr=subprocess.STDOUT)
			output += '\r\n'
		except Exception,e:
			exception_message = str(e)
			output += exception_message
			# [Exit Status 1] message means that application exited with status 1, we don't need to raise it as a red flag
			if 'exit status 1' not in exception_message:
				self.utilities.print_color("[!] Error executing the command: " + cmd,'red')
			output += '\r\n'
		output +=  self.utilities.seperator_single_line + '\r\n'
	
		print output
		return banner + output
	
	# Description: Iterate each command then open and execute Linux Terminal command
	# Return: (string) return the results output after executing all the commands
	def _execute_commands(self,commands):
		#Execute commands in terminal
		results = ''
		for key,val in commands.items():
			output = self._get_terminal_output(val[0],val[1])
			
			if(self.current_test== 'livehosts'):
				if '1 host up' in output:
					LIVE_HOSTS[self.ip_address]=[self.ip_address]
			if(self.current_test == 'portscan'):
				ports = set(re.findall('\d*/tcp', output))
				LIVE_HOSTS[self.ip_address] = ports
				
			results += output
		return results
	
	# Description: Iterate each website then open the web browser
	# Return: (void) 
	def _open_websites(self,websites):
		# Open websites in browser
		for website in websites:
			try:
				webbrowser.open_new_tab(website)
				# It's better to have a delay of 3 seconds between each new tab execution
				time.sleep(3)
			except Exception,e:
				self.utilities.print_color('[!] cannot open the browser for the website: ' + website,'red')
				
	# Description: Attack and exploit the machine hosts by executing the appropriate commands
	# Return: The terminal output results
	def _attack_machines(self,commands):
		ports_array = LIVE_HOSTS[self.ip_address]
		output = ''
		
		for port_number_item in ports_array:
			port_number_split = port_number_item.split('/')
			port_number = port_number_split[0]
			if(commands.has_key(port_number)):
				cmd = commands[port_number]
				app_name = self.utilities.get_application_service_name(port_number)
				output += self._get_terminal_output(app_name, cmd)
			
		return output
			
	# Description: Start PenTest
	# Return: (void)	
	def _start(self,commands,websites,report_folder_name,report_file_name):
		if commands == {} and websites == []:
			self.utilities.print_color('[!] No commands available!','red')
			return
		
		# if this is an exploit test then make an exception and call the exploitation logic
		if(self.current_test == 'exploit' or self.current_test == 'bruteforce'):
			results = self._attack_machines(commands)
			self._save_results(results,report_folder_name,report_file_name)
			
		else:
			# Execute and save terminal commands
			if commands != {}:
				results = self._execute_commands(commands)
				self._save_results(results,report_folder_name,report_file_name)
			
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
	
	# Description: Insert/Fill a parameter value in the file line
	# Return: (string) the new value with the parameter inserted	
	def _inject_parameter_in_file(self,line):
		line = line.replace('[domain]',self.company_domain_name)
		line = line.replace('[name]',self.utilities.extract_company_name(self.company_domain_name))
		line = line.replace('[ipAddress]',self.ip_address)
		line = line.replace('[users]',self.utilities.attack_category + "/users.txt")
		line = line.replace('[passwords]',self.utilities.attack_category + "/passwords.txt")
		return line
		
	# Description: Get/Load the terminal commands from file if needed
	# Return: (dictionary list) return the list of commands			
	def _get_commands_from_file(self,commands_file_path):
		commands = {}
		
		if os.path.isfile(commands_file_path):
			commands_file = open(commands_file_path,'r')
			
			counter = 0
			for command_line in commands_file.readlines():
				try:
					command_line_splitted = command_line.split(':')
					if(self.current_test == 'exploit' or self.current_test == 'bruteforce'):
						if(self.current_test == 'bruteforce'):
							commands[command_line_splitted[0]] = self._inject_parameter_in_file(command_line_splitted[1] + ":" + command_line_splitted[2])
						else:
							commands[command_line_splitted[0]] = self._inject_parameter_in_file(command_line_splitted[1])
					else:
						commands[counter] = [command_line_splitted[0],self._inject_parameter_in_file(command_line_splitted[1])]
						counter += 1
				except Exception,e:
						self.utilities.print_color('[!] Error: The file ' + commands_file_path + ' is corrupted!','red')
						self.utilities.print_color(str(e),'red')
				
		return commands
	
	# Description: Get/Load the websites from file if needed
	# Return: (array) return the list of websites				
	def _get_websites_from_file(self,websites_file_path):
		websites = []
	
		if os.path.isfile(websites_file_path):
			websites_file = open(websites_file_path,'r')
			for website_line in websites_file.readlines():
				websites.append(self._inject_parameter_in_file(website_line.strip('\r').strip('\n')))
				
		return websites
	
	
	# Description: Start penetration testing			
	def pen_test(self,action_name,category_name,ip_address=''):
		# Set the IP Address
		self.ip_address = str(ip_address)
		
		#Set the current test name
		self.current_test = action_name
		
		# Create the Client Root directory
		self._create_client_domain_folder()
		
		# get commands from file
		# e.g commands_file_path = 'Reconnaissance/dns_commands.txt'
		commands_file_path = category_name + '/' + action_name + '_commands.txt'		
		commands = self._get_commands_from_file(commands_file_path)
		
		#get websites from file
		# e.g websites_file_path= 'Reconnaissance/dns_websites.txt'
		websites_file_path = category_name + '/' + action_name + '_websites.txt'		
		websites = self._get_websites_from_file(websites_file_path)
				
		#e.g report_folder_name = 'Reports/test.com/reconnaissance'
		report_folder_name = self.utilities.reports_folder_name + '/' + self.company_domain_name + '/' + category_name
		
		#e.g report_file_name = 'dns_report.txt'
		report_file_name = action_name + '_report.txt'
		
		print 'Pentesting the ' + category_name + '/' + action_name
		print ''

		self._start(commands,websites,report_folder_name,report_file_name)

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
		print "-dns\t --dns_test\t Check/Test the DNS security"
		print 
		print "-emails\t --emails_test\t Look for email addresses"
		print 
		print "-whois\t --whois_test\t Check/Test the WHOIS data"
		print
		print "-files\t --files_test\t Look for files"
		print
		print "-socialmedia\t --socialmedia_test\t Search in the social media"
		print
		print "-websearch\t --websearch_test\t Web browser search"
		print
		print "-ip\t --ip_address\t pecify the IP address / Range"
		print
		print "-livehosts\t --livehosts_test\t Scan for live hosts"
		print
		print "-portscan\t --portscan_test\t Port Scanning"
		print
		print "-exploit\t --exploit_test\t Exploitation"
		print
		print "-bruteforce\t --bruteforce_test\t Brute-Forcing Application ports"
		print		
		print "Example: DNS and files"
		print "pat.py --company yourclientdomain.com -dns -files"
		print
		print "Example: Live Hosts Scanning"
		print "pat.py -c yourclientdomain.com -ip 10.0.0.1/24 -livehosts"
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
	
	
	# Description: Gets a list of IP addresses that comes from the input terminal
	# Return: a List of IP addresses
	def _get_ip_addresses(self,input_data):
		ip_addresses = []
	
		if "-" in input_data:
			input_data_splitted = input_data.split('-')
			first_ip_address = input_data_splitted[0]
			first_ip_address_splitted = first_ip_address.split('.')
			second_ip_address = '%s.%s.%s.%s'%(first_ip_address_splitted[0],first_ip_address_splitted[1],first_ip_address_splitted[2],input_data_splitted[1])
			ip_addresses = IPRange(first_ip_address,second_ip_address)
	
		elif "," in input_data:
			ip_addresses = input_data.split(',')
	
		else:
			ip_addresses = IPNetwork(input_data)
	
		return ip_addresses
	
	# Description: Process the terminal arguments
	# Return: (void)	
	def _process_arguments(self,args):
		# Initialize the Core class	
		core = Core(args.company,self.utilities)		

		if args.dns_test:
			core.pen_test('dns',self.utilities.reconnaissance_category)
		if args.whois_test:
			core.pen_test('whois',self.utilities.reconnaissance_category)
		if args.emails_test:
			core.pen_test('emails',self.utilities.reconnaissance_category)	
		if args.socialmedia_test:
			core.pen_test('socialmedia',self.utilities.reconnaissance_category)
		if args.files_test:
			core.pen_test('files',self.utilities.reconnaissance_category)
		if args.websearch_test:
			core.pen_test('websearch',self.utilities.reconnaissance_category)
		if args.livehosts_test:
			if args.ip_address == None:
				self._usage()
			#do not execute live hosts if the exploit test is specified
			#because the exploit test will execute it anyway
			if args.exploit_test or args.bruteforce_test:
				return
			
			for ip_item in self._get_ip_addresses(args.ip_address):
				core.pen_test('livehosts',self.utilities.internal_scanning_category,ip_item)
		if args.portscan_test:
			if args.ip_address == None:
				self._usage()
			#do not execute port scan if the exploit test is specified
			#because the exploit test will execute it anyway			
			if args.exploit_test or args.bruteforce_test:
				return
			
			# Did the live hosts test run before?
			if args.livehosts_test:
				self._port_scan_live_hosts(core)
			else:
				#if the live hosts didn't run before then run it and then scan
				for ip_item in self._get_ip_addresses(args.ip_address):
					core.pen_test('livehosts',self.utilities.internal_scanning_category,ip_item)
				#after finishing the live hosts scan, then start the port scan
				self._port_scan_live_hosts(core)
		if args.exploit_test:
			if args.ip_address == None:
				self._usage()			
			# Run Live Hosts / port scan first
			for ip_item in self._get_ip_addresses(args.ip_address):
				core.pen_test('livehosts',self.utilities.internal_scanning_category,ip_item)
			#after finishing the live hosts scan, then start the port scan
			self._port_scan_live_hosts(core)
			# let's start the exploitation
			self._attack_live_hosts(core, 'exploit')
		if args.bruteforce_test:
			if args.ip_address == None:
				self._usage()
			# No need to scan for live hosts and scan the ports if the exploit test has run previously
			if(args.exploit_test):
				self._attack_live_hosts(core, 'bruteforce')
			else:
				# Run Live Hosts / port scan first
				for ip_item in self._get_ip_addresses(args.ip_address):
					core.pen_test('livehosts',self.utilities.internal_scanning_category,ip_item)
				#after finishing the live hosts scan, then start the port scan
				self._port_scan_live_hosts(core)
				# let's start the exploitation
				self._attack_live_hosts(core, 'bruteforce')		
			
			
	#Description: Exploit Live Hosts
	#Return: (void)
	def _attack_live_hosts(self,core,attack_type):
		#if you found live hosts
		if LIVE_HOSTS != {}:
			for ip_item in LIVE_HOSTS:
				core.pen_test(attack_type,self.utilities.attack_category,ip_item)
		else:
			print '[!] Nothing to attack'			
	
	#Description: Port Scan Live Hosts
	#Return: (void)
	def _port_scan_live_hosts(self,core):
		#if you found live hosts
		if LIVE_HOSTS != {}:
			for ip_item in LIVE_HOSTS:
				core.pen_test('portscan',self.utilities.internal_scanning_category,ip_item)
		else:
			print '[!] No hosts found to scan'		
	
	# Description: Initialize the terminal arguments
	# Return: (void)	
	def _initialize_arguments(self):
		# Arguments
		parser = argparse.ArgumentParser('Pentester Automation Tool')
		parser.add_argument("-c","--company",type=str,help="Your Client Company Domain Name")
		parser.add_argument("-dns","--dns_test",help="Check/Test the DNS security",action="store_true")
		parser.add_argument("-whois","--whois_test",help="Check/Test the WHOIS data",action="store_true")
		parser.add_argument("-emails","--emails_test",help="Look for email addresses",action="store_true")
		parser.add_argument("-socialmedia","--socialmedia_test",help="Social Media search",action="store_true")
		parser.add_argument("-files","--files_test",help="Look for juicy files",action="store_true")
		parser.add_argument("-websearch","--websearch_test",help="Search engine search",action="store_true")
		parser.add_argument("-ip","--ip_address",type=str,help="Specify the IP address / Range")
		parser.add_argument("-livehosts","--livehosts_test",help="Scan for live hosts",action="store_true")
		parser.add_argument("-portscan","--portscan_test",help="Port Scanning",action="store_true")
		parser.add_argument("-exploit","--exploit_test",help="Attack/exploit the host machine",action="store_true")
		parser.add_argument("-bruteforce","--bruteforce_test",help="Port Scanning",action="store_true")
		
		# Parse the arguments
		args= parser.parse_args()
	
		# Do not proceed further if the company domain name is null
		if args.company == None:
			self._usage()		
		
		return args
	
	# Description: Start the application
	# Return: (void)	
	def start(self):
		try:
			# Terminal arguments
			args = self._initialize_arguments()
			
			# Print application banner
			self._print_banner(args.company)
			
			# Process the initilaized arguments
			self._process_arguments(args)
			
		except KeyboardInterrupt:
			print "Exiting Application ..."
			exit(0)
		except Exception,e:
			print str(e)
			exit(0)

if __name__ == '__main__':
	# Initialize the Utilities class
	utilities = Utilities()	
	
	main = Main(utilities)
	main.start()
		



