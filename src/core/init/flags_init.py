#!/usr/bin/python2.7	
# encoding: UTF-8

"""
This file is part of NodeXP, a detection & exploitation tool for 
node.js services (https://github.com/esmog/nodexp) created by 
Antonaropoulos Dimitrios (@esmog).
For more info about NodeXP see the 'README.md' file.
"""

import argparse
import settings
import src.interfaces.options.prompt as prompt
import src.interfaces.options.verbosity as verbosity
import src.core.exploitation.exploitation as exploitation
from colorama import init, Fore, Back, Style
init(autoreset=True)

def parse_input():
	try:	
		parse = argparse.ArgumentParser(add_help=False,description="Arguments Help Manual For NodeXP - Server Side Javascript Injection Tool")
		
		# Initial detection arguments
		initial = parse.add_argument_group('Initial arguments')
		initial.add_argument('--url', '-u', dest='url', action='store', required=True, help='Enter the desirable URL. If it has GET parameters enter "[INJECT_HERE]" on the parameter you want to inject on the --url. If it uses POST data then you have to use --pdata flag. \n -u="http://test.com/?parameter=[INJECT_HERE]"')
		initial.add_argument('--pdata', '-p', dest='post_data', action='store', help='Enter the POST data and place "[INJECT_HERE]" on the parameter you want to inject on. \n-p="parameter=[INJECT_HERE]"')	
		initial.add_argument('--cookies', '-c', dest='cookies', action='store', help='Enter cookies on your request headers.')
		initial.add_argument('--tech', '-t', dest='technique', action='store', choices=['blind', 'result'], default='result', help='Select an injection technique between blind injection and results based injection. Keys: blind, result. Default value = result')

		# Results based injection arguments
		results = parse.add_argument_group('Results based injection arguments')
		results.add_argument('--rand', '-r', dest='rand', action='store', choices=['char', 'num', 'all'], default='char', help='Select the type of random generated string between characters only, numbers only or both. Keys: char, num, all. Default value = char')
		results.add_argument('--digits', '-d', dest='dig', action='store', type=int, choices=range(16, 48), metavar="[16-48]", default=16, help='Enter the number of digits or chars of the random generated string, between 16 to 48. Default value = 16')

		# Blind based injection arguments
		blind = parse.add_argument_group('Blind injection arguments')
		blind.add_argument('--time', '-time', dest='time_threshold', action='store', type=int, choices=range(100, 20000), metavar="[100-20000]", default=250, help="Time threshold on blind injection in millieseconds. Default value = 250")
		blind.add_argument('--loop', '-l', dest='loop', action='store', type=int, choices=range(1, 1000), metavar="[1-1000]", default=10, help="Number of requests done to specify the average response time. Be careful, big values may be considered as brute force or dos attacks by website. Default value = 10")
		blind.add_argument('--email_length', '-elen', dest='elen', action='store', type=int, choices=range(1, 24), metavar="[1-24]", default=9, help="Length of the characters given as input to the vulnerable parameter, ex. email='testing@gmail.com'. Default value = 9")
		blind.add_argument('--num_length', '-nlen', dest='nlen', action='store', type=int, choices=range(1, 10), metavar="[1-10]", default=2, help="Length of the characters given as input to the vulnerable parameter. ex. tel=2102589834. Default value = 2")
		blind.add_argument('--char_length', '-clen', dest='clen', action='store', type=int, choices=range(1, 40), metavar="[1-40]", default=10, help="Length of the characters given as input to the vulnerable parameter. ex. input='My Surname'. Default value = 10")
		blind.add_argument('--time_factor', '-time_factor', dest='time_factor', action='store', type=restricted_float, default=2,  metavar="[1.0-4.0]", help="Time factor for minimum time threshold. Default value = 2")
		blind.add_argument('--valid_loop', '-valid_loop', dest='validation_loop', action='store', type=int, choices=range(5, 100), default=10,  metavar="[2-100]", help="Number of requests done to specify the validity of the blind injection results. Be careful, big values may be considered as brute force or dos attacks by webservers. Default value = 10")

		# Exploitation arguments
		exploit = parse.add_argument_group('Exploitation arguments')	
		exploit.add_argument('--payload_path', '-pp', dest='payload_path', action='store', type=int, choices=[0, 1], default=1, help='Set payload path to default or type new payload path later. The payload name will be \'nodejs_payload.js\'. Default value = 1 (cwd/scripts/)\nex. -pp=1')	
		exploit.add_argument('--rc_path', '-rp', dest='rc_path', action='store', type=int, choices=[0, 1], default=1,  help='Set .rc script path to default or type new .rc script path later. The .rc script name will be \'nodejs_shell.rc\' Default value = 1 (cwd/scripts/)\nex. -rp=1"')
		#exploit.add_argument('--rhost', '-rh', dest='rhost', action='store', help='Remote host ip address (bind shell case).\nex. -rh="192.168.1.1"')
		exploit.add_argument('--lhost', '-lh', dest='lhost', action='store', help='Local host ip address (bind shell case).\nex. -lh="192.168.1.1"')
		exploit.add_argument('--lport', '-lp', dest='lport', action='store', help='Ip address port number.\nex. -lp="6666"')
		exploit.add_argument('--encode', '-enc', dest='encode', action='store', type=int, choices=[0, 1], default=1, help='Encoding on your payload. Default value = 0\nex. -enc=1')
		exploit.add_argument('--shell', '-sh', dest='shell', action='store', choices=['reverse', 'bind', 'ssl'], default='reverse', help='Select an option between reverse, bind and ssl shell. Keys: reverse, bind, ssl. Default value = reverse\nex. -sh=bind')

		# Printing arguments
		printing = parse.add_argument_group('Printing arguments')
		printing.add_argument('--diff', '-diff', dest='diff', action='store', type=int, choices=[0, 1], default=1, help="Print the HTML differences of the responses between valid and malicious requests. Default value = 1") 

		printing.add_argument('--info', '-info', dest='print_info', action='store', type=int, choices=[0, 1], default=1, help="Print additional info. Default value = 1")	

		# Other arguments
		other = parse.add_argument_group('Other arguments')
		other.add_argument('-h', '--help', action='help', default=argparse.SUPPRESS, help='Show this help message and exit.')
		#other.add_argument('-f', '-superfast', dest='superfast', action='store', type=int, choices=[0, 1], default=0, help="Execute detection and exploitation functions and try for meterpreter shell with minimum feedback to the user.")
		
		#[future work] Additional attacks..
		# Remove this parameter	
		#parse.add_argument('--inc', '-i', dest='include', action='store', choices=['SSJI','XSS','REGEXDOS','COMMAND_INJECTION','HPP','DOS','BRUTE_FORCE','all'], default='SSJI', help='Enter the desirable Attack that you want to include. If you want to include all the attacks then enter --inc=all . \nAvailable attacks: Server Side Javascript Injection, Cross Site Scripting, Regural Expresion DOS, Command Injection-OS Injection, HTTP Pollution, DOS, Brute force. \nKeys: SSJI,XSS,REGEXDOS,COMMAND_INJECTION,HPP,DOS,BRUTE_FORCE. \nDefault Attack: SSJI.')
		# Remove this parameter
		#parse.add_argument('--exc', '-x', dest='exclude', action='store', choices=['SSJI','XSS','REGEXDOS','COMMAND_INJECTION','HPP','DOS','BRUTE_FORCE','all'], help='Enter the desirable Attack that you want to exclude. If you want to exclude all the attacks then enter --exc=all . \nAvailable attacks: Server Side Javascript Injection, Cross Site Scripting, Regural Expresion DOS, Command Injection-OS Injection, HTTP Pollution, DOS, Brute force. \nKeys: SSJI,XSS,REGEXDOS,COMMAND_INJECTION,HPP,DOS,BRUTE_FORCE. \nDefault Attack: SSJI.')
		#printing.add_argument('--debug', '-debug', dest='debug_msgs', action='store', type=int, choices=[0, 1], default=0, help="Print debug info. Default value = 0")
		#printing.add_argument('--progress', '-prog', dest='prog_msgs', action='store', type=int, choices=[0, 1], default=1, help="Print tools progress info. Default value = 1")
		
		args = parse.parse_args()

		return args

	except Exception as e:
		print(Fore.RED + "[!] ERROR: %s" %e)
		verbosity.error_info(e)	

def restricted_float(x):
    x = float(x)
    if x < 1.0 or x > 2.5:
        raise argparse.ArgumentTypeError("-Input %r not in range [1.0, 2.5]"%(x,))
    return x

def initialize_input(args):
	try:
		# Printing arguments
		settings.print_info = args.print_info
	 	settings.print_diff = args.diff

		# Initial detection arguments	
		settings.url = format(args.url)
		if args.post_data != None:
			settings.pdata = format(args.post_data)
		if args.cookies != 'None':
			settings.cookie = format(args.cookies)
		if args.technique != 'None':
			settings.technique = format(args.technique)
			verbosity.print_message(Fore.GREEN + Style.BRIGHT + '[i] Injection technique set to "%s based"' %(settings.technique), settings.print_info)
			
		# Results based injection arguments
		settings.rand = format(args.rand)
		settings.dig = format(args.dig)
		settings.initialize_rands()

		# Blind injection arguments
		settings.time_threshold = args.time_threshold # --> #time# in dictionary
		settings.loop = args.loop
		settings.elen = args.elen
		settings.nlen = args.nlen
		settings.clen = args.clen
		settings.initialize_blind_rands()
		settings.margin_factor = args.time_factor
		settings.validation_loop = args.validation_loop
		
		# Exploitation arguments
		settings.payload_path = args.payload_path
		settings.rc_path = args.rc_path
		if format(args.shell) == 'bind':
			settings.msf_payload = settings.msf_payload_bind
		elif format(args.shell) == 'reverse':
			settings.msf_payload = settings.msf_payload_reverse
		else:
			settings.msf_payload = settings.msf_payload_reverse_ssl

		# Initialize exploitation paths
		if settings.payload_path == 1:
			settings.payload_path = settings.cwd + '/scripts'
		if settings.rc_path == 1:
			settings.rc_path = settings.cwd + '/scripts'

		settings.lhost = str(args.lhost)
		settings.lport = str(args.lport)
		settings.encoding[0] = args.encode

		#[future work] Additional attacks..
		# settings.include = format(args.include)
		#if args.exclude != 'None':
		#	settings.exclude = format(args.exclude)

	except Exception as e:
		print(Fore.RED + "[!] ERROR: %s" %e)
		verbosity.error_info(e)
	
def concat_url(url_length,tempurl_array):
	url_without_query_parameters = ''
	for index in range(url_length):	
		url_without_query_parameters += "%s/"%tempurl_array[index]
	return url_without_query_parameters

def request_method():
	try:
		#POST & POST with GET PARAMETERS BLENDED!
		if settings.pdata != 'None':
			message = (Fore.GREEN + Style.BRIGHT + '[i] POST data found!')
			verbosity.print_message(message, settings.print_info)
			#tempurl_array = settings.url.split("/")
			# check if both get and post inserted
			if "?" in settings.url:
				# Ask to remove query parameter(s)
				prompt_message = Fore.WHITE + Style.BRIGHT + "[?] Query parameter(s) found on POST request. Do you want to remove query request(s) from URL?\n"			
				options_message = Style.DIM + Fore.WHITE + "[-] Enter 'y' for 'yes' or 'n' for 'no'.\n"
				if settings.print_info == 1:
					prompt_message += options_message
				yes_message = Style.DIM + Fore.WHITE + "[-] Removing query parameters."
				no_message = Style.DIM + Fore.WHITE + "[-] Continue with query parameters."
				answer = prompt.yesOrNo(prompt_message,yes_message,no_message)
				# Remove case
				if answer[1] == 1:
					tempurl_array = settings.url.split("?")
					url_length = len(tempurl_array)-1
					edited_url = concat_url(url_length,tempurl_array)
					settings.url = edited_url
				print answer[0]
			
			message = (Fore.WHITE + Style.DIM + '[-] Will execute POST REQUESTS on "%s" with POST DATA "%s"'%(settings.url, settings.pdata))
			verbosity.print_message(message,settings.print_info)

			# URL - (pre_url and url are the same on post scenario)
			settings.pre_url = settings.url
			
			# inject_here and pdata are the same on post scenario
			settings.initial_inject_here = settings.pdata
			settings.inject_here = settings.pdata
			settings.initial_parameter = settings.pdata
			settings.request_method = 1
		#GET	
		else:
			# split get parameters from url 
			print(Fore.GREEN + Style.BRIGHT + '[i] GET parameter found!')
			message = (Style.DIM + Fore.WHITE + '[-] Will execute GET REQUESTS on "'+ settings.url + '".')
			verbosity.print_message(message,settings.print_info)
			
			tempurl_array = settings.url.split("?")
			# URL without the get parameters
			settings.pre_url = tempurl_array[0]
			
			# GET parameters - with [INJECT_HERE]
			settings.initial_inject_here = tempurl_array[1]
			settings.inject_here = tempurl_array[1]
			
			# Whole URL - with [INJECT_HERE]
			settings.initial_parameter = settings.url
			settings.pdata = settings.initial_parameter
			settings.request_method = 0
	except Exception as e:
		print(Fore.RED + "[!] ERROR: %s" %e)
		verbosity.error_info(e)	

