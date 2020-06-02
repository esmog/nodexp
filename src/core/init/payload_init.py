#!/usr/bin/python2.7	
# encoding: UTF-8

"""
This file is part of NodeXP, a detection & exploitation tool for 
node.js services (https://github.com/esmog/nodexp) created by 
Antonaropoulos Dimitrios (@esmog).
For more info about NodeXP see the 'README.md' file.
"""

import src.core.init.settings as settings
import src.interfaces.options.prompt as prompt
import src.interfaces.options.verbosity as verbosity
import sys
import os
import re
import subprocess
#import base64
from colorama import Fore, Back, Style, init
from os.path import expanduser
import socket

def checkLPORT(portnumber):
	try:	
		port = int(portnumber)
		if port < 65536 and port >= 0:
   			message = (Fore.GREEN + "[!] Setting local port: 'LPORT' = '%d'" %(port))
			verbosity.print_message(message, settings.print_info)
			return port
		else: 	
			print(Fore.RED + "[!] ERROR: Port number range exceeded.")
			return get_input("[?] Please, set your local port.\n - ","LPORT")
	except ValueError:
   		print(Fore.RED + "[!] ERROR: Input is not an integer.")
		return get_input("[?] Please, set your local port.\n - ","LPORT")

def checkLHOST(ip):	
	try:
		Setting_ip = ip.split('.')
		if len(Setting_ip) != 4:
			print(Fore.RED + "[!] ERROR: Input is not a valid ip address")
			return get_input("[?] Please, set your local host ip.\n - ","LHOST")
		else:	
			socket.inet_aton(ip)
	   		message = (Fore.GREEN + "[!] Setting local host ip: 'LHOST' = '%s'" %(ip))
			verbosity.print_message(message, settings.print_info)
			return ip
	except socket.error:
	    	print(Fore.RED + "[!] ERROR: Input is not a valid ip address")
		return get_input("[?] Please, set your local host ip.\n - ","LHOST")

def pathExistenceOptions(options,path,flag):
	# Default cases 1,2,3 ...
	if options == '1':
		try:
			path = settings.home_directory
			return path
		except Exception as e:
			print(Fore.RED + "[!] ERROR: %s" %e)
			verbosity.error_info(e)		
	elif options == '2':
		try:
			path = "%s/Desktop" %(settings.home_directory)
			check = os.path.exists(path)
			if check == True: 
				return path
			else:
				exit(Fore.RED + "[!]ERROR: Default path does not exist!")
		except Exception as e:
			print(Fore.RED + "[!] ERROR: %s" %e)
			verbosity.error_info(e)
	elif options == '3':
		try:
			path = "%s/Documents" %(settings.home_directory)
			check = os.path.exists(path)
			if check == True: 
				return path
			else:
				exit(Fore.RED + "[!]ERROR: Default path does not exist!")
		except Exception as e:
			print(Fore.RED + "[!] ERROR: %s" %e)
			verbosity.error_info(e)
	# Retype path case...		
	else:
		# Setting new path..
		# ..Start over with options = path value	
		path_full_existense = checkPathExistence(options,flag)
		return path_full_existense

def checkPathExistenceInHomeDirectory(flag,path):
	try:
		print(Fore.YELLOW + "[i] Checking if path exist in home directory ...")
		path = "%s/%s" %(settings.home_directory,path)	
		first_check = os.path.exists(path)
		# Valid home directory path..
		if first_check == True:
			home_directory_select = prompt.yesOrNo("[?] Did you mean '%s' ?\n"%path + Fore.YELLOW + "[i] Enter 'y' for 'yes' or 'n' for 'no'.\n" + Fore.WHITE + " - ", Fore.GREEN + "[!] Setting  path: '%s' = '%s'" %(flag,path), Fore.RED + "[!] Not setting path '%s' for '%s'" %(path,flag))
			# Valid home directory path accepted
			if home_directory_select[1] == 1:
				return path
			# Valid home directory path NOT accepted
			else:				
				return 'None'	
		# Invalid home directory path..	
		else:
			print(Fore.RED + "[!] ERROR: '%s' is not a valid path for '%s'" %(path,flag))
			return 'None'
	except Exception as e:
		print(Fore.RED + "[!] ERROR: %s" %e)
		verbosity.error_info(e)

def checkPathExistence(path,flag):
	try:
		# Valid local path accepted
		path = re.sub(r"\/+", "/", path)
		if os.path.exists(path) == True:
			return path
		# Invalid local path..
		# .. check if path exists in home directory	
		else:
			print(Fore.RED + "[!] ERROR: '%s' is not a valid path for '%s'" %(flag,path))
			home_directory_path = checkPathExistenceInHomeDirectory(flag,path)
			return home_directory_path
	except Exception as e:
		print(Fore.RED + "[!] ERROR: %s" %e)
		verbosity.error_info(e)	

def initialize_path_functions(input_answer,msflag):
	try:
		# Check local path existence..
		path = checkPathExistence(input_answer,msflag)
		# Path does not exist.. 
		# .. give default choices or retype path..
		while path == 'None':
			options = raw_input("[?] Do you want to retype path or give one of the defaults [~/, ~/Desktop, ~/Documents]?\n" + Fore.YELLOW + "[i] (Press: 1,2,3 for defaults accordingly or type the new path)\n" + Fore.WHITE + " - ")
			path = pathExistenceOptions(options,path,msflag)
		message = (Fore.GREEN + "[!] Setting path: '%s' = '%s'" %(msflag,path))
		verbosity.print_message(message, settings.print_info)
		return path
	except Exception as e:
		print(Fore.RED + "[!] ERROR: %s" %e)
		verbosity.error_info(e)

def get_input(msg,flag):	
	input_answer = raw_input(msg)
	for msflag in settings.exploitation_flags:
		if msflag in flag:
			try:
				input_case = settings.exploitation_flags.index(msflag)
				if input_case == 0:
					lport = checkLPORT(input_answer)
					return lport
				elif input_case == 1:
					lhost = checkLHOST(input_answer)
					return lhost
				elif input_case == 2 or input_case == 3:
					path = initialize_path_functions(input_answer,msflag)
					return path
				else:
					print(Fore.RED + "[!] ERROR: Unknown case!")
					exit()
			# exception handling
			except Exception as e:
				print(Fore.RED + "[!] ERROR: %s" %e)
				verbosity.error_info(e)
