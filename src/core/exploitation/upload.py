#!/usr/bin/python2.7	
# encoding: UTF-8

"""
This file is part of NodeXP, a detection & exploitation tool for 
node.js services (https://github.com/esmog/nodexp) created by 
Antonaropoulos Dimitrios (@esmog).
For more info about NodeXP see the 'README.md' file.
"""

import src.core.init.settings as settings
import src.interfaces.options.verbosity as verbosity
from colorama import Fore, Back, Style, init
from time import sleep

def read_file():
	# Read payload and put it on a global variable..
	try:
		with open(settings.payload_path, 'r') as myfile:
    			settings.payload = myfile.read()
			return True
	except Exception as e:
		print(Fore.RED + "[!] ERROR: %s" %e)
		verbosity.error_info(e)
		return False

def read_spool():
	# Read spool file untill metasploit session made..		
	# keyword = False
	try:
		counter = 0
		with open(settings.spool_file, 'r') as spool:
			message = Fore.YELLOW + "\n[i] Waiting for Metasploit to be ready!"
			verbosity.print_message(message, settings.print_info)

			# Bind shell case ...
			if settings.msf_payload == settings.msf_payload_bind:
				while not 'Started bind TCP handler against %s:%s' % (settings.rhost, settings.lport) in spool.read():
					spool.seek(0,0)
					message = Fore.YELLOW + "..."
					verbosity.print_message(message, settings.print_info)
					sleep(5)
					counter += 1
					if counter > 10:
						exit(Fore.RED + "[!] ERROR: Waiting for connection response timeout. The given IP address might be wrong. Check the metasploit terminal window (msfconsole) for possible errors.")
				return True

			# Reverse shell case ...
			elif settings.msf_payload == settings.msf_payload_reverse:
				while not 'Started reverse TCP handler on %s:%s' % (settings.lhost, settings.lport) in spool.read():
					spool.seek(0, 0)
					message = Fore.YELLOW + "..."
					verbosity.print_message(message, settings.print_info)
					sleep(5)
					counter += 1
					if counter > 10:
						exit(Fore.RED + "[!] ERROR: Waiting for connection response timeout. The given IP address might be wrong. Check the metasploit terminal window (msfconsole) for possible errors.")
				print(Fore.GREEN + "[i] Metasploit is ready!\n" + Fore.YELLOW + "[i] Waiting for payload to be uploaded..")
				return True

			# Reverse ssl shell case ...
			else:
				while not 'Started reverse SSL handler on %s:%s' % (settings.lhost, settings.lport) in spool.read():
					spool.seek(0, 0)
					message = Fore.YELLOW + "..."
					verbosity.print_message(message, settings.print_info)
					sleep(5)
					counter += 1
					if counter > 10:
						exit(Fore.RED + "[!] ERROR: Waiting for connection response timeout. The given IP address might be wrong. Check the metasploit terminal window (msfconsole) for possible errors.")
				print(Fore.GREEN + "[i] Metasploit is ready!\n" + Fore.YELLOW + "[i] Waiting for payload to be uploaded..")
				return True


	except Exception as e:
		print(Fore.RED + "[!] ERROR: %s" %e)
		verbosity.error_info(e)
		return False

