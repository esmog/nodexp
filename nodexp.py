#!/usr/bin/python2.7	
# encoding: UTF-8

"""
This file is part of NodeXP, a detection & exploitation tool for 
node.js services (https://github.com/esmog/nodexp) created by 
Antonaropoulos Dimitrios (@esmog).
For more info about NodeXP see the 'README.md' file.
"""

import src.core.init.settings as settings
import src.core.init.flags_init as flags_init
import src.graphics.graphics as graphics
import src.interfaces.options.verbosity as verbosity
import src.core.detection.results_based.detection as detection
import src.core.detection.blind.blind as blind_technique
from colorama import init, Fore, Back, Style
init(autoreset=True)


def init():
	try:
		# Parse input
		user_input = flags_init.parse_input()

		# Show nodexp message
		graphics.ascii_art()

		# Global settings initialization & input initialization
		settings.init()
		flags_init.initialize_input(user_input)
		message = (Fore.WHITE + Style.DIM + "[-] Check and initialize input values")
		verbosity.print_message(message,settings.print_info)
		# Initialize input based on request method (GET or POST)
		flags_init.request_method()

	except Exception as e:
		print(Fore.RED + "[!] ERROR: %s" %e)
		verbosity.error_info(e)	

# Prepare nodexp
if __name__ == '__main__':
	init()
	'''
	try:
    		init()
 	except SystemExit:
    		import sys
    		sys.exit(0) 

  	except KeyboardInterrupt:
    		import sys
    		sys.exit(0)
	'''
	
# Start detection technique
try:
	if settings.technique == 'result':
		print settings.start_result
		detection.start_detection()
	elif settings.technique == 'blind':
		print settings.start_blind
		blind_technique.blind_injection()
	else:
		exit(Fore.RED + "[!] ERROR: No detection technique specified!")
except Exception as e:
	print(Fore.RED + "[!] ERROR: %s" %e)
	verbosity.error_info(e)	

