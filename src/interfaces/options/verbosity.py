#!/usr/bin/python2.7	
# encoding: UTF-8

"""
This file is part of NodeXP, a detection & exploitation tool for 
node.js services (https://github.com/esmog/nodexp) created by 
Antonaropoulos Dimitrios (@esmog).
For more info about NodeXP see the 'README.md' file.
"""

import os
import sys
import src.core.init.settings as settings
import traceback
from colorama import Fore, Back, Style, init

def print_message(message,print_msg):
	try:
		if print_msg == 1:
			print message
	except Exception as e:
		print(Fore.RED + "[!] ERROR: %s" %e)
		verbosity.error_info(e)

# Print more info on exceptions - errors :)
def error_info(e):
	exc_type, exc_obj, exc_tb = sys.exc_info()
   	fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
	print(Fore.RED + "[!] MORE INFO: error type %s, file %s, line %s" %(exc_type, fname, exc_tb.tb_lineno))
	print(Fore.RED + "[!] TRACEBACK:")
	traceback.print_exc()
	print(Fore.RED + "[!] END TRACEBACK.")
   	




