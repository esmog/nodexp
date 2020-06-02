#!/usr/bin/python2.7	
# encoding: UTF-8

"""
This file is part of NodeXP, a detection & exploitation tool for 
node.js services (https://github.com/esmog/nodexp) created by 
Antonaropoulos Dimitrios (@esmog).
For more info about NodeXP see the 'README.md' file.
"""

import src.core.init.settings as settings
import traceback
from colorama import Fore, Back, Style, init

def yesOrNo(prompt_message, return_1, return_0): # options_message
	continue_process = 1
	while continue_process == 1:
		try:
			if settings.print_info == 1:
				continue_answer = raw_input(prompt_message)
			else:
				continue_answer = raw_input(prompt_message)	
			if continue_answer in settings.continue_flag_y:
				continue_process = 0
				return [return_1,1]
			if continue_answer in settings.continue_flag_n:
				continue_process = 0
				return [return_0,0]
			else:
				print(Fore.RED + "[!] Sorry, invalid input.")
				return yesOrNo(prompt_message, return_1, return_0)
		except ValueError, e:
			print(Fore.RED + "[!] Sorry, invalid input.")
			return yesOrNo(prompt_message, return_1, return_0)
		except KeyboardInterrupt, e:
			exit(Fore.RED + "[!] Exit Program")
		except Exception as e:
			print(Fore.RED + "[!] Sorry, invalid input.")
			return yesOrNo(prompt_message, return_1, return_0)

