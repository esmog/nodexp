#!/usr/bin/python2.7	
# encoding: UTF-8

"""
This file is part of NodeXP, a detection & exploitation tool for 
node.js services (https://github.com/esmog/nodexp) created by 
Antonaropoulos Dimitrios (@esmog).
For more info about NodeXP see the 'README.md' file.
"""

import src.core.init.settings as settings
import urllib
import urllib2
import httplib
import sys
import os
import linecache
from bs4 import*
import difflib
import time
import src.interfaces.options.verbosity as verbosity
import src.interfaces.options.prompt as prompt
import src.interfaces.functions.interfaces as interfaces
import src.core.detection.blind.blind as blind_technique
import src.core.exploitation.exploitation as exploitation

try:
	from urllib.parse import urlparse
except ImportError:
	from urlparse import urlparse
from colorama import init, Fore, Back, Style
init(autoreset=True)

def parse_wordlist(try_counter, initial_data, initial_inject_here):
	try:
		text_loop = xrange(1,settings.total_line_count,2)
		for index in text_loop:
			# Re initialize url if not follow redirection
			if settings.follow_redirection == 0:
				settings.url = initial_data

			settings.inject_here = initial_inject_here
			payload = linecache.getline(settings.ssji_wordlist, index).rstrip()
			
			# Exit when no more payloads on wordlist 
			if payload == '---end' or payload == '':
				print(Fore.RED + '[!] End of payloads in the corresponding dictionary txt file.\n[!] Quit.')
				sys.exit()
				break

			# Get static expected responses
			expected_response = linecache.getline(settings.ssji_wordlist, index+1).rstrip()
			settings.expected_responses = expected_response.split(',')
			settings.expected_responses.extend(settings.error_responses)
			
			# Create randomized payload variables and it's dymamic expected response accordingly
			randomized_data = randomizer(payload,settings.expected_responses)
			payload = randomized_data[0]
			expected_response = randomized_data[1]
			
			# Initialize payload
			settings.inject_here = settings.inject_here.replace('[INJECT_HERE]', payload, 1)
			#settings.pdata = settings.inject_here
			parameter = settings.inject_here
			
			# GET case initalize payload
			if settings.request_method == 0:
				settings.url = settings.url.replace('[INJECT_HERE]', urllib.quote(payload), 1)
				parameter = settings.url

			# Message for each injection
			print('\n%s'%settings.hr)
			print('[i] Try no. ' + format(try_counter) + Fore.GREEN + Style.BRIGHT + ' (payload: '  + settings.inject_here + ')' + Fore.WHITE + Style.NORMAL + ':')
			print('%s'%settings.hr)
			
			# SSJI begins..
			verbosity.print_message(Fore.WHITE + Style.DIM + '[-] Starting injecting requests with current payload... ', settings.print_info)

			# Make request with payload
			payload_response = interfaces.make_request(parameter)
			
			# If HTTPError or BadStatusLine
			if settings.request_error == 1:
				settings.request_error = 0
				# Next payload..
				try_counter += 1
				continue	
				
			# Check for redirection on malicious request
			interfaces.check_redirection(payload_response[1], settings.technique)

			# Make valid request without payload
			valid_response = interfaces.make_request(settings.pre_url)

			# Check for expected keywords before injection with valid requests and ask for blind injection accordingly	
			ask_blind = check_keywords_before_injection(valid_response[0])
			if ask_blind == True:
				blind = interfaces.change_technique(settings.bl_prompt_message, settings.bl_options_message, settings.bl_alter_tech_msg, settings.bl_current_tech_msg)
				if blind == True:
					# Re-initialize input with [INJECT_HERE]
					settings.inject_here = settings.initial_inject_here
					blind_technique.blind_injection()
					sys.exit()
					break
		
			# Compare HTML results (both valid and injected requests)
			compare_html_pages(valid_response[3],payload_response[3])

			# Next payload..
			try_counter += 1
			detection = injection_results(payload_response[2],expected_response,try_counter)
			# Website is vulnerable on SSJI
			if detection == 1:
				
				# Ask for starting exploitation
				ask_exploitation = interfaces.change_technique(settings.ex_prompt_message,settings.ex_options_message,settings.ex_alter_tech_msg,settings.ex_current_tech_msg)
				if ask_exploitation == True:
					exploitation.initialize_payload_options(True)
	except Exception as e:
				print(Fore.RED + "[!] ERROR: %s" %e)
				verbosity.error_info(e)	

def start_detection():
	# GET AND POST CASES BLENDED!
	# Results Based Technique
	try:
		if settings.inject_here_replace in settings.inject_here: 
			try_counter = 1			
			# Parameter with and without payload for each detection case
			initial_data = settings.url
			initial_inject_here = settings.inject_here
			# Parse wordlist and initialize payloads
			parse_wordlist(try_counter, initial_data, initial_inject_here)
		else:
			sys.exit('ERROR: [INJECT_HERE] not found on your input! > %s' %settings.inject_here)
			
	except Exception as e:
		print(Fore.RED + "[!] ERROR: %s" %e)
		verbosity.error_info(e)

# Compare two html pages
# Only on results based technique!
def compare_html_pages(valid_html, infected_html):
	try:
		if settings.print_diff == 1:

			# Set info and prepare request
			if settings.print_info == 1:
					print Style.NORMAL + Fore.YELLOW + '[>]\n'
			if settings.request_method == 1:
				message =  Style.NORMAL + Fore.YELLOW +'[<] Compare HTML response before ( ' + Fore.GREEN + settings.pre_url + Fore.YELLOW + ' ) \nand after ( ' + Fore.RED + settings.url + ', & ' + settings.inject_here + Fore.YELLOW +' ) injection :'

			else:
				message =  Style.NORMAL + Fore.YELLOW + '[<] Compare HTML response before ( ' + Fore.GREEN + settings.pre_url + Fore.YELLOW + ' ) \nand after ( ' + Fore.RED + settings.url + Fore.YELLOW +' ) injection :'
			parameter = settings.inject_here
			verbosity.print_message(message, settings.print_info)			

			# Compare valid and malicious requests' responses 
			diff_lib = difflib.Differ()
			diff = diff_lib.compare(list(valid_html.stripped_strings),list(infected_html.stripped_strings))

			comparison = list(diff)
			counter = 0	
			differences_removed = []
			differences_added = []
			differences = []
			for i in comparison:
				first_char_comparison = comparison[counter][:1]
				if first_char_comparison == "-":
					splitted_comparison = comparison[counter].split("- ")
					differences_removed.append(splitted_comparison[1])
					differences.append(splitted_comparison[1])
				elif first_char_comparison == "+":
					splitted_comparison = comparison[counter].split("+ ")
					differences_added.append(splitted_comparison[1])
					differences.append(splitted_comparison[1])
				counter += 1
			if settings.print_diff not in [] :
				message = '[i] Removed content : \n' + Fore.WHITE + Style.DIM +'%s' %list(differences_removed)
				verbosity.print_message(message, settings.print_info)
				message = '[i] Added Content : \n' + Fore.WHITE + Style.DIM +'%s' %list(differences_added)
				verbosity.print_message(message, settings.print_info)

			# False negative error
			# No changes on html page based on your payload
			if not differences:
				print Fore.RED + '[i] HTML content does not seem to change based on your payload.'
				ask_blind = True
			else:
				ask_blind = False
			if ask_blind == True:
				blind = interfaces.change_technique(settings.bl_prompt_message, settings.bl_options_message, settings.bl_alter_tech_msg, settings.bl_current_tech_msg)
				if blind == True:
					# Re-initialize input with [INJECT_HERE]
					settings.inject_here = settings.initial_inject_here
					blind_technique.blind_injection()
					sys.exit()
	except Exception as e:
		print(Fore.RED + "[!] ERROR: %s" %e)
		verbosity.error_info(e)

def check_keywords_before_injection(simple_urlopen):
	message = Fore.YELLOW + '[>]\n\n[<] Check response for expected keywords on valid request (false positives) :'
	verbosity.print_message(message, settings.print_info)
	try:
		if settings.responded_keys:
			del settings.responded_keys[:]
		for keyword in settings.expected_responses:
			if keyword in simple_urlopen:
				settings.responded_keys.append(keyword)
		if settings.responded_keys:
			print Fore.RED + Style.BRIGHT +'[!] WARNING: EXCPECTED HTML RESPONSE CONTAINS MATCHING KEYWORD(S) BEFORE INJECTION!\n' + Style.NORMAL + Fore.WHITE +'[i] Expected response\'s matching keyword(s) (%s) found on page when valid request made; without injecting any payload. This might lead to false conclusions (false positives)! Blind injection technique might be more accurate in this case.' %list(settings.responded_keys)
			return True
		else:
			message = Fore.WHITE + Style.DIM + '[-] No keywords found.'#\n' + Fore.YELLOW + Style.NORMAL + '[>]'
			verbosity.print_message(message, settings.print_info)
			return False
	except Exception as e:
		print(Fore.RED + "[!] ERROR: %s" %e)
		verbosity.error_info(e)


def injection_results(plaintext_result,expected_response,try_counter):
	try:
		try_no = format(try_counter-1)
		if settings.print_info == 1:
			print Style.NORMAL + Fore.YELLOW + '[>]\n'
		message = Fore.YELLOW + '\n[<] Show injection (Try no. ' + try_no +  ') results :'
		verbosity.print_message(message, 1)

		expected_payload = list(set(expected_response)^set(settings.error_responses))

		# For any of the expected responses which exists in injected HTML response too!
		for payload in expected_response:
			if payload in plaintext_result:
				# If payload exists in HTML response before injection..	
				if payload in settings.responded_keys:
					# Response existed before injection. May be 'False Positive'
					message = Fore.RED + "[!] Response(s) '%s' existed before injection. High possibility for 'False Positive' assumption on this case!" %payload
					verbosity.print_message(message,1)
					settings.invalid_responses.append(payload)

				# If payload exists in payload's dynamic response..
				elif payload in expected_payload:
					# SSJI Done based on payload and it's dynamic response!
					message = Fore.GREEN + "[!] SSJI Done based on payload and it's dynamic response (%s)!" %payload
					verbosity.print_message(message,1)
					settings.valid_responses.append(payload)

				# If payload exists in settings.error_responses..
				elif payload in settings.error_responses:
					# SSJI Done based on error responses. May be 'False Positive'
					message = Fore.GREEN + "[!] SSJI Done based on error response (%s). Low possibility for 'False Positive' assumption on this case." %payload
					verbosity.print_message(message,1)
					settings.valid_responses.append(payload)
				else:
					sys.exit( Fore.RED + 'ERROR: Payload response error. Check payloads.txt file for possible syntax errors.')

		# Noone of the expected responses found in injected HTML response!		
		if not (settings.valid_responses) and not (settings.invalid_responses):
			message = Fore.RED + '[!] No remarkable responses. Website (' + settings.url + ')is NOT vulnerable on SSJI using "' + settings.inject_here + '" as payload and ' + settings.technique + 's based technique. Check payloads.txt file for possible syntax errors or change injection technique.\n' + Fore.YELLOW + '[>]'
			verbosity.print_message(message,1)
			return 0
			
		# If any of the expected responses found in the injected HTML response!
		elif (settings.valid_responses or settings.invalid_responses):

			# If both valid and invalid responses found...
			if settings.valid_responses and settings.invalid_responses:
				message = Fore.GREEN + '[i] Payload : ' + settings.inject_here + '\n[i] Valid Response(s): %s\n' %(list(settings.valid_responses)) + Fore.RED + '[i] Invalid Response(s): %s'%(list(settings.invalid_responses))
				ask_blind = False

			# If only valid responses found...
			elif settings.valid_responses:
				message = Fore.GREEN + '[i] Payload : ' + settings.inject_here + '\n[i] Valid Response(s): %s' %(list(settings.valid_responses))
				ask_blind = False

			# If only invalid responses found...
			elif settings.invalid_responses:
				message = Fore.GREEN + '[i] Payload : ' + settings.inject_here + Fore.RED + '\n[i] Invalid Response(s): %s\n[i] Not sure if website is vulnerable or not. Blind injection technique might be more accurate in this case.'%(list(settings.invalid_responses))
				ask_blind = True

			verbosity.print_message(message,1)
			
			if ask_blind == True:
				blind = interfaces.change_technique(settings.bl_prompt_message, settings.bl_options_message, settings.bl_alter_tech_msg, settings.bl_current_tech_msg)
				if blind == True:
					# Re-initialize input with [INJECT_HERE] for changing technique
					settings.inject_here = settings.initial_inject_here
					blind_technique.blind_injection()
					sys.exit()
				else:
					settings.valid_responses = []
					settings.invalid_responses = []
					return 0
			else:
				settings.valid_responses = []
				settings.invalid_responses = []		
				return 1
	except Exception as e:
		print(Fore.RED + "[!] ERROR: %s" %e)
		verbosity.error_info(e)

# Create random strings
# ### for concatenation and calculations of random strings
# *** for random strings
def randomizer(payload, expected_response):
	
	# Case for ### and $$$ - basically for eval()
	if settings.wildcards[2] in payload:
		if settings.rand == 'all':
			# Replace ### with random values
			# ean epistrafei to concatenation einai vulnerable
			payload_randomizer = '%s+"%s"'%(settings.random_num,settings.random_char)
			payload = payload.replace('###',payload_randomizer)

			# Replace $$$ with random values' expected result	
			expected_resp = settings.wildcards[1]
			if expected_resp in expected_response:
				index = expected_response.index(expected_resp)
				expected_response[index] = expected_resp.replace(expected_resp, settings.pentest_value)
				return [payload,expected_response]
			else:
				sys.exit("ERROR: Quit execution. Error occured on randomizer funtion. Check payloads txt file for syntax error.")
		else:
			# Replace ### with random values
			if settings.rand == 'char':
				payload_randomizer = '"%s"'%settings.pentest_value
			else:
				payload_randomizer = settings.pentest_value
			payload = payload.replace('###',payload_randomizer)
			
			# Replace $$$ with random values' expected result	
			expected_resp = settings.wildcards[1]
			if expected_resp in expected_response:
				index = expected_response.index(expected_resp)
				expected_response[index] = expected_resp.replace(expected_resp, settings.pentest_value)
				return [payload,expected_response]
			else:
				sys.exit("ERROR: Quit execution. Error occured on randomizer funtion. Check payloads txt file for syntax error.")	
	# Case for *** and $$$
	elif settings.wildcards[0] in payload:
		
		# Replace *** with random text value and random calculation
		payload_randomizer = settings.pentest_value
		payload = payload.replace('***',payload_randomizer)
		
		# Replace $$$ with random values' expected result	
		expected_resp = settings.wildcards[1]
		if expected_resp in expected_response:
			index = expected_response.index(expected_resp)
			expected_response[index] = expected_resp.replace(expected_resp, settings.pentest_value)
			return [payload,expected_response]
		else:
			sys.exit("ERROR: Quit execution. Error occured on randomizer funtion. Check payloads txt file for syntax error.")
	# Case for no ***,$$$ or ###	
	elif not settings.wildcards[2] in payload and not settings.wildcards[0] in payload:
		return [payload,expected_response] 

