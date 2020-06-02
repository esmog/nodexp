#!/usr/bin/python2.7	
# encoding: UTF-8

"""
This file is part of NodeXP, a detection & exploitation tool for 
node.js services (https://github.com/esmog/nodexp) created by 
Antonaropoulos Dimitrios (@esmog).
For more info about NodeXP see the 'README.md' file.
"""

import sys
import src.core.init.settings as settings
import src.interfaces.options.verbosity as verbosity
import src.interfaces.options.prompt as prompt
import urllib
import urllib2
import httplib
from bs4 import*
import difflib
from urllib2 import HTTPError, URLError
from colorama import Fore, Back, Style, init

def make_request(parameter):
	# Do request below..
	try:	
		# With or without cookies, GET or POST cases blended! :)
		if settings.request_method == 1:
		# POST request
			request = urllib2.Request(settings.url,data=parameter,headers={'Cookie':settings.cookie})
		else:
		# GET request
			request = urllib2.Request(parameter,headers={'Cookie':settings.cookie})

		html = urllib2.urlopen(request).read()
		html_soup = BeautifulSoup(html, "html.parser")
		html_redirection_object = urllib2.urlopen(request)
		html_prettify = html_soup.prettify()

		return html,html_redirection_object,html_prettify,html_soup

	except HTTPError as e:
		status = e.getcode()
		# ERROR on exploitation process. Cannot exploit!
		if settings.exploitation_state ==  1:
			print (Fore.RED + '\n[!] Server respond with status %d to your request. Website seems vulnerable but can not be exploited. Try again.'%(status))
			sys.exit()

		# ERROR on any other case..
		settings.request_error = 1
		# Print info..
		print (Fore.YELLOW + '\n[!] Server respond with status %d to your request with payload \' %s \'. Not sure if website is vulnerable or not.'%(status,parameter))
		print (Fore.RED + "[!] WARNING: The server couldn\'t fulfill the request! First of all, check if the given URL is correct. In case you injected any payload on your request, server seems to interact with it so, it might be vulnerable. In this case check payload txt files for syntax errors and try again. Else, service might be down or .")
		
		'''
		# Ask for blind and act accodingly..
       		blind = change_technique(settings.bl_prompt_message, settings.bl_options_message, settings.bl_alter_tech_msg, settings.bl_current_tech_msg)
		if blind == True:
			# Re-initialize input with [INJECT_HERE]
			settings.inject_here = settings.initial_inject_here
			blind_technique.blind_injection()
		'''	
		# Else return and continue searching for poc!
		html = e.read()
		html_soup = BeautifulSoup(html, "html.parser")
		html_prettify = html_soup.prettify()
		html_redirection_object = e

		return html,html_redirection_object,html_prettify,html_soup
	except httplib.BadStatusLine as e:
		error_message = e.args
		print(Fore.RED + "[!] ERROR: [%s]\n[!] MORE INFO: Server might be down or cannot successfully parse your request! Check your txt payload for syntax errors, change injection technique or simply try again later" %error_message)
		settings.request_error = 1
	except URLError as e:
		error_message = e.args
		print(Fore.RED + "[!] ERROR: [%s]\n[!] MORE INFO: Server might be down! Check your txt payload for syntax errors, change injection technique or simply try again later" %error_message)
		#verbosity.error_info(error_message)
		settings.request_error = 1
		
		return 0
	except Exception as e:
		print(Fore.RED + "[!] ERROR: %s" %e)
		verbosity.error_info(e)

def change_technique(prompt_message, options_message, alter_tech_msg, current_tech_msg):
	try:
		if settings.print_info == 1:
			prompt_message += options_message
	
		answer = prompt.yesOrNo(prompt_message, alter_tech_msg, current_tech_msg)
		print answer[0]

		# Change technique
		if answer[1] == 1:
			if settings.technique == 'result': settings.technique = 'blind'
			else: settings.technique = 'result' 
			return True

		# Remain on same technique
		elif answer[1] == 0:
			return False
		else:
			return prompt.yesOrNo(prompt_message, current_tech_msg, alter_tech_msg)
	except Exception as e:
		print(Fore.RED + "[!] ERROR: %s" %e)
		verbosity.error_info(e)

def check_redirection(res,tech):
	try:
		# Do not show this message everytime you make a request on blind injection
		if tech != 'blind':
			message = Fore.YELLOW + '\n[<] Checking for redirection'
			verbosity.print_message(message,settings.print_info)

		# Redirection made
		# Ask to follow..
		if res.url != settings.url:
			message = Fore.RED + Style.BRIGHT + '[!] WARNING: REDIRECTION FOUND!\n' + Style.NORMAL + Fore.WHITE + "    from: " + Fore.GREEN + Style.BRIGHT + settings.url + "\n" + Style.NORMAL + Fore.WHITE + "    to: " + Fore.RED + Style.BRIGHT + res.url
			print message
			# Ask to quit
			prompt_message = Fore.WHITE + Style.BRIGHT + "[?] Do you want to follow redirection?\n"			
			options_message = Style.DIM + Fore.WHITE + "[-] Enter 'y' for 'yes' or 'n' for 'no'.\n"

			if settings.print_info == 1:
				prompt_message += options_message

			error_msg = Fore.RED + '[-] Not follow redirection.'
			continue_msg = Fore.WHITE + Style.NORMAL + '[-] Follow redirection.'
			answer = prompt.yesOrNo(prompt_message,continue_msg,error_msg)	
			verbosity.print_message(answer[0],settings.print_info)
			settings.follow_redirection = 1

			# If follow redirection
			if answer[1] == 1:
				settings.url = res.url
				settings.pre_url = settings.url

			if settings.technique != 'blind':
				message = Style.NORMAL + Fore.YELLOW + '[>]'
				verbosity.print_message(message, settings.print_info)
		# No redirection	
		else:
			if tech != 'blind':
				message = Style.DIM + Fore.WHITE + '[-] No redirection made.'#\n' + Fore.YELLOW + Style.NORMAL + '[>]'
				verbosity.print_message(message,settings.print_info)
			settings.follow_redirection = 0
		return settings.follow_redirection
	except Exception as e:
		print(Fore.RED + "[!] ERROR: %s" %e)
		verbosity.error_info(e)
		sys.exit()

def percent_encoding(mal_code):
	percent_encoded_data = settings.inject_here.replace(settings.inject_here_replace, urllib.quote(mal_code), 1)
	percent_encoded_data = percent_encoded_data.replace('%23time%23', '#time#' ,1)	
	percent_encoded_data = percent_encoded_data.replace('%2A%2A%2A','***', 1)
	return percent_encoded_data
