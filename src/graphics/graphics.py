#!/usr/bin/python2.7	
# encoding: UTF-8

"""
This file is part of NodeXP, a detection & exploitation tool for 
node.js services (https://github.com/esmog/nodexp) created by 
Antonaropoulos Dimitrios (@esmog).
For more info about NodeXP see the 'README.md' file.
"""

from colorama import Fore, Back, Style, init
init(autoreset=True)

def ascii_art():
	print''
	print'|----------------------------------------------------------|'
	print'|          --Server Side Javascript Injection--            |'
	print'|    -Detection & Exploitation Tool on Node.js Servers-    |'
	print'|----------------------------------------------------------|'
	print'|----------------------------------------------------------|'
	print'|                                                          |'
	print'| '+Fore.BLUE+'888b    888'+Fore.RED+'         '+Fore.YELLOW+'      888'+Fore.BLUE+'         '+Fore.GREEN+'          '+Fore.RED+'         '+Fore.WHITE+'|'
	print'| '+Fore.BLUE+'8888b   888'+Fore.RED+'         '+Fore.YELLOW+'      888'+Fore.BLUE+'         '+Fore.GREEN+'          '+Fore.RED+'         '+Fore.WHITE+'|'
	print'| '+Fore.BLUE+'88888b  888'+Fore.RED+'         '+Fore.YELLOW+'      888'+Fore.BLUE+'         '+Fore.GREEN+'          '+Fore.RED+'         '+Fore.WHITE+'|'
	print'| '+Fore.BLUE+'888Y88b 888'+Fore.RED+'  .d88b. '+Fore.YELLOW+'  .d88888'+Fore.BLUE+'  .d88b. '+Fore.GREEN+' 888  888 '+Fore.RED+'88888b.  '+Fore.WHITE+'|'
	print'| '+Fore.BLUE+'888 Y88b888'+Fore.RED+' d88""88b'+Fore.YELLOW+' d88" 888'+Fore.BLUE+' d8P  Y8b'+Fore.GREEN+' `Y8bd8P` '+Fore.RED+'888 "88b '+Fore.WHITE+'|'
	print'| '+Fore.BLUE+'888  Y88888'+Fore.RED+' 888  888'+Fore.YELLOW+' 888  888'+Fore.BLUE+' 88888888'+Fore.GREEN+'   X88K   '+Fore.RED+'888  888 '+Fore.WHITE+'|'
	print'| '+Fore.BLUE+'888   Y8888'+Fore.RED+' Y88..88P'+Fore.YELLOW+' Y88b 888'+Fore.BLUE+' Y8b.    '+Fore.GREEN+' .d8""8b. '+Fore.RED+'888 d88P '+Fore.WHITE+'|'
	print'| '+Fore.BLUE+'888    Y888'+Fore.RED+'  "Y88P" '+Fore.YELLOW+'  "Y88888'+Fore.BLUE+'  "Y8888 '+Fore.GREEN+' 888  888 '+Fore.RED+'88888P"  '+Fore.WHITE+'|'
	print'| '+Fore.BLUE+'           '+Fore.RED+'         '+Fore.YELLOW+'         '+Fore.BLUE+'         '+Fore.GREEN+'          '+Fore.RED+'888      '+Fore.WHITE+'|'
	print'| '+Fore.BLUE+'           '+Fore.RED+'         '+Fore.YELLOW+'         '+Fore.BLUE+'         '+Fore.GREEN+'          '+Fore.RED+'888      '+Fore.WHITE+'|'
	print'| '+Fore.BLUE+'           '+Fore.RED+'         '+Fore.YELLOW+'         '+Fore.BLUE+'         '+Fore.GREEN+'          '+Fore.RED+'888      '+Fore.WHITE+'|'
	print'|----------------------------------------------------------|'
	print'|----------------------------------------------------------|'
	print'| nodexp v.1.0.0                                           |'
	print'| https://github.com/esmog/nodexp                          |'
	print'|----------------------------------------------------------|'
