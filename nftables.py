#!/usr/bin/env python3

import getpass
import sys
import subprocess
import socket
import ipaddress
import configparser
import traceback

#
# Verify the script was run as root. If not, print an error and abort.
#
def CheckRoot():
	if getpass.getuser() != "root":
		print("Please run as root or with sudo")
		sys.exit(1);

#
# Display a message and repeat until user inputs 'y' or 'n'.
# True or False is returned depending on the user input ('y' or 'n').
#
def input_verify(msg):
	user_input = ''
	while user_input not in ['y', 'n']:
		user_input = input(msg + " (y/n)? ").lower()

	return user_input == 'y'

