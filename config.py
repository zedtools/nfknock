#!/usr/bin/env python3

import getpass
import sys
import socket
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

#
# A class to represent either a 'knock', or the final port to be unlocked.
# It stores both a port and protocol, and is initialized from a string
# representation.
#
class PortSpec:
	TCP = 'tcp'
	UDP = 'udp'

	# portspec can be (where 'nnn' is a port number in string format):
	# - 'nnn' - a TCP port
	# - 'T:nnn' - a TCP port ('T' can be upper or lower case)
	# - 'U:nnn' - a UDP port ('U' can be upper or lower case)
	def __init__(self, portspec):
		try:
			port_array = portspec.rpartition(':')
			if port_array[1]:
				protocolspec = port_array[0]

				if protocolspec.lower() == 't':
					self.protocol = PortSpec.TCP
				elif protocolspec.lower() == 'u':
					self.protocol = PortSpec.UDP
				else:
					raise ValueError("Invalid protcol (expected 'U'/'P'): '{0}'".format(protocolspec))
			else:
				self.protocol = PortSpec.TCP

			self.port = int(port_array[2])
		except ValueError as e:
			print('Exception flew by!')
			traceback.print_exc()
			raise ValueError("Invalid port definition: '{0}'".format(portspec))

class Config:
	DEFAULT_IPV4_ALLOW = '10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16'
	DEFAULT_IPV6_ALLOW = 'fe80::/10'
	DEFAULT_SEQUENCE_TIMEOUT = 10
	DEFAULT_DOOR_TIMEOUT = 30
	IPv4 = socket.AF_INET
	IPv6 = socket.AF_INET6

	#
	# Load the configuration file. This initializes all the remaining
	# variables in self, beyond what was initialized in the constructor.
	#
	def __init__(self, config_file):
		config = configparser.ConfigParser()
		config.read(config_file)

		# knock sequence:
		# split on whitespace and convert each value to a PortSpec object
		self.sequence = list(map(
			lambda x: PortSpec(x),
			config.get('knock', 'sequence', fallback='').split()
		))

		if not self.sequence:
			raise ValueError('Configuration option "sequence" must be set under [knock]')

		# knock timeout between each knock in knock_sequence
		# default: 10
		self.sequence_timeout = int(config.get(
			'knock',
			'sequence_timeout',
			fallback=self.DEFAULT_SEQUENCE_TIMEOUT
		))

		# the port to open after the knock sequence is received
		self.door = PortSpec(config.get('knock', 'door', fallback='0'))

		if not self.door.port:
			raise ValueError('Configuration option "door" must be set under [knock]')

		# how long the door stays open if no connection is received
		# default: 30
		self.door_timeout = int(config.get('knock', 'door_timeout', fallback=self.DEFAULT_DOOR_TIMEOUT))

		# allowed networks: each is a whitespace separate list
		# default: all private addresses
		self.ipv4_allow = config.get(
			'ipv4',
			'allow',
			fallback='10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16'
		).split()
		self.ipv6_allow = config.get(
			'ipv6',
			'allow',
			fallback='fe80::/10'
		).split()

		# save files where persistent rules are saved
		self.iptables_save_file = config.get(
			'output',
			'iptables_save_file',
			fallback=''
		)
		self.ip6tables_save_file = config.get(
			'output',
			'ip6tables_save_file',
			fallback=''
		)
		self.nftables_save_file = config.get(
			'output',
			'nftables_save_file',
			fallback=''
		)

