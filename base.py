#!/usr/bin/env python3

import configparser
import getpass
import ipaddress
import socket
import sys
import traceback
from abc import ABC, abstractmethod

def CheckRoot():
	"""Verify the script was run as root. If not, print an error and abort."""
	if getpass.getuser() != "root":
		print("Please run as root or with sudo")
		sys.exit(1)

def input_verify(msg: str):
	"""Print a message prompt and ask for a y/n response. The user is repeatedly asked for a response until 'y' or 'n' is input.

	:param msg: Message to display as a prompt
	:type msg: str
	:return: True if response was y, False if the response was n
	:rtype: bool
	"""
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
	"""A class to represent either a 'knock', or the final port to be unlocked.
	It stores both a port and protocol, and is initialized from a string representation.
	"""
	TCP = 'tcp'
	UDP = 'udp'

	# portspec can be (where 'nnn' is a port number in string format):
	# - 'nnn' - a TCP port
	# - 'T:nnn' - a TCP port ('T' can be upper or lower case)
	# - 'U:nnn' - a UDP port ('U' can be upper or lower case)
	def __init__(self, portspec):
		"""Initialise the PortSpec object with the protocol and port, based on portspec.

		portspec can be (where 'nnn' is a port number in string format):
		'nnn' - a TCP port
		'T:nnn' - a TCP port ('T' can be upper or lower case)
		'U:nnn' - a UDP port ('U' can be upper or lower case)

		:param portspec: The portspec as per above
		:type portspec: str
		:raises ValueError: An invalid port type is specified
		:raises ValueError: An invalid port number is specified
		"""
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
	"""An class to load a configuration file"""
	DEFAULT_IPV4_ALLOW = '10.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.168.0.0/16'
	DEFAULT_IPV6_ALLOW = 'fe80::/10'
	DEFAULT_SEQUENCE_TIMEOUT = 10
	DEFAULT_DOOR_TIMEOUT = 30
	IPv4 = socket.AF_INET
	IPv6 = socket.AF_INET6

	#
	# Load the configuration file. This initializes all the remaining
	# variables in self, beyond what was initialized in the constructor.
	#
	def __init__(self, config_file: str, firewall: str):
		"""Load the configuration file, and store the values as attributes.

		Only one save_file option is loaded - the one under [firewall].

		:param config_file: The path to the configuration file
		:type config_file: str
		:param firewall: The type of firewall, used to determine the value of save_file
		:type firewall: str
		:raises ValueError: Any missing values encountered
		"""
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
		self.ipv4_allow = self.ParseNetworks(
			Config.IPv4,
			config.get(
				'ipv4',
				'allow',
				fallback=Config.DEFAULT_IPV4_ALLOW
			).split()
		)
		self.ipv6_allow = self.ParseNetworks(
			Config.IPv6,
			config.get(
				'ipv6',
				'allow',
				fallback=Config.DEFAULT_IPV6_ALLOW
			).split()
		)

		# save file where persistent rules are saved
		self.save_file = config.get(
			firewall,
			'save_file',
			fallback=''
		)

	@staticmethod
	def ParseNetworks(ipv, network_list):
		"""Check that network_list is a valid list of IPv4 or IPv6 addresses, depending on the ipv parameter.

		If any address is invalid, the ipaddress module will raise an exception. Any string format supported by the ipaddress module is allowed.

		A list of strings is returned in slash notation (e.g. 192.168.1.0/24), regardless of how the input was formatted.

		:param ipv: One of Config.IPv4 or Config.IPv6
		:type ipv: socket.AddressFamily
		:param network_list: List of networks to verify
		:type network_list: list[str]
		:return: A list of strings in slash notation sorted by network
		:rtype: list[str]
		"""
		# Loop over each provided network, and verify it is valid by using
		# the ipaddress module
		if ipv == Config.IPv4:
			net_list = [ipaddress.IPv4Network(net) for net in network_list]
		elif ipv == Config.IPv6:
			net_list = [ipaddress.IPv6Network(net) for net in network_list]
		else:
			raise ValueError(f'Invalid value for ipv parameter: {ipv}')

		return [str(net) for net in sorted(net_list) ]

class Firewall(ABC):
	def __init__(self, config_file: str, firewall: str):
		# load configuration file
		self.config = Config(config_file, firewall)

	@abstractmethod
	def CreateAllRules(self) -> None:
		"""Create all the firewall rules based on loaded configuration."""
		pass

	@abstractmethod
	def DumpRules(self) -> None:
		"""Print all rules previously generated by CreateAllRules()."""
		pass

	@abstractmethod
	def SavePersistent(self) -> None:
		"""Save the rules previously generated by CreateAllRules(), to the output file as per the loaded configuration."""
		pass
