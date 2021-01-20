#!/usr/bin/env python3

import string
import subprocess
import re

from base import Config, PortSpec, Firewall

class NFTables(Firewall):
	conf_template = 'templates/nftables.conf'

	def __init__(self, config_file: str):
		"""A class to generate nftables rules for port knocking.

		Call the constructor with a configuration file, the call the CreateAllRules()
		to apply the iptables rules, followed by SavePersistent() to persist the
		rules across reboots.

		:param config_file: The path to the configuration file
		:type config_file: str
		"""
		super().__init__(config_file, 'nftables')

		# Initalize an empty rulelist
		self.rulelist = ''

	def KnockRules(self, prefix: str = '\t\t'):
		"""Return a multi-line string with the knock rules. Each line is indented by prefix.

		:param prefix: The prefix to indent each line, defaults to '\t\t'
		:type prefix: str, optional
		:return: The generated rules
		:rtype: str
		"""
		rules: list[str] = []

		for i, p in enumerate(self.config.sequence, start=1):
			rules.append(f'{p.protocol} dport {p.port} mark set {i}')

		return prefix + ("\n" + prefix).join(rules)

	def CreateAllRules(self):
		"""Create the complete set of nftables rules based on loaded configuration."""
		num_knocks = len(self.config.sequence)
		if num_knocks >= 8:
			# nftables.conf uses a custom algorithm (decrement_ct_mark),
			# which limits the number of knocks allowed.
			raise ValueError(f'nftables.conf supports 7 knocks, {num_knocks} knocks requested')

		with open(self.conf_template) as f:
			# Load the templace configuration and substitute variables names
			template = string.Template(f.read())
			data = template.safe_substitute(
				nfk_allow_ipv4=", ".join(self.config.ipv4_allow),
				nfk_allow_ipv6=", ".join(self.config.ipv6_allow),
				nfk_knock_timeout=self.config.sequence_timeout,
				nfk_knock_rules=self.KnockRules(),
				nfk_last_knock=num_knocks,
				nfk_allow_protocol=self.config.door.protocol,
				nfk_allow_port=self.config.door.port,
				nfk_allow_timeout=self.config.door_timeout,
			)

			# Check to make sure all $nfk... variables were substituted.
			# Typos may mean some are missed.
			match = re.findall('\$nfk\w*|\${nfk\w+}', data)
			if match:
				# One or more $nft...  variables were not substituted.
				# Raise an error with the list of (unique) variables names.
				raise ValueError(f'Undefined variables in {self.conf_template}: {", ".join(set(match))}')
			self.rulelist = data

	def DumpRules(self):
		"""Display generated rules to stdout"""
		print(self.rulelist)

	def SavePersistent(self):
		"""Write the nftables rules to self.config.save_file"""
		with open(self.config.save_file, "w") as f:
			f.write(self.rulelist)

		# Check to ensure nftables service is enabled
		try:
			subprocess.check_call(['systemctl', '-q', 'is-enabled', 'nftables'])
		except subprocess.CalledProcessError as cpe:
			print("Enabling nftables service to load rules on boot")
			subprocess.check_call(['systemctl', '-q', 'enable', 'nftables'])

		# Load the saved rules into nftables
		try:
			cmd = ['nft', '-f', self.config.save_file]
			print(f'Running {" ".join(cmd)} to load rules')
			subprocess.check_call(['nft', '-f', self.config.save_file])
		except subprocess.CalledProcessError as cpe:
			print(f'Error loading nft rules (return code {cpe.returncode}. Please try running manually.')

