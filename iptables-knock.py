#!/usr/bin/env python3

import getpass
import sys
import subprocess
import socket
import ipaddress
import configparser

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

class IPTables:
	IPv4 = socket.AF_INET
	IPv6 = socket.AF_INET6
	DEFAULT_IPV4_SAVE = "/etc/iptables/rules.v4"
	DEFAULT_IPV6_SAVE = "/etc/iptables/rules.v6"
	DEFAULT_IPV4_ALLOW = '10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16'
	DEFAULT_IPV6_ALLOW = 'fe80::/10'
	DEFAULT_SEQUENCE_TIMEOUT = 10
	DEFAULT_DOOR_TIMEOUT = 30

	def __init__(self, ipv, config_file):
		self.ipv = ipv

		# iptables chains
		self.FORWARD = "FORWARD"
		self.INPUT = "INPUT"
		self.OUTPUT = "OUTPUT"

		self.KNOCKING = "KNOCKING"
		self.LOGACCEPT = "LOGACCEPT"
		self.LOGDROP = "LOGDROP"
		self.PASSED = "PASSED"

		self.BUILTIN_CHAINS = [
			self.FORWARD,
			self.INPUT,
			self.OUTPUT
		]

		self.CUSTOM_CHAINS = [
			self.KNOCKING,
			self.LOGACCEPT,
			self.LOGDROP,
			self.PASSED
		]

		# these are dynamically generated chains and lables, depending
		# on how many knocking ports there are
		self.GATE_NAME = "GATE"
		self.LABEL_NAME = "AUTH"
		self.CUSTOM_GATE_CHAINS = [ ]
		self.CUSTOM_AUTH_LABELS = [ ]

		# the logging chains - each of these log the packet, then jump
		# to the chain specified in self.log_target
		self.LOG_CHAINS = [
			self.LOGACCEPT,
			self.LOGDROP
		]

		# after logging, jump to target
		self.log_target = {
			self.LOGACCEPT: "ACCEPT",
			self.LOGDROP: "DROP"
		}

		# set up variables for things that differ between IPv4 and IPv6
		if self.ipv == IPTables.IPv4:
			self.iptables = "iptables"
			self.iptables_save = "iptables-save"
		elif self.ipv == IPTables.IPv6:
			self.iptables = "ip6tables"
			self.iptables_save = "ip6tables-save"
		else:
			raise ValueError("Invalid ipv parameter: " + ipv)

		# call LoadConfig to set other defaults, and load configuration file
		self.LoadConfig(config_file)

	def LoadConfig(self, config_file):
		config = configparser.ConfigParser()
		config.read(config_file)

		# knock sequence:
		# split on whitespace and convert each value to int
		sequence = list(map(
			lambda x: int(x),
			config.get('knock', 'sequence', fallback='').split()
		))

		if not sequence:
			raise ValueError('Configuration option "sequence" must be set under [knock]')

		# knock timeout between each knock in knock_sequence
		# default: 10
		sequence_timeout = int(config.get('knock', 'sequence_timeout', fallback=IPTables.DEFAULT_SEQUENCE_TIMEOUT))

		# the port to open after the knock sequence is received
		door = int(config.get('knock', 'door', fallback=0))

		if not door:
			raise ValueError('Configuration option "door" must be set under [knock]')

		# how long the door stays open if no connection is received
		# default: 30
		door_timeout = int(config.get('knock', 'door_timeout', fallback=IPTables.DEFAULT_DOOR_TIMEOUT))


		# allowed networks: each is a whitespace separate list
		# default: all private addresses
		ipv4_allow = config.get(
			'ipv4',
			'allow',
			fallback='10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16'
		).split()
		ipv6_allow = config.get(
			'ipv6',
			'allow',
			fallback='fe80::/10'
		).split()

		# save files where persistent rules are saved
		ipv4_save = config.get(
			'ipv4',
			'save_file',
			fallback=IPTables.DEFAULT_IPV4_SAVE
		)
		ipv6_save = config.get(
			'ipv6',
			'save_file',
			fallback=IPTables.DEFAULT_IPV6_SAVE
		)

		# set knocking ports and timeouts
		self.SetKnockingPorts(knock_sequence=sequence, unlock_port=door)
		self.SetTimeout(knock_timeout=sequence_timeout, final_timeout=door_timeout)

		# set IPv4/IPv6 specific options
		if self.ipv == socket.AF_INET:
			self.SetAllowedNetworks(ipv4_allow)
			self.save_file = ipv4_save
		elif self.ipv == socket.AF_INET6:
			self.SetAllowedNetworks(ipv6_allow)
			self.save_file = ipv6_save

	def SetICMPv6(self):
		# As per RFC 4890 section 4.4.1
		if self.ipv == IPTables.IPv6:
			for icmpv6_type in [1, 2, 3, 4, 133, 134, 135, 136, 141, 142, 148, 149]:
				self.AppendToChain("INPUT", [
					"--protocol", "icmpv6",	
					"--icmpv6-type", str(icmpv6_type),
					"--jump", "ACCEPT"
				])

	# Allow self.allowed_networks to be overridden, and user-defined networks
	# to be allowed in the INPUT chain
	def SetAllowedNetworks(self, network_list):
		# Loop over each provided network, and verify it is valid by using
		# the ipaddress module
		for network in network_list:
			if self.ipv == IPTables.IPv4:
				n = ipaddress.IPv4Network(network)
			elif self.ipv == IPTables.IPv6:
				n = ipaddress.IPv6Network(network)
		
		# all addresses were valid networks, so save the list
		self.allowed_networks = network_list
		

	def SetKnockingPorts(self, knock_sequence=[], unlock_port=22):
		self.knock_sequence = knock_sequence
		self.unlock_port = unlock_port

		# Generate one GATE chain for each port in knock_sequence
		self.CUSTOM_GATE_CHAINS = []
		self.CUSTOM_AUTH_LABELS = []
		for i in range(len(knock_sequence)):
			self.CUSTOM_GATE_CHAINS.append(self.GATE_NAME + str(i + 1))
			self.CUSTOM_AUTH_LABELS.append(self.LABEL_NAME + str(i + 1))

	def SetTimeout(self, knock_timeout, final_timeout):
		self.knock_timeout = knock_timeout
		self.final_timeout = final_timeout

	def RunIPTables(self, params):
		print("Running: " + " ".join([self.iptables] + params))
		subprocess.check_call([self.iptables] + params)
	
	def DumpRules(self):
		self.RunIPTables(["--list-rules"])

	def SavePersistent(self):
		self.RunIPTables(["--zero"])
		output = subprocess.check_output([self.iptables_save])

		with open(self.save_file, "w") as f:
			f.write(output.decode(sys.stdout.encoding))

	def Flush(self):
		for chain in self.BUILTIN_CHAINS:
			self.RunIPTables(["--policy", chain, "ACCEPT"])

		# Flush all rules, and delete all custom chains
		self.RunIPTables(["--flush"])
		self.RunIPTables(["--delete-chain"])

	def CreateChain(self, chain):
		self.RunIPTables(["--new-chain", chain])

	def AppendToChain(self, chain, rule_list):
		self.RunIPTables(["--append", chain] + rule_list)

	def SetupLogging(self):
		# log prefix will consist of the iptables command and chain,
		# e.g. "ip6tables-LOGDROP: "
		# save the iptables/ip6tables command here, and add the chain later
		log_prefix = self.iptables

		for chain in self.LOG_CHAINS:
			rules = [
				# Create log entry
				[
					"--match", "limit",
					"--limit", "5/min",
					"--jump", "LOG",
					"--log-prefix", log_prefix + "-" + chain + ": ",
					"--log-level", "notice"
				],
				# Jump to target
				["--jump", self.log_target[chain]]
			]

			for rule in rules:
				self.AppendToChain(chain, rule)
			
	def CreateChains(self):
		for chain in self.CUSTOM_CHAINS + self.CUSTOM_GATE_CHAINS:
			self.CreateChain(chain)

	def CreateLocalInputChainRules(self):
		chain = self.INPUT

		rules = [
			# Allow already established connections
			[
				"--match", "conntrack",
				"--ctstate", "ESTABLISHED,RELATED",
				"--jump", "ACCEPT"
			],
			# Allow local connections (needed by some services)
			[
				"--in-interface", "lo",
				"--jump", "ACCEPT"
			]
		]

		# Allow local or user-defined networks
		for addr in self.allowed_networks:
			rules.append([
				"--source", addr, "--jump", "ACCEPT"
			])

		# Allow IPv6 multicast - not needed?
		#ip6tables -A INPUT -d ff00::/8 -j ACCEPT

		for rule in rules:
			self.AppendToChain(chain, rule)
	
	def CreateGateRules(self, gate, port, prev_label=None, new_label=None, fail_chain=None, success_chain=None):
		strPort = str(port)

		# Check for label from previous gate, If found, remove it and proceed to next rule
		if prev_label is not None:
			self.AppendToChain(gate, [
				"--match", "recent",
				"--name", prev_label,
				"--remove"
			])

		# Cannot have both new_label and success_chain specified
		if new_label is not None and success_chain is not None:
			raise ValueError("Cannot specify both new_label and success_chain parameters")

		# If the correct port is knocked, apply the new label if needed
		if new_label is not None:
			self.AppendToChain(gate, [
				"--protocol", "tcp",
				"--dport", strPort,
				"--match", "recent",
				"--set", "--name", new_label,
				"--jump", "DROP"
			])

		# If the correct port is knocked, jump to the given chain
		if success_chain is not None:
			self.AppendToChain(gate, [
				"--protocol", "tcp",
				"--dport", strPort,
				"--jump", success_chain]
			)

		# For any other port, go back to fail_chain
		self.AppendToChain(gate, ["-j", fail_chain])

	def CreateKnockRule(self, chain, timeout, label, new_chain):
		self.AppendToChain(
			chain, [
				"--match", "recent",
				"--rcheck",
				"--seconds", str(timeout),
				"--name", label,
				"--jump", new_chain
			]
		)

	def CreateKnockingRules(self):
	
		# port knocking rules:
		# GATE1: This is where we start. We are waiting for the first port in the knocking sequence.
		# GATE2: The first port has matched, and we are waiting for the second port.
		# GATE3: ...and so on for each port in the knocking sequence.
		# PASSED: Allow connection to unlock port, and reset the knocking sequence as soon as we get it.
		# 
		# Each time we pass a gate, a custom AUTH label gets applied.
		# AUTH1: GATE1 has been passed
		# AUTH2: GATE2 has been passed
		# AUTH3: ...and so on. If we reached the last label, this mean the next expected port is the unlocked port.
		#
		# The AUTH labels tell us what gate the previous packet packet reached. This lets us perform the check for the
		# next gate. For example, if a new packet is received, and AUTH2 is set, this means we need to check GATE3 for
		# this packet.
		#
		# If an unexpected packet is received at GATE1, it is logged.
		#
		# Anywhere along this sequence after GATE1, if an unexpected packet is received we jump back to GATE1 to check if it
		# was the first port of a new sequence. If the first port does not match, GATE1 will log the packet.
		for i in range(len(self.CUSTOM_GATE_CHAINS)):
			# For each gate, check to see if we got the next port in the knocking sequence
			gate = self.CUSTOM_GATE_CHAINS[i]      # current gate
			port = self.knock_sequence[i]          # expected port
			new_label = self.CUSTOM_AUTH_LABELS[i] # label to apply if the expected port is received
			prev_label = None                      # previous label to check (None = do not check for previous label)
			fail_chain = self.LOGDROP              # for GATE1, any unexpected packet is logged
			if i > 0:
				prev_label = self.CUSTOM_AUTH_LABELS[i - 1] # expect to see label from previous gate
				fail_chain = self.CUSTOM_GATE_CHAINS[0]     # unexpected packet: jump back to GATE1 to reset the sequence

			# This creates rules for each gate, to:
			# - check if the correct port is received in the knocking sequence
			# - check if the label was applied from the previous gate (so we know we should be at this gate)
			# - apply the new label to indicate that this gate has been passed
			# - jump back to the first gate to either reset the knocking sequence, or log the packet if we
			#   are already at the first gate
			self.CreateGateRules(gate, port, prev_label=prev_label, new_label=new_label, fail_chain=fail_chain)

		# This rule checks the AUTH label to verify that we got through all the above gats. If so, allow the unlock_port
		# through, otherwise go back to the first gate
		self.CreateGateRules(
			self.PASSED,
			self.unlock_port,
			prev_label=self.CUSTOM_AUTH_LABELS[-1],
			fail_chain=self.CUSTOM_GATE_CHAINS[0],
			success_chain=self.LOGACCEPT
		)

		# TODO: Does this really need to be in reverse order? Rewrite in forward order to see if it is easier to understand.
		# Set up the KNOCKING chain. This chain is the main entry point where all the above gates are checked.
		# The rules in this chain are done in reverse, i.e. see if we have reached the final port, then see if
		# we are at the last gate, then the second-last gate, and so on.
		# If the AUTH labels are set correctly, this probably does not need to be done in reverse order,
		# but it does make the iptables rules easier to read.
		for i in range(len(self.CUSTOM_GATE_CHAINS)):
			timeout = self.final_timeout            # timeout to receive unlock_port after knocking sequence
			label = self.CUSTOM_AUTH_LABELS[-1 - i] # check to make sure the AUTH label from the previous gate was set
			new_chain = self.PASSED                 # jump to PASSED chain to allow unlock_port through

			# For i = 0, create the rule to all unlock_port through. This is done by checking if the final AUTH
			# label is set, and if so, jumping to the PASSED chain.
			# For all other values of i, check if the AUTH label from the previous gate has been set. If so,
			# jump to the next gate in the sequence
			if i > 0:
				timeout = self.knock_timeout            # timeout for each port in the knock sequence
				new_chain = self.CUSTOM_GATE_CHAINS[-i] # jump to the next gate in the knock sequence

			# This creates a rule to check each possible AUTH label:
			# - For each value of the AUTH label, jump to the next gate (e.g. if AUTH2 is set, jump to GATE 3)
			# - A timeout parameter is used to expire AUTH labels. This resets the knocking sequence if the next
			#   packet is not received in a timely fashion.
			self.CreateKnockRule(self.KNOCKING, timeout=timeout, label=label, new_chain=new_chain)

		# If none of the AUTH labels were set, then jump to GATE1 to check the knocking sequence
		# from the start.
		self.AppendToChain(self.KNOCKING, ["--jump", self.CUSTOM_GATE_CHAINS[0]])

	def CreateFinalRules(self):
		# Jump to the knocking chain to check for port knocks
		self.AppendToChain(self.INPUT, ["--jump", self.KNOCKING])

		# Drop everything else
		self.AppendToChain(self.INPUT, ["--jump", self.LOGDROP])
	
	def CreateAllRules(self):
		self.Flush()
		self.CreateChains()
		self.SetupLogging()
		self.CreateLocalInputChainRules()
		self.SetICMPv6()
		self.CreateKnockingRules()
		self.CreateFinalRules()

CheckRoot()

config_file = 'iptables-knock.cfg'
ip4 = IPTables(IPTables.IPv4, config_file)
ip6 = IPTables(IPTables.IPv6, config_file)

for iptables in [ip4, ip6]:
	# create iptables tules
	iptables.CreateAllRules()

	# list rules
	iptables.DumpRules()

	# prompt user to save rules
	if input_verify("Do you wish to save this configuration to " + iptables.save_file):
		iptables.SavePersistent()
		print("Configuration saved to " + iptables.save_file)

