#!/usr/bin/env python3

import getpass
import sys
import subprocess
import socket
import ipaddress
import configparser
import traceback

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

#
# The main IPTables class.
#
# Call the constructor with a configuration file, the call the CreateAllRules()
# to apply the iptables rules, followed by SavePersistent() to persist the
# rules across reboots.
#
class IPTables:
	IPv4 = socket.AF_INET
	IPv6 = socket.AF_INET6
	DEFAULT_IPV4_SAVE = "/etc/iptables/rules.v4"
	DEFAULT_IPV6_SAVE = "/etc/iptables/rules.v6"
	DEFAULT_IPV4_ALLOW = '10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16'
	DEFAULT_IPV6_ALLOW = 'fe80::/10'
	DEFAULT_SEQUENCE_TIMEOUT = 10
	DEFAULT_DOOR_TIMEOUT = 30

	#
	# Constructor parameters:
	# - ipv:         One of IPTables.IPv4 or IPTables.IPv6, depending on
	#                whether IPv6 or IPv6 rules are to be created.
	# - config_file: The path to the configuration file
	#
	def __init__(self, ipv, config_file):
		self.ipv = ipv

		# iptables chains
		self.FORWARD = "FORWARD"
		self.INPUT = "INPUT"
		self.OUTPUT = "OUTPUT"

		self.PREKNOCK = "PREKNOCK"
		self.KNOCKING = "KNOCKING"
		self.LOGACCEPT_KNOCK = "LOGACCEPTKNOCK"
		self.LOGACCEPT_PREKNOCK = "LOGACCEPTPREKNOCK"
		self.LOGDROP = "LOGDROP"
		self.PASSED = "PASSED"

		self.BUILTIN_CHAINS = [
			self.FORWARD,
			self.INPUT,
			self.OUTPUT
		]

		self.CUSTOM_CHAINS = [
			self.PREKNOCK,
			self.KNOCKING,
			self.LOGACCEPT_KNOCK,
			self.LOGACCEPT_PREKNOCK,
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
			self.LOGACCEPT_KNOCK,
			self.LOGACCEPT_PREKNOCK,
			self.LOGDROP
		]

		# after logging, jump to target chain
		self.log_target = {
			self.LOGACCEPT_KNOCK: "ACCEPT",
			self.LOGACCEPT_PREKNOCK: "ACCEPT",
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
		if config_file:
			self.LoadConfig(config_file)

	#
	# Load the configuration file. This initializes all the remaining
	# variables in self, beyond what was initialized in the constructor.
	#
	def LoadConfig(self, config_file):
		config = configparser.ConfigParser()
		config.read(config_file)

		# knock sequence:
		# split on whitespace and convert each value to a PortSpec object
		sequence = list(map(
			lambda x: PortSpec(x),
			config.get('knock', 'sequence', fallback='').split()
		))

		if not sequence:
			raise ValueError('Configuration option "sequence" must be set under [knock]')

		# knock timeout between each knock in knock_sequence
		# default: 10
		sequence_timeout = int(config.get('knock', 'sequence_timeout', fallback=IPTables.DEFAULT_SEQUENCE_TIMEOUT))

		# the port to open after the knock sequence is received
		door = PortSpec(config.get('knock', 'door', fallback='0'))

		if not door.port:
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

	#
	# Set ICMPv6 rules in iptables. These are required for IPv6 to work.
	#
	def SetICMPv6(self):
		# As per RFC 4890 section 4.4.1
		if self.ipv == IPTables.IPv6:
			for icmpv6_type in [1, 2, 3, 4, 133, 134, 135, 136, 141, 142, 148, 149]:
				self.AppendToChain("INPUT", [
					"--protocol", "icmpv6",
					"--icmpv6-type", str(icmpv6_type),
					"--jump", "ACCEPT"
				])

	#
	# Verify that network_list is a valid list of IPv4 or IPv6 addresses,
	# depending on self.ipv.
	#
	# If any address is invalid, the ipaddress module will raise an exception.
	#
	def VerifyNetworks(self, network_list):
		# Loop over each provided network, and verify it is valid by using
		# the ipaddress module
		for network in network_list:
			if self.ipv == IPTables.IPv4:
				n = ipaddress.IPv4Network(network)
			elif self.ipv == IPTables.IPv6:
				n = ipaddress.IPv6Network(network)

	#
	# Allow self.allowed_networks to be overridden, and user-defined networks
	# to be allowed in the INPUT chain. This method sets self.allowed_networks
	# safely, calling VerifyNetworks() to check the addresses.
	#
	def SetAllowedNetworks(self, network_list):
		self.VerifyNetworks(network_list)

		# all addresses were valid networks, so save the list
		self.allowed_networks = network_list

	#
	# Temporarily allow connections from a network until the next reboot (or
	# when iptables rules are recreated again). VerifyNetworks() is called to
	# ensure network_list contains valid addresses.
	#
	def AllowTransientNetworks(self, network_list):
		self.VerifyNetworks(network_list)

		rules = []
		for addr in network_list:
			# Add each network to the self.PREKNOCK chain
			rules.append([
				"--source", addr, "--jump", self.LOGACCEPT_PREKNOCK
			])


		# Insert each rule at start of list in reverse order. This
		# ensures that the rules appear in the same order as in the
		# network_list array.
		rules.reverse()
		for rule in rules:
			self.PrependToChain(self.PREKNOCK, rule)

	#
	# Initialize the PREKNOCK chain for the first time. This method can
	# also be called to clear any previously added transient networks,
	# which were added via AllowTransientNetworks().
	#
	def InitTransientNetworks(self):
		self.RunIPTables(["--flush", self.PREKNOCK])
		self.AppendToChain(self.PREKNOCK, [ "--jump", "RETURN" ])

	#
	# Initialize the sequence of knocking ports, and the final port to be
	# unlocked.
	# Parameters:
	# - knock_sequence: A list PortSpec objects, each representing one knock
	# - unlock_port:    The final port to be unlocked after the correct knock
	#                   sequence
	#
	def SetKnockingPorts(self, knock_sequence=[], unlock_port=PortSpec("T:22")):
		self.knock_sequence = knock_sequence
		self.unlock_port = unlock_port

		# Generate one GATE chain and AUTH label for each port in
		# knock_sequence
		self.CUSTOM_GATE_CHAINS = []
		self.CUSTOM_AUTH_LABELS = []
		for i in range(len(knock_sequence)):
			self.CUSTOM_GATE_CHAINS.append(self.GATE_NAME + str(i + 1))
			self.CUSTOM_AUTH_LABELS.append(self.LABEL_NAME + str(i + 1))

	#
	# Set the port knock timeouts.
	# Parameters:
	# - knock_timeout: The timeout, in seconds, between each port knock.
	#                  If this timeout expires between knocks, the knock
	#                  sequence is reset to the first knock.
	# - final_timeout: The timeout, in seconds, for which self.unlock_port
	#                  is open, after the entire knock sequence is received.
	#                  This value prevents unlock_port from staying open
	#                  indefinitely if no incoming connection is received.
	#
	def SetTimeout(self, knock_timeout, final_timeout):
		self.knock_timeout = knock_timeout
		self.final_timeout = final_timeout

	#
	# Run iptables with the parameters provided in the params argument.
	# params is an array of strings.
	#
	def RunIPTables(self, params):
		print("Running: " + " ".join([self.iptables] + params))
		subprocess.check_call([self.iptables] + params)

	#
	# Display all the iptables rules to stdout.
	# If chain is provided, list only rules for that chain, otherwise for
	# all chains
	#
	def DumpRules(self, chain=None):
		if chain:
			self.RunIPTables(["--list-rules", chain])
		else:
			self.RunIPTables(["--list-rules"])

	#
	# Save the iptables rules so that they persist across reboots.
	#
	def SavePersistent(self):
		# zero the packet and byte counters, so that they are initalized
		# to zero on each reboot
		self.RunIPTables(["--zero"])

		# save the iptables rules
		output = subprocess.check_output([self.iptables_save])

		# write the iptables rules to self.save_file
		with open(self.save_file, "w") as f:
			f.write(output.decode(sys.stdout.encoding))

	#
	# Flush all chains in iptables, and set the policy for built-in chains
	# to ACCEPT. Other rules in the custom chains will drop packets if they
	# do not meet the port knocking criteria.
	#
	def Flush(self):
		for chain in self.BUILTIN_CHAINS:
			self.RunIPTables(["--policy", chain, "ACCEPT"])

		# Flush all rules, and delete all custom chains
		self.RunIPTables(["--flush"])
		self.RunIPTables(["--delete-chain"])

	#
	# Create a single chain in iptables
	#
	def CreateChain(self, chain):
		self.RunIPTables(["--new-chain", chain])

	#
	# Prepend (insert) a single rule to a chain. This is equivalent to running
	# "iptables -I <chain> <rule...>".
	# Parameters:
	# - chain:     The chain to which the rule is to be appended
	# - rule_list: An array of strings, representing the rule to add
	#
	def PrependToChain(self, chain, rule_list):
		self.RunIPTables(["--insert", chain] + rule_list)

	#
	# Append a single rule to a chain. This is equivalent to running
	# "iptables -A <chain> <rule...>".
	# Parameters:
	# - chain:     The chain to which the rule is to be appended
	# - rule_list: An array of strings, representing the rule to add
	#
	def AppendToChain(self, chain, rule_list):
		self.RunIPTables(["--append", chain] + rule_list)

	#
	# Set up the logging chains. This logs the iptables command and chain
	# which triggered the log, plus details of the packet.
	#
	# This is currently hardcoded with --limit 5/min. This prevents the
	# log from being flooded, so keep in mind that some packets may not be
	# logged during testing.
	#
	def SetupLogging(self):
		# log prefix will consist of the iptables command and chain,
		# e.g. "ip6tables-LOGDROP: "
		# save the iptables/ip6tables command here, and add the chain later
		log_prefix = self.iptables

		# create a rule for each chain in self.LOG_CHAINS
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

	#
	# Create all custom chains required for port knocking
	#
	def CreateChains(self):
		for chain in self.CUSTOM_CHAINS + self.CUSTOM_GATE_CHAINS:
			self.CreateChain(chain)

	#
	# Set up the base rules in the INPUT chain
	#
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

		# Traverse the PREKNOCK chain for any user exceptions. Also call
		# InitTransientNetworks() to initialise the chain.
		self.InitTransientNetworks()
		rules.append([
			"--jump", self.PREKNOCK
		])

		# Allow IPv6 multicast - not needed?
		#ip6tables -A INPUT -d ff00::/8 -j ACCEPT

		for rule in rules:
			self.AppendToChain(chain, rule)

	#
	# Create the rules for an individual GATE. A packet must pass the checks in
	# the gate, which means it must match the required protocol and port, and
	# have the label prev_label set.
	#
	# If the checks pass, then either set new_label or jump to success_chain.
	# Both the new_label and success_chain parameters cannot both be set.
	#
	# If the checks fail, jump to fail_chain.
	#
	# Parameters:
	# - gate:          The name of the gate (the name of the iptables chain)
	# - protocol:      A packet with this protcol must be received to pass this gate
	# - port:          A packet with this port must be received to pass this gate
	# - prev_label:    (Optional) Check for this label using the iptables recent
	#                  module. If found, remove the label and proceed. If not
	#                  found, do not pass this gate. If this parameter is not
	#                  given, skip this check and proceed to the next check.
	# - new_label:     (Optional) Set this label using the iptables recent module,
	#                  and then drop the packet. If this parameter is set, then
	#                  the success_chain must be None.
	#                  If this paramter is not provided, drop the packet and log it.
	# - fail_chain:    Jump to this chain if the packet fails the checks in this gate.
	# - success_chain: (Optional) Jump to this chain if the packet passses the checks
	#                  in this gate. If this parameter is set, then the new_label
	#                  must be None.
	#
	def CreateGateRules(self, gate, protocol, port, prev_label=None, new_label=None, fail_chain=None, success_chain=None):
		strPort = str(port)

		# Ensure fail_chain is specified
		if fail_chain is None:
			raise ValueError("fail_chain parameter is mandatory")

		# One of new_label or success_chain must specified
		if new_label is None and success_chain is None:
			raise ValueError("One of new_label or success_chain must specified")

		# Cannot have both new_label and success_chain specified
		if new_label is not None and success_chain is not None:
			raise ValueError("Cannot specify both new_label and success_chain parameters")

		# Check for label from previous gate, If found, remove it and proceed to next rule
		if prev_label is not None:
			self.AppendToChain(gate, [
				"--match", "recent",
				"--name", prev_label,
				"--remove"
			])

		# If the correct port is knocked, apply the new label if needed
		if new_label is not None:
			self.AppendToChain(gate, [
				"--protocol", protocol,
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
		self.AppendToChain(gate, ["--jump", fail_chain])

	#
	# Check whether a knock (or the final packet) arrived in the time allowed.
	# This is done by using the iptables recent module, and checking how long
	# ago the previous gate's label was set.
	#
	# If the label was set less than timeout seconds ago, jump to new_chain,
	# otherwise continue to the next rule.
	#
	# Parameters:
	# - chain:     The chain in which to create the rule
	# - timeout:   Timeout, in seconds. If label was set longer than
	#              than this time ago, then consider the check failed
	# - label:     Check for this label
	# - new_chain: Jump to ths chain if the label is set
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

	#
	# This is where the knocking chains and rules are set up. This method
	# contains the top-level logic for port knocking, and it calls all the
	# other methods needed to set up the entire heirarchy of rules.
	#
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
			gate = self.CUSTOM_GATE_CHAINS[i]          # current gate
			protocol = self.knock_sequence[i].protocol # expected protocol
			port = self.knock_sequence[i].port         # expected port
			new_label = self.CUSTOM_AUTH_LABELS[i]     # label to apply if the expected port is received
			prev_label = None                          # previous label to check (None = do not check for previous label)
			fail_chain = self.LOGDROP                  # for GATE1, any unexpected packet is logged
			if i > 0:
				prev_label = self.CUSTOM_AUTH_LABELS[i - 1] # expect to see label from previous gate
				fail_chain = self.CUSTOM_GATE_CHAINS[0]     # unexpected packet: jump back to GATE1 to reset the sequence

			# This creates rules for each gate, to:
			# - check if the correct port is received in the knocking sequence
			# - check if the label was applied from the previous gate (so we know we should be at this gate)
			# - apply the new label to indicate that this gate has been passed
			# - jump back to the first gate to either reset the knocking sequence, or log the packet if we
			#   are already at the first gate
			self.CreateGateRules(gate, protocol, port, prev_label=prev_label, new_label=new_label, fail_chain=fail_chain)

		# This rule checks the AUTH label to verify that we got through all the above gates. If so, allow the unlock_port
		# through, otherwise go back to the first gate
		self.CreateGateRules(
			self.PASSED,
			self.unlock_port.protocol,
			self.unlock_port.port,
			prev_label=self.CUSTOM_AUTH_LABELS[-1],
			fail_chain=self.CUSTOM_GATE_CHAINS[0],
			success_chain=self.LOGACCEPT_KNOCK
		)

		# Set up the KNOCKING chain. Each rules checks to see if an AUTH label is
		# set, and if so, jump to to corresponding gate. Each successive AUTH
		# label represents successive knocks, while the final AUTH label means
		# that all kocks have been done, and unlock_port can be opened up.
		# - If AUTH1 is set, jump to GATE2
		# - If AUTH2 is set, jump to GATE3
		# - If the last AUTH label is set, jump to PASSED
		for i in range(len(self.CUSTOM_AUTH_LABELS)):
			# The current label (AUTH1, AUTH2, ...)
			label = self.CUSTOM_AUTH_LABELS[i]

			if i < len(self.CUSTOM_AUTH_LABELS) - 1:
				# For all AUTH labels but the last, jump to the next GATE
				new_chain = self.CUSTOM_GATE_CHAINS[i + 1]
				timeout = self.knock_timeout
			else:
				# For the last AUTH label, jump to PASSED.
				# Note that there is a different timeout here,
				# to open the unlock_port for a longer time
				# than allowed between knocks.
				new_chain = self.PASSED
				timeout = self.final_timeout

			# This creates a rule to check each possible AUTH label:
			# - For each value of the AUTH label, jump to the next gate
			# - A timeout parameter is used to expire AUTH labels. This
			#   resets the knocking sequence if the next packet is not
			#   received in a timely fashion.
			self.CreateKnockRule(self.KNOCKING, timeout=timeout, label=label, new_chain=new_chain)

		# If none of the AUTH labels were set, then jump to GATE1 to check the knocking sequence
		# from the start.
		self.AppendToChain(self.KNOCKING, ["--jump", self.CUSTOM_GATE_CHAINS[0]])

	#
	# Create final rules needed after the port knocking rules and chains
	# have been created, Currently this simply adds a rule to the INPUT
	# chain to jump to the KNOCKING chain.
	#
	# It also appends a jump to LOGDROP as a fail-safe. This last rule
	# should never be invoked, but it may be if there is a problem with the
	# KNOCKING chain rules. Since the INPUT chain has a policy of ACCEPT,
	# we do not want any packets accidentially slipping through.
	#
	def CreateFinalRules(self):
		# Jump to the knocking chain to check for port knocks
		self.AppendToChain(self.INPUT, ["--jump", self.KNOCKING])

		# Drop everything else
		self.AppendToChain(self.INPUT, ["--jump", self.LOGDROP])

	#
	# Top level method to create all the iptables rules. This includes the
	# base rules, plus the rules specific to port knocking.
	#
	def CreateAllRules(self):
		self.Flush()
		self.CreateChains()
		self.SetupLogging()
		self.CreateLocalInputChainRules()
		self.SetICMPv6()
		self.CreateKnockingRules()
		self.CreateFinalRules()

