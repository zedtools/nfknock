#!/usr/bin/env python3

import sys
import subprocess
import socket
from typing import List, Optional

from base import Config, PortSpec, Firewall

class IPTables(Firewall):
	def __init__(self, ipv: socket.AddressFamily, config_file: str):
		"""A class to create iptables/ip6tables rules for port knocking.

		Call the constructor with a configuration file, the call the CreateAllRules()
		to apply the iptables rules, followed by SavePersistent() to persist the
		rules across reboots.

		:param ipv: One of IPTables.IPv4 or IPTables.IPv6, depending on whether IPv6 or IPv6 rules are to be created
		:type ipv: socket.AddressFamily
		:param config_file: The path to the configuration file
		:type config_file: str
		:raises ValueError: [description]
		"""
		self.ipv = ipv

		# set up variables for things that differ between IPv4 and IPv6
		if self.ipv == Config.IPv4:
			self.iptables = "iptables"
			self.iptables_save = "iptables-save"
		elif self.ipv == Config.IPv6:
			self.iptables = "ip6tables"
			self.iptables_save = "ip6tables-save"
		else:
			raise ValueError("Invalid ipv parameter: " + str(ipv))

		super().__init__(config_file, self.iptables)

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
		self.CUSTOM_GATE_CHAINS: List[str] = [ ]
		self.CUSTOM_AUTH_LABELS: List[str] = [ ]

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

		# set knocking ports and timeouts
		self.SetKnockingPorts(knock_sequence=self.config.sequence, unlock_port=self.config.door)
		self.SetTimeout(knock_timeout=self.config.sequence_timeout, final_timeout=self.config.door_timeout)

		# set IPv4/IPv6 specific options
		if self.ipv == Config.IPv4:
			self.allowed_networks = self.config.ipv4_allow
		elif self.ipv == Config.IPv6:
			self.allowed_networks = self.config.ipv6_allow

	def SetICMPv6(self):
		"""Set ICMPv6 rules in iptables. These are required for IPv6 to work."""
		# As per RFC 4890 section 4.4.1
		if self.ipv == Config.IPv6:
			for icmpv6_type in [1, 2, 3, 4, 133, 134, 135, 136, 141, 142, 148, 149]:
				self.AppendToChain("INPUT", [
					"--protocol", "icmpv6",
					"--icmpv6-type", str(icmpv6_type),
					"--jump", "ACCEPT"
				])

	def AllowTransientNetworks(self, network_list: List[str]):
		"""Temporarily allow connections from a network until the next reboot
		(or when iptables rules are recreated again). VerifyNetworks() is
		called to ensure network_list contains valid addresses.

		:param network_list: List of networks to allow
		:type network_list: list[str]
		"""
		network_list = Config.ParseNetworks(self.ipv, network_list)

		rules: List[List[str]] = []
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

	def InitTransientNetworks(self):
		"""Initialize the PREKNOCK chain for the first time. This method can
		also be called to clear any previously added transient networks,
		which were added via AllowTransientNetworks().
		"""
		self.RunIPTables(["--flush", self.PREKNOCK])
		self.AppendToChain(self.PREKNOCK, [ "--jump", "RETURN" ])

	def SetKnockingPorts(self, knock_sequence: List[PortSpec] = [], unlock_port: PortSpec = PortSpec("T:22")):
		"""Initialize the sequence of knocking ports, and the final port to be unlocked.

		:param knock_sequence: A list PortSpec objects, each representing one knock, defaults to []
		:type knock_sequence: list[PortSpec], optional
		:param unlock_port: The final port to be unlocked after the correct knock sequence, defaults to PortSpec("T:22")
		:type unlock_port: PortSpec, optional
		"""
		self.knock_sequence = knock_sequence
		self.unlock_port = unlock_port

		# Generate one GATE chain and AUTH label for each port in
		# knock_sequence
		self.CUSTOM_GATE_CHAINS = []
		self.CUSTOM_AUTH_LABELS = []
		for i in range(len(knock_sequence)):
			self.CUSTOM_GATE_CHAINS.append(self.GATE_NAME + str(i + 1))
			self.CUSTOM_AUTH_LABELS.append(self.LABEL_NAME + str(i + 1))

	def SetTimeout(self, knock_timeout: int, final_timeout: int):
		"""Set the port knock timeouts.

		:param knock_timeout: The timeout, in seconds, between each port knock. If this timeout expires between knocks, the knock sequence is reset to the first knock.
		:type knock_timeout: int
		:param final_timeout: The timeout, in seconds, for which self.unlock_port is open, after the entire knock sequence is received. This value prevents unlock_port from staying open indefinitely if no incoming connection is received.
		:type final_timeout: int
		"""
		self.knock_timeout = knock_timeout
		self.final_timeout = final_timeout

	def RunIPTables(self, params: List[str]):
		"""Run iptables with the parameters provided in the params argument.

		:param params: List of command-line parameters
		:type params: list[str]
		"""
		print("Running: " + " ".join([self.iptables] + params))
		subprocess.check_call([self.iptables] + params)

	def DumpRules(self):
		"""Display all the iptables rules to stdout."""
		self.RunIPTables(["--list-rules"])

	def SavePersistent(self):
		"""Save the iptables rules so that they persist across reboots."""
		# zero the packet and byte counters, so that they are initalized
		# to zero on each reboot
		self.RunIPTables(["--zero"])

		# save the iptables rules
		output = subprocess.check_output([self.iptables_save])

		# write the iptables rules to self.config.save_file
		with open(self.config.save_file, "w") as f:
			f.write(output.decode(sys.stdout.encoding))

	def Flush(self):
		"""Flush all chains in iptables, and set the policy for built-in chains
		to ACCEPT. Other rules in the custom chains will drop packets if they
		do not meet the port knocking criteria.
		"""
		for chain in self.BUILTIN_CHAINS:
			self.RunIPTables(["--policy", chain, "ACCEPT"])

		# Flush all rules, and delete all custom chains
		self.RunIPTables(["--flush"])
		self.RunIPTables(["--delete-chain"])

	def CreateChain(self, chain: str):
		"""Create a single chain in iptables

		:param chain: The name of the new chain
		:type chain: str
		"""
		self.RunIPTables(["--new-chain", chain])

	def PrependToChain(self, chain: str, rule_list: List[str]):
		"""Prepend (insert) a single rule to a chain. This is equivalent to running:

		iptables -I <chain> <rule...>

		:param chain: The chain to which the rule is to be prepended
		:type chain: str
		:param rule_list: An array of strings, representing the rule to add
		:type rule_list: list[str]
		"""
		self.RunIPTables(["--insert", chain] + rule_list)

	def AppendToChain(self, chain: str, rule_list: List[str]):
		"""Append a single rule to a chain. This is equivalent to running:

		iptables -A <chain> <rule...>

		:param chain: The chain to which the rule is to be appended
		:type chain: str
		:param rule_list: An array of strings, representing the rule to add
		:type rule_list: list[str]
		"""
		self.RunIPTables(["--append", chain] + rule_list)

	def SetupLogging(self):
		"""Set up the logging chains. This logs the iptables command and chain
		which triggered the log, plus details of the packet.

		This is currently hardcoded with --limit 5/min. This prevents the
		log from being flooded, so keep in mind that some packets may not be
		logged during testing.
		"""
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

	def CreateChains(self):
		"""Create all custom chains required for port knocking"""
		for chain in self.CUSTOM_CHAINS + self.CUSTOM_GATE_CHAINS:
			self.CreateChain(chain)

	def CreateLocalInputChainRules(self):
		"""Set up the base rules in the INPUT chain"""
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

	def CreateGateRules(self, gate: str, protocol: str, port: int, prev_label: Optional[str] = None, new_label: Optional[str] = None, fail_chain: Optional[str] = None, success_chain: Optional[str] = None):
		"""Create the rules for an individual GATE. A packet must pass the checks in
		the gate, which means it must match the required protocol and port, and
		have the label prev_label set.

		If the checks pass, then either set new_label or jump to success_chain.
		Both the new_label and success_chain parameters cannot both be set.

		If the checks fail, jump to fail_chain.

		:param gate: The name of the gate (the name of the iptables chain)
		:type gate: str
		:param protocol: A packet with this protcol must be received to pass this gate
		:type protocol: str
		:param port: A packet with this port must be received to pass this gate
		:type port: int
		:param prev_label: Check for this label using the iptables recent module. If found, remove the label and proceed. If not found, do not pass this gate. If this parameter is not given, skip this check and proceed to the next check, defaults to None
		:type prev_label: str, optional
		:param new_label: Set this label using the iptables recent module, and then drop the packet. If this parameter is set, then the success_chain must be None. If this paramter is not provided, drop the packet and log it, defaults to None
		:type new_label: str, optional
		:param fail_chain: Jump to this chain if the packet fails the checks in this gate, defaults to None
		:type fail_chain: str, optional
		:param success_chain: Jump to this chain if the packet passses the checks in this gate. If this parameter is set, then the new_label must be None, defaults to None
		:type success_chain: str, optional
		:raises ValueError: If fail_chain is not specified
		:raises ValueError: If neither new_label nor success_chain is specified
		:raises ValueError: If both new_label and success_chain are specified
		"""
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

	def CreateKnockRule(self, chain: str, timeout: int, label: str, new_chain: str):
		"""Check whether a knock (or the final packet) arrived in the time allowed.
		This is done by using the iptables recent module, and checking how long
		ago the previous gate's label was set.

		If the label was set less than timeout seconds ago, jump to new_chain,
		otherwise continue to the next rule.

		:param chain: The chain in which to create the rule
		:type chain: str
		:param timeout: Timeout, in seconds. If label was set longer than than this time ago, then consider the check failed.
		:type timeout: int
		:param label: Check for this label
		:type label: str
		:param new_chain: Jump to ths chain if the label is set
		:type new_chain: str
		"""
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
		"""This is where the knocking chains and rules are set up. This method
		contains the top-level logic for port knocking, and it calls all the
		other methods needed to set up the entire heirarchy of rules.
		"""
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

	def CreateFinalRules(self):
		"""Create final rules needed after the port knocking rules and chains
		have been created, Currently this simply adds a rule to the INPUT
		chain to jump to the KNOCKING chain.

		It also appends a jump to LOGDROP as a fail-safe. This last rule
		should never be invoked, but it may be if there is a problem with the
		KNOCKING chain rules. Since the INPUT chain has a policy of ACCEPT,
		we do not want any packets accidentially slipping through.
		"""
		# Jump to the knocking chain to check for port knocks
		self.AppendToChain(self.INPUT, ["--jump", self.KNOCKING])

		# Drop everything else
		self.AppendToChain(self.INPUT, ["--jump", self.LOGDROP])

	def CreateAllRules(self):
		"""Top level method to create all the iptables rules. This includes the
		base rules, plus the rules specific to port knocking.
		"""
		self.Flush()
		self.CreateChains()
		self.SetupLogging()
		self.CreateLocalInputChainRules()
		self.SetICMPv6()
		self.CreateKnockingRules()
		self.CreateFinalRules()

