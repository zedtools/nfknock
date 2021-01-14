#!/usr/bin/env python3

#
# The main NFTables class.
#
# Call the constructor with a configuration file, the call the CreateAllRules()
# to apply the iptables rules, followed by SavePersistent() to persist the
# rules across reboots.
#
class NFTables:
	#
	# Constructor parameters:
	# - config_file: The path to the configuration file
	#
	def __init__(self, config_file):
		self.config = Config(config_file)

		self.config.sequence # list of PortSpec
		self.config.door # PortSpec
		self.config.sequence_timeout # int
		self.config.door_timeout # int
		self.config.nftables_save_file # string

		Config.VerifyNetworks(Config.IPv4, self.config.ipv4_allow) # list of string
		Config.VerifyNetworks(Config.IPv6, self.config.ipv6_allow) # list of string

		# use the above to generate nftables rules
