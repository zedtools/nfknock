#!/usr/bin/env python3

import config
import iptables
import nftables

# verify we are running as root (needed to modify iptables rules)
config.CheckRoot()

# create IPTables objects, and load configuration file
config_file = 'nfknock.cfg'
ip4 = iptables.IPTables(config.Config.IPv4, config_file)
ip6 = iptables.IPTables(config.Config.IPv6, config_file)

for ipt in [ip4, ip6]:
	if ipt.save_file:
		# create iptables tules
		ipt.CreateAllRules()

		# list rules
		ipt.DumpRules()

		# prompt user to save rules
		if config.input_verify("Do you wish to save this configuration to " + ipt.save_file):
			ipt.SavePersistent()
			print("Configuration saved to " + ipt.save_file)

