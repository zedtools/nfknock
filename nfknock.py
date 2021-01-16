#!/usr/bin/env python3

import base
import iptables
import nftables

# verify we are running as root (needed to modify iptables rules)
base.CheckRoot()

# create IPTables objects, and load configuration file
config_file = 'nfknock.cfg'
all_fw : list[base.Firewall] = [
	iptables.IPTables(base.Config.IPv4, config_file),
	iptables.IPTables(base.Config.IPv6, config_file),
	nftables.NFTables(config_file),
]

for fw in all_fw:
	if fw.config.save_file:
		# create iptables tules
		fw.CreateAllRules()

		# list rules
		fw.DumpRules()

		# prompt user to save rules
		if base.input_verify("Do you wish to save this configuration to " + fw.config.save_file):
			print("Saving configuration to " + fw.config.save_file)
			fw.SavePersistent()

