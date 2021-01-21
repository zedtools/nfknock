#!/usr/bin/env python3

import iptables
import argparse
import sys
from typing import List

import base
import nftables

# create the argument parser
parser = argparse.ArgumentParser(description='Allow connections from remote addresses without requiring a port knock. Any networks added via this command are transient, and will not persist across reboots, or if the port knocking configuration is reapplied from the configuration file.')
parser.add_argument('-a', '--add', action='append', default=[], help='Add a network to allowed list of transient networks')
parser.add_argument('-f', '--flush', action='store_true', help='Remove all previously allowed transient networks')
parser.add_argument('-l', '--list', action='store_true', help='List all currently allowed transient networks')

# parse command line arguments
args = parser.parse_args()

# verify we are running as root (needed to modify iptables rules)
base.CheckRoot()

# create IPTables and NFTables objects, and load configuration file
config_file = 'nfknock.cfg'
all_fw: List[base.Firewall] = [fw for fw in [
	iptables.IPTables(base.Config.IPv4, config_file),
	iptables.IPTables(base.Config.IPv6, config_file),
	nftables.NFTables(config_file),
] if fw.config.save_file]

# parse each --add argument
add_ipv4 = []
add_ipv6 = []
for network in args.add:
	if '.' in network:
		# assume this is a IPv4 address
		add_ipv4.append(network)
	elif ':' in network:
		# assume this is a IPv6 address
		add_ipv6.append(network)
	else:
		print('%s: Invalid network format (neither IPv4 or IPv6): %s' % (__file__, network))
		sys.exit(1)

# perform actions based on command line arguments
for fw in all_fw:
	if args.flush:
		# delete all existing transient networks
		fw.InitTransientNetworks()
	if add_ipv4 or add_ipv6:
		# one or more I Pv4/IPv6 networks to add
		fw.AllowTransientNetworks(ipv4_list=add_ipv4, ipv6_list=add_ipv6)
	if args.list:
		fw.DumpTransientNetworks()
