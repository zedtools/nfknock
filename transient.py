#!/usr/bin/env python3

import iptables
import argparse
import sys

# create the argument parser
parser = argparse.ArgumentParser(description='Allow connections from remote addresses without requiring a port knock. Any networks added via this command are transient, and will not persist across reboots, or if the port knocking configuration is reapplied from the configuration file.')
parser.add_argument('-a', '--add', action='append', default=[], help='Add a network to allowed list of transient networks')
parser.add_argument('-f', '--flush', action='store_true', help='Remove all previously allowed transient networks')
parser.add_argument('-l', '--list', action='store_true', help='List all currently allowed transient networks')

# parse command line arguments
args = parser.parse_args()

# verify we are running as root (needed to modify iptables rules)
iptables.CheckRoot()

# create IPTables objects
ip4 = iptables.IPTables(iptables.IPTables.IPv4, config_file=None)
ip6 = iptables.IPTables(iptables.IPTables.IPv6, config_file=None)

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
if args.flush:
	# delete all existing transient networks
	ip4.InitTransientNetworks()
	ip6.InitTransientNetworks()
if add_ipv4:
	# one or more IPv4 networks to add
	ip4.AllowTransientNetworks(add_ipv4)
if add_ipv6:
	# one or more IPv6 networks to add
	ip6.AllowTransientNetworks(add_ipv6)
if args.list:
	print('IPv4 Rules:')
	ip4.DumpRules(chain=ip4.PREKNOCK)
	print('\nIPv6 Rules:')
	ip6.DumpRules(chain=ip6.PREKNOCK)
