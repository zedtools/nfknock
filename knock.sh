#!/bin/sh
#
# Client script to do a port knock using nmap.
#
# Edit DEFAULT_HOST and DEFAULT_PORTS below for defaults, otherwise provide
# the host and ports on the command line or via environment variables.
#

DEFAULT_HOST=default-host.net
DEFAULT_PORTS=10000,10001,10002

# Allow HOST and PORTS to be set via environment variables. If not set, then
# initialize to default values.
if [ -z "$HOSTS" ]
then
	HOST=$DEFAULT_HOST
fi

if [ -z "$PORTS" ]
then
	PORTS=$DEFAULT_PORTS
fi

# Allow host and ports to be provided by command line. Any values from the
# command line override both the environment variables and the defaults.
if [ -n "$1" ]
then
	HOST=$1
fi

if [ -n "$2" ]
then
	PORTS=$2
fi

# Detect if IPv6 address was passed in
if echo $HOST | grep : > /dev/null
then
	echo "Detected IPv6 address: $HOST"
	IPV6_FLAG=-6
fi

# The --max-retries option should only send one TCP SYN packet, but it seems to
# send a retry. If the --scan-delay option is not given, the retry packets seem
# to be in a random order, probably because the original TCP packets were too
# close.
# Using --scan-delay 50ms and --host-timeout 300ms seems to prevent the 
# retransmission
nmap -v $IPV6_FLAG -Pn --scan-delay 50ms --host-timeout 300ms --max-retries 0 -r -p $PORTS $HOST | grep Scanning
