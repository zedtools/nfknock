#!/bin/sh

if [ -z "$HOSTS" ]
then
	HOST=default-host.net
fi

if [ -z "$PORTS" ]
then
	PORTS=10000,10001,10002
fi

if [ -n "$1" ]
then
	HOST=$1
fi
	
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
