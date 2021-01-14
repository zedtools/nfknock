#!/bin/bash
#
# Client script to do a port knock using nmap.
#
# Edit DEFAULT_HOST and DEFAULT_PORTS below for defaults, otherwise provide
# the host and ports on the command line or via environment variables.
#
# Edit DELAY below to set the delay between each port knock. If you have highly
# variable latency, which can cause packets to arrive out of order, increase
# this value.
#
# The PORTS argument is a comma-separated list of ports passed to the nmap
# command. Examples:
# - 10000   = TCP port 10000
# - T:10000 = TCP port 10000
# - U:10000 = UDP port 10000
#
# Note that sending UDP packets require root privileges. This is a limitation
# of nmap.
#
# If nmap is not sending ports, or duplicate packets are sent for each knock,
# try changing the values in NMAP_ARGS below, or setting TCP_SCANTYPE to -Ss.

DEFAULT_HOST=default-host.net
DEFAULT_PORTS=10000,10001,10002

# Delay between port knocks in seconds
DELAY=0.5

# The nmap scan type For a TCP port, By default (a blank value), this will
# cause nmap to attempt a TCP SYN scan, or fall back to a TCP connect scan if
# root privileges are missing. Set this to -sS to for a TCP SYN scan.
# Note that using -sS requires root privileges.
#TCP_SCANTYPE=-sS

# Return true (0) if the argument is a valid IPv4 address, e.g. 10.0.0.1
function isIPv4Address
{
	ipv4=$(echo $1 | awk '/^[0-9.]+$/ { print $1 }')
	if [[ -n "$ipv4" ]]
	then
		true
	else
		false
	fi
}

# Return true (0) if the argument is a valid IPv5 address, e.g. fe80::1
function isIPv6Address
{
	ipv6=$(echo $1 | awk '/^[0-9A-Fa-f:]+$/ { print $1 }')
	if [[ -n "$ipv6" ]]
	then
		true
	else
		false
	fi
}

# Do a DNS lookup on the first argument and return the IP address.
# If an IP address is passed in, return it unchanged.
function getIPAddress
{
	name=$1

	if isIPv4Address $name
	then
		echo -n $name
	elif isIPv6Address $name
	then
		echo -n $name
	else
		lookup=$(host $name)
		ipv4=$(echo $lookup | awk '/has address/ { print $4 }')
		ipv6=$(echo $lookup | awk '/has IPv6 address/ { print $	5 }')

		if [[ -n "$ipv4" ]]
		then
			echo -n $ipv4
		elif [[ -n "ipv6" ]]
		then
			echo -n $ipv6
		else
			echo -n ""
		fi
	fi
}

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
IP_ADDR=$(getIPAddress $HOST)
if isIPv6Address $IP_ADDR
then
	echo "Detected IPv6 address: $HOST ($IP_ADDR)"
	IPV6_FLAG=-6
fi

# Set up NMAP arguments.
#
# The following arguments cause just a single packet to be sent, regardless of
# the scan type.
# -Pn
#     Skip host discovery, as we don't want other packets send in between port
#     knocks
# --max-retries 0:
#     Tells nmap to only send one TCP packet, though the OS may still send TCP
#     retransmission packets
NMAP_ARGS=(-Pn --max-retries 0)

# Set up NMAP TCP arguments.
#
# By default, NMAP tries a TCP SYN scan (-sS), falling back to a TCP connect
# scan (-sT) if root privileges are missing. The TCP connect scan resends
# SYN packets if no response is received, which messes up port knocking. Note
# that the OS does this, not nmap.
#
# While a TCP SYN scan can be used, it would be nice to be able to send TCP
# packets without root privileges. Fortunately, there is a way to massage the
# TCP connect scan to do this.
#
# If this does not work, set TCP_SCANTYPE=-Ss above, though note that this
# requires root privileges.
#
# The following arguments needed for a TCP connect scan, to ensure that the
# nmap process terminates before the OS can send any TCP retransmissions.
# --host-timeout 50ms:
#     Ensures that nmap terminates before the OS can send a TCP retransmission.
#     Note that if this value is too low, then no packets are sent at all.
# --scan-delay 1ms:
#     For some reason the --host-timeout parameter does not apply unless
#     --scan-delay is also provided, so provide a dummy value
NMAP_TCP_ARGS=(--host-timeout 50ms --scan-delay 1ms)

# Some networks drop empty UDP packets, so add some dummy data (0x00)
NMAP_UDP_ARGS=(--data 00)

# split the PORTS argument into individual ports
IFS=',' read -r -a array <<< "$PORTS"
for port in "${array[@]}"
do
	if [[ $port == U:* ]]
	then
		# for a UDP port, set the nmap scan type to UDP
		echo "Scanning UDP port: $port"
		scantype=-sU
		scan_args=${NMAP_UDP_ARGS[@]}
	else
		# For a TCP port, set the scan type to TCP_SCANTYPE. By
		# default (a blank value), this will cause nmap to attempt a
		# TCP SYN scan, or fall back to a TCP connect scan if root privileges are missing.
		echo "Scanning TCP port: $port"
		scantype=$TCP_SCANTYPE
		scan_args=${NMAP_TCP_ARGS[@]}
	fi

	# Call nmap and then sleep DELAY seconds in between each knock.
	# Note that if nmap needs to run as sudo (for -sS or -sU), and is not,
	# it will print an error to stderr.
	nmap $IPV6_FLAG $scantype ${NMAP_ARGS[@]} ${scan_args[@]} -p $port $HOST >> /dev/null
	sleep $DELAY
done
