#
# Called by watchknock.sh to scan the syslog for port-knock connection 
# attempts. Every time a successful port knock is made, logmail.sh is
# called to send a notification email.
#

# scan for any accepted connections
/iptables-LOGACCEPT/ || /ip6tables-LOGACCEPT/ || /NFT#knock-accepted/ || /NFT#transient-accepted/ {
	# work out the source IP by getting the "SRC=..." value from the log
	ip="Unknown"
	if (match($0, "SRC=[A-za-z0-9.:]+")) {
		pattern = substr($0,RSTART,RLENGTH);
		sub(/SRC=/, "", pattern);
		ip = pattern
	}

	msg="Unexpected log entry"
	if (match($0, /LOGACCEPTKNOCK|NFT#knock-accepted/)) {
		msg="Received successful knock"
	}
	else if (match($0, /LOGACCEPTPREKNOCK|NFT#transient-accepted/)) {
		msg="Allowed connection from transient network"
	}

	# strip off the leading "SRC=" to get the IP address
	sub(/SRC=/, "", ip);

	# call logmail.sh with the IP address, as well as the full line from
	# the log file
	cmd=sprintf("\"%s/logmail.sh\" \"%s\" \"%s\" \"%s\"", BASEDIR, ip, msg, $0);
	system(cmd);
}
