#!/bin/bash
#
# Called by watchknock.awk when a successful connection is made after the knock
# sequence.
#
# Send an email notifying that there was a successful port knock, with details
# of the remote client.
#

# parameters passed in by watchknock.awk
IP=$1
LOG=$2

DIRNAME=$(dirname $0)
CFG_FILE=$DIRNAME/logmail.cfg
ERR_LOG=$DIRNAME/logmail.log

# Load configuration options
. "$DIRNAME/logmail.cfg"

if [[ -v SMTP_SERVER ]] && [[ -v MAILFROM ]] && [[ -v MAILTO ]]
then
	# look up whois data for the remote client
	WHOIS_DATA=$(whois $IP)

	echo -e "Received successful knock from IP: $IP\n\nLog entry: $LOG\n\nWHOIS:\n\n$WHOIS_DATA" | mailx -r "$MAILFROM" -s "$(hostname): Knock from $IP" -S smtp=$SMTP_SERVER "$MAILTO"
else
	echo "Error: environment varialbes SMTP_SERVER, MAILFROM and MAILTO must be set" >> $ERR_LOG
fi
