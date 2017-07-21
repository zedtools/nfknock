#!/bin/bash
#
# Monitor the syslog for any successful port knock connections.
#
# Call this script at startup, such as via /etc/rc.local. Running as root is
# not necessary, but access to read the syslog is needed.
#
# This script pipes any new syslog entries to watchknock.awk, which does the
# rest of the work.
#

BASEDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

tail -F /var/log/syslog | mawk -W interactive -v BASEDIR=$BASEDIR -f $BASEDIR/watchknock.awk &
