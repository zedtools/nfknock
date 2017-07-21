# iptables-knock
Port knocking via iptables
-------------

This package configured iptables rules for port knocking.

There are two parts to this package:
1. A script to set up the iptables rules that allow a hidden port to be opened
   after a port-knock sequence is received.
2. A second script that runs in the background, monitoring the log for port
   knocking attempts. Every successful port knock will send an email
   notification.

NOTE: Port knocking is not a secure solution, as the knock sequence can be
eavesdropped by a man-in-the-middle. Make sure any service exposed to the
internet on the hidden port is configured securely. However, port knocking
helps to defend against port scanners, and it adds an extra layer an attacker
must penetrate. This can be useful to reduce the risk of vulnerabilities being
exploited in the service. For example, if you run a SSH daemon, there may be
recently discovered or unknown vulnerabilities in the daemon. In addition, you
will get a notification as soon as this first layer is penerated, allowing you
to change the port-knock sequence.

Requirements:
- iptables
- iptables-persistent (for Debian-based systems)
- python 3.3+ (tested with python 3.4)

The following are additional requirements for logging:
- Heirloom mailx
- mawk

On Debian, all these requirements can be installed by:
- sudo apt-get install iptables iptables-persistent python3 heirloom-mailx mawk

Port knocking with iptables setup instructions:
1. Edit iptables-knock.cfg to edit port knocking configuration.
2. Run iptables-knock.py as root or with sudo. This will automatically set up
   the iptables rules.

For logging, complete the following additional steps:
1. Edit logmail.cfg and configure your email settings
2. Configure watchknock.sh to run on boot. The easiest way to do this is to
   add it to /etc/rc.local on Debian, though this may vary by platform. You
   can run as a limited user, as long as that user has read access to the
   syslog. Use sudo with the -u option to run as a different user.
3. Start watchknock.sh manually or reboot to start logging.

One the server is configured, you can use the client script knock.sh to do the
port knock.