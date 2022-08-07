# nfknock
Port knocking via nftables
-------------

This package configures firewall rules for port knocking. Both nftables and
iptables are supported.

There are two parts to this package:
1. A script to set up the firewall rules that allow a hidden port to be opened
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
- python 3.7+

Requirements for iptables:
- iptables
- iptables-persistent (for Debian-based systems)

Requirements for nftables:
- nftables 0.9.3
- Linux kernel 5.4

The following are additional requirements for logging:
- S-nail
- mawk
- whois

On Debian 11, some of these are already present. Missing requirements can be installed by:
- sudo apt install s-nail whois

For the cfg files below, sample cfg files can be found under the directory cfg-sample.

Port knocking setup instructions:
1. Copy cfg-sample/nfknock.cfg to nfknock.cfg.
2. Edit nfknock.cfg to edit port knocking configuration.
3. Run nfknock.py as root or with sudo. This will automatically set up the firewall, including
   enabling the nftables service if needed.

To temporarily allow networks without adding them to nfknock.cfg, use the command transient.py.

For logging, complete the following additional steps:
1. Copy cfg-sample/logmail.cfg to logmail.cfg.
2. Edit logmail.cfg and configure your email settings.
3. Configure watchknock.sh to run on boot. You can run it as a limited user, as long
   as that user has read access to the syslog. The easiest way to achieve this on
   Debian is:
   1. Create a limited user and add that user to the adm group (for syslog access):
      * sudo usermod -aG adm *username*
   2. Add the following to /etc/rc.local:
      * sudo -u *username* /path/to/.../watchknock.sh
4. Start watchknock.sh manually or reboot to start logging.

Once the server is configured, you can use the client script knock.sh to do the
port knock.
