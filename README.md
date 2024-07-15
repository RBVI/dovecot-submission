Dovecot Submission
------------------

In today's Internet, there are lots of unauthenticated connections being
made to the mail submission port (587).  It is possible that the connections
are being used to find valid user name and password combinations that can
be used to login.  Each connection uses a process and network state and
that can slow the system down, in effect, a denial of service attack.  That
can be stopped by using the firewall to only allow access to IMAP/POP3 
(dovecot) users.

This is be done by:

  1. create a dovecot firewall zone
  2. permanently add port 587/tcp
  3. permanently add source ipset:dovecot
  4. Run a daemon that calls "doveadm who" to update the dovecot ipset

In practice, IP addresses will never be removed from the dovecot ipset
because those IP addresses are unlikely to be attacking us.

The downside is that users need to check their email before sending any
unless their IP address is already in the dovecot ipset.  Or if the access
to the mail submission port is allowed via some other firewwall zone.

Cluster Environments
--------------------

dovecot is assumed to be running on just one node.  This daemon needs
to run on the same node.  On the other nodes, the dovecot ipset should
be empty.
