#!/bin/bash
#
# Create zone to keep track of IP addresses that should be
# allowed to connect to SMTP submission port
#
ZONE=dovecot
IPSET=$ZONE
#PORT=587/tcp
PORT=9999/tcp

FWC='firewall-cmd --permanent'
$FWC --delete-zone=$ZONE
$FWC --delete-ipset=$ZONE
$FWC --new-zone=$ZONE
$FWC --new-ipset=$IPSET --type=hash:ip
$FWC --zone=$ZONE --add-port=$PORT
$FWC --zone=$ZONE --add-source=ipset:$IPSET
firewall-cmd --reload
