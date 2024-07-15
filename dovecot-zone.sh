#!/bin/bash
#
# Create zone to keep track of IP addresses that should be
# allowed to connect to SMTP submission port
#
ZONE=dovecot
IPSET=$ZONE
PORT=587/tcp

FWC='firewall-cmd --permanent'
#echo "Removing $ZONE zone and $ZONE ipset if already there"
#$FWC --quiet --delete-zone=$ZONE
#$FWC --quiet --delete-ipset=$ZONE
echo "Creating $ZONE zone"
$FWC --new-zone=$ZONE
echo "Creating $IPSET ipset"
$FWC --new-ipset=$IPSET --type=hash:ip
echo "Adding submission port $PORT to $ZONE zone"
$FWC --zone=$ZONE --add-port=$PORT
echo "Adding source $IPSET ipset to $ZONE zone"
$FWC --zone=$ZONE --add-source=ipset:$IPSET
echo "Reloading firewall zone configuration"
firewall-cmd --reload
