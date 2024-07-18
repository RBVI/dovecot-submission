#!/bin/bash
#
# Whitelist known good networks where the user's IP address jumps around.
# This typically happens on cell phone networks.  Consequently, the ipset
# is smaller and doesn't need updating as often.
#
# Comments give:
#    Arin.net name (full name/remark)

ZONE=dovecot
FWC="firewall-cmd --permanent --zone=$ZONE"

# TMO9 (T-Mobile USA, Inc.)
$FWC --add-source=172.32.0.0/11
# ATT-MOBILITY-LLC (AT&T Mobility)
$FWC --add-source=108.144.0.0/13 --add-source=108.152.0.0/14
# ATT-MOBILITY-LLC (AT&T Mobility LLC)
$FWC --add-source=107.64.0.0/10
# WIRELESSDATANETWORK (Verizon Business)
$FWC --add-source=174.192.0.0/10
# Internet-OM (Orange Mobile)
$FWC --add-source=92.184.98.0/23
# PL-IDEA-MOBILE (Orange Mobile)
$FWC --add-source=91.94.0.0/17
# SFBA-CPE46 (Comcast Cable Communications, LLC)
$FWC --add-source=98.42.0.0/16
# KAISER-F11-26 (KAISER FOUNDATION HEALTH PLAN)
$FWC --add-source=12.222.26.0/24
