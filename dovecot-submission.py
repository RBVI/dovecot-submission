#!/usr/libexec/platform-python
# vi:set expandtab shiftwidth=4:
#
# Maintain ipset with valid dovecot connections.
# See README.md for details
#

import firewall.client
from ipaddress import ip_address, ip_network
import os
import re
import signal
import subprocess
import sys
import time

DEFAULT_PROCESSING_INTERVAL = 30  # seconds
ZONE_NAME = "dovecot"
IPSET_NAME = "dovecot"
LOCAL_NETWORK = "127.0.0.0/24"
SUBMISSION = "submission"
SUBMISSION_PORT = "587"
WHO_IPS = re.compile(r'\((?P<ips>[0-9. ]*)\)\s*$')

run = True
in_sleep = False
processing_interval = DEFAULT_PROCESSING_INTERVAL


def read_doveadm_who():
    # TODO? use dovecot API to directly query dovecot/anvil
    try:
        text = subprocess.check_output(
            ["/bin/doveadm", "who"],
            encoding='utf-8',
            env={'LANG': 'en_US.UTF-8'}
        )
    except Exception:
        return
    ips = set()
    for line in text.split('\n'):
        m = WHO_IPS.search(line)
        if m is None:
            continue
        ips.update(ip_address(x) for x in m.group('ips').split())
    return ips


def find_local_sources(fw):
    # Scan firewalld zones for ones that allow connections to submission port
    # and save their sources to exclude from ipset.
    networks = [ip_network(LOCAL_NETWORK)]
    zones = fw.getActiveZones()
    for zone in zones:
        settings = fw.getZoneSettings(zone)
        if settings.getTarget() == "ACCEPT":
            has_submission = True
        else:
            has_submission = (SUBMISSION in settings.getServices()
                              or (SUBMISSION_PORT, 'tcp') in settings.getPorts())
        if not has_submission:
            continue
        for src in settings.getSources():
            if src[0].isdigit():
                networks.append(ip_network(src))
    return networks


def ipset_on_startup(fw):
    entries = fw.getEntries(ZONE_NAME)
    return set(ip_address(x) for x in entries)


def add_ips_to_ipset(fw, ips, local_sources):
    # Add IP addresses to ipset that are not in local sources.
    # firewall API only allows the whole ipset to be changed.
    entries = fw.getEntries(ZONE_NAME)
    new_entries = [str(ip) for ip in ips if not any(ip in net for net in local_sources)]
    if new_entries:
        entries += new_entries
        fw.setEntries(ZONE_NAME, entries)


def service_is_active(service):
    cmd = ["/bin/systemctl", "--quiet", "is-active", service]
    return subprocess.run(cmd).returncode == os.EX_OK


def make_zone_if_needed(fw):
    # TODO:
    # It should be possible to do everything that is in the
    # dovecot-zone.sh shell script in code.  That would simplify
    # installation.
    return


def handler_stop_signals(signum, frame):
    global run
    global processing_interval
    run = False
    processing_interval = 0
    if in_sleep:
        raise SystemExit(signum)


def main():
    global in_sleep

    if not service_is_active("firewalld"):
        print("firewall deamon is not running", file=sys.stderr)
        raise SystemExit(os.EX_TEMPFAIL)

    fw = firewall.client.FirewallClient()
    # TODO: make_zone_if_needed(fw)

    if not service_is_active("dovecot"):
        print("dovecot is not running", file=sys.stderr)
        raise SystemExit(os.EX_OK)

    signal.signal(signal.SIGINT, handler_stop_signals)
    signal.signal(signal.SIGTERM, handler_stop_signals)

    local_sources = find_local_sources(fw)
    current_ips = ipset_on_startup(fw)
    doveadm_failures = 0
    while run:
        dovecot_ips = read_doveadm_who()
        if dovecot_ips is None:
            if doveadm_failures == 30:
                print("unable to run 'doveadm who'", file=sys.stderr)
                raise SystemExit(os.EX_TEMPFAIL)
            doveadm_failures += 1
        else:
            doveadm_failures = 0
            new_ips = dovecot_ips - current_ips
            if new_ips:
                add_ips_to_ipset(fw, new_ips, local_sources)
                current_ips.update(new_ips)
        in_sleep = True
        time.sleep(processing_interval)
        in_sleep = False


if __name__ == "__main__":
    main()
