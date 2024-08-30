#!/usr/libexec/platform-python
# vi:set expandtab shiftwidth=4:
"""
Maintain ipset with valid dovecot connections that firewalld can use to
restrict access to email submission port (587).
"""

from ipaddress import ip_address, ip_network
import os
import re
import signal
import subprocess
import sys
import syslog
import time
import firewall.client

DEFAULT_PROCESSING_INTERVAL = 30  # seconds
FIREWALL_TIMEOUT = 15
DOVEADM_TIMEOUT = 15
ZONE_NAME = "dovecot"
IPSET_NAME = "dovecot"
LOCAL_NETWORK = "127.0.0.0/24"
SUBMISSION = "submission"
SUBMISSION_PORT = "587"
WHO_IPS = re.compile(r'\((?P<ips>[0-9. ]*)\)\s*$')

DEBUG = False
run = True
in_sleep = False
processing_interval = DEFAULT_PROCESSING_INTERVAL


def read_doveadm_who():
    """Find out who is using dovecot"""
    # TODO? use dovecot API to directly query dovecot/anvil
    try:
        text = subprocess.check_output(
            ["/bin/doveadm", "who"],
            encoding='utf-8',
            env={'LANG': 'en_US.UTF-8'},
            timeout=DOVEADM_TIMEOUT
        )
    except Exception as err:
        syslog.syslog(f"'doveadm who' failed: {err}")
        return None
    ips = set()
    for line in text.split('\n'):
        match = WHO_IPS.search(line)
        if match is None:
            continue
        ips.update(ip_address(x) for x in match.group('ips').split())
    return ips


def find_local_sources(fw):
    """Discover networks with access to submission port

    Scan firewalld zones for ones that allow connections to submission port
    # and save their sources to exclude from ipset.
    """
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
    """Get existing contents of ipset"""
    entries = fw.getEntries(ZONE_NAME)
    if DEBUG:
        syslog.syslog(f"{len(entries)} found on startup in {ZONE_NAME} ipset")
    return set(ip_address(x) for x in entries)


def add_ips_to_ipset(ips, local_sources):
    """Extend ipset with additonal values

    Add IP addresses to ipset that are not in local sources.
    firewall API only allows the whole ipset to be changed.
    """
    try:
        fw = firewall.client.FirewallClient()
        fw.bus.default_timeout = FIREWALL_TIMEOUT
        entries = fw.getEntries(ZONE_NAME)
    except Exception as err:
        syslog.syslog(f"unable to contact firewalld: {err}")
        return
    new_entries = [str(ip) for ip in ips if not any(ip in net for net in local_sources)]
    if new_entries:
        entries += new_entries
        try:
            fw.setEntries(ZONE_NAME, entries)
            if DEBUG:
                syslog.syslog(f"{len(new_entries)} added to {ZONE_NAME} ipset")
        except Exception as err:
            syslog.syslog(f"unable to add ipset entries: {err}")


def service_is_active(service):
    """Check if systemd service is running"""
    cmd = ["/bin/systemctl", "--quiet", "is-active", service]
    return subprocess.run(cmd, check=False).returncode == os.EX_OK


def make_zone_if_needed(fw):
    """Create ipset if not already there"""
    # TODO:
    # It should be possible to do everything that is in the
    # dovecot-zone.sh shell script in code.  That would simplify
    # installation.
    return


def handler_stop_signals(signum, _frame):
    """Shortcurcuit sleep if interrupted or terminated"""
    global run
    global processing_interval
    run = False
    processing_interval = 0
    if in_sleep:
        raise SystemExit(signum)


def main():
    """Run main program"""
    global in_sleep

    if not service_is_active("firewalld"):
        print("firewall deamon is not running", file=sys.stderr)
        raise SystemExit(os.EX_UNAVAILABLE)

    if not service_is_active("dovecot"):
        print("dovecot is not running", file=sys.stderr)
        raise SystemExit(os.EX_UNAVAILABLE)

    syslog.openlog(logoption=syslog.LOG_PID, facility=syslog.LOG_MAIL)
    syslog.syslog("starting")

    try:
        fw = firewall.client.FirewallClient()
        fw.bus.default_timeout = FIREWALL_TIMEOUT
        local_sources = find_local_sources(fw)
        current_ips = ipset_on_startup(fw)
        # TODO: make_zone_if_needed(fw)
        del fw
    except Exception as err:
        syslog.syslog(str(err))
        raise SystemExit(os.EX_OSERR) from err


    signal.signal(signal.SIGINT, handler_stop_signals)
    signal.signal(signal.SIGTERM, handler_stop_signals)

    doveadm_failures = 0
    while run:
        dovecot_ips = read_doveadm_who()
        if dovecot_ips is None:
            if doveadm_failures == 30:
                syslog.syslog("too many doveadm failures")
                raise SystemExit(os.EX_TEMPFAIL)
            doveadm_failures += 1
        else:
            doveadm_failures = 0
            new_ips = dovecot_ips - current_ips
            if new_ips:
                add_ips_to_ipset(new_ips, local_sources)
                current_ips.update(new_ips)
        in_sleep = True
        time.sleep(processing_interval)
        in_sleep = False


if __name__ == "__main__":
    main()
