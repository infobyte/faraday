#!/usr/bin/env python2

# Faraday Penetration Test IDE
# Copyright (C) 2015  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information

from w3af_api_client import Connection, Scan
import subprocess
import os
import argparse
import time
import signal
from pprint import pprint
import atexit
child_pid = None


def kill_child():
    global child_pid
    if child_pid is None:
        pass
    else:
        os.kill(child_pid, signal.SIGTERM)


def main():
    atexit.register(kill_child)

    my_env = os.environ
    cmd = my_env["CS_W3AF"] if 'CS_W3AF' in my_env else "/root/tools/w3af/w3af_api"
    profile = my_env["CS_W3AF_PROFILE"] if 'CS_W3AF_PROFILE' in my_env else "/root/tools/w3af/profiles/fast_scan.pw3af"

    # Parser argument in command line
    parser = argparse.ArgumentParser(description='w3af_client is develop for automating security testing')
    parser.add_argument('-t', '--target', help='Network or Host for scan', required=False)
    parser.add_argument('-o', '--output', help='Output file', required=False)
    args = parser.parse_args()

    if args.target is None or args.output is None:
        print "Argument errors check -h"
        exit(0)

    print 'Starting w3af api ...'
    global child_pid
    proc = subprocess.Popen([cmd])
    child_pid = proc.pid

    print 'Waiting for W3af to load, 5 seconds ...'
    time.sleep(5)

    # Connect to the REST API and get it's version
    conn = Connection('http://127.0.0.1:5000/')
    print conn.get_version()

    # Define the target and configuration
    # scan_profile = file('/root/tools/w3af/profiles/fast_scan_xml.pw3af').read()
    scan_profile = file(profile).read()
    scan_profile = "[output.xml_file]\noutput_file = %s\n%s\n" % (args.output, scan_profile )
    # scan_profile = file('/root/tools/w3af/profiles/fast_scan.pw3af').read()

    target_urls = [args.target]

    scan = Scan(conn)
    s = scan.start(scan_profile, target_urls)
    time.sleep(2)

    # Wait some time for the scan to start and then
    scan.get_urls()
    scan.get_log()
    scan.get_findings()

    while(scan.get_status()['status'] == "Running"):
        print 'Scan progress: %s' + str(scan.get_status()['rpm'])
        time.sleep(2)

if __name__ == "__main__":
    main()
