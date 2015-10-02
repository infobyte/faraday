#!/usr/bin/env python
###
## Faraday Penetration Test IDE
## Copyright (C) 2015  Infobyte LLC (http://www.infobytesec.com/)
## See the file 'doc/LICENSE' for the license information
###

'''
By tartamar
'''
import argparse
import time
import re
from pprint import pprint
from zapv2 import ZAPv2
import subprocess
import os
import signal
import atexit
child_pid = None

def kill_child():
    global child_pid
    if child_pid is None:
        pass
    else:
        os.kill(child_pid, signal.SIGTERM)

def is_http_url(page):
    """
    Returns true if s is valid http url, else false 
    Arguments:
    - `page`:
    """
    if re.findall('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', page):
        return True
    else:
        return False

def exportfile(filename,zap):
    #Output for XML Report
    print 'Generating XML Report...'
    filex=open(filename, 'w')
    filex.write(zap.core.xmlreport)
    filex.close()        

def main():

    atexit.register(kill_child)

    my_env = os.environ
    cmd = my_env["CS_ZAP"] if 'CS_ZAP' in my_env else "/usr/share/zaproxy/zap.sh"

    #Parser argument in command line
    parser = argparse.ArgumentParser(description='PyZap is develop for automating security testing')
    parser.add_argument('-t','--target', help='Network or Host for scan', required=False)
    parser.add_argument('-o','--output', help='Output file', required=False)
    args = parser.parse_args()

    # Review de Command input
    if args.target == None:
        # Do nothing
        # Input data for test
        target = raw_input('[+] Enter your target: ')
        if is_http_url(target) == True:
            print '[-] Target selected: ', target
        else:
            print '[w] Please type a correct URL address'
            quit()
    else:
        # Check for valid URL addres
        if is_http_url(args.target) == True:
            target = args.target
            print '[-] Target selected: ', target
        else:
            print '[w] Please type a correct URL Address'
            quit()
    print 'Starting ZAP ...'

    global child_pid
    proc = subprocess.Popen([cmd,'-daemon'])
    child_pid = proc.pid

    print 'Waiting for ZAP to load, 10 seconds ...'
    time.sleep(10)
    zap = ZAPv2()
    # Use the line below if ZAP is not listening on 8090
    zap = ZAPv2(proxies={'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'})

    # do stuff
    print 'Accessing target %s' % target
    # try have a unique enough session...
    zap.urlopen(target)
    # Give the sites tree a chance to get updated
    time.sleep(2)

    print 'Spidering target %s' % target
    print target
    zap.spider.scan(target)
    # Give the Spider a chance to start
    time.sleep(2)
    #print 'Status %s' % zap.spider.status
    while(int(zap.spider.status) < 100):
        print 'Spider progress %: ' + zap.spider.status
        time.sleep(2)

    print 'Spider completed'
    # Give the passive scanner a chance to finish
    time.sleep(5)

    print 'Scanning target %s' % target
    zap.ascan.scan(target)
    while(int(zap.ascan.status) < 100):
        print 'Scan progress %: ' + zap.ascan.status
        time.sleep(5)

    print 'Scan completed'

    # Report the results

    print 'Hosts: ' + ', '.join(zap.core.hosts)
    # print 'Alerts: '
    # pprint (zap.core.alerts())
    #pprint (zap.core.xmlreport())
    exportfile(args.output,zap)

    print 'Shutting down ZAP ...'
    zap.core.shutdown
    #EOF

if __name__ == "__main__":
    main()