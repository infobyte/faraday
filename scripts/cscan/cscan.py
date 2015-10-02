#!/usr/bin/env python
###
## Faraday Penetration Test IDE
## Copyright (C) 2015  Infobyte LLC (http://www.infobytesec.com/)
## See the file 'doc/LICENSE' for the license information
###

import subprocess
import os
import argparse
import time
from pprint import pprint
from config import config

def lockFile(lockfile):

    if os.path.isfile(lockfile):
        return False
    else:
        f = open(lockfile, 'w')
        f.close()
        return True

def main():

    lockf = ".lock.pod"
    if not lockFile(lockf):
        print "You can run only one instance of cscan (%s)" % lockf
        exit(0)

    my_env = os.environ
    env = config.copy()
    env.update(my_env)
    #Parser argument in command line
    parser = argparse.ArgumentParser(description='continues scanning on Faraday')
    parser.add_argument('-p','--plugin', help='Scan only the following plugin ej: ./cscan.py -p nmap.sh', required=False)
    args = parser.parse_args()

    for dirpath, dnames, fnames in os.walk("./scripts/web/"):
        for f in  fnames:
            if args.plugin and args.plugin != f:
                continue
            script = os.path.join(dirpath, f)
            cmd = "%s websites.txt output/" % (script)
            print "Running: %s" % cmd
            proc = subprocess.call(cmd, shell=True, stdin=None, stderr=subprocess.PIPE,  env=dict(env))

    for dirpath, dnames, fnames in os.walk("./scripts/network/"):
        for f in  fnames:
            if args.plugin and args.plugin != f:
                continue
            script = os.path.join(dirpath, f)
            cmd = "%s ips.txt output/" % (script)
            print "Running: %s" % cmd
            proc = subprocess.call(cmd, shell=True, stdin=None, stderr=subprocess.PIPE, env=dict(env))

    #Remove lockfile           
    os.remove(lockf)

if __name__ == "__main__":
    main()