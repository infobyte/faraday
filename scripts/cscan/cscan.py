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

def target_list(script, categories):
    dictionary = {
        "network": "ips.txt",
        "web": "websites.txt",
        "extra": "ips.txt"
    }

    category = 'network'
    for c in categories:
        if os.path.exists(os.path.join('scripts', c, script)):
            return dictionary[c]

def main():
    lockf = ".lock.pod"
    if not lockFile(lockf):
        print "You can run only one instance of cscan (%s)" % lockf
        exit(0)

    my_env = os.environ
    env = config.copy()
    env.update(my_env)

    parser = argparse.ArgumentParser(description='continues scanning on Faraday')
    parser.add_argument('-s','--script', help='Scan only the following script ej: ./cscan.py -p nmap.sh', required=False)
    parser.add_argument('-S','--scripts', help='Scan the following scripts list ej: ./cscan.py -p nmap.sh,nikto.sh', required=False)
    parser.add_argument('-c','--category', help='Scan only for given category ej: ./cscan.py -c network', required=False)
    parser.add_argument('-t','--targets', help='Choose a custom target list ej: ./cscan.py -t custom-list.txt', required=False)
    parser.add_argument('-o','--output', help='Choose a custom output directory', required=False)
    parser.add_argument('-l','--log', help='Choose a custom log directory', required=False)
    args = parser.parse_args()

    output = 'output/'
    if args.output:
        output = args.output

    logdir = 'log/'
    if args.log:
        logdir = args.log

    for d in [logdir, output]:
        if not os.path.isdir(d):
            os.makedirs(d)

    if args.script:
        scripts = [args.script]
    elif args.scripts:
        scripts = args.scripts.split(",")
    else:
        scripts = env["CS_SCRIPTS"].split(",")

    categories = env["CS_CATEGORIES"].split(",")
    for category in categories:
        env["PATH"] += ":%s" % os.path.abspath("./scripts/" + category)

    for script in scripts:
        if args.targets:
            targets = args.targets
        else:
            targets = target_list(script, categories)

        cmd = "%s %s %s %s" % (script, targets, output, logdir)
        print "\n\nRunning: %s" % cmd
        proc = subprocess.call(cmd, shell=True, stdin=None, env=dict(env))

    #Remove lockfile
    os.remove(lockf)

if __name__ == "__main__":
    main()
