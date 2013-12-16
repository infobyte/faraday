'''
Faraday Penetration Test IDE - Community Version
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
import hashlib
import uuid
import time
import socket
import struct
import sys

def get_hash(parts):
                                     
    return hashlib.sha1("._.".join(parts)).hexdigest()

def new_id():
    return uuid.uuid4()
    
def get_macaddress(host):
    if sys.platform in ['linux','linux2']:
        with open("/proc/net/arp") as fh:
            for line in fh:
                fields = line.strip().split()
                if fields[0] == host:
                    return fields[3]
    else:
        return None
    
def gateway():
    ip=""
    if sys.platform in ['linux','linux2']:
        with open("/proc/net/route") as fh:
            for line in fh:
                fields = line.strip().split()
                if fields[1] != '00000000' or not int(fields[3], 16) & 2:
                    continue
                ip=socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))
                mac=get_macaddress(ip)
                return [str(ip),str(mac)]
    elif sys.platform in ['darwin']:
                                    
        return None
    else:
        return None
    

                                                       