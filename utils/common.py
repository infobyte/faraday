'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
import hashlib
import uuid
import time
import socket
import struct
import sys
import requests

def sha1OfFile(filepath):
    with open(filepath, 'rb') as f:
        return hashlib.sha1(f.read()).hexdigest()

def sha1OfStr(strvalue):
    return hashlib.sha1(strvalue).hexdigest()        

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


def checkSSL(uri):
    """
    This method checks SSL validation
    It only returns True if the certificate is valid
    and the http server returned a 200 OK
    """
    try:
        res = requests.get(uri, timeout=5)
        return res.ok
    except Exception:
        return False
