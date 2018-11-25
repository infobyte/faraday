#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
import socket
import subprocess
import getpass

from threading import Event
from sys import platform as _platform


def get_private_ip():
    """
    This method returns the first private ip address
    configured for this machine.
    TODO: The problem is what happens when the machine
    has more than one private ip
    """
    try:
        ip = socket.gethostbyname(socket.gethostname())
    except socket.gaierror:
        return ''
    if ip:
        if not ip.startswith('127'):
            return ip
    ip = socket.gethostbyname(socket.getfqdn())
    if ip:
        if not ip.startswith('127'):
            return ip
    if _platform == "linux" or _platform == "linux2": # linux
        ip = subprocess.check_output(["ip addr | grep 'state UP' -A2 | tail -n1 | awk '{print $2}' | cut -f1 -d'/'"], shell=True)
    elif _platform == "darwin": # MAC OS X
        ip = subprocess.check_output(["ifconfig | grep 'inet ' | grep -Fv 127.0.0.1 | awk '{print $2}' "], shell=True)
        ip = ip.rstrip() # removes '\n'
    return ip


def get_hostname():
    return socket.gethostname()

def get_user():
    return getpass.getuser()


class CommandRunInformation(object):
    """Command Run information object containing:
        command, parameters, time, workspace, etc."""
    class_signature = "CommandRunInformation"

    def __init__(self, **kwargs):
        self.type = self.__class__.__name__
        self.user = get_user()
        self.ip = get_private_ip()
        self.hostname = get_hostname()
        self.itime = None
        self.duration = None
        self.params = None
        self.workspace = None
        self.import_source = None
        self._id = None
        self.id_available = Event()

        for k, v in kwargs.items():
            setattr(self, k, v)

    def getID(self):
        if self._id is None:
            self.id_available.wait(timeout=1)
        return self._id

    def setID(self, id):
        self._id = id
        self.id_available.set()

    def toDict(self):
        return self.__dict__

    def fromDict(self, dictt):
        for k, v in dictt.items():
            setattr(self, k, v)
        return self
