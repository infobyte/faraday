#!/usr/bin/python
'''
Faraday Penetration Test IDE - Community Version
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
from unittest import TestCase
import unittest
import sys
sys.path.append('.')
import model.controller as controller
import plugins.core as plcore
from mockito import mock, verify, when, any
from model import api
from model.hosts import Host, Interface, Service
from model.workspace import WorkspaceOnCouch, WorkspaceManager, WorkspaceOnFS
from model.common import ModelObjectVuln, ModelObjectVulnWeb, ModelObjectNote, ModelComposite, ModelObjectCred
from persistence.orm import WorkspacePersister
import random

from model.visitor import VulnsLookupVisitor
import test_cases.common as test_utils

from managers.all import CommandManager, CouchdbManager, PersistenceManagerFactory

class ModelObjectComposite(unittest.TestCase):

    def testAddInterfaceToHost(self): 
        host = Host('coco')
        inter = Interface('cuca')
        host.addChild(inter.getID(), inter)

        self.assertIn(inter, host.childs.values(), 'Interface not in childs')
        self.assertIn(inter, host.getAllInterfaces(), 'Interface not accessible')


if __name__ == '__main__':
    unittest.main() 




