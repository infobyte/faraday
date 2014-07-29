#!/usr/bin/python
'''
Faraday Penetration Test IDE - Community Version
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
import unittest
import sys
sys.path.append('.')

from config.configuration import getInstanceConfiguration
from model.workspace import Workspace
from managers.reports_managers import ReportManager

from persistence.persistence_managers import DBTYPE
from mockito import mock, verify, when, any
CONF = getInstanceConfiguration()

class UnitTestWorkspaceManager(unittest.TestCase):
    def testCreateReportManager(self):
        timer = 10
        report_manager = ReportManager(timer, mock())

        self.assertIsNotNone(report_manager)



if __name__ == '__main__':
    unittest.main()

