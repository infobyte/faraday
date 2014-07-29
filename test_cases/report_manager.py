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
from managers.reports_managers import ReportManager, NoReportsWatchException

from persistence.persistence_managers import DBTYPE
from mockito import mock, verify, when, any
CONF = getInstanceConfiguration()

from test_cases import common

class UnitTestWorkspaceManager(unittest.TestCase):
    def testCreateReportManager(self):
        timer = 10
        report_manager = ReportManager(timer, mock())

        self.assertIsNotNone(report_manager)

    def testWatchReportPath(self):
        import os.path 
        import os
        workspace_name = common.new_random_workspace_name()
        timer = 10

        report_manager = ReportManager(timer, mock())
        report_manager.watch(workspace_name)

        self.assertTrue(os.path.exists(os.path.join(CONF.getReportPath(),
                            workspace_name)), 'Report directory not found')
        
    def testStartReportNoPathRunsException(self): 
        report_manager = ReportManager(0, mock())
        self.assertRaises(NoReportsWatchException, report_manager.startWatch) 

if __name__ == '__main__':
    unittest.main()

