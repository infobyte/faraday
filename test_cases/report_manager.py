#!/usr/bin/python
"""
Faraday Penetration Test IDE.

Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
"""

import mock
import unittest
import sys
sys.path.append('.')

from plugins.core import PluginControllerForApi
from managers.reports_managers import ReportProcessor
from managers.reports_managers import ReportParser

class UnitTestReportParser(unittest.TestCase):

    def testSendReportWithPlugin(self):

        plugin_controller = mock.Mock(spec=PluginControllerForApi)
        plugin_controller.processCommandInput.return_value = (True, None, None)
        report_processor = ReportProcessor(plugin_controller)

        file_mock = mock.MagicMock(spec=file)
        file_mock.read.return_value = 'Stringreturned'

        with mock.patch('__builtin__.open', create=True) as mock_open:
            res = report_processor._sendReport("nmap", 'strings')
            self.assertTrue(res, "The plugin should be executed")

    def testSendReportWithoutPlugin(self):

        plugin_controller = mock.Mock(spec=PluginControllerForApi)
        plugin_controller.processCommandInput.return_value = (False, None, None)
        report_processor = ReportProcessor(plugin_controller)

        file_mock = mock.MagicMock(spec=file)
        file_mock.read.return_value = 'Stringreturned'

        with mock.patch('__builtin__.open', create=True) as mock_open:
            res = report_processor._sendReport("nmap", 'strings')
            self.assertFalse(res, "The plugin should not be executed")

if __name__ == '__main__':
    unittest.main()
