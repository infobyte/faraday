'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

from utils.logs import getLogger
from managers.reports_managers import ReportProcessor


class CliApp():
    def __init__(self, workspace_manager, plugin_controller):
        self.workspace_manager = workspace_manager
        self.plugin_controller = plugin_controller

    def run(self, args):
        workspace = args.workspace
        try:
            self.workspace_manager.openWorkspace(workspace)
        except Exception as e:
            getLogger(self).error(
                ("The workspace %s is not accessible, "
                 "check configuration") % workspace)
            getLogger(self).error(str(e))
            return -1

        rp = ReportProcessor(self.plugin_controller)
        rp.processReport(args.filename)
