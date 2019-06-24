'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
import logging

from faraday.client.managers.reports_managers import ReportProcessor

logger = logging.getLogger(__name__)

class CliApp():
    def __init__(self, workspace_manager, plugin_controller):
        self.workspace_manager = workspace_manager
        self.plugin_controller = plugin_controller

    def run(self, args):
        workspace = args.workspace
        try:
            self.workspace_manager.openWorkspace(workspace)
        except Exception as e:
            logger.error(
                ("The workspace %s is not accessible, "
                 "check configuration") % workspace)
            logger.error(str(e))
            return -1

        rp = ReportProcessor(self.plugin_controller)
        rp.processReport(args.filename)
