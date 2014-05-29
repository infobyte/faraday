'''
Faraday Penetration Test IDE - Community Version
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

import model.guiapi


class ChangeController(object):
    def __init__(self):
        self.workspace = None

    def setWorkspace(self, workspace):
        self.workspace = workspace

    def loadChanges(self, changes):
        # first, we notify the changes
        for change in changes:
            model.guiapi.notification_center.changeFromInstance(change)
        # then we reload the workspace
        self.workspace.load()
