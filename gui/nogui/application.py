#!/usr/bin/env python
'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

import time

from gui.gui_app import FaradayUi
from gui.nogui.eventwatcher import EventWatcher
import model.guiapi
from utils.logs import getLogger

from config.configuration import getInstanceConfiguration
CONF = getInstanceConfiguration()


class GuiApp(FaradayUi):
    def __init__(self, model_controller, plugin_manager, workspace_manager, plugin_controller):
        FaradayUi.__init__(self,
                           model_controller,
                           plugin_manager,
                           workspace_manager,
                           plugin_controller)
        self._stop = False
        model.guiapi.setMainApp(self)
        self.event_watcher = EventWatcher()
        model.guiapi.notification_center.registerWidget(self.event_watcher)

    def run(self, args):
        workspace = args.workspace
        try:
            ws = super(GuiApp, self).openWorkspace(workspace)
        except Exception as e:
            getLogger(self).error(
                ("Your last workspace %s is not accessible, "
                 "check configuration") % workspace)
            getLogger(self).error(str(e))
            ws = self.openDefaultWorkspace()
        workspace = ws.name
        CONF.setLastWorkspace(workspace)
        CONF.saveConfig()
        getLogger(self).info("Workspace %s loaded" % workspace)
        while True:
            if self._stop:
                return
            time.sleep(0.01)

    def quit(self):
        self._stop = True

    def postEvent(self, receiver, event):
        receiver.update(event)
