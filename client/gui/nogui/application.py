#!/usr/bin/env python
'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

import time

from faraday.client.gui.gui_app import FaradayUi
from faraday.client.gui.nogui.eventwatcher import EventWatcher
import faraday.client.model.guiapi
from faraday.utils.logs import getLogger

from faraday.config.configuration import getInstanceConfiguration
CONF = getInstanceConfiguration()


class GuiApp(FaradayUi):
    def __init__(self, model_controller, plugin_manager, workspace_manager, plugin_controller):
        FaradayUi.__init__(self,
                           model_controller,
                           plugin_manager,
                           workspace_manager,
                           plugin_controller)
        self._stop = False
        faraday.client.model.guiapi.setMainApp(self)
        self.event_watcher = EventWatcher()
        faraday.client.model.guiapi.notification_center.registerWidget(self.event_watcher)

    def run(self, args):
        workspace = args.workspace
        try:
            ws = super(GuiApp, self).openWorkspace(workspace)
        except Exception as e:
            getLogger(self).error(
                ("Your last workspace %s is not accessible, "
                 "check configuration.") % workspace)
            getLogger(self).error(
                    "You may try and go to ~/.faraday/config/user.xml "
                    "to set a valid api_uri and last_workspace")
            getLogger(self).error(str(e))
            return -1
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
