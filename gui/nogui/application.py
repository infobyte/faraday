#!/usr/bin/env python
'''
Faraday Penetration Test IDE - Community Version
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

import time

from gui.gui_app import FaradayUi
from gui.nogui.eventwatcher import EventWatcher
import model.guiapi


class GuiApp(FaradayUi):
    def __init__(self, model_controller, plugin_manager, workspace_manager):
        FaradayUi.__init__(self,
                           model_controller,
                           plugin_manager,
                           workspace_manager)
        self._stop = False
        model.guiapi.setMainApp(self)
        self.event_watcher = EventWatcher()
        model.guiapi.notification_center.registerWidget(self.event_watcher)

    def run(self, args):

        while True:
            if self._stop:
                return
            time.sleep(0.01)

    def quit(self):
        self._stop = True

    def postEvent(self, receiver, event):
        receiver.update(event)
