#!/usr/bin/env python
'''
Faraday Penetration Test IDE - Community Version
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

from gui.gui_app import FaradayUi


class GuiApp(FaradayUi):
    def __init__(self, model_controller, plugin_manager, workspace_manager):
        FaradayUi.__init__(self,
                           model_controller,
                           plugin_manager,
                           workspace_manager)

    def run(self, args):
        while True:
            # find a way to keep this thread running, until CTRL+C is pressed
            pass
