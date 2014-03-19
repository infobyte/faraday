#!/usr/bin/env python
'''
Faraday Penetration Test IDE - Community Version
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''


class UiFactory(object):
    @staticmethod
    def create(main_app, model_controller, gui="gtk"):
        if gui == "gtk":
            from gui.gtk.application import GuiApp
        elif gui == "qt3":
            from gui.qt3.application import GuiApp
        else:
            from gui.nogui.application import GuiApp

        return GuiApp(main_app, model_controller)


class FaradayUi(object):
    def __init__(self, main_app, model_controller, gui="gtk"):
        self.main_app = main_app
        self.model_controller = model_controller

    def setSplashImage(self, ipath):
        pass

    def startSplashScreen(self):
        pass

    def stopSplashScreen(self):
        pass

    def loadWorkspaces(self):
        pass

    def run(self, args):
        pass

    def quit(self):
        pass

    def postEvent(self, event):
        pass
