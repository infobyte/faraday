#!/usr/bin/env python
'''
Faraday Penetration Test IDE - Community Version
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''


class NoUi(object):
    def __init__(self):
        pass

    def run(self, args):
        while True:
            # find a way to keep this thread running, until CTRL+C is pressed
            pass

    def quit(self):
        pass

    def setSplashImage(self, ipath):
        pass

    def startSplashScreen(self):
        pass

    def stopSplashScreen(self):
        pass

    def loadWorkspaces(self):
        pass


class FaradayUi(object):
    def __init__(self, model_controller, gui="gtk"):
        if gui == "gtk":
            from gui.gtk.application import GuiApp
            self.gui = GuiApp(model_controller)
        elif gui == "qt3":
            from gui.qt3.application import GuiApp
            self.gui = GuiApp(model_controller)
        else:
            self.gui = NoUi()

    def setSplashImage(self, ipath):
        self.gui.setSplashImage(ipath)

    def startSplashScreen(self):
        self.gui.startSplashScreen()

    def stopSplashScreen(self):
        self.gui.stopSplashScreen()

    def loadWorkspaces(self):
        self.gui.loadWorkspaces()

    def run(self, args):
        self.gui.run(args)

    def quit(self):
        self.gui.quit()
