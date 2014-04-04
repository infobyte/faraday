#!/usr/bin/env python
'''
Faraday Penetration Test IDE - Community Version
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''


class UiFactory(object):
    @staticmethod
    def create(model_controller, plugin_manager, workspace_manager, gui="gtk"):
        if gui == "gtk":
            from gui.gtk.application import GuiApp
        elif gui == "qt3":
            from gui.qt3.application import GuiApp
        else:
            from gui.nogui.application import GuiApp

        return GuiApp(model_controller, plugin_manager, workspace_manager)


class FaradayUi(object):
    def __init__(self, model_controller, plugin_manager,
                 workspace_manager, gui="qt3"):
        #self.main_app = main_app
        self.model_controller = model_controller
        self.plugin_manager = plugin_manager
        self.workspace_manager = workspace_manager

    def getModelController(self):
        return self.model_controller

    def getPluginManager(self):
        return self.plugin_manager

    def getWorkspaceManager(self):
        return self.workspace_manager

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

    def postEvent(self, receiver, event):
        pass

    def createLoggerWidget(self):
        pass
