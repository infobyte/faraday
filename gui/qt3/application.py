#!/usr/bin/env python
'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

import os
import traceback

try:
    import qt
except ImportError:
    print "[-] Python QT3 was not found in the system, please install it and try again"
    print "Check the deps file"

from gui.gui_app import FaradayUi
from gui.qt3.mainwindow import MainWindow
from gui.qt3.customevents import QtCustomEvent
from gui.qt3.logconsole import GUIHandler
from shell.controller.env import ShellEnvironment

import model.guiapi
import model.api
import model.log
from utils.logs import addHandler

from config.configuration import getInstanceConfiguration
CONF = getInstanceConfiguration()


class GuiApp(qt.QApplication, FaradayUi):
    def __init__(self, model_controller, plugin_manager, workspace_manager):
        FaradayUi.__init__(self,
                           model_controller,
                           plugin_manager,
                           workspace_manager)
        qt.QApplication.__init__(self, [])

        self._shell_envs = dict()

        model.guiapi.setMainApp(self)

        self._main_window = MainWindow(CONF.getAppname(),
                                       self,
                                       self.getModelController(),
                                       self.getPluginManager())
        self.setMainWidget(self.getMainWindow())

        notifier = model.log.getNotifier()
        notifier.widget = self._main_window
        model.guiapi.notification_center.registerWidget(self._main_window)

        self.loghandler = GUIHandler()
        addHandler(self.loghandler)

        self._splash_screen = qt.QSplashScreen(
            qt.QPixmap(os.path.join(CONF.getImagePath(), "splash2.png")),
            qt.Qt.WStyle_StaysOnTop)

    def getMainWindow(self):
        return self._main_window

    def run(self, args):
        self.createLoggerWidget()
        self._main_window.showAll()
        couchURL = CONF.getCouchURI()
        if couchURL:
            url = "%s/reports/_design/reports/index.html" % couchURL
            model.api.log("Faraday ui is ready")
            model.api.log("Make sure you have couchdb up and running if you want visualizations.")
            model.api.log("If couchdb is up, point your browser to: [%s]" % url)
        else:
            model.api.log("Please configure Couchdb for fancy HTML5 Dashboard")
        exit_code = self.exec_loop()
        return exit_code

    def createLoggerWidget(self):
        self.loghandler.registerGUIOutput(self._main_window.getLogConsole())

    def loadWorkspaces(self):
        self.getMainWindow().getWorkspaceTreeView().loadAllWorkspaces()

    def setSplashImage(self, ipath):
        pass

    def startSplashScreen(self):
        splash_timer = qt.QTimer.singleShot(1700, lambda *args: None)
        self._splash_screen.show()

    def splashMessage(self, message):
        self._splash_screen.message(
            message,
            qt.Qt.AlignLeft | qt.Qt.AlignBottom,
            qt.QColor(180, 0, 0))

    def stopSplashScreen(self):
        self._splash_screen.finish(self._main_window)

    def quit(self):
        self.loghandler.clearWidgets()
        self.getMainWindow().hide()
        envs = [env for env in self._shell_envs.itervalues()]
        for env in envs:
            env.terminate()
        # exit status
        notifier = model.log.getNotifier()
        notifier.widget = None
        qt.QApplication.quit(self)

    def postEvent(self, receiver, event):
        if receiver is None:
            receiver = self.getMainWindow()
        qt.QApplication.postEvent(receiver, QtCustomEvent.create(event))

    def createShellEnvironment(self, name=None):

        model.api.devlog("createShellEnvironment called \
            - About to create new shell env with name %s" % name)

        shell_env = ShellEnvironment(name, self,
                                     self.getMainWindow().getTabManager(),
                                     self.model_controller,
                                     self.plugin_manager.createController,
                                     self.deleteShellEnvironment)

        self._shell_envs[name] = shell_env
        self.getMainWindow().addShell(shell_env.widget)
        shell_env.run()

    def deleteShellEnvironment(self, name, ref=None):
        def _closeShellEnv(name):
            try:
                env = self._shell_envs[name]
                env.terminate()
                tabmanager.removeView(env.widget)
                del self._shell_envs[name]
            except Exception:
                model.api.devlog("ShellEnvironment could not be deleted")
                model.api.devlog("%s" % traceback.format_exc())

        model.api.devlog("deleteShellEnvironment called \
            - name = %s - ref = %r" % (name, ref))
        tabmanager = self.getMainWindow().getTabManager()
        if len(self._shell_envs) > 1:
            _closeShellEnv(name)
        else:
            if ref is not None:
                result = self.getMainWindow().exitFaraday()
                if result == qt.QDialog.Accepted:
                    self.quit()
                else:
                    _closeShellEnv(name)
                    self.getMainWindow().createShellTab()

    def removeWorkspace(self, name):
        model.api.log("Removing Workspace: %s" % name)
        return self.getWorkspaceManager().removeWorkspace(name)

    def createWorkspace(self, name, description="", w_type=""):

        if name in self.getWorkspaceManager().getWorkspacesNames():

            model.api.log("A workspace with name %s already exists"
                          % name, "ERROR")
        else:
            model.api.log("Creating workspace '%s'" % name)
            model.api.devlog("Looking for the delegation class")
            manager = self.getWorkspaceManager()

            w = manager.createWorkspace(name, description,
                                         manager.namedTypeToDbType(w_type))

            self.getMainWindow().refreshWorkspaceTreeView()

            self.getMainWindow().getWorkspaceTreeView().loadAllWorkspaces()

    def openWorkspace(self, name):
        try:
            self.getWorkspaceManager().openWorkspace(name)
        except Exception:
            model.api.log("An exception was captured while opening \
                workspace %s\n%s" % (name, traceback.format_exc()), "ERROR")
