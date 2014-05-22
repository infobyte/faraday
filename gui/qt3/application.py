#!/usr/bin/env python
'''
Faraday Penetration Test IDE - Community Version
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
from shell.controller.env import ShellEnvironment
from model.workspace import WorkspaceOnFS, WorkspaceOnCouch

import model.guiapi
import model.api
import model.log

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

        self._splash_screen = qt.QSplashScreen(
            qt.QPixmap(os.path.join(CONF.getImagePath(), "splash2.png")),
            qt.Qt.WStyle_StaysOnTop)

    def getMainWindow(self):
        return self._main_window

    def run(self, args):
        self._main_window.createShellTab()
        self.createLoggerWidget()
        self._main_window.showAll()
        exit_code = self.exec_loop()
        return exit_code

    def createLoggerWidget(self):
        if not model.log.getLogger().isGUIOutputRegistered():
            model.log.getLogger().registerGUIOutput(self._main_window.getLogConsole())

    def loadWorkspaces(self):
        self.getMainWindow().getWorkspaceTreeView().loadAllWorkspaces()

    def setSplashImage(self, ipath):
        pass

    def startSplashScreen(self):
        splash_timer = qt.QTimer.singleShot(1700, lambda *args: None)
        self._splash_screen.show()

    def stopSplashScreen(self):
        self._splash_screen.finish(self._main_window)

    def quit(self):
        model.log.getLogger().clearWidgets()
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

    def syncWorkspaces(self):
        try:
            self.getWorkspaceManager().saveWorkspaces()
        except Exception:
            model.api.log("An exception was captured while synchronizing \
                workspaces\n%s" % traceback.format_exc(), "ERROR")

    def saveWorkspaces(self):
        try:
            self.getWorkspaceManager().saveWorkspaces()
        except Exception:
            model.api.log("An exception was captured while saving \
                workspaces\n%s" % traceback.format_exc(), "ERROR")

    def createWorkspace(self, name, description="", w_type=""):

        if name in self.getWorkspaceManager().getWorkspacesNames():

            model.api.log("A workspace with name %s already exists"
                          % name, "ERROR")
        else:
            model.api.log("Creating workspace '%s'" % name)
            model.api.devlog("Looking for the delegation class")
            manager = self.getWorkspaceManager()
            workingClass = globals()[manager.getWorkspaceType(name)]

            w = manager.createWorkspace(name, description, workspaceClass=workingClass)
            self.getWorkspaceManager().setActiveWorkspace(w)
            self.getModelController().setWorkspace(w)

            self.getMainWindow().refreshWorkspaceTreeView()

            self.getMainWindow().getWorkspaceTreeView().loadAllWorkspaces()

    def openWorkspace(self, name):
        self.saveWorkspaces()
        try:
            workspace = self.getWorkspaceManager().openWorkspace(name)
            self.getModelController().setWorkspace(workspace)
        except Exception:
            model.api.log("An exception was captured while opening \
                workspace %s\n%s" % (name, traceback.format_exc()), "ERROR")
