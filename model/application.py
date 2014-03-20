#!/usr/bin/env python
'''
Faraday Penetration Test IDE - Community Version
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
import os
import sys
import signal

# TODO: no seria mejor activar todo ?
# XXX: something strange happens if we import
# this module at the bottom of the list....
from auth.manager import SecurityManager
from auth.manager import codes
from workspace import WorkspaceManager
#from shell.controller.env import ShellEnvironment
import model.controller
import model.api
import model.guiapi
import model.log
import traceback
from managers.all import PluginManager

#from gui.qt3.mainwindow import MainWindow
from utils.error_report import exception_handler
from utils.error_report import installThreadExcepthook

#from gui.gui_app import FaradayUi
from gui.gui_app import UiFactory

from config.configuration import getInstanceConfiguration
CONF = getInstanceConfiguration()


class MainApplication(object):
    """
    """

    logger = None

    @staticmethod
    def getLogger():

        if MainApplication.logger is None:
            MainApplication.logger = model.log.getLogger()
        return MainApplication.logger

    def __init__(self, args):
        self._original_excepthook = sys.excepthook

        self._configuration = CONF

        self._security_manager = SecurityManager()

        self._model_controller = model.controller.ModelController(
            security_manager=self._security_manager)

        self._plugin_manager = PluginManager(os.path.join(CONF.getConfigPath(),
                                             "plugins"))

        self._workspace_manager = WorkspaceManager(self._model_controller,
                                                   self._plugin_manager.createController("ReportManager"))

        self.gui_app = UiFactory.create(self._model_controller,
                                        self._plugin_manager,
                                        self._workspace_manager,
                                        args.gui)

        self.gui_app.setSplashImage(os.path.join(
            CONF.getImagePath(), "splash2.png"))

        self.gui_app.setLogger(self.getLogger())

        #self._splash_screen = qt.QSplashScreen(qt.QPixmap(os.path.join(CONF.getImagePath(),"splash2.png")),
        #                                       qt.Qt.WStyle_StaysOnTop)

        #notifier = model.log.getNotifier()
        #notifier.widget = self._main_window

        #model.guiapi.setMainApp(self)

    def enableExceptHook(self):
        sys.excepthook = exception_handler
        installThreadExcepthook()

    def disableLogin(self):
        CONF.setAuth(sys.disablelogin)

    def start(self):
        try:

            #splash_timer = qt.QTimer.singleShot(1700, lambda *args:None)
            #self._splash_screen.show()
            self.gui_app.startSplashScreen()

            signal.signal(signal.SIGINT, signal.SIG_DFL)

            #self._writeSplashMessage("Setting up remote API's...")

            model.api.devlog("Starting application...")
            model.api.devlog("Setting up remote API's...")

            model.api.setUpAPIs(self._model_controller,
                                CONF.getApiConInfoHost(),
                                CONF.getApiConInfoPort())
            model.guiapi.setUpGUIAPIs(self._model_controller)

            #self._writeSplashMessage("Starting model controller daemon...")

            model.api.devlog("Starting model controller daemon...")
            self._model_controller.start()
            model.api.startAPIServer()

            #self._writeSplashMessage("Setting up main GUI...")

            #self._writeSplashMessage("Creating default shell...")

            #self._main_window.createShellTab()

            #self._writeSplashMessage("Ready...")
            #self.logger.log("Faraday ready...")
            model.api.devlog("Faraday ready...")

            self.gui_app.stopSplashScreen()
            #self._main_window.showAll()

            logged = True

            while True:

                username, password = "usuario", "password"

                if username is None and password is None:
                    break
                result = self._security_manager.authenticateUser(username, password)
                if result == codes.successfulLogin:
                    logged = True
                    break

            if logged:
                #self._main_window.showLoggedUser(self._security_manager.current_user.display_name)
                model.api.__current_logged_user = username

                self._workspace_manager.loadWorkspaces()

                last_workspace = CONF.getLastWorkspace()
                w = self._workspace_manager.createWorkspace(last_workspace)
                self._workspace_manager.setActiveWorkspace(w)

                self.gui_app.loadWorkspaces()

                self._workspace_manager.startReportManager()

        except Exception:

            print "There was an error while starting Faraday"
            print "-" * 50
            traceback.print_exc()
            print "-" * 50
            self.__exit(-1)

        if logged:
            exit_code = self.gui_app.run([])
            #exit_code = self.app.exec_loop()
        else:
            exit_code = -1

        return self.__exit(exit_code)

    def __exit(self, exit_code=0):
        """
        Exits the application with the provided code.
        It also waits until all app threads end.
        """
        self._workspace_manager.stopAutoLoader()
        self._workspace_manager.stopReportManager()
        #self._main_window.hide()
        model.api.devlog("Closing Faraday...")
        self._workspace_manager.saveWorkspaces()
        model.api.devlog("stopping model controller thread...")
        self._model_controller.stop()
        model.api.devlog("stopping model controller thread...")
        self.gui_app.quit()
        model.api.devlog("Waiting for controller threads to end...")
        self._model_controller.join()
        model.api.stopAPIServer()

        return exit_code

    def quit(self):
        """
        Redefined quit handler to nicely end up things
        """

        self.gui_app.quit()

    def getWorkspaceManager(self):
        return self._workspace_manager

    # def _writeSplashMessage(self, text):
    #     self._splash_screen.message(text, qt.Qt.AlignRight | qt.Qt.AlignTop, qt.Qt.red)
