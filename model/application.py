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
from model.controller import ModelController
from persistence.persistence_managers import DbManager
from controllers.change import ChangeController
from managers.model_managers import WorkspaceManager
import model.api
import model.guiapi
import apis.rest.api as restapi
import model.log
from utils.logs import getLogger
import traceback
from managers.all import PluginManager
from managers.mappers_manager import MapperManager
from managers.reports_managers import ReportManager

from utils.error_report import exception_handler
from utils.error_report import installThreadExcepthook

from gui.gui_app import UiFactory

from config.configuration import getInstanceConfiguration
CONF = getInstanceConfiguration()


class MainApplication(object):
    """
    """

    def __init__(self, args):
        self._original_excepthook = sys.excepthook

        self._configuration = CONF

        self._security_manager = SecurityManager()
        self._mappers_manager = MapperManager()
        self._changes_controller = ChangeController(self._mappers_manager)
        self._db_manager = DbManager()

        self._model_controller = ModelController(
            self._security_manager,
            self._mappers_manager)

        self._plugin_manager = PluginManager(
            os.path.join(CONF.getConfigPath(), "plugins"),
            self._mappers_manager)

        #self._reports_manager = ReportManager(10, self._plugin_manager.createController("ReportManager"))

        self._workspace_manager = WorkspaceManager(
            self._db_manager,
            self._mappers_manager,
            self._changes_controller)

        self.gui_app = UiFactory.create(self._model_controller,
                                        self._plugin_manager,
                                        self._workspace_manager,
                                        args.gui)

        self.gui_app.setSplashImage(os.path.join(
            CONF.getImagePath(), "splash2.png"))

    def enableExceptHook(self):
        sys.excepthook = exception_handler
        installThreadExcepthook()

    def disableLogin(self):
        CONF.setAuth(sys.disablelogin)

    def start(self):
        try:

            self.gui_app.startSplashScreen()

            signal.signal(signal.SIGINT, self.ctrlC)

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
                model.api.devlog("Starting application...")
                model.api.devlog("Setting up remote API's...")
                # We need to create the last used workspace (or the default
                # workspace) before we start the model controller and the
                # report manager

                last_workspace = CONF.getLastWorkspace()
                if not self._workspace_manager.workspaceExists(last_workspace):
                    self._workspace_manager.createWorkspace(last_workspace)
                else:
                    self._workspace_manager.openWorkspace(last_workspace)

                model.api.setUpAPIs(
                    self._model_controller,
                    self._workspace_manager,
                    CONF.getApiConInfoHost(),
                    CONF.getApiConInfoPort())
                model.guiapi.setUpGUIAPIs(self._model_controller)

                model.api.devlog("Starting model controller daemon...")

                self._model_controller.start()
                model.api.startAPIServer()
                restapi.startAPIs(
                    self._plugin_manager,
                    self._model_controller,
                    self._mappers_manager)
                # Start report manager here

                model.api.devlog("Faraday ready...")
                model.api.__current_logged_user = username

                self.gui_app.loadWorkspaces()

            self.gui_app.stopSplashScreen()

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
        model.api.devlog("Closing Faraday...")
        model.api.devlog("stopping model controller thread...")
        model.api.stopAPIServer()
        restapi.stopServer()
        # we should stop the report manager here
        self._model_controller.stop()
        self._model_controller.join()
        self.gui_app.quit()
        model.api.devlog("Waiting for controller threads to end...")
        return exit_code

    def quit(self):
        """
        Redefined quit handler to nicely end up things
        """
        self.gui_app.quit()

    def ctrlC(self, signal, frame):
        getLogger(self).info("Exiting...")
        self.__exit(exit_code=0)

    def getWorkspaceManager(self):
        return self._workspace_manager
