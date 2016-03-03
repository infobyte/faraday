#!/usr/bin/env python
'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
import os
import sys
import signal
import threading
import requests

from model.controller import ModelController
from persistence.persistence_managers import DbManager
from controllers.change import ChangeController
from managers.workspace_manager import WorkspaceManager
import model.api
import model.guiapi
import apis.rest.api as restapi
import model.log
from utils.logs import getLogger
import traceback
from plugins.manager import PluginManager
from managers.mapper_manager import MapperManager
from utils.error_report import exception_handler
from utils.error_report import installThreadExcepthook

from gui.gui_app import UiFactory
from model.cli_app import CliApp

from config.configuration import getInstanceConfiguration
CONF = getInstanceConfiguration()


class TimerClass(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.__event = threading.Event()

    def run(self):
        while not self.__event.is_set():
            try:
                res = requests.get(
                    "https://www.faradaysec.com/scripts/updatedb.php",
                    params={'version': CONF.getVersion()},
                    timeout=1,
                    verify=True)
                res.status_code
            except Exception:
                model.api.devlog("CWE database couldn't be updated")
            self.__event.wait(43200)

    def stop(self):
        self.__event.set()


class MainApplication(object):
    """
    """

    def __init__(self, args):
        self._original_excepthook = sys.excepthook

        self.args = args

        self._mappers_manager = MapperManager()
        self._changes_controller = ChangeController()
        self._db_manager = DbManager()

        self._model_controller = ModelController(self._mappers_manager)

        self._plugin_manager = PluginManager(
            os.path.join(CONF.getConfigPath(), "plugins"),
            self._mappers_manager)

        self._workspace_manager = WorkspaceManager(
            self._db_manager,
            self._mappers_manager,
            self._changes_controller)

        if self.args.cli:
            self.app = CliApp(self._workspace_manager)
            CONF.setMergeStrategy("new")
        else:
            self.app = UiFactory.create(self._model_controller,
                                        self._plugin_manager,
                                        self._workspace_manager,
                                        self.args.gui)

        self.timer = TimerClass()
        self.timer.start()

    def enableExceptHook(self):
        sys.excepthook = exception_handler
        installThreadExcepthook()

    def disableLogin(self):
        CONF.setAuth(sys.disablelogin)

    def start(self):
        try:
            signal.signal(signal.SIGINT, self.ctrlC)

            model.api.devlog("Starting application...")
            model.api.devlog("Setting up remote API's...")

            if not self.args.workspace:
                workspace = CONF.getLastWorkspace()
                self.args.workspace = workspace

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
                self._mappers_manager,
                CONF.getApiConInfoHost(),
                CONF.getApiRestfulConInfoPort())

            model.api.devlog("Faraday ready...")

            exit_code = self.app.run(self.args)

        except Exception:
            print "There was an error while starting Faraday"
            print "-" * 50
            traceback.print_exc()
            print "-" * 50
            exit_code = -1

        finally:
            return self.__exit(exit_code)

    def __exit(self, exit_code=0):
        """
        Exits the application with the provided code.
        It also waits until all app threads end.
        """
        model.api.log("Closing Faraday...")
        model.api.devlog("stopping model controller thread...")
        model.api.stopAPIServer()
        restapi.stopServer()
        self._changes_controller.stop()
        self._model_controller.stop()
        self._model_controller.join()
        self.timer.stop()
        model.api.devlog("Waiting for controller threads to end...")
        return exit_code

    def quit(self):
        """
        Redefined quit handler to nicely end up things
        """
        self.app.quit()

    def ctrlC(self, signal, frame):
        getLogger(self).info("Exiting...")
        self.app.quit()

    def getWorkspaceManager(self):
        return self._workspace_manager
