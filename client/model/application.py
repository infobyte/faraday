#!/usr/bin/env python
'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
import os
import sys
import signal
import json
import threading
from json import loads
from time import sleep
try:
    from Queue import Queue
except ImportError:
    from queue import Queue
import requests

from faraday.client.model.controller import ModelController
from faraday.client.managers.workspace_manager import WorkspaceManager
from faraday.client.plugins.controller import PluginController
from faraday.client.persistence.server.server import login_user

from faraday.utils.logs import setUpLogger
import faraday.client.model.api
import faraday.client.model.guiapi
import faraday.client.apis.rest.api as restapi
import faraday.client.model.log
from faraday.utils.logs import getLogger
import traceback
from faraday.client.plugins.manager import PluginManager
from faraday.client.managers.mapper_manager import MapperManager
from faraday.utils.error_report import exception_handler
from faraday.utils.error_report import installThreadExcepthook

from faraday.client.gui.gui_app import UiFactory
from faraday.client.model.cli_app import CliApp

from faraday.config.configuration import getInstanceConfiguration
CONF = getInstanceConfiguration()


class TimerClass(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.__event = threading.Event()

    def sendNewstoLogGTK(self, json_response):

        information = loads(json_response)

        for news in information["news"]:
            faraday.client.model.guiapi.notification_center.sendCustomLog(
                "NEWS -" + news["url"] + "|" + news["description"])

    def run(self):
        while not self.__event.is_set():
            try:
                sleep(5)
                res = requests.get(
                    "https://www.faradaysec.com/scripts/updatedb.php",
                    params={'version': CONF.getVersion()},
                    timeout=1,
                    verify=True)

                self.sendNewstoLogGTK(res.text)

            except Exception:
                faraday.client.model.api.devlog(
                    "NEWS: Can't connect to faradaysec.com...")

            self.__event.wait(43200)

    def stop(self):
        self.__event.set()


class MainApplication(object):

    def __init__(self, args):
        self._original_excepthook = sys.excepthook

        self.args = args

        logger = getLogger(self)
        if args.creds_file:
            try:
                with open(args.creds_file, 'r') as fp:
                    creds = json.loads(fp.read())
                    username = creds.get('username')
                    password = creds.get('password')
                    session_cookie = login_user(CONF.getServerURI(),
                                                username, password)
                    if session_cookie:
                        logger.info('Login successful')
                        CONF.setDBUser(username)
                        CONF.setDBSessionCookies(session_cookie)
                    else:
                        logger.error('Login failed')
            except (IOError, ValueError):
                logger.error("Credentials file couldn't be loaded")

        self._mappers_manager = MapperManager()
        pending_actions = Queue()
        self._model_controller = ModelController(self._mappers_manager, pending_actions)

        self._plugin_manager = PluginManager(
            os.path.join(CONF.getConfigPath(), "plugins"),
            pending_actions=pending_actions,
        )

        self._workspace_manager = WorkspaceManager(
            self._mappers_manager)

        # Create a PluginController and send this to UI selected.
        self._plugin_controller = PluginController(
            'PluginController',
            self._plugin_manager,
            self._mappers_manager,
            pending_actions
        )

        if self.args.cli:

            self.app = CliApp(self._workspace_manager, self._plugin_controller)

            if self.args.keep_old:
                CONF.setMergeStrategy("old")
            else:
                CONF.setMergeStrategy("new")

        else:
            self.app = UiFactory.create(self._model_controller,
                                        self._plugin_manager,
                                        self._workspace_manager,
                                        self._plugin_controller,
                                        self.args.gui)

        self.timer = TimerClass()
        self.timer.start()

    def on_connection_lost(self):
        """All it does is send a notification to the notification center"""
        faraday.client.model.guiapi.notification_center.DBConnectionProblem()

    def enableExceptHook(self):
        sys.excepthook = exception_handler
        installThreadExcepthook()

    def start(self):
        try:
            signal.signal(signal.SIGINT, self.ctrlC)

            faraday.client.model.api.devlog("Starting application...")
            faraday.client.model.api.devlog("Setting up remote API's...")

            if not self.args.workspace:
                workspace = CONF.getLastWorkspace()
                self.args.workspace = workspace

            faraday.client.model.api.setUpAPIs(
                self._model_controller,
                self._workspace_manager,
                CONF.getApiConInfoHost(),
                CONF.getApiConInfoPort())
            faraday.client.model.guiapi.setUpGUIAPIs(self._model_controller)

            faraday.client.model.api.devlog("Starting model controller daemon...")

            self._model_controller.start()
            faraday.client.model.api.startAPIServer()
            restapi.startAPIs(
                self._plugin_controller,
                self._model_controller,
                CONF.getApiConInfoHost(),
                CONF.getApiRestfulConInfoPort()
            )

            faraday.client.model.api.devlog("Faraday ready...")

            exit_code = self.app.run(self.args)

        except Exception as exception:
            print("There was an error while starting Faraday:")
            print("*" * 3)
            print(exception) # instead of traceback.print_exc()
            print("*" * 3)
            exit_code = -1

        finally:
            return self.__exit(exit_code)

    def __exit(self, exit_code=0):
        """
        Exits the application with the provided code.
        It also waits until all app threads end.
        """
        faraday.client.model.api.log("Closing Faraday...")
        faraday.client.model.api.devlog("stopping model controller thread...")
        faraday.client.model.api.stopAPIServer()
        restapi.stopServer()
        self._model_controller.stop()
        if self._model_controller.isAlive():
            # runs only if thread has started, i.e. self._model_controller.start() is run first
            self._model_controller.join()
        self.timer.stop()
        faraday.client.model.api.devlog("Waiting for controller threads to end...")
        return exit_code

    def quit(self):
        """
        Redefined quit handler to nicely end up things
        """
        self.app.quit()

    def ctrlC(self, signal, frame):
        getLogger(self).info("Exiting...")
        self.app.quit()
