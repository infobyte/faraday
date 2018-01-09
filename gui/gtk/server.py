#!/usr/bin/python2.7
# -*- coding: utf-8 -*-
'''
Faraday Penetration Test IDE
Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

import time
import threading

from model.guiapi import notification_center
from decorators import safe_io_with_server
from persistence.server import models, server_io_exceptions


class ServerIO(object):
    def __init__(self, active_workspace):
        self.__active_workspace = active_workspace
        self.stream = None  # will be set when active workpsace is set
        self.changes_lock = models.get_changes_lock()

    @property
    def active_workspace(self):
        return self.__active_workspace

    @active_workspace.setter
    def active_workspace(self, new_workspace):
        self.__active_workspace = new_workspace
        if self.stream:
            self.stream.stop()
        self.stream = self.get_changes_stream()
        self.continously_get_changes()

    @safe_io_with_server([])
    def get_hosts(self, **params):
        return models.get_hosts(self.active_workspace, **params)

    @safe_io_with_server(0)
    def get_hosts_number(self):
        return models.get_hosts_number(self.active_workspace)

    @safe_io_with_server([])
    def get_interfaces(self, **params):
        return models.get_interfaces(self.active_workspace, **params)

    @safe_io_with_server(0)
    def get_interfaces_number(self):
        return models.get_interfaces_number(self.active_workspace)

    @safe_io_with_server([])
    def get_services(self, **params):
        return models.get_services(self.active_workspace, **params)

    @safe_io_with_server(0)
    def get_services_number(self):
        return models.get_services_number(self.active_workspace)

    @safe_io_with_server([])
    def get_all_vulns(self, **params):
        return models.get_all_vulns(self.active_workspace, **params)

    @safe_io_with_server(0)
    def get_vulns_number(self):
        return models.get_vulns_number(self.active_workspace)

    @safe_io_with_server([])
    def get_workspaces_names(self):
        return models.get_workspaces_names()

    @safe_io_with_server(None)
    def get_object(self, object_signature, object_id):
        return models.get_object(self.active_workspace, object_signature, object_id)

    @safe_io_with_server(None)
    def get_host(self, host_id):
        return models.get_host(self.active_workspace, host_id)

    @safe_io_with_server((0, 0, 0, 0))
    def get_workspace_numbers(self):
        return models.get_workspace_numbers(self.active_workspace)

    @safe_io_with_server(False)
    def server_info(self):
        return models.server_info()

    @safe_io_with_server(False)
    def test_server_url(self, url):
        return models.test_server_url(url)

    @safe_io_with_server(None)
    def get_changes_stream(self):
        return models.get_changes_stream(self.active_workspace)

    @safe_io_with_server((None, None))
    def get_deleted_object_name_and_type(self, obj_id):
        return models.get_deleted_object_name_and_type(self.active_workspace, obj_id)

    def continously_get_changes(self):
        """Creates a thread which will continuously check the changes
        coming from other instances of Faraday. Return the thread on any
        exception, of if self.stream is None.
        """

        def get_changes():
            if not self.stream:
                return False
            while True:
                try:
                    for obj_information in self.stream:
                        action = obj_information.get('action')
                        obj_id = obj_information.get('id')
                        obj_type = obj_information.get('type')
                        obj_name = obj_information.get('name')
                        obj = self.get_object(obj_type, obj_id)
                        if action == 'CREATE':
                            notification_center.addObject(obj)
                        elif action == 'UPDATE':
                            notification_center.editObject(obj)
                        elif action == 'DELETE':
                            notification_center.deleteObject(obj_id, obj_type)
                        else:
                            raise Exception('Invalid action')
                        notification_center.changeFromInstance(
                                action,
                                obj_id,
                                obj_type,
                                obj_name)
                except server_io_exceptions.ChangesStreamStoppedAbruptly:
                    notification_center.WorkspaceProblem()
                    return False
                time.sleep(0.5)

        get_changes_thread = threading.Thread(target=get_changes)
        get_changes_thread.daemon = True
        get_changes_thread.start()

    def continously_check_server_connection(self):
        """Starts a thread which requests from the server every second, so
        we know if the connection is still alive.
        """
        def test_server_connection():
            tolerance = 0
            while True:
                time.sleep(1)
                test_was_successful = self.server_info() is not None
                if test_was_successful:
                    tolerance = 0
                else:
                    tolerance += 1
                    if tolerance == 3:
                        notification_center.DBConnectionProblem()

        test_server_thread = threading.Thread(target=test_server_connection)
        test_server_thread.daemon = True
        test_server_thread.start()
