#!/usr/bin/python2.7
# -*- coding: utf-8 -*-
'''
Faraday Penetration Test IDE
Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

import threading, time, requests
from model.guiapi import notification_center
from decorators import safe_io_with_server
from persistence.server import models

class ServerIO(object):
    def __init__(self, active_workspace):
        self.__active_workspace = active_workspace
        self.stream = None  # will be set when active workpsace is set

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

    @safe_io_with_server(False)
    def is_server_up(self):
        return models.is_server_up()

    @safe_io_with_server(None)
    def get_changes_stream(self):
        return models.get_changes_stream(self.active_workspace)

    def continously_get_changes(self):
        """Creates a thread which will continuously check the changes
        coming from other instances of Faraday. Return the thread on any
        exception, of if self.stream is None.
        """

        # There is very arcane, dark magic involved in this method.
        # What you need to know: do not touch it.
        # If you touch it, do check out persitence/server/changes_stream.py
        # there lies _most_ of the darkest magic

        def filter_changes(change):
            local_changes = models.local_changes()
            if not change or change.get('last_seq'):
                return None
            if change['id'].startswith('_design'): # XXX: is this still neccesary?
                return None
            if change['changes'][0]['rev'] == local_changes.get(change['id']):
                del local_changes[change['id']]
                return None
            return change

        def notification_dispatcher(obj_id, obj_type, obj_name, deleted, revision):
            if deleted:
                notification_center.deleteObject(obj_id)
            else:
                is_new_object = revision.split("-")[0] == "1"
                obj = self.get_object(obj_type, obj_id)
                if obj:
                    if is_new_object:
                        notification_center.addObject(obj)
                        update = False
                    else:
                        notification_center.editObject(obj)
                        update = True
            notification_center.changeFromInstance(obj_id, obj_type,
                                                   obj_name, deleted=deleted,
                                                   update=update)

        def get_changes():
            # dark maaaaaagic *sing with me!* dark maaaaaagic
            if self.stream:
                try:
                    for change in self.stream:
                        change, obj_type, obj_name = change
                        change = filter_changes(change)
                        if change:
                            deleted = bool(change.get('deleted'))
                            obj_id = change.get('id')
                            revision = change.get("changes")[-1].get('rev')
                            notification_dispatcher(obj_id, obj_type, obj_name,
                                                    deleted, revision)
                except requests.exceptions.RequestException:
                    notification_center.WorkspaceProblem()
                    return False
            else:
                return False

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
                test_was_successful = self.is_server_up()
                if test_was_successful:
                    tolerance = 0
                else:
                    tolerance += 1
                    if tolerance == 3:
                        notification_center.CouchDBConnectionProblem()

        test_server_thread = threading.Thread(target=test_server_connection)
        test_server_thread.daemon = True
        test_server_thread.start()
