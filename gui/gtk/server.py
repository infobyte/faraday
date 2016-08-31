import threading, time
from model.guiapi import notification_center
from decorators import safe_io_with_server
from persistence.server import models

class ServerIO(object):
    def __init__(self, active_workspace):
        self.active_workspace = active_workspace

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

    @safe_io_with_server(False)
    def is_server_up(self):
        return models.is_server_up()

    @safe_io_with_server(None)
    def get_changes_stream(self):
        return models.get_changes_stream(self.active_workspace)

    def continously_get_changes(self):
        def filter_changes(change):
            if not change or change.get('last_seq'):
                return None
            if change['id'].startswith('_design'): # XXX: is this still neccesary?
                return None
            return change

        def get_changes():
            stream = self.get_changes_stream()
            if stream:
                for change in stream:
                    change, obj_type, obj_name = change
                    change = filter_changes(change)
                    if change:
                        deleted = bool(change.get('deleted'))
                        obj_id = change.get('id')
                        revision = change.get("changes")[-1].get('rev')
                        print "CHANGE"
                        notification_center.changeFromInstance(obj_type,
                                                               obj_name,
                                                               deleted)

        get_changes_thread = threading.Thread(target=get_changes)
        get_changes_thread.daemon = True
        get_changes_thread.start()

    def continously_check_server_connection(self):
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
                        "TEST SERVER CONNECTION"
                        notification_center.CouchDBConnectionProblem()



        test_server_thread = threading.Thread(target=test_server_connection)
        test_server_thread.daemon = True
        test_server_thread.start()
