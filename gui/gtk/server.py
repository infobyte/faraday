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
