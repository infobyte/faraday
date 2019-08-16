import json
import logging
import socket

from faraday.searcher.api import ApiError
from faraday.server.api.modules.hosts import HostSchema
from faraday.server.api.modules.services import ServiceSchema
from faraday.server.api.modules.vulns import VulnerabilitySchema, VulnerabilityWebSchema
from faraday.server.models import Workspace, Vulnerability, VulnerabilityWeb, Service, Host, Command

logger = logging.getLogger('Faraday searcher')


class SqlApi:
    def __init__(self, workspace_name, test_cient=None, session=None):
        self.session = session
        self.command_id = None  # Faraday uses this to tracker searcher changes.
        workspace = self.session.query(Workspace).filter_by(name=workspace_name).all()
        if len(workspace) > 0:
            self.workspace = workspace[0]
        else:
            raise ApiError("Workspace %s doesn't exist" % workspace_name)

    def filter_vulnerabilities(self, **kwargs):
        vulnerabilities = []
        vulnerabilities_query = self.session.query(Vulnerability, Workspace.id).join(Workspace).filter(
            Workspace.name == self.workspace.name)
        for attr, value in kwargs.iteritems():
            if attr == 'regex':
                vulnerabilities_query = vulnerabilities_query.filter(Vulnerability.name.op('~')(value))
                vulnerabilities = [vulnerability for vulnerability, pos in
                                   vulnerabilities_query.distinct(Vulnerability.id)]
            elif hasattr(Vulnerability, attr):
                vulnerabilities_query = vulnerabilities_query.filter(getattr(Vulnerability, attr) == value)
                vulnerabilities = [vulnerability for vulnerability, pos in
                                   vulnerabilities_query.distinct(Vulnerability.id)]

        web_vulnerabilities = []
        web_vulnerabilities_query = self.session.query(Vulnerability, Workspace.id).join(Workspace).filter(
            Workspace.name == self.workspace.name)
        for attr, value in kwargs.iteritems():
            if attr == 'regex':
                web_vulnerabilities_query = web_vulnerabilities_query.filter(VulnerabilityWeb.name.op('~')(value))
                web_vulnerabilities = [web_vulnerability for web_vulnerability, pos in
                                       web_vulnerabilities_query.distinct(VulnerabilityWeb.id)]
            elif hasattr(VulnerabilityWeb, attr):
                web_vulnerabilities_query = web_vulnerabilities_query.filter(getattr(VulnerabilityWeb, attr) == value)
                web_vulnerabilities = [web_vulnerability for web_vulnerability, pos in
                                       web_vulnerabilities_query.distinct(Vulnerability.id)]

        return list(set(vulnerabilities + web_vulnerabilities))

    def filter_services(self, **kwargs):
        services = []
        services_query = self.session.query(Service, Workspace.id).join(Workspace).filter(
            Workspace.name == self.workspace.name)
        for attr, value in kwargs.iteritems():
            if attr == 'regex':
                services_query = services_query.filter(Service.name.op('~')(value))
                services = [service for service, pos in
                            services_query.distinct(Service.id)]
            elif hasattr(Service, attr):
                services_query = services_query.filter(getattr(Service, attr) == value)
                services = [service for service, pos in
                            services_query.distinct(Service.id)]

        return services

    def filter_hosts(self, **kwargs):
        hosts = []
        hosts_query = self.session.query(Host, Workspace.id).join(Workspace).filter(
            Workspace.name == self.workspace.name)
        for attr, value in kwargs.iteritems():
            if attr == 'regex':
                hosts_query = hosts_query.filter(Host.ip.op('~')(value))
                hosts = [host for host, pos in
                         hosts_query.distinct(Host.id)]
            elif hasattr(Host, attr):
                hosts_query = hosts_query.filter(getattr(Host, attr) == value)
                hosts = [host for host, pos in
                         hosts_query.distinct(Host.id)]

        return hosts

    def fetch_vulnerabilities(self):
        vulnerabilities = self.session.query(Vulnerability, Workspace.id).join(Workspace).filter(
            Workspace.name == self.workspace.name)

        vulnerabilities = [vulnerability for vulnerability, pos in
                           vulnerabilities.distinct(Vulnerability.id)]

        vulnerabilities = VulnerabilitySchema(many=True).dumps(vulnerabilities)
        vulnerabilities_data = json.loads(vulnerabilities.data)

        web_vulnerabilities = self.session.query(Vulnerability, Workspace.id).join(Workspace).filter(
            Workspace.name == self.workspace.name)

        web_vulnerabilities = [web_vulnerability for web_vulnerability, pos in
                               web_vulnerabilities.distinct(VulnerabilityWeb.id)]

        web_vulnerabilities = VulnerabilityWebSchema(many=True).dumps(web_vulnerabilities)
        web_vulnerabilities_data = json.loads(web_vulnerabilities.data)

        return vulnerabilities_data + web_vulnerabilities_data

    def fetch_services(self):
        services = self.session.query(Service, Workspace.id).join(Workspace).filter(
            Workspace.name == self.workspace.name)
        services = [service for service, pos in
                    services.distinct(Service.id)]
        return services

    def fetch_hosts(self):
        hosts = self.session.query(Host, Workspace.id).join(Workspace).filter(
            Workspace.name == self.workspace.name)
        hosts = [host for host, pos in
                 hosts.distinct(Host.id)]
        return hosts

    def create_command(self, itime, params, tool_name):
        self.itime = itime
        self.params = params
        self.tool_name = tool_name
        data = self._command_info()

        command = Command(**data)
        self.session.add(command)
        self.session.flush()

        return command.id

    def _command_info(self, duration=None):
        try:
            ip = socket.gethostbyname(socket.gethostname())
        except socket.gaierror:
            ip = socket.gethostname()
        data = {
            "itime": self.itime,
            "command": self.tool_name,
            "ip": ip,
            "import_source": "shell",
            "tool": "Searcher",
            "params": json.dumps(self.params),
        }
        if duration:
            data.update({"duration": duration})
        return data

    def close_command(self, command_id, duration):
        data = self._command_info(duration)
        self._put(self._url('ws/{}/commands/{}/'.format(self.workspace, command_id)), data, 'command')
