import json
import logging

from faraday.searcher.api import ApiError
from faraday.server.api.modules.hosts import HostSchema
from faraday.server.api.modules.services import ServiceSchema
from faraday.server.api.modules.vulns import VulnerabilitySchema, VulnerabilityWebSchema
from faraday.server.models import Workspace, Vulnerability, VulnerabilityWeb, Service, Host

logger = logging.getLogger('Faraday searcher')


class SqlApi:
    def __init__(self, session, workspace_name):
        self.session = session

        workspace = self.session.query(Workspace).filter_by(name=workspace_name).all()
        if len(workspace) > 0:
            self.workspace = workspace[0]
        else:
            raise ApiError("Workspace %s doesn't exist" % workspace_name)

    def filter_vulnerabilities(self, kwargs):
        vulnerabilities = []
        vulnerabilities_query = self.session.query(Vulnerability, Workspace.id).join(Workspace).filter(
            Workspace.name == self.workspace.name)
        for attr, value in kwargs.iteritems():
            if attr == 'regex':
                vulnerabilities_query = vulnerabilities_query.filter(Vulnerability.name.op('~')(value))
                vulnerabilities = [vulnerability for vulnerability, pos in
                                   vulnerabilities_query.distinct(Vulnerability.id)]
                continue
            if hasattr(Vulnerability, attr):
                vulnerabilities_query = vulnerabilities_query.filter(getattr(Vulnerability, attr) == value)
                vulnerabilities = [vulnerability for vulnerability, pos in
                                   vulnerabilities_query.distinct(Vulnerability.id)]

        vulnerabilities = VulnerabilitySchema(many=True).dumps(vulnerabilities)
        vulnerabilities_data = json.loads(vulnerabilities.data)

        web_vulnerabilities = []
        web_vulnerabilities_query = self.session.query(Vulnerability, Workspace.id).join(Workspace).filter(
            Workspace.name == self.workspace.name)
        for attr, value in kwargs.iteritems():
            if attr == 'regex':
                web_vulnerabilities_query = web_vulnerabilities_query.filter(VulnerabilityWeb.name.op('~')(value))
                web_vulnerabilities = [web_vulnerability for web_vulnerability, pos in
                                       web_vulnerabilities_query.distinct(VulnerabilityWeb.id)]
                continue
            if hasattr(VulnerabilityWeb, attr):
                web_vulnerabilities_query = web_vulnerabilities_query.filter(getattr(VulnerabilityWeb, attr) == value)
                web_vulnerabilities = [web_vulnerability for web_vulnerability, pos in
                                       web_vulnerabilities_query.distinct(Vulnerability.id)]

        web_vulnerabilities = VulnerabilityWebSchema(many=True).dumps(web_vulnerabilities)
        web_vulnerabilities_data = json.loads(web_vulnerabilities.data)

        return vulnerabilities_data + web_vulnerabilities_data

    def filter_services(self, kwargs):
        services = []
        services_query = self.session.query(Service, Workspace.id).join(Workspace).filter(
            Workspace.name == self.workspace.name)
        for attr, value in kwargs.iteritems():
            if attr == 'regex':
                services_query = services_query.filter(Service.name.op('~')(value))
                services = [service for service, pos in
                            services_query.distinct(Service.id)]
                continue
            if hasattr(Service, attr):
                services_query = services_query.filter(getattr(Service, attr) == value)
                services = [service for service, pos in
                            services_query.distinct(Service.id)]

        services = ServiceSchema(many=True).dumps(services)
        services_data = json.loads(services.data)

        return services_data

    def filter_hosts(self, kwargs):
        hosts = []
        hosts_query = self.session.query(Host, Workspace.id).join(Workspace).filter(
            Workspace.name == self.workspace.name)
        for attr, value in kwargs.iteritems():
            if attr == 'regex':
                hosts_query = hosts_query.filter(Host.ip.op('~')(value))
                hosts = [host for host, pos in
                         hosts_query.distinct(Host.id)]
                continue
            if hasattr(Host, attr):
                hosts_query = hosts_query.filter(getattr(Host, attr) == value)
                hosts = [host for host, pos in
                         hosts_query.distinct(Host.id)]

        hosts = HostSchema(many=True).dumps(hosts)
        hosts_data = json.loads(hosts.data)

        return hosts_data
