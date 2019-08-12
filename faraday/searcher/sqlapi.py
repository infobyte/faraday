import json
import logging

from faraday.server.api.modules.bulk_create import ServiceSchema, HostSchema
from faraday.server.api.modules.vulns import VulnerabilitySchema, VulnerabilityWebSchema
from faraday.server.models import Workspace, Vulnerability, VulnerabilityWeb, Service, Host

logger = logging.getLogger('Faraday searcher')


class SqlApi:
    def __init__(self, session, workspace):
        self.session = session
        self.workspace = workspace

    def filter_vulnerabilities(self, kwargs):
        kwargs['workspace_id'] = self.workspace

        vulnerabilities = self.session.query(Vulnerability, Workspace.id).filter_by(**kwargs)
        vulnerabilities = VulnerabilitySchema(many=True).dumps(vulnerabilities.all())
        vulnerabilities_data = json.loads(vulnerabilities.data)

        web_vulnerabilities = self.session.query(VulnerabilityWeb, Workspace.id).filter_by(**kwargs)
        web_vulnerabilities = VulnerabilityWebSchema(many=True).dumps(web_vulnerabilities.all())
        web_vulnerabilities_data = json.loads(web_vulnerabilities.data)

        return vulnerabilities_data + web_vulnerabilities_data

    def filter_services(self, kwargs):
        kwargs['workspace_id'] = self.workspace

        services = self.session.query(Service, Workspace.id).filter_by(**kwargs)
        services = ServiceSchema(many=True).dumps(services.all())
        services_data = json.loads(services.data)

        return services_data

    def filter_hosts(self, kwargs):
        kwargs['workspace_id'] = self.workspace

        hosts = self.session.query(Host, Workspace.id).filter_by(**kwargs)
        hosts = HostSchema(many=True).dumps(hosts.all())
        hosts_data = json.loads(hosts.data)

        return hosts_data
