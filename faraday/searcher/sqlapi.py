
import json
import logging
import socket
from datetime import datetime

from sqlalchemy.orm.attributes import flag_modified

from faraday.searcher.api import ApiError
from faraday.server.models import Workspace, Vulnerability, VulnerabilityWeb, Service, Host, Command, \
    VulnerabilityTemplate, CommandObject, Reference, ReferenceVulnerabilityAssociation, Tag, TagObject
from faraday.server.utils.database import get_or_create

logger = logging.getLogger('Faraday searcher')


class SqlApi:
    def __init__(self, workspace_name, test_cient=None, session=None):
        self.session = session
        self.command_id = None  # Faraday uses this to tracker searcher changes.
        workspace = self.session.query(Workspace).filter_by(name=workspace_name).all()
        if len(workspace) > 0:
            self.workspace = workspace[0]
        else:
            raise ApiError(f"Workspace {workspace_name} doesn't exist")

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
            "start_date": datetime.fromtimestamp(self.itime),
            "command": self.tool_name,
            "ip": ip,
            "import_source": "shell",
            "tool": "Searcher",
            "params": json.dumps(self.params),
            "workspace_id": self.workspace.id
        }
        if duration:
            data.update({"duration": duration})
        return data

    def close_command(self, command_id, duration):
        data = self._command_info(duration)
        command = Command.query.get(command_id)
        if command:
            for (key, value) in data.items():
                setattr(command, key, value)
            self.session.commit()

    def fetch_vulnerabilities(self):
        vulnerabilities = self.session.query(Vulnerability, Workspace.id).join(Workspace).filter(
            Workspace.name == self.workspace.name)

        vulnerabilities = [vulnerability for vulnerability, pos in
                           vulnerabilities.distinct(Vulnerability.id)]

        web_vulnerabilities = self.session.query(VulnerabilityWeb, Workspace.id).join(Workspace).filter(
            Workspace.name == self.workspace.name)

        web_vulnerabilities = [web_vulnerability for web_vulnerability, pos in
                               web_vulnerabilities.distinct(VulnerabilityWeb.id)]

        return list(set(vulnerabilities + web_vulnerabilities))

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

    def fetch_templates(self):
        templates = self.session.query(VulnerabilityTemplate)
        templates = [template for template, pos in
                     templates.distinct(Host.id)]
        return templates

    def _filter_vulns(self, vulnerability_object, **kwargs):
        vulnerabilities = []
        vulnerabilities_query = self.session. \
            query(vulnerability_object). \
            join(vulnerability_object.workspace). \
            filter(Workspace.name == self.workspace.name)
        for attr, value in kwargs.items():
            if attr == 'regex':
                vulnerabilities_query = vulnerabilities_query.filter(vulnerability_object.name.op('~')(value))
                vulnerabilities = vulnerabilities_query.all()
            elif hasattr(vulnerability_object, attr):
                filter_attr = getattr(vulnerability_object, attr)
                if hasattr(getattr(vulnerability_object, attr).prop, 'entity'):
                    map_attr = {
                        'creator': 'username'
                    }
                    filter_attr = getattr(filter_attr.comparator.entity.class_, map_attr.get(attr, attr))
                vulnerabilities_query = vulnerabilities_query.filter(filter_attr == str(value))
                vulnerabilities = vulnerabilities_query.all()
        return vulnerabilities

    def filter_vulnerabilities(self, **kwargs):
        vulnerabilities = self._filter_vulns(Vulnerability, **kwargs)
        web_vulnerabilities = self._filter_vulns(VulnerabilityWeb, **kwargs)
        return list(set(vulnerabilities + web_vulnerabilities))

    def filter_services(self, **kwargs):
        services = []
        services_query = self.session.query(Service, Workspace.id).join(Workspace).filter(
            Workspace.name == self.workspace.name)
        for attr, value in kwargs.items():
            if attr == 'regex':
                services_query = services_query.filter(Service.name.op('~')(value))
                services = [service for service, pos in
                            services_query.distinct(Service.id)]
            elif hasattr(Service, attr):
                services_query = services_query.filter(getattr(Service, attr) == str(value))
                services = [service for service, pos in
                            services_query.distinct(Service.id)]

        return services

    def filter_hosts(self, **kwargs):
        hosts = []
        hosts_query = self.session.query(Host, Workspace.id).join(Workspace).filter(
            Workspace.name == self.workspace.name)
        for attr, value in kwargs.items():
            if attr == 'regex':
                hosts_query = hosts_query.filter(Host.ip.op('~')(value))
                hosts = [host for host, pos in
                         hosts_query.distinct(Host.id)]
            elif hasattr(Host, attr):
                hosts_query = hosts_query.filter(getattr(Host, attr) == str(value))
                hosts = [host for host, pos in
                         hosts_query.distinct(Host.id)]

        return hosts

    def filter_templates(self, **kwargs):
        templates = []
        templates_query = self.session.query(VulnerabilityTemplate)
        for attr, value in kwargs.items():
            if hasattr(VulnerabilityTemplate, attr):
                templates_query = templates_query.filter(getattr(VulnerabilityTemplate, attr) == str(value))
                templates = list(templates_query.distinct(VulnerabilityTemplate.id))

        return templates

    def _get_create_command_object(self, object, object_type):
        cmd_object_relation, created = get_or_create(
            self.session,
            CommandObject,
            workspace_id=self.workspace.id,
            command_id=self.command_id,
            object_type=object_type,
            object_id=object.id,
        )
        cmd_object_relation.created_persistent = False
        if created:
            self.session.add(cmd_object_relation)
            self.session.commit()

    def update_vulnerability(self, vulnerability):
        self.session.add(vulnerability)
        flag_modified(vulnerability, "custom_fields")
        self.session.commit()
        return self._get_create_command_object(vulnerability, 'vulnerability')

    def update_service(self, service):
        self.session.add(service)
        self.session.commit()
        return self._get_create_command_object(service, 'service')

    def update_host(self, host):
        self.session.add(host)
        self.session.commit()
        return self._get_create_command_object(host, 'host')

    def delete_vulnerability(self, vulnerability_id):
        vuln = Vulnerability.query.get(vulnerability_id)
        if vuln is None:
            vuln = VulnerabilityWeb.query.get(vulnerability_id)
        self.session.delete(vuln)
        self.session.commit()

    def delete_service(self, service_id):
        service = Service.query.get(service_id)
        if service:
            self.session.delete(service)
            self.session.commit()

    def delete_host(self, host_id):
        host = Host.query.get(host_id)
        if host:
            self.session.delete(host)
            self.session.commit()

    @staticmethod
    def intersection(objects, models):
        return list(set(objects).intersection(set(models)))

    def set_array(self, field, value, add=True, key=None, object=None):
        try:
            list(field)
        except KeyError:
            return field

        if key == 'refs' and object:
            if add:
                self.add_reference(value, object.id)
            else:
                self.remove_reference(value, object.id)

        if key == 'tags' and object:
            if add:
                self.add_tag(value, object)
            else:
                self.remove_tag(value, object.id)

    def add_reference(self, reference, object_id):
        ref = Reference(name=reference, workspace_id=self.workspace.id)
        self.session.add(ref)
        self.session.commit()

        reference_association = ReferenceVulnerabilityAssociation(vulnerability_id=object_id, reference_id=ref.id)
        self.session.add(reference_association)
        self.session.commit()

    def remove_reference(self, reference, object_id):
        ref = Reference.query.filter(name=reference, workspace_id=self.workspace.id).first()
        if ref:
            reference_association = ReferenceVulnerabilityAssociation.query.filter(vulnerability_id=object_id,
                                                                                   reference_id=ref.id).first()
            if reference_association:
                self.session.delete(reference_association)
                self.session.commit()

    def add_tag(self, tag, _object):
        tag = Tag(name=tag, slug=tag)
        self.session.add(tag)
        self.session.commit()
        object_type = type(_object).__name__
        tag_object = TagObject(object_id=_object.id, object_type=object_type, tag_id=tag.id)
        self.session.add(tag_object)
        self.session.commit()

    def remove_tag(self, reference, object_id):
        tag = Tag.query.filter(name=reference).first()
        if tag:
            tag_object = TagObject.query.filter(object_id=object_id, tag_id=tag.id).first()
            if tag_object:
                self.session.delete(tag_object)
                self.session.commit()
