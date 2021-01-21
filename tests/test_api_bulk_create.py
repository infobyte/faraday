from datetime import datetime, timedelta, timezone
import string

import pytest
from marshmallow import ValidationError
from faraday.server.models import (
    db,
    Command,
    CommandObject,
    Credential,
    Host,
    Service,
    Vulnerability,
    VulnerabilityGeneric,
    VulnerabilityWeb,
    Workspace
)
from faraday.server.api.modules import bulk_create as bc
from tests.factories import CustomFieldsSchemaFactory

host_data = {
    "ip": "127.0.0.1",
    "description": "test",
    "hostnames": ["test.com", "test2.org"]
}

service_data = {
    "name": "http",
    "port": 80,
    "protocol": "tcp",
}

vuln_data = {
    'name': 'sql injection',
    'desc': 'test',
    'severity': 'high',
    'type': 'Vulnerability',
    'impact': {
        'accountability': True,
        'availability': False,
    },
    'refs': ['CVE-1234'],
    'tool': 'some_tool',
    'data': 'test data',
    'custom_fields': {}
}

vuln_web_data = {
    'type': 'VulnerabilityWeb',
    'method': 'POST',
    'website': 'https://faradaysec.com',
    'path': '/search',
    'parameter_name': 'q',
    'status_code': 200,
}


credential_data = {
    'name': 'test credential',
    'description': 'test',
    'username': 'admin',
    'password': '12345',
}


command_data = {
    'tool': 'pytest',
    'command': 'pytest tests/test_api_bulk_create.py',
    'user': 'root',
    'hostname': 'pc',
    'start_date': '2014-12-22T03:12:58.019077+00:00',
}


def count(model, workspace):
    return model.query.filter(model.workspace == workspace).count()


def new_empty_command(workspace: Workspace):
    command = Command()
    command.workspace = workspace
    command.start_date = datetime.now()
    command.import_source = 'report'
    command.tool = "In progress"
    command.command = "In progress"
    db.session.commit()
    return command


def test_create_host(session, workspace):
    assert count(Host, workspace) == 0
    bc.bulk_create(workspace, None, dict(hosts=[host_data]))
    db.session.commit()
    host = Host.query.filter(Host.workspace == workspace).one()
    assert host.ip == "127.0.0.1"
    assert set({hn.name for hn in host.hostnames}) == {"test.com", "test2.org"}


def test_create_duplicated_hosts(session, workspace):
    assert count(Host, workspace) == 0
    bc.bulk_create(workspace, None, dict(hosts=[host_data, host_data]))
    db.session.commit()
    assert count(Host, workspace) == 1


def test_create_host_add_hostnames(session, workspace):
    assert count(Host, workspace) == 0
    bc.bulk_create(workspace, None, dict(hosts=[host_data]))
    db.session.commit()
    host_copy = host_data.copy()
    host_copy['hostnames'] = ["test3.org"]
    bc.bulk_create(workspace, None, dict(hosts=[host_copy]))
    db.session.commit()
    host = Host.query.filter(Host.workspace == workspace).one()
    assert host.ip == "127.0.0.1"
    assert set({hn.name for hn in host.hostnames}) == {"test.com", "test2.org", "test3.org"}

def test_create_existing_host(session, host):
    session.add(host)
    session.commit()
    assert count(Host, host.workspace) == 1
    data = {
        "ip": host.ip,
        "description": host.description,
        "hostnames": [hn.name for hn in host.hostnames]
    }
    bc.bulk_create(host.workspace, None, dict(hosts=[data]))
    assert count(Host, host.workspace) == 1


def test_create_host_with_services(session, workspace):
    host_data_ = host_data.copy()
    host_data_['services'] = [service_data]
    bc.bulk_create(workspace, None, dict(hosts=[host_data_]))
    assert count(Host, workspace) == 1
    assert count(Service, workspace) == 1
    service = Service.query.filter(Service.workspace == workspace).one()
    assert service.name == 'http'
    assert service.port == 80


def test_create_service(session, host):
    data = bc.BulkServiceSchema().load(service_data)
    bc._create_service(host.workspace, host, data)
    assert count(Service, host.workspace) == 1
    service = Service.query.filter(Service.workspace == host.workspace).one()
    assert service.name == 'http'
    assert service.port == 80


def test_create_existing_service(session, service):
    session.add(service)
    session.commit()
    data = {
        "name": service.name,
        "port": service.port,
        "protocol": service.protocol,
    }
    data = bc.BulkServiceSchema().load(data)
    bc._create_service(service.workspace, service.host, data)
    assert count(Service, service.host.workspace) == 1

def test_create_host_vuln(session, host):
    data = bc.VulnerabilitySchema().load(vuln_data)
    bc._create_hostvuln(host.workspace, host, data)
    assert count(VulnerabilityGeneric, host.workspace) == 1
    assert count(Vulnerability, host.workspace) == 1
    vuln = host.workspace.vulnerabilities[0]
    assert vuln.name == 'sql injection'
    assert vuln.description == 'test'
    assert vuln.severity == 'high'
    assert vuln.impact_accountability
    assert not vuln.impact_availability
    assert not vuln.impact_confidentiality
    assert vuln.references == {u'CVE-1234'}
    assert vuln.tool == "some_tool"


def test_create_service_vuln(session, service):
    data = bc.VulnerabilitySchema().load(vuln_data)
    bc._create_servicevuln(service.workspace, service, data)
    assert count(VulnerabilityGeneric, service.workspace) == 1
    assert count(Vulnerability, service.workspace) == 1
    vuln = service.workspace.vulnerabilities[0]
    assert vuln.service == service
    assert vuln.name == 'sql injection'
    assert vuln.description == 'test'
    assert vuln.severity == 'high'
    assert vuln.impact_accountability
    assert not vuln.impact_availability
    assert not vuln.impact_confidentiality
    assert vuln.references == {u'CVE-1234'}
    assert vuln.tool == "some_tool"


def test_create_host_vuln_without_tool(session, host):
    no_tool_data = vuln_data.copy()
    no_tool_data.pop('tool')
    data = bc.VulnerabilitySchema().load(no_tool_data)
    bc._create_hostvuln(host.workspace, host, data)
    vuln = host.workspace.vulnerabilities[0]
    assert vuln.tool == "Web UI"


def test_creates_vuln_with_command_object_with_tool(session, service):
    host_data_ = host_data.copy()
    service_data_ = service_data.copy()
    vuln_web_data_ = vuln_data.copy()
    service_data_['vulnerabilities'] = [vuln_web_data_]
    host_data_['services'] = [service_data_]
    command = new_empty_command(service.workspace)
    bc.bulk_create(
        service.workspace,
        command,
        dict(
            command=command_data,
            hosts=[host_data_]
            )
    )
    assert count(Vulnerability, service.workspace) == 1
    vuln = service.workspace.vulnerabilities[0]
    assert vuln.tool == vuln_data['tool']


def test_creates_vuln_with_command_object_without_tool(session, service):
    host_data_ = host_data.copy()
    service_data_ = service_data.copy()
    vuln_web_data_ = vuln_data.copy()
    vuln_web_data_.pop('tool')
    service_data_['vulnerabilities'] = [vuln_web_data_]
    host_data_['services'] = [service_data_]
    command = new_empty_command(service.workspace)
    bc.bulk_create(
        service.workspace,
        command,
        dict(command=command_data, hosts=[host_data_])
    )
    assert count(Vulnerability, service.workspace) == 1
    vuln = service.workspace.vulnerabilities[0]
    assert vuln.tool == command_data['tool']

def test_cannot_create_host_vulnweb(session, host):
    data = vuln_data.copy()
    data['type'] = 'VulnerabilityWeb'
    with pytest.raises(ValidationError):
        bc._create_hostvuln(host.workspace, host, data)
    assert count(VulnerabilityGeneric, host.workspace) == 0


def test_create_existing_host_vuln(session, host, vulnerability_factory):
    vuln = vulnerability_factory.create(
        workspace=host.workspace, host=host, service=None)
    session.add(vuln)
    session.commit()
    vuln.references = ['old']
    session.add(vuln)
    session.commit()
    data = {
        'name': vuln.name,
        'desc': vuln.description,
        'severity': vuln.severity,
        'type': 'Vulnerability',
        'refs': ['new']
    }
    data = bc.VulnerabilitySchema().load(data)
    bc._create_hostvuln(host.workspace, host, data)
    session.commit()
    assert count(Vulnerability, host.workspace) == 1
    vuln = Vulnerability.query.get(vuln.id)  # just in case it isn't refreshed
    assert 'old' in vuln.references  # it must preserve the old references


@pytest.mark.skip(reason="unique constraing on credential isn't working")
def test_create_existing_host_cred(session, host, credential_factory):
    cred = credential_factory.create(
        workspace=host.workspace, host=host, service=None)
    session.add(cred)
    session.commit()
    data = {
        'name': cred.name,
        'description': cred.description,
        'username': cred.username,
        'password': cred.password,
    }
    bc._create_credential(host.workspace, data, host=host)
    session.commit()
    assert count(Credential, host.workspace) == 1


def test_create_host_with_vuln(session, workspace):
    host_data_ = host_data.copy()
    host_data_['vulnerabilities'] = [vuln_data]
    bc.bulk_create(workspace, None, dict(hosts=[host_data_]))
    assert count(Host, workspace) == 1
    host = workspace.hosts[0]
    assert count(Vulnerability, workspace) == 1
    vuln = Vulnerability.query.filter(Vulnerability.workspace == workspace).one()
    assert vuln.name == 'sql injection'
    assert vuln.host == host


def test_create_host_with_cred(session, workspace):
    host_data_ = host_data.copy()
    host_data_['credentials'] = [credential_data]
    bc.bulk_create(workspace, None, dict(hosts=[host_data_]))
    assert count(Host, workspace) == 1
    host = workspace.hosts[0]
    assert count(Credential, workspace) == 1
    cred = Credential.query.filter(Credential.workspace == workspace).one()
    assert cred.host == host
    assert cred.name == 'test credential'
    assert cred.username == 'admin'
    assert cred.password == '12345'


def test_create_service_with_vuln(session, host):
    service_data_ = service_data.copy()
    service_data_['vulnerabilities'] = [vuln_data]
    data = bc.BulkServiceSchema().load(service_data_)
    bc._create_service(host.workspace, host, data)
    assert count(Service, host.workspace) == 1
    service = host.workspace.services[0]
    assert count(Vulnerability, service.workspace) == 1
    vuln = Vulnerability.query.filter(
        Vulnerability.workspace == service.workspace).one()
    assert vuln.name == 'sql injection'
    assert vuln.service == service


def test_create_service_with_cred(session, host):
    service_data_ = service_data.copy()
    service_data_['credentials'] = [credential_data]
    data = bc.BulkServiceSchema().load(service_data_)
    bc._create_service(host.workspace, host, data)
    assert count(Service, host.workspace) == 1
    service = host.workspace.services[0]
    assert count(Credential, service.workspace) == 1
    cred = Credential.query.filter(
        Credential.workspace == service.workspace).one()
    assert cred.service == service
    assert cred.name == 'test credential'
    assert cred.username == 'admin'
    assert cred.password == '12345'


def test_create_service_with_invalid_vuln(session, host):
    service_data_ = service_data.copy()
    vuln_data_ = vuln_data.copy()
    del vuln_data_['name']
    service_data_['vulnerabilities'] = [vuln_data_]
    with pytest.raises(ValidationError):
        data = bc.BulkServiceSchema().load(service_data_)
        bc._create_service(host.workspace, host, data)
    assert count(Service, host.workspace) == 0
    assert count(Vulnerability, host.workspace) == 0


def test_create_service_with_invalid_vulns(session, host):
    service_data_ = service_data.copy()
    vuln_data_ = vuln_data.copy()
    del vuln_data_['name']
    service_data_['vulnerabilities'] = [1, 2, 3]
    with pytest.raises(ValidationError):
        data = bc.BulkServiceSchema().load(service_data_)
        bc._create_service(host.workspace, host, data)
    assert count(Service, host.workspace) == 0
    assert count(Vulnerability, host.workspace) == 0


def test_create_service_with_vulnweb(session, host):
    service_data_ = service_data.copy()
    vuln_data_ = vuln_data.copy()
    vuln_data_.update(vuln_web_data)
    service_data_['vulnerabilities'] = [vuln_data_]
    data = bc.BulkServiceSchema().load(service_data_)
    bc._create_service(host.workspace, host, data)
    assert count(Service, host.workspace) == 1
    service = host.workspace.services[0]
    assert count(Vulnerability, service.workspace) == 0
    assert count(VulnerabilityWeb, service.workspace) == 1
    vuln = VulnerabilityWeb.query.filter(
        Vulnerability.workspace == service.workspace).one()
    assert vuln.name == 'sql injection'
    assert vuln.service == service
    assert vuln.method == 'POST'
    assert vuln.website == 'https://faradaysec.com'
    assert vuln.status_code == 200


@pytest.mark.parametrize("duration", [None, "30"])
def test_update_command(session, workspace, duration):
    command = new_empty_command(workspace)
    assert count(Command, workspace) == 1
    command_data_ = command_data.copy()
    if duration is not None:
        command_data_["duration"] = duration
    bc.bulk_create(workspace, command, dict(command=command_data_, hosts=[]))
    assert count(Command, workspace) == 1
    command = workspace.commands[0]
    assert command.tool == 'pytest'
    assert command.user == 'root'
    if duration is not None:
        assert (command.end_date - command.start_date).microseconds == 30
    else:
        assert command.end_date is not None


def test_updates_command_object(session, workspace):
    host_data_ = host_data.copy()
    service_data_ = service_data.copy()
    vuln_web_data_ = vuln_data.copy()
    vuln_web_data_.update(vuln_web_data)
    service_data_['vulnerabilities'] = [vuln_data, vuln_web_data_]
    service_data_['credentials'] = [credential_data]
    host_data_['services'] = [service_data_]
    host_data_['vulnerabilities'] = [vuln_data]
    host_data_['credentials'] = [credential_data]
    command = new_empty_command(workspace)
    bc.bulk_create(
        workspace,
        command,
        dict(command=command_data, hosts=[host_data_])
    )

    command = workspace.commands[0]
    host = workspace.hosts[0]
    service = host.services[0]
    vuln_host = Vulnerability.query.filter(
        Vulnerability.workspace == workspace,
        Vulnerability.service == None).one()
    vuln_service = Vulnerability.query.filter(
        Vulnerability.workspace == workspace,
        Vulnerability.host == None).one()
    vuln_web = VulnerabilityWeb.query.filter(
        VulnerabilityWeb.workspace == workspace).one()
    host_cred = Credential.query.filter(
        Credential.workspace == workspace,
        Credential.host == host).one()
    serv_cred = Credential.query.filter(
        Credential.workspace == workspace,
        Credential.service == service).one()

    objects_with_command_object = [
        ('host', host),
        ('service', service),
        ('vulnerability', vuln_host),
        ('vulnerability', vuln_service),
        ('vulnerability', vuln_web),
        ('credential', host_cred),
        ('credential', serv_cred),
    ]

    for (table_name, obj) in objects_with_command_object:
        assert obj.id is not None and command.id is not None
        CommandObject.query.filter(
            CommandObject.workspace == workspace,
            CommandObject.command == command,
            CommandObject.object_type == table_name,
            CommandObject.object_id == obj.id,
            CommandObject.created_persistent == True,
        ).one()


def test_creates_command_object_on_duplicates(
        session, command, service,
        vulnerability_factory, vulnerability_web_factory,
        credential_factory):
    vuln_host = vulnerability_factory.create(
        workspace=service.workspace, host=service.host, service=None)
    vuln_service = vulnerability_factory.create(
        workspace=service.workspace, service=service, host=None)
    vuln_web = vulnerability_web_factory.create(
        workspace=service.workspace, service=service)
    host_cred = credential_factory.create(
        workspace=service.workspace, host=service.host, service=None)
    session.add(command)
    session.add(service)
    session.add(vuln_host)
    session.add(vuln_service)
    session.add(vuln_web)
    session.add(host_cred)
    session.commit()
    assert command.workspace == service.workspace
    assert len(command.workspace.command_objects) == 0

    objects_with_command_object = [
        ('host', service.host),
        ('service', service),
        ('vulnerability', vuln_host),
        ('vulnerability', vuln_service),
        ('vulnerability', vuln_web),
        # ('credential', host_cred),  # Commented because unique constraint of credential is not working
    ]

    for (table_name, obj) in objects_with_command_object:
        assert obj.id is not None and command.id is not None
        db.session.add(CommandObject(
            object_type=table_name,
            object_id=obj.id,
            command=command,
            created_persistent=True,
            workspace=command.workspace,
        ))
    session.commit()

    data = {
        'hosts': [
            {
                'ip': service.host.ip,
                'description': service.host.description,
                'vulnerabilities': [
                    {
                        'name': vuln_host.name,
                        'severity': 'high',
                        'desc': vuln_host.description,
                        'type': 'Vulnerability',
                    }
                ],
                'credentials': [
                    {
                        'name': host_cred.name,
                        'username': host_cred.username,
                    }
                ],
                'services': [
                    {
                        'name': service.name,
                        'protocol': service.protocol,
                        'port': service.port,
                        'vulnerabilities': [
                            {
                                'name': vuln_service.name,
                                'severity': 'high',
                                'desc': vuln_service.description,
                                'type': 'Vulnerability',
                            },
                            {
                                'name': vuln_web.name,
                                'severity': 'high',
                                'desc': vuln_web.description,
                                'type': 'VulnerabilityWeb',
                                'method': vuln_web.method,
                                'pname': vuln_web.parameter_name,
                                'path': vuln_web.path,
                                'website': vuln_web.website,
                            },
                        ]
                    }
                ]
            }
        ]
    }

    data['command'] = command_data.copy()

    command2 = new_empty_command(command.workspace)
    bc.bulk_create(command.workspace, command2, data)
    assert count(Command, command.workspace) == 2

    new_command = Command.query.filter_by(tool='pytest').one()

    for (table_name, obj) in objects_with_command_object:
        assert obj.id is not None and new_command.id is not None
        CommandObject.query.filter(
            CommandObject.workspace == command.workspace,
            CommandObject.command == new_command,
            CommandObject.object_type == table_name,
            CommandObject.object_id == obj.id,
            CommandObject.created_persistent == False,
        ).one()


@pytest.mark.usefixtures('logged_user')
def test_bulk_create_endpoint(session, workspace, test_client, logged_user):
    assert count(Host, workspace) == 0
    assert count(VulnerabilityGeneric, workspace) == 0
    url = f'v2/ws/{workspace.name}/bulk_create/'
    host_data_ = host_data.copy()
    service_data_ = service_data.copy()
    service_data_['vulnerabilities'] = [vuln_data]
    host_data_['services'] = [service_data_]
    host_data_['credentials'] = [credential_data]
    host_data_['vulnerabilities'] = [vuln_data]
    res = test_client.post(
        url,
        data=dict(hosts=[host_data_], command=command_data)
    )
    assert res.status_code == 201, res.json
    assert count(Host, workspace) == 1
    assert count(Service, workspace) == 1
    assert count(Vulnerability, workspace) == 2
    assert count(Command, workspace) == 1
    host = Host.query.filter(Host.workspace == workspace).one()
    assert host.ip == "127.0.0.1"
    assert host.creator_id == logged_user.id
    assert set({hn.name for hn in host.hostnames}) == {"test.com", "test2.org"}
    assert len(host.services) == 1
    assert len(host.vulnerabilities) == 1
    assert len(host.services[0].vulnerabilities) == 1
    service = Service.query.filter(Service.workspace == workspace).one()
    assert service.creator_id == logged_user.id
    credential = Credential.query.filter(Credential.workspace == workspace).one()
    assert credential.creator_id == logged_user.id
    command = Command.query.filter(Credential.workspace == workspace).one()
    assert command.creator_id == logged_user.id
    assert res.json["command_id"] == command.id


@pytest.mark.usefixtures('logged_user')
def test_bulk_create_endpoint_run_over_closed_vuln(session, workspace, test_client):
    assert count(Host, workspace) == 0
    assert count(VulnerabilityGeneric, workspace) == 0
    url = f'v2/ws/{workspace.name}/bulk_create/'
    host_data_ = host_data.copy()
    host_data_['vulnerabilities'] = [vuln_data]
    res = test_client.post(url, data=dict(hosts=[host_data_]))
    assert res.status_code == 201, res.json
    assert count(Host, workspace) == 1
    assert count(Vulnerability, workspace) == 1
    host = Host.query.filter(Host.workspace == workspace).one()
    vuln = Vulnerability.query.filter(Vulnerability.workspace == workspace).one()
    assert host.ip == "127.0.0.1"
    assert set({hn.name for hn in host.hostnames}) == {"test.com", "test2.org"}
    assert vuln.status == "open"
    close_url = f"v2/ws/{workspace.name}/vulns/{vuln.id}/"
    res = test_client.get(close_url)
    vuln_data_del = res.json
    vuln_data_del["status"] = "closed"
    res = test_client.put(close_url, data=dict(vuln_data_del))
    assert res.status_code == 200, res.json
    assert count(Host, workspace) == 1
    assert count(Vulnerability, workspace) == 1
    assert vuln.status == "closed"
    res = test_client.post(url, data=dict(hosts=[host_data_]))
    assert res.status_code == 201, res.json
    assert count(Host, workspace) == 1
    assert count(Vulnerability, workspace) == 1
    vuln = Vulnerability.query.filter(Vulnerability.workspace == workspace).one()
    assert vuln.status == "re-opened"


@pytest.mark.usefixtures('logged_user')
def test_bulk_create_endpoint_without_host_ip(session, workspace, test_client):
    url = f'v2/ws/{workspace.name}/bulk_create/'
    host_data_ = host_data.copy()
    host_data_.pop('ip')
    res = test_client.post(url, data=dict(hosts=[host_data_]))
    assert res.status_code == 400


def test_bulk_create_endpoints_fails_without_auth(session, workspace, test_client):
    url = f'v2/ws/{workspace.name}/bulk_create/'
    res = test_client.post(url, data=dict(hosts=[host_data]))
    assert res.status_code == 401
    assert count(Host, workspace) == 0


@pytest.mark.parametrize('token_type', ['agent', 'token'])
def test_bulk_create_endpoints_fails_with_invalid_token(
        session, token_type, workspace, test_client):
    url = f'v2/ws/{workspace.name}/bulk_create/'
    res = test_client.post(
        url,
        data=dict(hosts=[host_data]),
        headers=[("authorization", f"{token_type} 1234")]
    )
    if token_type == 'token':
        # TODO change expected status code to 403
        assert res.status_code == 401
    else:
        assert res.status_code == 403
    assert count(Host, workspace) == 0


def test_bulk_create_with_agent_token_in_different_workspace_fails(
        session, agent, second_workspace, test_client):
    assert agent.workspaces
    assert second_workspace not in agent.workspaces
    session.add(second_workspace)
    session.add(agent)
    session.commit()
    assert agent.token
    url = f'v2/ws/{second_workspace.name}/bulk_create/'
    res = test_client.post(
        url,
        data=dict(hosts=[host_data]),
        headers=[("authorization", f"agent {agent.token}")]
    )
    assert res.status_code == 404
    assert b'No such workspace' in res.data
    assert count(Host, second_workspace) == 0


def test_bulk_create_with_not_existent_workspace_fails(
        session, agent, test_client):
    assert agent.workspaces
    session.add(agent)
    session.commit()
    assert agent.token
    url = "v2/ws/im_a_incorrect_ws/bulk_create/"
    res = test_client.post(
        url,
        data=dict(hosts=[host_data]),
        headers=[("authorization", f"agent {agent.token}")]
    )
    assert res.status_code == 404
    assert b'No such workspace' in res.data
    for workspace in agent.workspaces:
        assert count(Host, workspace) == 0


def test_bulk_create_endpoint_with_agent_token_without_execution_id(session, agent, test_client):
    session.add(agent)
    session.commit()
    for workspace in agent.workspaces:
        assert count(Host, workspace) == 0
        url = f'v2/ws/{workspace.name}/bulk_create/'
        res = test_client.post(
            url,
            data=dict(hosts=[host_data]),
            headers=[("authorization", f"agent {agent.token}")]
        )
        assert res.status_code == 400
        assert b"\'execution_id\' argument expected" in res.data
        assert count(Host, workspace) == 0
        assert count(Command, workspace) == 0


@pytest.mark.parametrize('start_date', [None, datetime.now()])
@pytest.mark.parametrize('duration', [None, 1200])
def test_bulk_create_endpoint_with_agent_token(session,
                                               test_client,
                                               agent_execution_factory,
                                               start_date, duration):
    agent_execution = agent_execution_factory.create()
    agent = agent_execution.executor.agent
    extra_agent_execution = agent_execution_factory.create()

    for workspace in agent.workspaces:
        agent_execution.executor.parameters_metadata = {}
        agent_execution.parameters_data = {}
        agent_execution.workspace = workspace
        agent_execution.command.workspace = workspace
        session.add(agent_execution)
        session.add(extra_agent_execution)
        session.commit()

        command_data = {}
        if start_date:
            command_data.update({
                'tool': agent.name,  # Agent name
                'command': agent_execution.executor.name,
                'user': '',
                'hostname': '',
                'params': '',
                'import_source': 'agent',
                'start_date': str(start_date)
            })
        if duration:
            command_data.update({
                'tool': agent.name,  # Agent name
                'command': agent_execution.executor.name,
                'user': '',
                'hostname': '',
                'params': '',
                'import_source': 'agent',
                'duration': str(duration)
            })

        data_kwargs = {
            "hosts": [host_data],
            "execution_id": -1
        }
        if command_data:
            data_kwargs["command"] = command_data

        initial_host_count = Host.query.filter(Host.workspace == workspace and Host.creator_id is None).count()
        assert count(Command, workspace) == 1
        url = f'v2/ws/{workspace.name}/bulk_create/'
        res = test_client.post(
            url,
            data=dict(**data_kwargs),
            headers=[("authorization", f"agent {agent.token}")]
        )
        assert res.status_code == 400

        assert Host.query.filter(Host.workspace == workspace and Host.creator_id is None).count() == initial_host_count
        assert count(Command, workspace) == 1
        data_kwargs["execution_id"] = extra_agent_execution.id
        res = test_client.post(
            url,
            data=dict(**data_kwargs),
            headers=[("authorization", f"agent {agent.token}")]
        )
        assert res.status_code == 400
        assert Host.query.filter(Host.workspace == workspace and Host.creator_id is None).count() == initial_host_count
        assert count(Command, workspace) == 1
        data_kwargs["execution_id"] = agent_execution.id
        res = test_client.post(
            url,
            data=dict(**data_kwargs),
            headers=[("authorization", f"agent {agent.token}")]
        )

        if start_date or duration is None:
            assert res.status_code == 201, res.json
            assert Host.query.filter(Host.workspace == workspace and Host.creator_id is None).count() == \
                   initial_host_count + 1
            assert count(Command, workspace) == 1
            command = Command.query.filter(Command.workspace == workspace).one()
            assert command.tool == agent.name
            assert command.command == agent_execution.executor.name
            assert command.params == ""
            assert command.import_source == 'agent'
            command_id = res.json["command_id"]
            assert command.id == command_id
            assert command.id == agent_execution.command.id
            assert command.start_date is not None
            if duration is None:
                assert command.end_date is None
            else:
                assert command.end_date == command.start_date + timedelta(microseconds=duration)
        else:
            assert res.status_code == 400, res.json



def test_bulk_create_endpoint_with_agent_token_with_param(session, agent_execution, test_client):
    agent = agent_execution.executor.agent
    session.add(agent_execution)
    session.commit()
    for workspace in agent.workspaces:
        agent_execution.workspace = workspace
        agent_execution.command.workspace = workspace
        session.add(agent_execution)
        session.commit()
        assert count(Host, workspace) == 0
        assert count(Command, workspace) == 1
        url = f'v2/ws/{workspace.name}/bulk_create/'
        res = test_client.post(
            url,
            data=dict(hosts=[host_data], execution_id=agent_execution.id),
            headers=[("authorization", f"agent {agent.token}")]
        )
        assert res.status_code == 201
        assert count(Host, workspace) == 1
        host = Host.query.filter(Host.workspace == workspace).one()
        assert host.creator_id is None
        assert count(Command, workspace) == 1
        command = Command.query.filter(Command.workspace == workspace).one()
        assert command.tool == agent.name
        assert command.command == agent_execution.executor.name
        params = ', '.join([f'{key}={value}' for (key, value) in agent_execution.parameters_data.items()])
        assert command.params == str(params)
        assert command.import_source == 'agent'
        command_id = res.json["command_id"]
        assert command.id == command_id
        assert command.id == agent_execution.command.id


def test_bulk_create_endpoint_with_agent_token_readonly_workspace(
        session, agent, test_client):
    for workspace in agent.workspaces:
        workspace.readonly = True
        session.add(agent)
        session.add(workspace)
    session.commit()
    for workspace in agent.workspaces:

        url = f'v2/ws/{workspace.name}/bulk_create/'
        res = test_client.post(
            url,
            data=dict(hosts=[host_data]),
            headers=[("authorization", f"agent {agent.token}")]
        )
        assert res.status_code == 403


def test_bulk_create_endpoint_with_agent_token_disabled_workspace(
        session, agent, test_client):
    for workspace in agent.workspaces:
        workspace.active = False
        session.add(agent)
        session.add(workspace)
    session.commit()
    for workspace in agent.workspaces:
        url = f'v2/ws/{workspace.name}/bulk_create/'
        res = test_client.post(
            url,
            data=dict(hosts=[host_data]),
            headers=[("authorization", f"agent {agent.token}")]
        )
        assert res.status_code == 403

def test_sanitize_request_and_response(session, workspace, host):
    invalid_request_text = 'GET /exampla.do HTTP/1.0\n  \x89\n\x1a  SOME_TEXT'
    invalid_response_text = '<html> \x89\n\x1a  SOME_TEXT</html>'
    sanitized_request_text = 'GET /exampla.do HTTP/1.0\n  \n  SOME_TEXT'
    sanitized_response_text = '<html> \n  SOME_TEXT</html>'
    host_data_ = host_data.copy()
    service_data_ = service_data.copy()
    vuln_web_data_ = vuln_web_data.copy()
    vuln_web_data_['name'] = 'test'
    vuln_web_data_['severity'] = 'low'
    vuln_web_data_['request'] = invalid_request_text
    vuln_web_data_['response'] = invalid_response_text
    service_data_['vulnerabilities'] = [vuln_web_data_]
    host_data_['services'] = [service_data_]
    command = new_empty_command(workspace)
    bc.bulk_create(
        workspace,
        command,
        dict(command=command_data, hosts=[host_data_])
    )
    vuln = VulnerabilityWeb.query.filter(VulnerabilityWeb.workspace == workspace).one()
    assert vuln.request == sanitized_request_text
    assert vuln.response == sanitized_response_text


@pytest.mark.usefixtures('logged_user')
def test_bulk_create_endpoint_raises_400_with_no_data(
        session, test_client, workspace):
    url = f'v2/ws/{workspace.name}/bulk_create/'
    res = test_client.post(
        url,
        data="",
        use_json_data=False,
        headers=[("Content-Type", "application/json")]
    )
    assert res.status_code == 400

@pytest.mark.usefixtures('logged_user')
def test_bulk_create_endpoint_with_vuln_run_date(session, workspace, test_client):
    assert count(Host, workspace) == 0
    assert count(VulnerabilityGeneric, workspace) == 0
    url = f'v2/ws/{workspace.name}/bulk_create/'
    run_date = datetime.now(timezone.utc) - timedelta(days=30)
    host_data_copy = host_data.copy()
    vuln_data_copy = vuln_data.copy()
    vuln_data_copy['run_date'] = run_date.timestamp()
    host_data_copy['vulnerabilities'] = [vuln_data_copy]
    res = test_client.post(url, data=dict(hosts=[host_data_copy]))
    assert res.status_code == 201, res.json
    assert count(Host, workspace) == 1
    assert count(VulnerabilityGeneric, workspace) == 1
    vuln = Vulnerability.query.filter(Vulnerability.workspace == workspace).one()
    assert vuln.create_date.date() == run_date.date()

@pytest.mark.usefixtures('logged_user')
def test_bulk_create_endpoint_with_vuln_future_run_date(session, workspace, test_client):
    assert count(Host, workspace) == 0
    assert count(VulnerabilityGeneric, workspace) == 0
    url = f'v2/ws/{workspace.name}/bulk_create/'
    run_date = datetime.now(timezone.utc) + timedelta(days=10)
    host_data_copy = host_data.copy()
    vuln_data_copy = vuln_data.copy()
    vuln_data_copy['run_date'] = run_date.timestamp()
    host_data_copy['vulnerabilities'] = [vuln_data_copy]
    res = test_client.post(url, data=dict(hosts=[host_data_copy]))
    assert res.status_code == 201, res.json
    assert count(Host, workspace) == 1
    assert count(VulnerabilityGeneric, workspace) == 1
    vuln = Vulnerability.query.filter(Vulnerability.workspace == workspace).one()
    print(vuln.create_date)
    assert vuln.create_date.date() < run_date.date()

@pytest.mark.usefixtures('logged_user')
def test_bulk_create_endpoint_with_invalid_vuln_run_date(session, workspace, test_client):
    assert count(Host, workspace) == 0
    assert count(VulnerabilityGeneric, workspace) == 0
    url = f'v2/ws/{workspace.name}/bulk_create/'
    host_data_copy = host_data.copy()
    vuln_data_copy = vuln_data.copy()
    vuln_data_copy['run_date'] = "INVALID_VALUE"
    host_data_copy['vulnerabilities'] = [vuln_data_copy]
    res = test_client.post(url, data=dict(hosts=[host_data_copy]))
    assert res.status_code == 400, res.json
    assert count(VulnerabilityGeneric, workspace) == 0


@pytest.mark.usefixtures('logged_user')
def test_bulk_create_endpoint_fails_with_list_in_NullToBlankString(session, workspace, test_client, logged_user):
    assert count(Host, workspace) == 0
    assert count(VulnerabilityGeneric, workspace) == 0
    url = f'v2/ws/{workspace.name}/bulk_create/'
    host_data_ = host_data.copy()
    host_data_['services'] = [service_data]
    host_data_['credentials'] = [credential_data]
    host_data_['vulnerabilities'] = [vuln_data]
    host_data_['default_gateway'] = ["localhost"] # Can not be a list
    res = test_client.post(url, data=dict(hosts=[host_data_]))
    assert res.status_code == 400, res.json
    assert count(Host, workspace) == 0
    assert count(Service, workspace) == 0
    assert count(Credential, workspace) == 0
    assert count(Vulnerability, workspace) == 0


@pytest.mark.usefixtures('logged_user')
def test_bulk_create_with_custom_fields_list(test_client, workspace, session, logged_user):
    custom_field_schema = CustomFieldsSchemaFactory(
        field_name='changes',
        field_type='list',
        field_display_name='Changes',
        table_name='vulnerability'
    )
    session.add(custom_field_schema)
    session.commit()

    assert count(Host, workspace) == 0
    assert count(VulnerabilityGeneric, workspace) == 0
    url = f'v2/ws/{workspace.name}/bulk_create/'
    host_data_ = host_data.copy()
    service_data_ = service_data.copy()
    vuln_data_ = vuln_data.copy()
    vuln_data_['custom_fields'] = {'changes': ['1', '2', '3']}
    service_data_['vulnerabilities'] = [vuln_data_]
    host_data_['services'] = [service_data_]
    host_data_['credentials'] = [credential_data]
    host_data_['vulnerabilities'] = [vuln_data_]
    res = test_client.post(
        url,
        data=dict(hosts=[host_data_], command=command_data)
    )
    assert res.status_code == 201, res.json
    assert count(Host, workspace) == 1
    assert count(Service, workspace) == 1
    assert count(Vulnerability, workspace) == 2
    assert count(Command, workspace) == 1
    host = Host.query.filter(Host.workspace == workspace).one()
    assert host.ip == "127.0.0.1"
    assert host.creator_id == logged_user.id
    assert set({hn.name for hn in host.hostnames}) == {"test.com", "test2.org"}
    assert len(host.services) == 1
    assert len(host.vulnerabilities) == 1
    assert len(host.services[0].vulnerabilities) == 1
    service = Service.query.filter(Service.workspace == workspace).one()
    assert service.creator_id == logged_user.id
    credential = Credential.query.filter(Credential.workspace == workspace).one()
    assert credential.creator_id == logged_user.id
    command = Command.query.filter(Credential.workspace == workspace).one()
    assert command.creator_id == logged_user.id
    assert res.json["command_id"] == command.id
    for vuln in Vulnerability.query.filter(Vulnerability.workspace == workspace):
        assert vuln.custom_fields['changes'] == ['1', '2', '3']


@pytest.mark.usefixtures('logged_user')
def test_vuln_web_cannot_have_host_parent(session, workspace, test_client, logged_user):
    url = f'v2/ws/{workspace.name}/bulk_create/'
    host_data_ = host_data.copy()
    vuln_web_data_ = vuln_web_data.copy()
    vuln_web_data_['severity'] = "high"
    vuln_web_data_['name'] = "test"
    host_data_['vulnerabilities'] = [vuln_web_data_]
    res = test_client.post(
        url,
        data=dict(hosts=[host_data_], command=command_data)
    )
    assert res.status_code == 400
