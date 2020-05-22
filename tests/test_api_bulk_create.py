from __future__ import absolute_import
from datetime import datetime, timedelta, timezone

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
)
from faraday.server.api.modules import bulk_create as bc

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
    'duration': 30,
}


def count(model, workspace):
    return model.query.filter(model.workspace == workspace).count()


def test_create_host(session, workspace):
    assert count(Host, workspace) == 0
    bc.bulk_create(workspace, dict(hosts=[host_data]))
    db.session.commit()
    host = Host.query.filter(Host.workspace == workspace).one()
    assert host.ip == "127.0.0.1"
    assert set({hn.name for hn in host.hostnames}) == {"test.com", "test2.org"}


def test_create_duplicated_hosts(session, workspace):
    assert count(Host, workspace) == 0
    bc.bulk_create(workspace, dict(hosts=[host_data, host_data]))
    db.session.commit()
    assert count(Host, workspace) == 1


def test_create_existing_host(session, host):
    session.add(host)
    session.commit()
    assert count(Host, host.workspace) == 1
    data = {
        "ip": host.ip,
        "description": host.description,
        "hostnames": [hn.name for hn in host.hostnames]
    }
    bc.bulk_create(host.workspace, dict(hosts=[data]))
    assert count(Host, host.workspace) == 1


def test_create_host_with_services(session, workspace):
    host_data_ = host_data.copy()
    host_data_['services'] = [service_data]
    bc.bulk_create(workspace, dict(hosts=[host_data_]))
    assert count(Host, workspace) == 1
    assert count(Service, workspace) == 1
    service = Service.query.filter(Service.workspace == workspace).one()
    assert service.name == 'http'
    assert service.port == 80


def test_create_service(session, host):
    data = bc.BulkServiceSchema(strict=True).load(service_data)
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
    data = bc.BulkServiceSchema(strict=True).load(data)
    bc._create_service(service.workspace, service.host, data)
    assert count(Service, service.host.workspace) == 1

def test_create_host_vuln(session, host):
    data = bc.VulnerabilitySchema(strict=True).load(vuln_data)
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
    data = bc.VulnerabilitySchema(strict=True).load(vuln_data)
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
    data = bc.VulnerabilitySchema(strict=True).load(no_tool_data)
    bc._create_hostvuln(host.workspace, host, data)
    vuln = host.workspace.vulnerabilities[0]
    assert vuln.tool == "Web UI"


def test_creates_vuln_with_command_object_with_tool(session, service):
    host_data_ = host_data.copy()
    service_data_ = service_data.copy()
    vuln_web_data_ = vuln_data.copy()
    service_data_['vulnerabilities'] = [vuln_web_data_]
    host_data_['services'] = [service_data_]
    bc.bulk_create(service.workspace, dict(command=command_data, hosts=[host_data_]))
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
    bc.bulk_create(service.workspace, dict(command=command_data, hosts=[host_data_]))
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
    data = bc.VulnerabilitySchema(strict=True).load(data)
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
    bc.bulk_create(workspace, dict(hosts=[host_data_]))
    assert count(Host, workspace) == 1
    host = workspace.hosts[0]
    assert count(Vulnerability, workspace) == 1
    vuln = Vulnerability.query.filter(Vulnerability.workspace == workspace).one()
    assert vuln.name == 'sql injection'
    assert vuln.host == host


def test_create_host_with_cred(session, workspace):
    host_data_ = host_data.copy()
    host_data_['credentials'] = [credential_data]
    bc.bulk_create(workspace, dict(hosts=[host_data_]))
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
    data = bc.BulkServiceSchema(strict=True).load(service_data_)
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
    data = bc.BulkServiceSchema(strict=True).load(service_data_)
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
        data = bc.BulkServiceSchema(strict=True).load(service_data_)
        bc._create_service(host.workspace, host, data)
    assert count(Service, host.workspace) == 0
    assert count(Vulnerability, host.workspace) == 0


def test_create_service_with_invalid_vulns(session, host):
    service_data_ = service_data.copy()
    vuln_data_ = vuln_data.copy()
    del vuln_data_['name']
    service_data_['vulnerabilities'] = [1, 2, 3]
    with pytest.raises(ValidationError):
        data = bc.BulkServiceSchema(strict=True).load(service_data_)
        bc._create_service(host.workspace, host, data)
    assert count(Service, host.workspace) == 0
    assert count(Vulnerability, host.workspace) == 0


def test_create_service_with_vulnweb(session, host):
    service_data_ = service_data.copy()
    vuln_data_ = vuln_data.copy()
    vuln_data_.update(vuln_web_data)
    service_data_['vulnerabilities'] = [vuln_data_]
    data = bc.BulkServiceSchema(strict=True).load(service_data_)
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


def test_create_command(session, workspace):
    bc.bulk_create(workspace, dict(command=command_data, hosts=[]))
    assert count(Command, workspace) == 1
    command = workspace.commands[0]
    assert command.tool == 'pytest'
    assert command.user == 'root'
    assert (command.end_date - command.start_date).microseconds == 30


def test_creates_command_object(session, workspace):
    host_data_ = host_data.copy()
    service_data_ = service_data.copy()
    vuln_web_data_ = vuln_data.copy()
    vuln_web_data_.update(vuln_web_data)
    service_data_['vulnerabilities'] = [vuln_data, vuln_web_data_]
    service_data_['credentials'] = [credential_data]
    host_data_['services'] = [service_data_]
    host_data_['vulnerabilities'] = [vuln_data]
    host_data_['credentials'] = [credential_data]
    bc.bulk_create(workspace, dict(command=command_data, hosts=[host_data_]))

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

    bc.bulk_create(command.workspace, data)
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
    url = 'v2/ws/{}/bulk_create/'.format(workspace.name)
    host_data_ = host_data.copy()
    host_data_['services'] = [service_data]
    host_data_['credentials'] = [credential_data]
    host_data_['vulnerabilities'] = [vuln_data]
    res = test_client.post(url, data=dict(hosts=[host_data_]))
    assert res.status_code == 201, res.json
    assert count(Host, workspace) == 1
    assert count(Vulnerability, workspace) == 1
    host = Host.query.filter(Host.workspace == workspace).one()
    assert host.ip == "127.0.0.1"
    assert host.creator_id == logged_user.id
    assert set({hn.name for hn in host.hostnames}) == {"test.com", "test2.org"}
    service = Service.query.filter(Service.workspace == workspace).one()
    assert service.creator_id == logged_user.id
    credential = Credential.query.filter(Credential.workspace == workspace).one()
    assert credential.creator_id == logged_user.id


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
    url = 'v2/ws/{}/bulk_create/'.format(workspace.name)
    host_data_ = host_data.copy()
    host_data_.pop('ip')
    res = test_client.post(url, data=dict(hosts=[host_data_]))
    assert res.status_code == 400


def test_bulk_create_endpoints_fails_without_auth(session, workspace, test_client):
    url = 'v2/ws/{}/bulk_create/'.format(workspace.name)
    res = test_client.post(url, data=dict(hosts=[host_data]))
    assert res.status_code == 401
    assert count(Host, workspace) == 0


@pytest.mark.parametrize('token_type', ['agent', 'token'])
def test_bulk_create_endpoints_fails_with_invalid_token(
        session, token_type, workspace, test_client):
    url = 'v2/ws/{}/bulk_create/'.format(workspace.name)
    res = test_client.post(
        url,
        data=dict(hosts=[host_data]),
        headers=[("authorization", "{} 1234".format(token_type))]
    )
    if token_type == 'token':
        # TODO change expected status code to 403
        assert res.status_code == 401
    else:
        assert res.status_code == 403
    assert count(Host, workspace) == 0


def test_bulk_create_with_agent_token_in_different_workspace_fails(
        session, agent, second_workspace, test_client):
    assert agent.workspace
    assert agent.workspace != second_workspace
    session.add(second_workspace)
    session.add(agent)
    session.commit()
    assert agent.token
    url = 'v2/ws/{}/bulk_create/'.format(second_workspace.name)
    res = test_client.post(
        url,
        data=dict(hosts=[host_data]),
        headers=[("authorization", "agent {}".format(agent.token))]
    )
    assert res.status_code == 404
    assert b'No such workspace' in res.data
    assert count(Host, second_workspace) == 0


def test_bulk_create_with_not_existent_workspace_fails(
        session, agent, test_client):
    assert agent.workspace
    session.add(agent)
    session.commit()
    assert agent.token
    url = 'v2/ws/{}/bulk_create/'.format("im_a_incorrect_ws")
    res = test_client.post(
        url,
        data=dict(hosts=[host_data]),
        headers=[("authorization", "agent {}".format(agent.token))]
    )
    assert res.status_code == 404
    assert b'No such workspace' in res.data
    assert count(Host, agent.workspace) == 0


def test_bulk_create_endpoint_with_agent_token_without_execution_id(session, agent, test_client):
    session.add(agent)
    session.commit()
    assert count(Host, agent.workspace) == 0
    url = 'v2/ws/{}/bulk_create/'.format(agent.workspace.name)
    res = test_client.post(
        url,
        data=dict(hosts=[host_data]),
        headers=[("authorization", "agent {}".format(agent.token))]
    )
    assert res.status_code == 400
    assert b"\'execution_id\' argument expected" in res.data
    assert count(Host, agent.workspace) == 0
    assert count(Command, agent.workspace) == 0


def test_bulk_create_endpoint_with_agent_token(session, agent_execution, test_client, workspace_factory,
                                               agent_execution_factory):
    agent = agent_execution.executor.agent
    agent_execution.executor.parameters_metadata = {}
    agent_execution.parameters_data = {}
    extra_agent_execution = agent_execution_factory.create()
    session.add(agent_execution)
    session.add(extra_agent_execution)
    session.commit()
    assert count(Host, agent.workspace) == 0
    url = 'v2/ws/{}/bulk_create/'.format(agent.workspace.name)
    res = test_client.post(
        url,
        data=dict(hosts=[host_data], execution_id=-1),
        headers=[("authorization", "agent {}".format(agent.token))]
    )
    assert res.status_code == 400

    assert count(Host, agent.workspace) == 0
    assert count(Command, agent.workspace) == 0
    res = test_client.post(
        url,
        data=dict(hosts=[host_data], execution_id=extra_agent_execution.id),
        headers=[("authorization", "agent {}".format(agent.token))]
    )
    assert res.status_code == 400
    assert count(Host, agent.workspace) == 0
    assert count(Command, agent.workspace) == 0
    res = test_client.post(
        url,
        data=dict(hosts=[host_data], execution_id=agent_execution.id),
        headers=[("authorization", "agent {}".format(agent.token))]
    )
    assert res.status_code == 201
    assert count(Host, agent.workspace) == 1
    host = Host.query.filter(Host.workspace == agent.workspace).one()
    assert host.creator_id is None
    assert count(Command, agent.workspace) == 1
    command = Command.query.filter(Command.workspace == agent.workspace).one()
    assert command.tool == agent.name
    assert command.command == agent_execution.executor.name
    assert command.params == ""
    assert command.import_source == 'agent'


def test_bulk_create_endpoint_with_agent_token_with_param(session, agent_execution, test_client):
    agent = agent_execution.executor.agent
    session.add(agent_execution)
    session.commit()
    assert count(Host, agent.workspace) == 0
    url = 'v2/ws/{}/bulk_create/'.format(agent.workspace.name)
    res = test_client.post(
        url,
        data=dict(hosts=[host_data], execution_id=agent_execution.id),
        headers=[("authorization", "agent {}".format(agent.token))]
    )
    assert res.status_code == 201
    assert count(Host, agent.workspace) == 1
    host = Host.query.filter(Host.workspace == agent.workspace).one()
    assert host.creator_id is None
    assert count(Command, agent.workspace) == 1
    command = Command.query.filter(Command.workspace == agent.workspace).one()
    assert command.tool == agent.name
    assert command.command == agent_execution.executor.name
    params = ', '.join([f'{key}={value}' for (key, value) in agent_execution.parameters_data.items()])
    assert command.params == str(params)
    assert command.import_source == 'agent'


def test_bulk_create_endpoint_with_agent_token_readonly_workspace(
        session, agent, test_client):
    agent.workspace.readonly = True
    session.add(agent)
    session.add(agent.workspace)
    session.commit()
    url = 'v2/ws/{}/bulk_create/'.format(agent.workspace.name)
    res = test_client.post(
        url,
        data=dict(hosts=[host_data]),
        headers=[("authorization", "agent {}".format(agent.token))]
    )
    assert res.status_code == 403


def test_bulk_create_endpoint_with_agent_token_disabled_workspace(
        session, agent, test_client):
    agent.workspace.active = False
    session.add(agent)
    session.add(agent.workspace)
    session.commit()
    url = 'v2/ws/{}/bulk_create/'.format(agent.workspace.name)
    res = test_client.post(
        url,
        data=dict(hosts=[host_data]),
        headers=[("authorization", "agent {}".format(agent.token))]
    )
    assert res.status_code == 403

@pytest.mark.usefixtures('logged_user')
def test_bulk_create_endpoint_raises_400_with_no_data(
        session, test_client, workspace):
    url = 'v2/ws/{}/bulk_create/'.format(workspace.name)
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
    url = 'v2/ws/{}/bulk_create/'.format(workspace.name)
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
    url = 'v2/ws/{}/bulk_create/'.format(workspace.name)
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
    url = 'v2/ws/{}/bulk_create/'.format(workspace.name)
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
    url = 'v2/ws/{}/bulk_create/'.format(workspace.name)
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

