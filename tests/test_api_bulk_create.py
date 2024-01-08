from datetime import datetime, timedelta
import time

import pytest
from flask import current_app
from marshmallow import ValidationError
from sqlalchemy import true, null
import jwt

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
    Workspace,
    User, PolicyViolation,
    CVE,
    CWE,
)
from faraday.server.api.modules import bulk_create as bc
from faraday.server.utils.reports_processor import send_report_data
from tests.factories import CustomFieldsSchemaFactory
from faraday.server.utils.agents import get_command_and_agent_execution

host_data = {
    "ip": "127.0.0.1",
    "description": "test",
    "hostnames": ["test.com", "test2.org"],
}

service_data = {
    "name": "http",
    "port": 80,
    "protocol": "tcp",
    "status": "open",
}
vuln_data = {
    'name': 'kernel vuln',
    'desc': 'test',
    'severity': 'high',
    'type': 'Vulnerability',
    'impact': {'accountability': True, 'availability': False},
    'refs': [{'name': 'http://some_url.com/example', 'type': 'other'}],
    'cve': ['CVE-2021-1234', 'CVE-2020-0001'],
    'cwe': ['cwe-123', 'CWE-485'],
    'tool': 'some_tool',
    'policyviolations': ['policy_1', 'policy_2'],
    'data': 'test data\nmore data',
    'custom_fields': {'changes': ['1', '2', '3']},
}

vuln_web_data = {
    'type': 'VulnerabilityWeb',
    'method': 'POST',
    'website': 'https://faradaysec.com',
    'path': '/search',
    'parameter_name': 'q',
    'status_code': 200,
    'owasp': ['owasp1', 'owasp2']
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
    'start_date': (datetime.utcnow() - timedelta(days=7)).isoformat(),
}


def count(model, workspace):
    return model.query.filter(model.workspace == workspace).count()


def new_empty_command(workspace: Workspace):
    command = Command()
    command.workspace = workspace
    command.start_date = datetime.utcnow()
    command.import_source = 'report'
    command.tool = "In progress"
    command.command = "In progress"
    db.session.commit()
    return command


def test_create_host(session, workspace):
    assert count(Host, workspace) == 0
    host_data_copy = host_data.copy()
    command = new_empty_command(workspace)
    db.session.add(command)
    db.session.commit()
    command_dict = {'id': command.id, 'tool': command.tool, 'user': command.user}
    bc._create_host(workspace, host_data_copy, command_dict)
    host = Host.query.filter(Host.workspace == workspace).one()
    assert host.ip == "127.0.0.1"
    assert set({hn.name for hn in host.hostnames}) == {"test.com", "test2.org"}


def test_create_service(session, workspace, host):
    assert count(Service, workspace) == 0
    service_data_copy = service_data.copy()
    command = new_empty_command(workspace)
    db.session.add(command)
    db.session.commit()
    command_dict = {'id': command.id, 'tool': command.tool, 'user': command.user}
    bc._create_service(workspace, host, service_data_copy, command_dict)
    service = Service.query.filter(Service.workspace == workspace).one()
    assert count(Service, workspace) == 1
    assert service.name == service_data["name"]


def check_vuln_fields(original, created):
    ...


def test_create_host_vuln(session, workspace, host):
    custom_field = CustomFieldsSchemaFactory(
        field_name='changes',
        field_type='list',
        field_display_name='Changes',
        table_name='vulnerability'
    )
    new_vuln = bc.VulnerabilitySchema().load(vuln_data)
    command = new_empty_command(workspace)
    db.session.add(command)
    db.session.commit()
    command_dict = {'id': command.id, 'tool': command.tool, 'user': command.user}
    created_vuln_data, vuln_id = bc._create_hostvuln(workspace, host, new_vuln, command_dict)
    created_vuln = created_vuln_data[vuln_id]['vuln_data']
    assert vuln_id > 0
    assert created_vuln_data[vuln_id]['command']['command_id'] == command_dict['id']
    assert created_vuln_data[vuln_id]['command']['object_id'] == vuln_id
    assert created_vuln['custom_fields'] == vuln_data['custom_fields']
    assert created_vuln['name'] == vuln_data['name']
    assert created_vuln['data'] == vuln_data['data']
    assert created_vuln['impact_accountability'] == vuln_data['impact']['accountability']
    assert created_vuln['impact_availability'] == vuln_data['impact']['availability']
    assert created_vuln['impact_availability'] == vuln_data['impact']['availability']
    assert created_vuln['impact_integrity'] is False
    assert created_vuln['impact_confidentiality'] is False

    # Policy Violations
    assert len(created_vuln_data[vuln_id]['policy_violations_associations']) == len(vuln_data['policyviolations'])
    associations = created_vuln_data[vuln_id]['policy_violations_associations']
    elements = set()
    for element in associations:
        assert element['vulnerability_id'] == vuln_id
        obj = PolicyViolation.query.filter(PolicyViolation.id == element['policy_violation_id']).first()
        if obj:
            elements.add(obj.name)
    assert elements == set(vuln_data['policyviolations'])

    # CVE
    assert len(created_vuln_data[vuln_id]['cve_associations']) == len(vuln_data['cve'])
    associations = created_vuln_data[vuln_id]['cve_associations']
    elements = set()
    for element in associations:
        assert element['vulnerability_id'] == vuln_id
        obj = CVE.query.filter(CVE.id == element['cve_id']).first()
        if obj:
            elements.add(obj.name)
    assert elements == set(vuln_data['cve'])

    # CWE
    assert len(created_vuln_data[vuln_id]['cwe_associations']) == len(vuln_data['cwe'])
    associations = created_vuln_data[vuln_id]['cwe_associations']
    elements = set()
    for element in associations:
        assert element['vulnerability_id'] == vuln_id
        obj = CWE.query.filter(CWE.id == element['cwe_id']).first()
        if obj:
            elements.add(obj.name)
    assert elements == set(vuln_data['cwe'])

    # OWASP
    # Normal vulnerability has not owasp
    # assert len(created_vuln_data[vuln_id]['owasp_objects']) == len(vuln_data['owasp'])
    # associations = created_vuln_data[vuln_id]['owasp_objects']
    # elements = set()
    # for element in associations:
    #     assert element['vulnerability_id'] == vuln_id
    #     obj = OWASP.query.filter(OWASP.id == element['owasp_id']).first()
    #     if obj:
    #         elements.add(obj.name)
    # assert elements == set(vuln_data['owasp'])

    # References
    assert len(created_vuln_data[vuln_id]['references']) == len(vuln_data['refs'])
    associations = created_vuln_data[vuln_id]['references']
    elements = set()
    for element in associations:
        assert element['vulnerability_id'] == vuln_id
        # References are created after vulnerability creation ...
        elements.add(element['name'])
    assert elements == {ref['name'] for ref in vuln_data['refs']}


def test_create_vuln_web(session, workspace, service):
    custom_field = CustomFieldsSchemaFactory(
        field_name='changes',
        field_type='list',
        field_display_name='Changes',
        table_name='vulnerability'
    )

    command = new_empty_command(workspace)
    db.session.add(command)
    db.session.commit()
    command_dict = {'id': command.id, 'tool': command.tool, 'user': command.user}
    vuln_data_copy = vuln_data.copy()
    vuln_data_copy.update(vuln_web_data)
    new_vuln = bc.VulnerabilitySchema().load(vuln_data_copy)
    created_vuln_data, vuln_id = bc._create_servicevuln(workspace, service, new_vuln, command_dict)
    assert vuln_id > 0
    created_vuln = created_vuln_data[vuln_id]['vuln_data']
    assert created_vuln_data[vuln_id]['command']['command_id'] == command_dict['id']
    assert created_vuln_data[vuln_id]['command']['object_id'] == vuln_id
    assert created_vuln['custom_fields'] == vuln_data['custom_fields']
    assert created_vuln['type'] == 'vulnerability_web'
    assert created_vuln['name'] == vuln_data['name']
    assert created_vuln['data'] == vuln_data['data']
    assert created_vuln['impact_accountability'] == vuln_data['impact']['accountability']
    assert created_vuln['impact_availability'] == vuln_data['impact']['availability']
    assert created_vuln['impact_availability'] == vuln_data['impact']['availability']
    assert created_vuln['impact_integrity'] is False
    assert created_vuln['impact_confidentiality'] is False

    # Policy Violations
    assert len(created_vuln_data[vuln_id]['policy_violations_associations']) == len(vuln_data['policyviolations'])
    associations = created_vuln_data[vuln_id]['policy_violations_associations']
    elements = set()
    for element in associations:
        assert element['vulnerability_id'] == vuln_id
        obj = PolicyViolation.query.filter(PolicyViolation.id == element['policy_violation_id']).first()
        if obj:
            elements.add(obj.name)
    assert elements == set(vuln_data['policyviolations'])

    # CVE
    assert len(created_vuln_data[vuln_id]['cve_associations']) == len(vuln_data['cve'])
    associations = created_vuln_data[vuln_id]['cve_associations']
    elements = set()
    for element in associations:
        assert element['vulnerability_id'] == vuln_id
        obj = CVE.query.filter(CVE.id == element['cve_id']).first()
        if obj:
            elements.add(obj.name)
    assert elements == set(vuln_data['cve'])

    # CWE
    assert len(created_vuln_data[vuln_id]['cwe_associations']) == len(vuln_data['cwe'])
    associations = created_vuln_data[vuln_id]['cwe_associations']
    elements = set()
    for element in associations:
        assert element['vulnerability_id'] == vuln_id
        obj = CWE.query.filter(CWE.id == element['cwe_id']).first()
        if obj:
            elements.add(obj.name)
    assert elements == set(vuln_data['cwe'])

    # OWASP
    # for now is readonly so, should be 0
    assert len(created_vuln_data[vuln_id]['owasp_objects']) == 0

    # References
    assert len(created_vuln_data[vuln_id]['references']) == len(vuln_data['refs'])
    associations = created_vuln_data[vuln_id]['references']
    elements = set()
    for element in associations:
        assert element['vulnerability_id'] == vuln_id
        # References are created after vulnerability creation ...
        elements.add(element['name'])
    assert elements == {ref['name'] for ref in vuln_data['refs']}


def test_create_vuln_web_on_host_raises_exception(session, workspace, host):
    command = new_empty_command(workspace)
    db.session.add(command)
    db.session.commit()
    vuln_data_copy = vuln_data.copy()
    vuln_data_copy.update(vuln_web_data)
    with pytest.raises(ValidationError):
        command_dict = {'id': command.id, 'tool': command.tool, 'user': command.user}
        bc._create_hostvuln(workspace, host, vuln_data_copy, command_dict)


def test_create_host_with_vuln(session, workspace):
    assert count(Host, workspace) == 0
    assert count(Vulnerability, workspace) == 0
    command = new_empty_command(workspace)
    db.session.add(command)
    db.session.commit()
    command_dict = {'id': command.id, 'tool': command.tool, 'user': command.user}
    new_vuln = bc.VulnerabilitySchema().load(vuln_data)
    host_data_copy = host_data.copy()
    host_data_copy['vulnerabilities'] = [new_vuln]
    bc._create_host(workspace, host_data_copy, command_dict)
    assert count(Host, workspace) == 1
    assert count(Vulnerability, workspace) == 1


def test_create_host_with_service(session, workspace):
    assert count(Host, workspace) == 0
    assert count(Vulnerability, workspace) == 0
    service_data_copy = service_data.copy()
    command = new_empty_command(workspace)
    db.session.add(command)
    db.session.commit()
    command_dict = {'id': command.id, 'tool': command.tool, 'user': command.user}
    host_data_copy = host_data.copy()
    host_data_copy['services'] = [service_data_copy]
    bc._create_host(workspace, host_data_copy, command_dict)
    assert count(Host, workspace) == 1
    assert count(Service, workspace) == 1


def test_create_existing_host(session, workspace, host):
    assert count(Host, workspace) == 1
    command = new_empty_command(workspace)
    db.session.add(command)
    db.session.commit()
    command_dict = {'id': command.id, 'tool': command.tool, 'user': command.user}
    host_data_copy = host_data.copy()
    host_data_copy['ip'] = host.ip
    created = bc._create_host(workspace, host_data_copy, command_dict)
    assert created == []
    assert count(Host, workspace) == 1


def test_create_existing_host_add_hostnames(session, workspace, host):
    assert count(Host, workspace) == 1
    assert len(host.hostnames) == 0
    command = new_empty_command(workspace)
    db.session.add(command)
    db.session.commit()
    command_dict = {'id': command.id, 'tool': command.tool, 'user': command.user}
    host_data_copy = host_data.copy()
    host_data_copy['ip'] = host.ip
    host_data_copy['hostnames'] = ['hostname']
    bc._create_host(workspace, host_data_copy, command_dict)
    existing_host = Host.query.filter(Host.workspace == workspace).one()
    assert len(existing_host.hostnames) == 1


def test_create_duplicated_hosts(session, workspace):
    assert count(Host, workspace) == 0
    host_data_copy = host_data.copy()
    command = new_empty_command(workspace)
    db.session.add(command)
    db.session.commit()
    command_dict = {'id': command.id, 'tool': command.tool, 'user': command.user}
    bc._create_host(workspace, host_data_copy, command_dict)
    db.session.commit()
    assert count(Host, workspace) == 1


def test_create_host_add_hostnames(session, workspace):
    assert count(Host, workspace) == 0
    host_data_copy = host_data.copy()
    command = new_empty_command(workspace)
    db.session.add(command)
    db.session.commit()
    command_dict = {'id': command.id, 'tool': command.tool, 'user': command.user}
    bc._create_host(workspace, host_data_copy, command_dict)
    host_data_new_copy = host_data.copy()
    host_data_new_copy['hostnames'] = ["test3.org"]
    other_command = new_empty_command(workspace)
    db.session.add(other_command)
    db.session.commit()
    other_command_dict = {'id': other_command.id, 'tool': other_command.tool, 'user': other_command.user}
    bc._create_host(workspace, host_data_new_copy, other_command_dict)
    host = Host.query.filter(Host.workspace == workspace).one()
    assert host.ip == "127.0.0.1"
    assert set({hn.name for hn in host.hostnames}) == {"test.com", "test2.org", "test3.org"}


def test_create_host_with_services(session, workspace):
    service_data_copy = service_data.copy()
    host_data_copy = host_data.copy()
    host_data_copy['services'] = [service_data_copy]
    command = new_empty_command(workspace)
    db.session.add(command)
    db.session.commit()
    command_dict = {'id': command.id, 'tool': command.tool, 'user': command.user}
    bc._create_host(workspace, host_data_copy, command_dict)
    assert count(Host, workspace) == 1
    assert count(Service, workspace) == 1
    service = Service.query.filter(Service.workspace == workspace).one()
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
    command = new_empty_command(service.workspace)
    db.session.add(command)
    db.session.commit()
    command_dict = {'id': command.id, 'tool': command.tool, 'user': command.user}
    bc._create_service(service.workspace, service.host, data, command_dict)
    assert count(Service, service.host.workspace) == 1


def test_create_service_vuln(session, service):
    new_vuln = bc.VulnerabilitySchema().load(vuln_data)
    command = new_empty_command(service.workspace)
    db.session.add(command)
    db.session.commit()
    command_dict = {'id': command.id, 'tool': command.tool, 'user': command.user}
    created_vuln_data, vuln_id = bc._create_servicevuln(service.workspace, service, new_vuln, command_dict)
    vuln = created_vuln_data[vuln_id]['vuln_data']
    references = created_vuln_data[vuln_id]['references']
    assert vuln['service_id'] == service.id
    assert vuln['name'] == 'kernel vuln'
    assert vuln['description'] == 'test'
    assert vuln['severity'] == 'high'
    assert vuln['impact_accountability'] is True
    assert vuln['impact_availability'] is False
    # assert vuln['impact_confidentiality'] is False
    assert {f'{r["name"]}-{r["type"]}' for r in references} == {f"{v['name']}-{v['type']}" for v in vuln_data['refs']}
    assert len(created_vuln_data[vuln_id]['cve_associations']) == len(set(vuln_data['cve']))
    assert len(created_vuln_data[vuln_id]['cwe_associations']) == len({cwe.upper() for cwe in vuln_data['cwe']})
    assert vuln['tool'] == "some_tool"


def test_create_not_fail_with_cve(session, host):
    with_erroneous_cve_list = vuln_data.copy()
    with_erroneous_cve_list['cve'] = ['CVSS: 10.0', 'OSVDB:339, OSVDB:8750, OSVDB:11516',
                                      'CVE-1999-0170, CVE-1999-0211, CVE-1999-0554', 'cve-1111-9988']
    cves_ok = ['CVE-1999-0170', 'CVE-1999-0211', 'CVE-1999-0554', 'CVE-1111-9988']
    new_vuln = bc.VulnerabilitySchema().load(with_erroneous_cve_list)
    command = new_empty_command(host.workspace)
    db.session.add(command)
    db.session.commit()
    command_dict = {'id': command.id, 'tool': command.tool, 'user': command.user}
    created_vuln_data, vuln_id = bc._create_hostvuln(host.workspace, host, new_vuln, command_dict)
    assert len(created_vuln_data[vuln_id]['cve_associations']) == len(cves_ok)


def test_creates_vuln_with_command_object_with_tool(session, service):
    host_data_copy = host_data.copy()
    service_data_copy = service_data.copy()
    new_vuln = bc.VulnerabilitySchema().load(vuln_data)
    service_data_copy['vulnerabilities'] = [new_vuln]
    host_data_copy['services'] = [service_data_copy]
    command = new_empty_command(service.workspace)
    db.session.add(command)
    db.session.commit()
    command_dict = {'id': command.id, 'tool': command.tool, 'user': command.user}
    created_vuln_data, vuln_id = bc._create_servicevuln(service.workspace, service, new_vuln, command_dict)
    assert created_vuln_data[vuln_id]['vuln_data']['tool'] == vuln_data['tool']


def test_creates_vuln_with_command_object_without_tool(session, service):
    host_data_copy = host_data.copy()
    service_data_copy = service_data.copy()
    vuln_web_data_copy = vuln_data.copy()
    vuln_web_data_copy.pop('tool')
    new_vuln = bc.VulnerabilitySchema().load(vuln_web_data_copy)
    service_data_copy['vulnerabilities'] = [new_vuln]
    host_data_copy['services'] = [service_data_copy]
    command = new_empty_command(service.workspace)
    command.tool = command_data['tool']
    db.session.add(command)
    db.session.commit()
    command_dict = {'id': command.id, 'tool': command.tool, 'user': command.user}
    db.session.commit()
    created_vuln_data, vuln_id = bc._create_servicevuln(service.workspace, service, new_vuln, command_dict)
    assert created_vuln_data[vuln_id]['vuln_data']['tool'] == command_data['tool']


def test_cannot_create_host_vulnweb(session, host):
    vuln_data_copy = vuln_data.copy()
    vuln_data_copy['type'] = 'VulnerabilityWeb'
    command = new_empty_command(host.workspace)
    db.session.add(command)
    db.session.commit()
    command_dict = {'id': command.id, 'tool': command.tool, 'user': command.user}
    with pytest.raises(ValidationError):
        bc._create_hostvuln(host.workspace, host, vuln_data_copy, command_dict)
    assert count(VulnerabilityGeneric, host.workspace) == 0


def test_create_existing_host_vuln(session, host, vulnerability_factory):
    vuln = vulnerability_factory.create(workspace=host.workspace, host=host, service=None)
    session.add(vuln)
    session.commit()
    vuln.references = ['old']
    session.add(vuln)
    session.commit()
    new_vuln_data = {
        'name': vuln.name,
        'description': vuln.description,
        'severity': vuln.severity,
        'type': 'vulnerability',
        'refs': [{'name': 'new', 'type': 'other'}]
    }
    command = new_empty_command(host.workspace)
    db.session.add(command)
    db.session.commit()
    command_dict = {'id': command.id, 'tool': command.tool, 'user': command.user}
    bc._create_hostvuln(host.workspace, host, new_vuln_data, command_dict)
    assert count(Vulnerability, host.workspace) == 1
    vuln = Vulnerability.query.get(vuln.id)  # just in case it isn't refreshed
    assert 'old' in vuln.references  # it must preserve the old references


def test_bulk_create_on_closed_vuln(session, host, vulnerability_factory):
    vuln = vulnerability_factory.create(workspace=host.workspace, host=host, service=None, status="closed")
    session.add(vuln)
    session.commit()
    session.add(vuln)
    session.commit()
    new_vuln_data = {
        'name': vuln.name,
        'description': vuln.description,
        'severity': vuln.severity,
        'type': 'vulnerability',
        'status': 'open'
    }
    new_host_data = {
        "ip": host.ip,
        "description": host.description,
        "hostnames": [hn.name for hn in host.hostnames],
        "vulnerabilities": [new_vuln_data]
    }
    command = new_empty_command(host.workspace)
    db.session.add(command)
    db.session.commit()
    command_dict = {'id': command.id, 'tool': command.tool, 'user': command.user}
    bc._create_host(host.workspace, new_host_data, command_dict)
    vuln = Vulnerability.query.get(vuln.id)
    assert vuln.status == "re-opened"


def test_bulk_create_endpoint_with_vuln_run_date(session, workspace):
    run_date = datetime.utcnow() - timedelta(days=30)
    host_data_copy = host_data.copy()
    vuln_data_copy = vuln_data.copy()
    vuln_data_copy['run_date'] = run_date.timestamp()
    new_vuln = bc.VulnerabilitySchema().load(vuln_data_copy)
    host_data_copy['vulnerabilities'] = [new_vuln]
    command = new_empty_command(workspace)
    db.session.add(command)
    db.session.commit()
    command_dict = {'id': command.id, 'tool': command.tool, 'user': command.user}
    bc._create_host(workspace, host_data_copy, command_dict)
    assert count(Host, workspace) == 1
    assert count(VulnerabilityGeneric, workspace) == 1
    vuln = Vulnerability.query.filter(Vulnerability.workspace == workspace).one()
    assert vuln.create_date.date() == run_date.date()


def test_bulk_create_endpoint_with_future_vuln_run_date(session, workspace):
    run_date = datetime.utcnow() + timedelta(days=30)
    host_data_copy = host_data.copy()
    vuln_data_copy = vuln_data.copy()
    vuln_data_copy['run_date'] = run_date.timestamp()
    new_vuln = bc.VulnerabilitySchema().load(vuln_data_copy)
    host_data_copy['vulnerabilities'] = [new_vuln]
    command = new_empty_command(workspace)
    db.session.add(command)
    db.session.commit()
    command_dict = {'id': command.id, 'tool': command.tool, 'user': command.user}
    bc._create_host(workspace, host_data_copy, command_dict)
    assert count(Host, workspace) == 1
    assert count(VulnerabilityGeneric, workspace) == 1
    vuln = Vulnerability.query.filter(Vulnerability.workspace == workspace).one()
    assert vuln
    assert vuln.create_date.date() < run_date.date()


def test_bulk_create_endpoint_with_invalid_vuln_run_date(session, workspace):
    host_data_copy = host_data.copy()
    vuln_data_copy = vuln_data.copy()
    vuln_data_copy['run_date'] = "INVALID"
    host_data_copy['vulnerabilities'] = [vuln_data_copy]
    command = new_empty_command(workspace)
    db.session.add(command)
    db.session.commit()
    command_dict = {'id': command.id, 'tool': command.tool, 'user': command.user}
    with pytest.raises(Exception):
        bc._create_host(workspace, host_data_copy, command_dict)


def test_create_host_with_cred(session, workspace):
    host_data_copy = host_data.copy()
    host_data_copy['credentials'] = [credential_data]
    command = new_empty_command(workspace)
    db.session.add(command)
    db.session.commit()
    command_dict = {'id': command.id, 'tool': command.tool, 'user': command.user}
    bc._create_host(workspace, host_data_copy, command_dict)
    assert count(Host, workspace) == 1
    host = workspace.hosts[0]
    assert count(Credential, workspace) == 1
    cred = Credential.query.filter(Credential.workspace == workspace).one()
    assert cred.host == host
    assert cred.name == 'test credential'
    assert cred.username == 'admin'
    assert cred.password == '12345'


def test_create_service_with_vuln(session, host):
    new_vuln = bc.VulnerabilitySchema().load(vuln_data)
    service_data_copy = service_data.copy()
    service_data_copy['vulnerabilities'] = [new_vuln]
    command = new_empty_command(host.workspace)
    db.session.add(command)
    db.session.commit()
    command_dict = {'id': command.id, 'tool': command.tool, 'user': command.user}
    bc._create_service(host.workspace, host, service_data_copy, command_dict)
    assert count(Service, host.workspace) == 1
    service = host.workspace.services[0]
    assert count(Vulnerability, service.workspace) == 1
    vuln = Vulnerability.query.filter(Vulnerability.workspace == service.workspace).one()
    assert vuln.name == 'kernel vuln'
    assert vuln.service == service


def test_create_service_with_cred(session, host):
    service_data_copy = service_data.copy()
    service_data_copy['credentials'] = [credential_data]
    command = new_empty_command(host.workspace)
    db.session.add(command)
    db.session.commit()
    command_dict = {'id': command.id, 'tool': command.tool, 'user': command.user}
    bc._create_service(host.workspace, host, service_data_copy, command_dict)
    assert count(Service, host.workspace) == 1
    service = host.workspace.services[0]
    assert count(Credential, service.workspace) == 1
    cred = Credential.query.filter(Credential.workspace == service.workspace).one()
    assert cred.service == service
    assert cred.name == 'test credential'
    assert cred.username == 'admin'
    assert cred.password == '12345'


def test_create_service_with_invalid_vuln(session, host):
    service_data_copy = service_data.copy()
    vuln_data_copy = vuln_data.copy()
    del vuln_data_copy['name']
    service_data_copy['vulnerabilities'] = [vuln_data_copy]
    with pytest.raises(ValidationError):
        data = bc.BulkServiceSchema().load(service_data_copy)
        command = new_empty_command(host.workspace)
        db.session.add(command)
        db.session.commit()
        command_dict = {'id': command.id, 'tool': command.tool, 'user': command.user}
        bc._create_service(host.workspace, host, data, command_dict)
    assert count(Service, host.workspace) == 0
    assert count(Vulnerability, host.workspace) == 0


def test_create_service_with_invalid_vulns(session, host):
    service_data_copy = service_data.copy()
    vuln_data_ = vuln_data.copy()
    del vuln_data_['name']
    service_data_copy['vulnerabilities'] = [1, 2, 3]
    with pytest.raises(ValidationError):
        data = bc.BulkServiceSchema().load(service_data_copy)
        command = new_empty_command(host.workspace)
        db.session.add(command)
        db.session.commit()
        command_dict = {'id': command.id, 'tool': command.tool, 'user': command.user}
        bc._create_service(host.workspace, host, data, command_dict)
    assert count(Service, host.workspace) == 0
    assert count(Vulnerability, host.workspace) == 0


def test_create_service_with_vulnweb(session, host):
    service_data_copy = service_data.copy()
    vuln_data_copy = vuln_data.copy()
    vuln_data_copy.update(vuln_web_data)
    new_vuln_web = bc.BulkVulnerabilityWebSchema().load(vuln_data_copy)
    service_data_copy['vulnerabilities'] = [new_vuln_web]
    command = new_empty_command(host.workspace)
    db.session.add(command)
    db.session.commit()
    command_dict = {'id': command.id, 'tool': command.tool, 'user': command.user}
    bc._create_service(host.workspace, host, service_data_copy, command_dict)
    assert count(Service, host.workspace) == 1
    service = host.workspace.services[0]
    assert count(Vulnerability, service.workspace) == 0
    assert count(VulnerabilityWeb, service.workspace) == 1
    vuln = VulnerabilityWeb.query.filter(Vulnerability.workspace == service.workspace).one()
    assert vuln.name == 'kernel vuln'
    assert vuln.service == service
    assert vuln.method == 'POST'
    assert vuln.website == 'https://faradaysec.com'
    assert vuln.status_code == 200


def test_updates_command_object(session, workspace):
    host_data_copy = host_data.copy()
    service_data_copy = service_data.copy()
    new_vuln = bc.VulnerabilitySchema().load(vuln_data)
    vuln_web_data_copy = vuln_data.copy()
    vuln_web_data_copy.update(vuln_web_data)
    new_vuln_web = bc.BulkVulnerabilityWebSchema().load(vuln_web_data_copy)
    service_data_copy['vulnerabilities'] = [new_vuln, new_vuln_web]
    service_data_copy['credentials'] = [credential_data]
    host_data_copy['services'] = [service_data_copy]
    host_data_copy['vulnerabilities'] = [new_vuln]
    host_data_copy['credentials'] = [credential_data]
    command = new_empty_command(workspace)
    db.session.add(command)
    db.session.commit()
    command_dict = {'id': command.id, 'tool': command.tool, 'user': command.user}
    bc._create_host(workspace, host_data_copy, command_dict)

    command = workspace.commands[0]
    host = workspace.hosts[0]
    service = host.services[0]
    vuln_host = Vulnerability.query.filter(
        Vulnerability.workspace == workspace,
        Vulnerability.service == null()).one()
    vuln_service = Vulnerability.query.filter(
        Vulnerability.workspace == workspace,
        Vulnerability.host == null()).one()
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
            CommandObject.created_persistent == true(),
        ).one()


def test_bulk_create_update_service(session, service):
    session.add(service)
    session.commit()
    new_service_version = f"{service.version}_changed"
    new_service_name = f"{service.name}_changed"
    new_service_description = f"{service.description}_changed"
    new_service_owned = not service.owned
    data = {
        "version": new_service_version,
        "name": new_service_name,
        "description": new_service_description,
        "port": service.port,
        "protocol": service.protocol,
        "owned": new_service_owned,
    }
    data = bc.BulkServiceSchema().load(data)
    command = new_empty_command(service.workspace)
    db.session.add(command)
    db.session.commit()
    command_dict = {'id': command.id, 'tool': command.tool, 'user': command.user}
    bc._create_service(service.workspace, service.host, data, command_dict)
    assert count(Service, service.host.workspace) == 1
    assert service.version == new_service_version
    assert service.name == new_service_name
    assert service.description == new_service_description
    assert service.owned == new_service_owned


@pytest.mark.skip(reason="Check why is not sanitized")
def test_sanitize_request_and_response(session, workspace):
    invalid_request_text = 'GET /example.do HTTP/1.0\n  \x89\n\x1a  SOME_TEXT'
    invalid_response_text = '<html> \x89\n\x1a  SOME_TEXT</html>'
    sanitized_request_text = 'GET /example.do HTTP/1.0\n  \n  SOME_TEXT'
    sanitized_response_text = '<html> \n  SOME_TEXT</html>'
    host_data_copy = host_data.copy()
    service_data_copy = service_data.copy()
    vuln_web_data_copy = vuln_web_data.copy()
    vuln_web_data_copy['name'] = 'test'
    vuln_web_data_copy['severity'] = 'low'
    vuln_web_data_copy['request'] = invalid_request_text
    vuln_web_data_copy['response'] = invalid_response_text
    new_vuln_web = bc.BulkVulnerabilityWebSchema().load(vuln_web_data_copy)
    service_data_copy['vulnerabilities'] = [new_vuln_web]
    host_data_copy['services'] = [service_data_copy]
    command = new_empty_command(workspace)
    db.session.add(command)
    db.session.commit()
    command_dict = {'id': command.id, 'tool': command.tool, 'user': command.user}
    bc._create_host(workspace, host_data_copy, command_dict)
    vuln = VulnerabilityWeb.query.filter(VulnerabilityWeb.workspace == workspace).one()
    assert vuln.request == sanitized_request_text
    assert vuln.response == sanitized_response_text


def test_create_vuln_with_custom_fields(session, workspace):
    custom_field = CustomFieldsSchemaFactory(
        field_name='changes',
        field_type='list',
        field_display_name='Changes',
        table_name='vulnerability'
    )
    session.add(custom_field)
    session.commit()
    host_data_copy = host_data.copy()
    vuln_data_copy = vuln_data.copy()
    vuln_data_copy['custom_fields'] = {'changes': ['1', '2', '3']}
    new_vuln = bc.VulnerabilitySchema().load(vuln_data_copy)
    host_data_copy['vulnerabilities'] = [new_vuln]
    command = new_empty_command(workspace)
    db.session.add(command)
    db.session.commit()
    command_dict = {'id': command.id, 'tool': command.tool, 'user': command.user}
    bc._create_host(workspace, host_data_copy, command_dict)
    assert count(Host, workspace) == 1
    assert count(Vulnerability, workspace) == 1
    assert count(Command, workspace) == 1
    for vuln in Vulnerability.query.filter(Vulnerability.workspace == workspace):
        assert vuln.custom_fields['changes'] == ['1', '2', '3']


def test_creates_command_object_on_duplicates(session, command, service, vulnerability_factory,
                                              vulnerability_web_factory, credential_factory):
    vuln_host = vulnerability_factory.create(workspace=service.workspace, host=service.host, service=None)
    vuln_service = vulnerability_factory.create(workspace=service.workspace, service=service, host=None)
    vuln_web = vulnerability_web_factory.create(workspace=service.workspace, service=service)
    host_cred = credential_factory.create(workspace=service.workspace, host=service.host, service=None)
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

    new_vuln = bc.BulkVulnerabilityWebSchema().load(vuln_data)
    vuln_web_data_copy = vuln_data.copy()
    vuln_web_data_copy.update(vuln_web_data)
    new_vuln_web = bc.BulkVulnerabilityWebSchema().load(vuln_web_data_copy)
    service_data_copy = service_data.copy()
    service_data_copy['vulnerabilities'] = [new_vuln_web, new_vuln]

    data = {
        "ip": service.host.ip,
        "description": service.host.description,
        "credentials": [credential_data.copy()],
        "vulnerabilities": [new_vuln],
        "services": [service_data_copy]
    }

    command2 = new_empty_command(command.workspace)
    command2.tool = command_data['tool']
    db.session.add(command2)
    session.commit()
    command2_dict = {'id': command2.id, 'tool': command2.tool, 'user': command2.user}
    bc._create_host(command.workspace, data, command2_dict)
    assert count(Command, command.workspace) == 2


class TestBulkCreateAPI:

    def test_bulk_create_endpoints_fails_without_auth(self, session, workspace, test_client):
        url = f'/v3/ws/{workspace.name}/bulk_create'
        res = test_client.post(url, data=dict(hosts=[host_data.copy()], command=command_data.copy()))
        assert res.status_code == 401
        assert count(Host, workspace) == 0

    @pytest.mark.usefixtures('logged_user')
    def test_bulk_create_endpoint_with_invalid_data(self, session, workspace, test_client, logged_user):
        invalid_data = {}
        url = f'/v3/ws/{workspace.name}/bulk_create'
        res = test_client.post(url, data=invalid_data)
        assert res.status_code == 400, res.json

    @pytest.mark.usefixtures('logged_user')
    def test_bulk_create_endpoint_without_host_ip(self, session, workspace, test_client):
        url = f'/v3/ws/{workspace.name}/bulk_create'
        host_data_copy = host_data.copy()
        host_data_copy.pop('ip')
        res = test_client.post(url, data=dict(hosts=[host_data_copy], command=command_data.copy()))
        assert res.status_code == 400

    @pytest.mark.usefixtures('logged_user')
    def test_bulk_create_endpoint_without_command(self, session, workspace, test_client):
        url = f'/v3/ws/{workspace.name}/bulk_create'
        res = test_client.post(url, data=dict(hosts=[host_data.copy()]))
        assert res.status_code == 400

    def test_bulk_create_with_not_existent_workspace_fails(self, session, agent, test_client):
        session.add(agent)
        session.commit()
        assert agent.token
        url = "/v3/ws/incorrect_ws/bulk_create"
        res = test_client.post(
            url,
            data=dict(hosts=[host_data.copy()]),
            headers=[("authorization", f"agent {agent.token}")]
        )
        assert res.status_code == 404
        assert b'No such workspace' in res.data

    @pytest.mark.parametrize('token_type', ['agent', 'token'])
    def test_bulk_create_endpoints_fails_with_invalid_token(self, token_type, workspace, test_client):
        iat = int(time.time())
        exp = iat + 4200
        jwt_data = {'user_id': "invalid_id", 'iat': iat, 'exp': exp}
        token = jwt.encode(jwt_data, current_app.config['SECRET_KEY'], algorithm="HS512")
        url = f'/v3/ws/{workspace.name}/bulk_create'
        res = test_client.post(
            url,
            data=dict(hosts=[host_data.copy()], command=command_data.copy()),
            headers=[("authorization", f"{token_type} {token}")]
        )
        if token_type == 'token':
            # TODO change expected status code to 403
            assert res.status_code == 401
        else:
            assert res.status_code == 403
        assert count(Host, workspace) == 0

    def test_bulk_create_endpoint_with_agent_token_without_execution_id(self, session, agent, test_client, workspace):
        session.add(agent)
        session.commit()
        assert count(Host, workspace) == 0
        url = f'/v3/ws/{workspace.name}/bulk_create'
        res = test_client.post(
            url,
            data=dict(hosts=[host_data], command=command_data.copy()),
            headers=[("authorization", f"agent {agent.token}")]
        )
        assert res.status_code == 400
        assert b"argument expected: execution_id" in res.data
        assert count(Host, workspace) == 0
        assert count(Command, workspace) == 0

    def test_bulk_create_endpoint_with_agent_token_with_param(self, session, agent_execution, test_client, workspace):
        user = User.query.first()
        cm = Command.query.first()
        session.delete(cm)
        session.commit()
        command, new_agent_execution = get_command_and_agent_execution(executor=agent_execution.executor,
                                                                       workspace=workspace,
                                                                       user_id=user.id,
                                                                       parameters=agent_execution.parameters_data)
        agent = agent_execution.executor.agent
        session.add(new_agent_execution)
        session.commit()
        assert count(Host, workspace) == 0
        assert count(Command, workspace) == 1
        url = f'/v3/ws/{workspace.name}/bulk_create'
        res = test_client.post(
            url,
            data=dict(hosts=[host_data], execution_id=new_agent_execution.id, command=command_data.copy()),
            headers=[("authorization", f"agent {agent.token}")]
        )
        assert res.status_code == 201
        assert count(Command, workspace) == 1
        command = Command.query.filter(Command.workspace == workspace).one()
        assert command.tool == agent.name
        assert command.command == agent_execution.executor.name
        params = ', '.join([f'{key}={value}' for (key, value) in agent_execution.parameters_data.items()])
        assert command.params == str(params)
        assert command.import_source == 'agent'
        command_id = res.json["command_id"]
        assert command.id == command_id
        assert command.id == new_agent_execution.command.id

    @pytest.mark.skip(reason="Must think a new way to test this with async bulk_create")
    @pytest.mark.parametrize('start_date', [None, datetime.utcnow()])
    @pytest.mark.parametrize('duration', [None, 1200])
    def test_bulk_create_endpoint_with_agent_token(self,
                                                   session,
                                                   test_client,
                                                   agent_execution_factory,
                                                   start_date, duration,
                                                   workspace):
        agent_execution = agent_execution_factory.create()
        agent = agent_execution.executor.agent
        extra_agent_execution = agent_execution_factory.create()

        agent_execution.executor.parameters_metadata = {}
        agent_execution.parameters_data = {}
        agent_execution.workspace = workspace
        agent_execution.command.workspace = workspace
        session.add(agent_execution)
        session.add(extra_agent_execution)
        session.commit()

        command_dict = {}
        if start_date:
            command_dict.update({
                'tool': agent.name,  # Agent name
                'command': agent_execution.executor.name,
                'user': '',
                'hostname': '',
                'params': '',
                'import_source': 'agent',
                'start_date': str(start_date)
            })
        if duration:
            command_dict.update({
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
        if command_dict:
            data_kwargs["command"] = command_dict
        else:
            data_kwargs["command"] = command_data.copy()

        initial_host_count = Host.query.filter(Host.workspace == workspace and Host.creator_id is None).count()
        assert count(Command, workspace) == 1
        url = f'/v3/ws/{workspace.name}/bulk_create'
        res = test_client.post(
            url,
            data=dict(**data_kwargs),
            headers=[("authorization", f"agent {agent.token}")]
        )
        assert res.status_code == 400

        assert Host.query.filter(
            Host.workspace == workspace and Host.creator_id is None).count() == initial_host_count
        assert count(Command, workspace) == 1
        data_kwargs["execution_id"] = extra_agent_execution.id
        res = test_client.post(
            url,
            data=dict(**data_kwargs),
            headers=[("authorization", f"agent {agent.token}")]
        )
        assert res.status_code == 400
        assert Host.query.filter(
            Host.workspace == workspace and Host.creator_id is None).count() == initial_host_count
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

    def test_bulk_create_endpoint_with_agent_token_readonly_workspace(self, session, agent, test_client, workspace):
        workspace.readonly = True
        session.add(agent)
        session.add(workspace)
        session.commit()
        url = f'/v3/ws/{workspace.name}/bulk_create'
        res = test_client.post(
            url,
            data=dict(hosts=[host_data.copy()], command=command_data.copy()),
            headers=[("authorization", f"agent {agent.token}")]
        )
        assert res.status_code == 403

    def test_bulk_create_endpoint_with_agent_token_disabled_workspace(self, session, agent, test_client, workspace):
        workspace.active = False
        session.add(agent)
        session.add(workspace)
        session.commit()
        url = f'/v3/ws/{workspace.name}/bulk_create'
        res = test_client.post(
            url,
            data=dict(hosts=[host_data.copy()], command=command_data.copy()),
            headers=[("authorization", f"agent {agent.token}")]
        )
        assert res.status_code == 403

    @pytest.mark.usefixtures('logged_user')
    def test_bulk_create_endpoint_raises_400_with_no_data(self, session, test_client, workspace):
        url = f'/v3/ws/{workspace.name}/bulk_create'
        res = test_client.post(
            url,
            data="",
            use_json_data=False,
            headers=[("Content-Type", "application/json")]
        )
        assert res.status_code == 400

    @pytest.mark.usefixtures('logged_user')
    def test_bulk_create_endpoint_fails_with_list_in_null_to_blank_string(self, session, workspace, test_client,
                                                                          logged_user):
        assert count(Host, workspace) == 0
        assert count(VulnerabilityGeneric, workspace) == 0
        url = f'/v3/ws/{workspace.name}/bulk_create'
        new_vuln = bc.VulnerabilitySchema().load(vuln_data)
        host_data_copy = host_data.copy()
        host_data_copy['services'] = [service_data]
        host_data_copy['credentials'] = [credential_data]
        host_data_copy['vulnerabilities'] = [new_vuln]
        host_data_copy['default_gateway'] = ["localhost"]  # Can not be a list
        res = test_client.post(url, data=dict(hosts=[host_data_copy], command=command_data.copy()))
        assert res.status_code == 400, res.json
        assert count(Host, workspace) == 0
        assert count(Service, workspace) == 0
        assert count(Credential, workspace) == 0
        assert count(Vulnerability, workspace) == 0

    @pytest.mark.usefixtures('logged_user')
    def test_bulk_create_with_custom_fields_list(self, test_client, workspace, session, logged_user):
        custom_field_schema = CustomFieldsSchemaFactory(
            field_name='changes',
            field_type='list',
            field_display_name='Changes',
            table_name='vulnerability'
        )
        session.add(custom_field_schema)
        session.commit()
        creator_id = logged_user.id

        assert count(Host, workspace) == 0
        assert count(VulnerabilityGeneric, workspace) == 0
        host_data_copy = host_data.copy()
        service_data_copy = service_data.copy()
        service_data_copy['creator_id'] = creator_id
        vuln_data_copy = vuln_data.copy()
        vuln_data_copy['custom_fields'] = {'changes': ['1', '2', '3']}
        new_vuln = bc.VulnerabilitySchema().load(vuln_data_copy)
        service_data_copy['vulnerabilities'] = [new_vuln]
        credential_data_copy = credential_data.copy()
        credential_data_copy['creator_id'] = creator_id
        host_data_copy['services'] = [service_data_copy]
        host_data_copy['credentials'] = [credential_data_copy]
        host_data_copy['vulnerabilities'] = [new_vuln]
        host_data_copy['creator_id'] = creator_id
        command = new_empty_command(workspace)
        command.creator_id = creator_id
        session.commit()
        command_dict = {'id': command.id, 'tool': command.tool, 'user': command.user}
        bc._create_host(workspace, host_data_copy, command_dict)
        assert count(Host, workspace) == 1
        assert count(Service, workspace) == 1
        assert count(Vulnerability, workspace) == 2
        assert count(Command, workspace) == 1
        host = Host.query.filter(Host.workspace == workspace).one()
        assert host.ip == "127.0.0.1"
        assert host.creator_id == creator_id
        assert set({hn.name for hn in host.hostnames}) == {"test.com", "test2.org"}
        assert len(host.services) == 1
        assert len(host.vulnerabilities) == 1
        assert len(host.services[0].vulnerabilities) == 1
        service = Service.query.filter(Service.workspace == workspace).one()
        assert service.creator_id == creator_id
        credential = Credential.query.filter(Credential.workspace == workspace).one()
        assert credential.creator_id == creator_id
        command = Command.query.filter(Credential.workspace == workspace).one()
        assert command.creator_id == creator_id
        for vuln in Vulnerability.query.filter(Vulnerability.workspace == workspace):
            assert vuln.custom_fields['changes'] == ['1', '2', '3']

    @pytest.mark.usefixtures('logged_user')
    def test_vuln_web_cannot_have_host_parent(self, session, workspace, test_client, logged_user):
        url = f'/v3/ws/{workspace.name}/bulk_create'
        host_data_copy = host_data.copy()
        vuln_web_data_copy = vuln_web_data.copy()
        vuln_web_data_copy['severity'] = "high"
        vuln_web_data_copy['name'] = "test"
        host_data_copy['vulnerabilities'] = [vuln_web_data_copy]
        res = test_client.post(url, data=dict(hosts=[host_data_copy], command=command_data.copy()))
        assert res.status_code == 400

    @pytest.mark.usefixtures('logged_user')
    def test_send_report(self, session, workspace, test_client, logged_user):
        cmd = new_empty_command(workspace)
        host_data_copy = host_data.copy()
        host_data_copy['vulnerabilities'] = []

        vulnerability = vuln_data.copy()
        vulnerability['severity'] = "medium"
        vulnerability['name'] = "test"
        vulnerability['desc'] = "test"
        host_data_copy['vulnerabilities'].append(vulnerability)

        vulnerability2 = vuln_data.copy()
        vulnerability2['severity'] = "high"
        vulnerability2['name'] = "test"
        vulnerability2['desc'] = "test2"
        host_data_copy['vulnerabilities'].append(vulnerability2)

        vulnerability3 = vuln_data.copy()
        vulnerability3['severity'] = "critical"
        vulnerability3['name'] = "test"
        vulnerability3['desc'] = "test3"
        host_data_copy['vulnerabilities'].append(vulnerability3)

        hosts = {"hosts": [host_data_copy], "command": command_data}
        report = send_report_data(workspace.name, cmd.id, hosts, logged_user.id, True)
        created = VulnerabilityGeneric.query.filter(VulnerabilityGeneric.name == vulnerability['name']).all()
        assert len(created) == 3
