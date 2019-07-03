import pytest
from marshmallow import ValidationError
from faraday.server.models import (
    db,
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
    'refs': ['CVE-1234']
}

vuln_web_data = {
    'type': 'VulnerabilityWeb',
    'method': 'POST',
    'website': 'https://faradaysec.com',
    'path': '/search',
    'parameter_name': 'q',
    'status_code': 200,
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
    bc.create_service(host.workspace, host, service_data)
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
    bc.create_service(service.workspace, service.host, data)
    assert count(Service, service.host.workspace) == 1

def test_create_host_vuln(session, host):
    bc.create_hostvuln(host.workspace, host, vuln_data)
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


def test_create_service_vuln(session, service):
    bc.create_servicevuln(service.workspace, service, vuln_data)
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


def test_cannot_create_host_vulnweb(session, host):
    data = vuln_data.copy()
    data['type'] = 'VulnerabilityWeb'
    with pytest.raises(ValidationError):
        bc.create_hostvuln(host.workspace, host, data)
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
    bc.create_hostvuln(host.workspace, host, data)
    session.commit()
    assert count(Vulnerability, host.workspace) == 1
    vuln = Vulnerability.query.get(vuln.id)  # just in case it isn't refreshed
    assert 'old' in vuln.references  # it must preserve the old references


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


def test_create_service_with_vuln(session, host):
    service_data_ = service_data.copy()
    service_data_['vulnerabilities'] = [vuln_data]
    bc.create_service(host.workspace, host, service_data_)
    assert count(Service, host.workspace) == 1
    service = host.workspace.services[0]
    assert count(Vulnerability, service.workspace) == 1
    vuln = Vulnerability.query.filter(
        Vulnerability.workspace == service.workspace).one()
    assert vuln.name == 'sql injection'
    assert vuln.service == service


def test_create_service_with_invalid_vuln(session, host):
    service_data_ = service_data.copy()
    vuln_data_ = vuln_data.copy()
    del vuln_data_['name']
    service_data_['vulnerabilities'] = [vuln_data_]
    with pytest.raises(ValidationError):
        bc.create_service(host.workspace, host, service_data_)
    assert count(Service, host.workspace) == 0
    assert count(Vulnerability, host.workspace) == 0


def test_create_service_with_invalid_vulns(session, host):
    service_data_ = service_data.copy()
    vuln_data_ = vuln_data.copy()
    del vuln_data_['name']
    service_data_['vulnerabilities'] = [1, 2, 3]
    with pytest.raises(ValidationError):
        bc.create_service(host.workspace, host, service_data_)
    assert count(Service, host.workspace) == 0
    assert count(Vulnerability, host.workspace) == 0


def test_create_service_with_vulnweb(session, host):
    service_data_ = service_data.copy()
    vuln_data_ = vuln_data.copy()
    vuln_data_.update(vuln_web_data)
    service_data_['vulnerabilities'] = [vuln_data_]
    bc.create_service(host.workspace, host, service_data_)
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
