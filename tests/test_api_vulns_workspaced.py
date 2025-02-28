'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
'''
import csv
import json
import urllib
import datetime
from pathlib import Path
from tempfile import NamedTemporaryFile
from base64 import b64encode
from io import BytesIO, StringIO
from posixpath import join

from sqlalchemy.orm.util import was_deleted

try:
    from urllib import urlencode
except ImportError:
    from urllib.parse import urlencode, urljoin

import pytz
import pytest
from dateutil import parser
from depot.manager import DepotManager

from hypothesis import given, settings, strategies as st
from cvss import CVSS3

from faraday.server.api.modules.vulns_base import VulnerabilitySchema
from faraday.server.api.modules.vulns_workspaced import VulnerabilityWorkspacedFilterSet, VulnerabilityWorkspacedView
from faraday.server.fields import FaradayUploadedFile
from faraday.server.schemas import NullToBlankString
from tests import factories
from tests.conftest import TEST_DATA_PATH
from tests.test_api_workspaced_base import (
    ReadWriteAPITests,
    BulkDeleteTestsMixin,
    BulkUpdateTestsMixin
)
from faraday.server.models import (
    VulnerabilityGeneric,
    Vulnerability,
    VulnerabilityWeb,
    CustomFieldsSchema,
    Reference,
    PolicyViolation,
    CommandObject,
    File,
    Host,
    Service,
    CVE,
    SeveritiesHistogram,
    CWE,
    Command,
)
from tests.factories import (
    ServiceFactory,
    CommandFactory,
    CommandObjectFactory,
    HostFactory,
    EmptyCommandFactory,
    UserFactory,
    VulnerabilityWebFactory,
    VulnerabilityFactory,
    ReferenceFactory,
    PolicyViolationFactory,
    HostnameFactory,
    WorkspaceFactory,
    CustomFieldsSchemaFactory,
    CredentialFactory
)


def _create_post_data_vulnerability(name, vuln_type, parent_id,
                                    parent_type, refs, policyviolations,
                                    status='open', cve=[], cvss2={}, cvss3={}, cvss4={}, cwe=[],  # TODO: Remove defaults []
                                    attachments=None, impact=None,
                                    description='desc1234',
                                    confirmed=True, data='data1234',
                                    easeofresolution=Vulnerability.EASE_OF_RESOLUTIONS[0],
                                    owned=False, resolution='res1234',
                                    severity='critical',
                                    update_controller_action='UI Web',
                                    service_id=None,
                                    tool=""
                                    ):
    if not impact:
        impact = {'accountability': False, 'availability': False,
                  'confidentiality': False,
                  'integrity': False}
    data = {
        'metadata': {
            'update_time': 1508254070.211,
            'update_user': '',
            'update_action': 0,
            'creator': 'UI Web',
            'create_time': 1508254070.211,
            'update_controller_action': update_controller_action,
            'owner': ''},
        'obj_id': '5a60af7f01dde6d3acfa8e9d3bef265c361a49d2',
        'owner': '',
        'parent': parent_id,
        'parent_type': parent_type,
        'type': vuln_type,
        'ws': 'airbnb',
        'confirmed': confirmed,
        'data': data,
        'desc': description,
        'easeofresolution': easeofresolution,
        'impact': impact,
        'name': name,
        'owned': owned,
        'policyviolations': policyviolations,
        'refs': refs,
        'cve': cve,
        'cvss2': cvss2,
        'cvss3': cvss3,
        'cvss4': cvss4,
        'cwe': cwe,
        'resolution': resolution,
        'severity': severity,
        'status': status,
        '_attachments': {},
        'description': '',
        'protocol': '',
        'version': '',
        'tool': tool
    }

    if vuln_type == 'VulnerabilityWeb':
        data.update({
            "method": "GET",
            "params": "pepe",
            "path": "/pepep",
            "pname": "pepe",
            "query": "queue&dfsa",
            "request": "",
            "response": "",
            "website": "www.pepe.com"})

    if attachments:
        data['_attachments'] = {}
        for attachment in attachments:
            attachment_data = attachment.read()
            if isinstance(attachment_data, str):
                attachment_data = attachment_data.encode('utf-8')
            data['_attachments'][attachment.name] = {
                "content_type": "application/x-shellscript",
                "data": b64encode(attachment_data).decode('utf-8')
            }

    if service_id:
        data.update({
            'service_id': service_id,
        })

    return data


ORDER = [
            [{'field': 'status', 'direction': 'desc'}],
            [{'field': 'severity', 'direction': 'desc'}],
            [{'field': 'target', 'direction': 'desc'}],
            [{'field': 'name', 'direction': 'desc'}],
            [
                {'field': 'status', 'direction': 'desc'}, {'field': 'severity', 'direction': 'desc'},
                {'field': 'target', 'direction': 'desc'}, {'field': 'name', 'direction': 'desc'}
            ],
        ]


GROUP = [
            [{'field': 'status'}],
            [{'field': 'severity'}],
            [{'field': 'target'}],
            [{'field': 'name'}],
            [
                {'field': 'status'}, {'field': 'severity'},
                {'field': 'target'}, {'field': 'name'}
            ],
        ]


@pytest.mark.usefixtures('logged_user')
class TestListVulnerabilityView(ReadWriteAPITests, BulkUpdateTestsMixin, BulkDeleteTestsMixin):
    model = Vulnerability
    factory = factories.VulnerabilityFactory
    api_endpoint = 'vulns'
    # unique_fields = ['ip']
    # update_fields = ['ip', 'description', 'os']
    view_class = VulnerabilityWorkspacedView
    patchable_fields = ['name']

    def test_backward_json_compatibility(self, test_client, second_workspace, session):
        new_obj = self.factory.create(workspace=second_workspace)
        session.add(new_obj)
        session.commit()
        res = test_client.get(self.url())
        assert res.status_code == 200
        assert 'vulnerabilities' in res.json
        for vuln in res.json['vulnerabilities']:
            assert {'id', 'key', 'value'} == set(vuln.keys())
            object_properties = [
                'status',
                'issuetracker',
                'description',
                'parent',
                'tags',
                'severity',
                '_rev',
                'easeofresolution',
                'owned',
                'hostnames',
                'pname',
                'query',
                'owner',
                'path',
                'data',
                'response',
                'refs',
                'desc',
                'impact',
                'confirmed',
                'name',
                'service',
                'obj_id',
                'type',
                'cwe',
                'cve',
                'policyviolations',
                'request',
                '_attachments',
                'target',
                '_id',
                'resolution',
                'method',
                'metadata',
                'website',
                'params',
            ]
            expected = set(object_properties)
            result = set(vuln['value'].keys())
            assert expected - result == set()

    def test_handles_vuln_with_no_creator(self,
                                          workspace,
                                          test_client,
                                          session):
        # This can happen when a user is deleted but its objects persist
        vuln = self.factory.create(workspace=workspace, creator=None)
        session.add(vuln)
        session.commit()
        res = test_client.get(self.url(vuln))
        assert res.status_code == 200
        assert res.json['owner'] is None

    def test_shows_policy_violations(self, workspace, test_client, session,
                                     policy_violation_factory):
        pvs = policy_violation_factory.create_batch(
            5, workspace=workspace)
        for pv in pvs:
            self.first_object.policy_violation_instances.add(pv)
        session.add(self.first_object)
        session.commit()
        res = test_client.get(self.url(self.first_object))
        assert res.status_code == 200
        assert len(res.json['policyviolations']) == 5
        assert set(res.json['policyviolations']) == {pv.name for pv in pvs}

    def test_shows_refs(self, workspace, test_client, session,
                        vulnerability_reference_factory, host_factory, vulnerability_factory):
        host = host_factory.create(ip='testhost', workspace=workspace)
        session.add(host)
        vuln = vulnerability_factory.create(workspace=workspace, host=host)
        session.add(vuln)
        session.commit()
        refs = vulnerability_reference_factory.create_batch(
            5, vulnerability_id=vuln.id)
        session.commit()
        res = test_client.get(self.url(vuln.id))
        assert res.status_code == 200
        assert len(res.json['refs']) == 5
        assert {f"{v['name']}-{v['type']}" for v in res.json['refs']} == {f"{ref.name}-{ref.type}"
                                                                                   for ref in refs}

    @pytest.mark.parametrize('creator_func', [
        (lambda host: factories.VulnerabilityFactory.create(
            workspace=host.workspace, host=host, service=None)),
        (lambda host: factories.VulnerabilityFactory.create(
            workspace=host.workspace, host=None,
            service=factories.ServiceFactory.create(
                workspace=host.workspace, host=host
            ))),
        (lambda host: factories.VulnerabilityWebFactory.create(
            workspace=host.workspace, service=factories.ServiceFactory.create(
                workspace=host.workspace, host=host
            ))),
    ], ids=['standard_vuln_with_host', 'standard_vuln_with_service',
            'web_vuln_with_service'])
    def test_hostnames(self, host_with_hostnames, test_client, session,
                       creator_func):
        vuln = creator_func(host_with_hostnames)
        vuln = self.factory.create(host=host_with_hostnames,
                                   service=None,
                                   workspace=host_with_hostnames.workspace)
        session.commit()
        res = test_client.get(self.url(vuln))
        assert res.status_code == 200
        assert isinstance(res.json['hostnames'], list)
        assert set(res.json['hostnames']) == {hostname.name for hostname in
                                              host_with_hostnames.hostnames}

    def test_create_vuln(self, host_with_hostnames, test_client, session):
        """
        This one should only check basic vuln properties
        :param host_with_hostnames:
        :param test_client:
        :param session:
        :return:
        """
        session.commit()  # flush host_with_hostnames
        raw_data = _create_post_data_vulnerability(
            name='New vulns',
            vuln_type='Vulnerability',
            parent_id=host_with_hostnames.id,
            parent_type='Host',
            refs=[],
            policyviolations=[],
            description='helloworld',
            severity='low',
        )
        ws = host_with_hostnames.workspace
        vuln_count_previous = session.query(Vulnerability).count()
        res = test_client.post(self.url(workspace=ws), data=raw_data)
        assert res.status_code == 201
        assert vuln_count_previous + 1 == session.query(Vulnerability).count()
        assert res.json['name'] == 'New vulns'
        assert res.json['type'] == 'Vulnerability'
        assert res.json['parent'] == host_with_hostnames.id
        assert res.json['parent_type'] == 'Host'
        assert res.json['desc'] == 'helloworld'
        assert res.json['description'] == 'helloworld'
        assert res.json['severity'] == 'low'

    def test_histogram_creation(self, vulnerability_factory, second_workspace, test_client, session):
        """
        This one should only check basic vuln properties
        :param host_with_hostnames:
        :param test_client:
        :param session:
        :return:
        """

        vulns = VulnerabilityWeb.query.all()
        for vuln in vulns:
            session.delete(vuln)
        session.commit()

        vulns = Vulnerability.query.all()
        for vuln in vulns:
            session.delete(vuln)
        session.commit()

        session.query(SeveritiesHistogram).delete()
        session.commit()
        vulns_unconfirmed = vulnerability_factory.create_batch(4, confirmed=False,
                                                               workspace=self.workspace,
                                                               status='open',
                                                               severity='critical')

        vulns_confirmed = vulnerability_factory.create_batch(4, confirmed=True,
                                                             workspace=self.workspace,
                                                             status='open',
                                                             severity='critical')

        session.add_all(vulns_confirmed + vulns_unconfirmed)
        session.commit()

        histogram = SeveritiesHistogram.query.all()
        assert len(histogram) == 1
        assert histogram[0].workspace_id == self.workspace.id
        assert histogram[0].critical == 8
        assert histogram[0].confirmed == 4
        assert histogram[0].date == datetime.date.today()

        vulns_high = vulnerability_factory.create_batch(4,
                                                        confirmed=True,
                                                        workspace=second_workspace,
                                                        status='open',
                                                        severity='high')

        owner = UserFactory.create()
        service = ServiceFactory.create(workspace=self.workspace)
        vuln_web = VulnerabilityWebFactory.create(
            confirmed=True,
            service=service,
            creator=owner,
            workspace=self.workspace,
            severity='medium'
        )

        vulns_critical = vulnerability_factory.create_batch(4,
                                                            confirmed=False,
                                                            workspace=second_workspace,
                                                            status='open',
                                                            severity='critical')

        session.add_all(vulns_high + vulns_critical + [vuln_web])
        session.commit()

        vhigh_id = vulns_high[0].id
        vhigh2_id = vulns_high[1].id
        vhigh3_id = vulns_high[2].id

        histogram = SeveritiesHistogram.query.filter(SeveritiesHistogram.workspace == self.workspace).all()
        assert len(histogram) == 1
        assert histogram[0].workspace_id == self.workspace.id
        assert histogram[0].critical == 8
        assert histogram[0].medium == 1
        assert histogram[0].confirmed == 5

        histogram = SeveritiesHistogram.query.filter(SeveritiesHistogram.workspace == second_workspace).all()
        assert len(histogram) == 1
        assert histogram[0].workspace_id == second_workspace.id
        assert histogram[0].critical == 4
        assert histogram[0].high == 4
        assert histogram[0].medium == 0
        assert histogram[0].confirmed == 4
        assert histogram[0].date == datetime.date.today()

        v = Vulnerability.query.get(vhigh_id)
        v.confirmed = False
        session.commit()

        histogram = SeveritiesHistogram.query.filter(SeveritiesHistogram.workspace == second_workspace).all()
        assert len(histogram) == 1
        assert histogram[0].workspace_id == second_workspace.id
        assert histogram[0].critical == 4
        assert histogram[0].high == 4
        assert histogram[0].confirmed == 3
        assert histogram[0].date == datetime.date.today()

        v = Vulnerability.query.get(vhigh_id)
        v.status = 'closed'
        session.commit()

        histogram = SeveritiesHistogram.query.filter(SeveritiesHistogram.workspace == second_workspace).all()
        assert len(histogram) == 1
        assert histogram[0].workspace_id == second_workspace.id
        assert histogram[0].critical == 4
        assert histogram[0].high == 3
        assert histogram[0].confirmed == 3
        assert histogram[0].date == datetime.date.today()

        v = Vulnerability.query.get(vhigh_id)
        v.status = 'closed'
        session.commit()

        histogram = SeveritiesHistogram.query.filter(SeveritiesHistogram.workspace == second_workspace).all()
        assert len(histogram) == 1
        assert histogram[0].workspace_id == second_workspace.id
        assert histogram[0].critical == 4
        assert histogram[0].high == 3
        assert histogram[0].confirmed == 3
        assert histogram[0].date == datetime.date.today()

        v = Vulnerability.query.get(vhigh_id)
        v.status = 'open'
        v.confirmed = False
        session.commit()

        histogram = SeveritiesHistogram.query.filter(SeveritiesHistogram.workspace == second_workspace).all()
        assert len(histogram) == 1
        assert histogram[0].workspace_id == second_workspace.id
        assert histogram[0].critical == 4
        assert histogram[0].high == 4
        assert histogram[0].confirmed == 3
        assert histogram[0].date == datetime.date.today()

        v = Vulnerability.query.get(vhigh_id)
        v.status = 're-opened'
        v.confirmed = True
        session.commit()

        histogram = SeveritiesHistogram.query.filter(SeveritiesHistogram.workspace == second_workspace).all()
        assert len(histogram) == 1
        assert histogram[0].workspace_id == second_workspace.id
        assert histogram[0].critical == 4
        assert histogram[0].high == 4
        assert histogram[0].confirmed == 4
        assert histogram[0].date == datetime.date.today()

        v = Vulnerability.query.get(vhigh_id)
        v.status = 'risk-accepted'
        session.commit()

        histogram = SeveritiesHistogram.query.filter(SeveritiesHistogram.workspace == second_workspace).all()
        assert len(histogram) == 1
        assert histogram[0].workspace_id == second_workspace.id
        assert histogram[0].critical == 4
        assert histogram[0].high == 3
        assert histogram[0].confirmed == 3
        assert histogram[0].date == datetime.date.today()

        v = VulnerabilityWeb.query.get(vuln_web.id)
        v.status = 'closed'
        session.commit()

        histogram = SeveritiesHistogram.query.filter(SeveritiesHistogram.workspace == self.workspace).all()
        assert len(histogram) == 1
        assert histogram[0].workspace_id == self.workspace.id
        assert histogram[0].critical == 8
        assert histogram[0].medium == 0
        assert histogram[0].date == datetime.date.today()
        assert histogram[0].confirmed == 4

        v = VulnerabilityWeb.query.get(vuln_web.id)
        v.status = 'closed'
        session.commit()

        histogram = SeveritiesHistogram.query.filter(SeveritiesHistogram.workspace == self.workspace).all()
        assert len(histogram) == 1
        assert histogram[0].workspace_id == self.workspace.id
        assert histogram[0].critical == 8
        assert histogram[0].medium == 0
        assert histogram[0].date == datetime.date.today()
        assert histogram[0].confirmed == 4

        v = VulnerabilityWeb.query.get(vuln_web.id)
        v.status = 'open'
        session.commit()

        histogram = SeveritiesHistogram.query.filter(SeveritiesHistogram.workspace == self.workspace).all()
        assert len(histogram) == 1
        assert histogram[0].workspace_id == self.workspace.id
        assert histogram[0].critical == 8
        assert histogram[0].medium == 1
        assert histogram[0].date == datetime.date.today()
        assert histogram[0].confirmed == 5

        v = VulnerabilityWeb.query.get(vuln_web.id)
        v.status = 're-opened'
        session.commit()

        histogram = SeveritiesHistogram.query.filter(SeveritiesHistogram.workspace == self.workspace).all()
        assert len(histogram) == 1
        assert histogram[0].workspace_id == self.workspace.id
        assert histogram[0].critical == 8
        assert histogram[0].medium == 1
        assert histogram[0].date == datetime.date.today()
        assert histogram[0].confirmed == 5

        v = VulnerabilityWeb.query.get(vuln_web.id)
        v.status = 'risk-accepted'
        session.commit()

        histogram = SeveritiesHistogram.query.filter(SeveritiesHistogram.workspace == self.workspace).all()
        assert len(histogram) == 1
        assert histogram[0].workspace_id == self.workspace.id
        assert histogram[0].critical == 8
        assert histogram[0].medium == 0
        assert histogram[0].date == datetime.date.today()
        assert histogram[0].confirmed == 4

        v = VulnerabilityWeb.query.get(vuln_web.id)
        v.status = 'closed'
        session.commit()

        histogram = SeveritiesHistogram.query.filter(SeveritiesHistogram.workspace == self.workspace).all()
        assert len(histogram) == 1
        assert histogram[0].workspace_id == self.workspace.id
        assert histogram[0].critical == 8
        assert histogram[0].medium == 0
        assert histogram[0].date == datetime.date.today()
        assert histogram[0].confirmed == 4

        v = Vulnerability.query.get(vhigh_id)
        v.confirmed = False
        session.commit()

        histogram = SeveritiesHistogram.query.filter(SeveritiesHistogram.workspace == second_workspace).all()
        assert len(histogram) == 1
        assert histogram[0].workspace_id == second_workspace.id
        assert histogram[0].critical == 4
        assert histogram[0].high == 3
        assert histogram[0].confirmed == 3
        assert histogram[0].date == datetime.date.today()

        v = Vulnerability.query.get(vhigh_id)
        v.confirmed = True
        session.commit()

        histogram = SeveritiesHistogram.query.filter(SeveritiesHistogram.workspace == second_workspace).all()
        assert len(histogram) == 1
        assert histogram[0].workspace_id == second_workspace.id
        assert histogram[0].critical == 4
        assert histogram[0].high == 3
        assert histogram[0].confirmed == 3
        assert histogram[0].date == datetime.date.today()

        v = Vulnerability.query.get(vhigh_id)
        v.status = "re-opened"
        v.confirmed = True
        session.commit()

        histogram = SeveritiesHistogram.query.filter(SeveritiesHistogram.workspace == second_workspace).all()
        assert len(histogram) == 1
        assert histogram[0].workspace_id == second_workspace.id
        assert histogram[0].critical == 4
        assert histogram[0].high == 4
        assert histogram[0].confirmed == 4
        assert histogram[0].date == datetime.date.today()

        v = Vulnerability.query.get(vhigh_id)
        v.confirmed = False
        session.commit()

        histogram = SeveritiesHistogram.query.filter(SeveritiesHistogram.workspace == second_workspace).all()
        assert len(histogram) == 1
        assert histogram[0].workspace_id == second_workspace.id
        assert histogram[0].critical == 4
        assert histogram[0].high == 4
        assert histogram[0].confirmed == 3
        assert histogram[0].date == datetime.date.today()

        v = session.query(Vulnerability).filter(Vulnerability.id == vhigh_id).first()
        session.delete(v)
        session.commit()

        histogram = SeveritiesHistogram.query.filter(SeveritiesHistogram.workspace == second_workspace).all()
        assert len(histogram) == 1
        assert histogram[0].workspace_id == second_workspace.id
        assert histogram[0].critical == 4
        assert histogram[0].high == 3
        assert histogram[0].confirmed == 3
        assert histogram[0].date == datetime.date.today()

        Vulnerability.query.filter(Vulnerability.id.in_([vhigh2_id, vhigh3_id])).delete(synchronize_session=False)
        session.commit()

        histogram = SeveritiesHistogram.query.filter(SeveritiesHistogram.workspace == second_workspace).all()
        assert len(histogram) == 1
        assert histogram[0].workspace_id == second_workspace.id
        assert histogram[0].critical == 4
        assert histogram[0].high == 1
        assert histogram[0].confirmed == 1
        assert histogram[0].date == datetime.date.today()

        v = VulnerabilityWeb.query.get(vuln_web.id)
        v.status = 'open'
        session.commit()

        histogram = SeveritiesHistogram.query.filter(SeveritiesHistogram.workspace == self.workspace).all()
        assert len(histogram) == 1
        assert histogram[0].workspace_id == self.workspace.id
        assert histogram[0].critical == 8
        assert histogram[0].medium == 1
        assert histogram[0].date == datetime.date.today()
        assert histogram[0].confirmed == 5

        VulnerabilityWeb.query.filter(VulnerabilityWeb.id == vuln_web.id).delete()
        session.commit()

        histogram = SeveritiesHistogram.query.filter(SeveritiesHistogram.workspace == self.workspace).all()
        assert len(histogram) == 1
        assert histogram[0].workspace_id == self.workspace.id
        assert histogram[0].critical == 8
        assert histogram[0].medium == 0
        assert histogram[0].confirmed == 4
        assert histogram[0].date == datetime.date.today()

        Vulnerability.query.filter(Vulnerability.workspace == self.workspace,
                                   Vulnerability.status == 'open',
                                   Vulnerability.severity == 'critical',
                                   Vulnerability.confirmed == False).update({'status': 'closed'})  # noqa: E712
        session.commit()

        histogram = SeveritiesHistogram.query.filter(SeveritiesHistogram.workspace == self.workspace).all()
        assert len(histogram) == 1
        assert histogram[0].workspace_id == self.workspace.id
        assert histogram[0].critical == 4
        assert histogram[0].medium == 0
        assert histogram[0].date == datetime.date.today()
        assert histogram[0].confirmed == 4

        Vulnerability.query.filter(Vulnerability.workspace == self.workspace,
                                   Vulnerability.status == 'open',
                                   Vulnerability.severity == 'critical').update({'severity': 'medium'})
        session.commit()

        histogram = SeveritiesHistogram.query.filter(SeveritiesHistogram.workspace == self.workspace).all()
        assert len(histogram) == 1
        assert histogram[0].workspace_id == self.workspace.id
        assert histogram[0].critical == 0
        assert histogram[0].medium == 4
        assert histogram[0].date == datetime.date.today()
        assert histogram[0].confirmed == 4

        Vulnerability.query.filter(Vulnerability.workspace == self.workspace,
                                   Vulnerability.status == 'open',
                                   Vulnerability.severity == 'medium').update({'severity': 'critical', 'status': 'closed'})
        session.commit()

        histogram = SeveritiesHistogram.query.filter(SeveritiesHistogram.workspace == self.workspace).all()
        assert len(histogram) == 1
        assert histogram[0].workspace_id == self.workspace.id
        assert histogram[0].critical == 0
        assert histogram[0].medium == 0
        assert histogram[0].date == datetime.date.today()
        assert histogram[0].confirmed == 0

        Vulnerability.query.filter(Vulnerability.workspace == self.workspace,
                                   Vulnerability.status == 'closed',
                                   Vulnerability.severity == 'critical',
                                   Vulnerability.confirmed == True).update({'severity': 'medium', 'status': 're-opened'})  # noqa: E712
        session.commit()

        histogram = SeveritiesHistogram.query.filter(SeveritiesHistogram.workspace == self.workspace).all()
        assert len(histogram) == 1
        assert histogram[0].workspace_id == self.workspace.id
        assert histogram[0].critical == 0
        assert histogram[0].medium == 4
        assert histogram[0].date == datetime.date.today()
        assert histogram[0].confirmed == 4

    def test_create_cannot_create_vuln_with_empty_name_fails(
            self, host, session, test_client):
        # I'm using this to test the NonBlankColumn which works for
        # all models. Think twice before removing this test
        session.commit()  # flush host_with_hostnames
        raw_data = _create_post_data_vulnerability(
            name='',
            vuln_type='Vulnerability',
            parent_id=host.id,
            parent_type='Host',
            refs=[],
            policyviolations=[],
            description='aaa',
            severity='low',
        )
        res = test_client.post(self.url(), data=raw_data)
        assert res.status_code == 400
        assert b'Shorter than minimum length 1' in res.data

    def test_create_cannot_create_vuln_with_empty_fields(
            self, session, test_client):
        # I'm using this to test the NonBlankColumn which works for
        # all models. Think twice before removing this test
        session.commit()  # flush host_with_hostnames
        raw_data = _create_post_data_vulnerability(
            name='',
            vuln_type='',
            parent_id='',
            parent_type='',
            refs=[],
            policyviolations=[],
            description='',
            severity='',
        )
        res = test_client.post(self.url(), data=raw_data)
        assert res.status_code == 400

    def test_create_create_vuln_with_empty_desc_success(
            self, host, session, test_client):
        # I'm using this to test the NonBlankColumn which works for
        # all models. Think twice before removing this test
        session.commit()  # flush host_with_hostnames
        raw_data = _create_post_data_vulnerability(
            name='Empty desc',
            vuln_type='Vulnerability',
            parent_id=host.id,
            parent_type='Host',
            refs=[],
            policyviolations=[],
            description='',
            severity='low',
        )
        res = test_client.post(self.url(), data=raw_data)
        assert res.status_code == 201

    def test_create_vuln_with_attachments(self, host_with_hostnames, test_client, session):
        session.commit()  # flush host_with_hostnames
        attachment = NamedTemporaryFile(mode="wb+")
        file_content = b'test file'
        attachment.write(file_content)
        attachment.seek(0)
        raw_data = _create_post_data_vulnerability(
            name='New vulns',
            vuln_type='Vulnerability',
            parent_id=host_with_hostnames.id,
            parent_type='Host',
            refs=[],
            policyviolations=[],
            description='helloworld',
            severity='low',
            attachments=[attachment]
        )

        res = test_client.post(self.url(), data=raw_data)
        vuln_id = res.json['_id']
        assert res.status_code == 201
        filename = attachment.name.split('/')[-1]
        assert filename in res.json['_attachments']
        attachment.close()
        # check the attachment can be downloaded
        res = test_client.get(join(self.url(), f'{vuln_id}/attachment/{filename}'))
        assert res.status_code == 200
        assert res.data == file_content

        res = test_client.get(join(
            self.url(),
            f'{vuln_id}/attachment/notexistingattachment.png'
        ))
        assert res.status_code == 404

    @pytest.mark.usefixtures('ignore_nplusone')
    def test_update_vuln_add_attachment_on_update(self, test_client, session):
        host = HostFactory.create(workspace=self.workspace)
        vuln = VulnerabilityFactory.create(workspace=self.workspace, host_id=host.id)
        session.add(vuln)
        session.commit()  # flush host_with_hostnames
        attachment = NamedTemporaryFile()
        file_content = b'test file'
        attachment.write(file_content)
        attachment.seek(0)
        raw_data = self._create_put_data(
            'Updated with attachment',
            'Updated vuln',
            'open',
            host.id,
            'Host',
            attachments=[attachment]
        )
        res = test_client.put(self.url(obj=vuln, workspace=self.workspace), data=raw_data)
        assert res.status_code == 200
        filename = attachment.name.split('/')[-1]
        res = test_client.get(join(
            self.url(), f'{vuln.id}/attachment/{filename}'
        ))
        assert res.status_code == 200
        assert res.data == file_content

        new_attachment = NamedTemporaryFile()
        new_filename = new_attachment.name.split('/')[-1]
        file_content = b'new test file'
        new_attachment.write(file_content)
        new_attachment.seek(0)
        raw_data = self._create_put_data(
            'Updated with attachment',
            'Updated vuln',
            'open',
            host.id,
            'Host',
            attachments=[new_attachment]
        )
        res = test_client.put(self.url(obj=vuln, workspace=self.workspace),
                              data=raw_data)
        assert res.status_code == 200

        # verify that the old file was deleted and the new one exists
        res = test_client.get(join(
            self.url(), f'{vuln.id}/attachment/{filename}'
        ))
        assert res.status_code == 404
        res = test_client.get(join(
            self.url(), f'{vuln.id}/attachment/{new_filename}'
        ))
        assert res.status_code == 200
        assert res.data == file_content

    def test_get_attachments_by_vuln(self, test_client, session, workspace):
        vuln = VulnerabilityFactory.create(workspace=workspace)
        session.add(vuln)
        session.commit()
        png_file = Path(__file__).parent / 'data' / 'faraday.png'

        with open(png_file, 'rb') as file_obj:
            new_file = FaradayUploadedFile(file_obj.read())

        new_attach = File(object_type='vulnerability', object_id=vuln.id, name='Faraday', filename='faraday.png',
                          content=new_file)
        session.add(new_attach)
        session.commit()

        res = test_client.get(join(self.url(workspace=workspace), f'{vuln.id}/attachment'))
        assert res.status_code == 200
        assert new_attach.filename in res.json
        assert 'image/png' in res.json[new_attach.filename]['content_type']

    def test_create_vuln_props(self, host_with_hostnames, test_client, session):
        """
        This one should check all the vuln props that don't have a specific case
        :param host_with_hostnames:
        :param test_client:
        :param session:
        :return:
        """
        session.commit()  # flush host_with_hostnames
        vuln_props = {
            'confirmed': False,
            'data': 'hellodata',
            'easeofresolution': Vulnerability.EASE_OF_RESOLUTIONS[0],
            'owned': True,
            'resolution': 'helloresolution',
            'status': 'closed',
        }
        vuln_props_excluded = ['owned']
        raw_data = _create_post_data_vulnerability(
            name='New vulns',
            vuln_type='Vulnerability',
            parent_id=host_with_hostnames.id,
            parent_type='Host',
            refs=[],
            policyviolations=[],
            description='helloworld',
            severity='low',
            **vuln_props
        )
        ws = host_with_hostnames.workspace
        vuln_count_previous = session.query(Vulnerability).count()
        res = test_client.post(self.url(workspace=ws), data=raw_data)
        assert res.status_code == 201
        for prop, value in vuln_props.items():
            if prop not in vuln_props_excluded:
                assert res.json[prop] == value, prop

    def test_create_idempotent(self, host_with_hostnames, test_client, session):
        """
        This test makes sure that creating the same vuln twice doesn't duplicate the entry or has any other collateral effects
        :param host_with_hostnames:
        :param test_client:
        :param session:
        :return:
        """
        session.commit()  # flush host_with_hostnames
        raw_data = _create_post_data_vulnerability(
            name='Vulnerability name goes here',
            vuln_type='Vulnerability',
            parent_id=host_with_hostnames.id,
            parent_type='Host',
            refs=[],
            policyviolations=[],
            description='Description goes here',
            severity='critical',
        )
        ws = host_with_hostnames.workspace
        vuln_count_previous = session.query(Vulnerability).count()
        res = test_client.post(self.url(workspace=ws), data=raw_data)
        assert res.status_code == 201
        assert vuln_count_previous + 1 == session.query(Vulnerability).count()
        res = test_client.post(self.url(workspace=ws), data=raw_data)
        assert res.status_code == 409
        assert vuln_count_previous + 1 == session.query(Vulnerability).count()

    def test_create_vuln_with_closed_status(self, host_with_hostnames, test_client, session):
        session.commit()  # flush host_with_hostnames
        raw_data = _create_post_data_vulnerability(
            name='New vulns',
            vuln_type='Vulnerability',
            parent_id=host_with_hostnames.id,
            parent_type='Host',
            status='closed',
            refs=[],
            policyviolations=[]
        )
        ws = host_with_hostnames.workspace
        vuln_count_previous = session.query(Vulnerability).count()
        res = test_client.post(self.url(workspace=ws), data=raw_data)
        assert res.status_code == 201
        assert vuln_count_previous + 1 == session.query(Vulnerability).count()
        assert res.json['status'] == 'closed'
        assert res.json['name'] == 'New vulns'
        assert res.json['type'] == 'Vulnerability'
        assert res.json['parent'] == host_with_hostnames.id
        assert res.json['parent_type'] == 'Host'

    def _create_put_data(self,
                         name, desc, status, parent, parent_type,
                         attachments=None, impact=None, refs=[],
                         policy_violations=[], cve=[], cvss2={}, cvss3={}, cwe=[]):

        if not impact:
            impact = {"accountability": False, "availability": False, "confidentiality": False, "integrity": False}

        raw_data = {
            "_id": "e1b45f5375facfb1435d37e182ebc22de5f77bb3.e05df1c85617fffb575d2ced2679e9a0ebda7c3e",
            "metadata": {
                "update_time": 1509045001.279,
                "update_user": "",
                "update_action": 0,
                "creator": "UI Web",
                "create_time": 1509045001.279,
                "update_controller_action":
                    "UI Web New",
                "owner": ""},
            "obj_id": "e05df1c85617fffb575d2ced2679e9a0ebda7c3e",
            "owner": "",
            "parent": parent,
            "type": "Vulnerability",
            "ws": "cloud",
            "confirmed": True,
            "data": "",
            "desc": desc,
            "easeofresolution": None,
            "impact": impact,
            "name": name,
            "owned": False,
            "policyviolations": policy_violations,
            "refs": refs,
            "resolution": "",
            "severity": "critical",
            "status": status,
            "_attachments": {},
            "description": "",
            "parent_type": parent_type,
            "protocol": "",
            "version": "",
            "cve": cve,
            "cwe": cwe,
        }

        if attachments:
            raw_data['_attachments'] = {}
            for attachment in attachments:
                raw_data['_attachments'][attachment.name] = {
                    "content_type": "application/x-shellscript",
                    "data": b64encode(attachment.read()).decode()
                }

        return raw_data

    def test_update_vuln_from_open_to_close(self, test_client, session, host_with_hostnames):
        vuln = self.factory.create(status='open', host=host_with_hostnames, service=None,
                                   workspace=host_with_hostnames.workspace)
        session.commit()
        raw_data = self._create_put_data(
            name='New name',
            desc='New desc',
            status='closed',
            parent=vuln.host.id,
            parent_type='Host',
            refs=[{'name': 'ref1', 'type': 'exploit'}],
            policy_violations=['pv0']
        )
        vuln_count_previous = session.query(Vulnerability).count()
        res = test_client.put(self.url(vuln), data=raw_data)
        assert res.status_code == 200
        assert vuln_count_previous == session.query(Vulnerability).count()
        assert res.json['status'] == 'closed'
        assert res.json['name'] == 'New name'
        assert res.json['desc'] == 'New desc'

    def test_update_vuln_from_correct_type_to_incorrect(self, test_client, session, host_with_hostnames):
        vuln = self.factory.create(status='open', host=host_with_hostnames, service=None,
                                   workspace=host_with_hostnames.workspace)
        session.commit()
        raw_data = self._create_put_data(
            name='New name',
            desc='New desc',
            status='open',
            parent=vuln.host.id,
            parent_type='Host',
            refs=['ref1'],
            policy_violations=['pv0']
        )
        raw_data['type'] = "ASDADADASD"
        vuln_count_previous = session.query(Vulnerability).count()
        res = test_client.put(self.url(vuln), data=raw_data)
        assert res.status_code in [400, 409]
        assert vuln_count_previous == session.query(Vulnerability).count()

    def test_update_vuln_cve(self, test_client, session, host_with_hostnames):
        vuln = self.factory.create(status='open', cve=['CVE-2021-1234'], host=host_with_hostnames, service=None,
                                   workspace=host_with_hostnames.workspace)
        session.add(vuln)
        session.commit()

        vuln = self.factory.create(status='open', cve=['CVE-2021-1234'], host=host_with_hostnames, service=None,
                                   workspace=host_with_hostnames.workspace)
        session.add(vuln)
        session.commit()

        raw_data = self._create_put_data(
            name='New name',
            desc='New desc',
            status='open',
            parent=vuln.host.id,
            parent_type='Host',
            policy_violations=['pv0'],
            cve=['cve-2021-1234']
        )
        vuln_count_previous = session.query(CVE).count()
        assert vuln_count_previous == 1
        res = test_client.put(self.url(vuln), data=raw_data)
        assert res.status_code == 200
        assert vuln_count_previous == session.query(CVE).count()

    def test_update_vuln_cwe(self, test_client, session, host_with_hostnames):
        v1 = self.factory.create(status='open', host=host_with_hostnames, service=None,
                                   workspace=host_with_hostnames.workspace)
        v1.cwe = [CWE(name='CWE-123'), CWE(name='CWE-124')]
        session.add(v1)
        session.commit()

        v2 = self.factory.create(status='open', host=host_with_hostnames, service=None,
                                   workspace=host_with_hostnames.workspace)
        v2.cwe = [CWE(name='CWE-890'), CWE(name='cwe-999')]
        session.add(v2)
        session.commit()

        raw_data = self._create_put_data(
            name='New name',
            desc='New desc',
            status='open',
            parent=v1.host.id,
            parent_type='Host',
            policy_violations=['pv0'],
            cwe=['CWE-189']
        )
        vuln_count_previous = session.query(CWE).count()
        assert vuln_count_previous == 4
        res = test_client.put(self.url(v1), data=raw_data)
        assert res.status_code == 200
        assert len(res.json['cwe']) == 1
        assert res.json['cwe'][0] == 'CWE-189'
        current_cwes = session.query(CWE).count()
        assert current_cwes == vuln_count_previous + 1

    def test_create_vuln_web(self, host_with_hostnames, test_client, session):
        service = ServiceFactory.create(host=host_with_hostnames, workspace=host_with_hostnames.workspace)
        session.commit()  # flush host_with_hostnames
        raw_data = _create_post_data_vulnerability(
            name='New vulns',
            vuln_type='VulnerabilityWeb',
            parent_id=service.id,
            parent_type='Service',
            refs=[],
            policyviolations=[]
        )
        ws = host_with_hostnames.workspace
        vuln_count_previous = session.query(Vulnerability).count()
        vuln_web_count_previous = session.query(VulnerabilityWeb).count()
        res = test_client.post(self.url(workspace=ws), data=raw_data)
        assert res.status_code == 201
        assert vuln_web_count_previous + 1 == session.query(VulnerabilityWeb).count()
        assert vuln_count_previous == session.query(Vulnerability).count()
        assert res.json['name'] == 'New vulns'
        assert res.json['owner'] == 'test'
        assert res.json['type'] == 'VulnerabilityWeb'
        assert res.json['parent'] == service.id
        assert res.json['parent_type'] == 'Service'
        assert res.json['method'] == 'GET'
        assert res.json['path'] == '/pepep'

    @pytest.mark.parametrize('param_name', ['query', 'query_string'])
    @pytest.mark.usefixtures('mock_envelope_list')
    def test_filter_by_querystring(
            self, test_client, session, second_workspace,
            vulnerability_web_factory, param_name):
        # VulnerabilityFilterSet has duplicate fields with the same function.
        # This was designed to maintain backwards compatibility

        VulnerabilityGeneric.query.delete(synchronize_session='fetch')

        # Vulns that shouldn't be shown
        not_expected = vulnerability_web_factory.create_batch(
            5, workspace=second_workspace, query_string='aaa')

        # Vulns that must be shown
        expected_vulns = vulnerability_web_factory.create_batch(
            5, workspace=second_workspace, query_string='bbb')
        session.add_all(not_expected)
        session.add_all(expected_vulns)
        session.commit()
        expected_ids = {vuln.id for vuln in expected_vulns}

        res = test_client.get(urljoin(
            self.url(workspace=second_workspace), f'?{param_name}=bbb'))
        assert res.status_code == 200

        for vuln in res.json['data']:
            assert vuln['query'] == 'bbb'
        assert {vuln['_id'] for vuln in res.json['data']} == expected_ids

    @pytest.mark.usefixtures('mock_envelope_list')
    @pytest.mark.parametrize('medium_name', ['medium', 'med'])
    def test_filter_by_severity(self, test_client, session,
                                second_workspace,
                                vulnerability_factory,
                                vulnerability_web_factory,
                                medium_name,
                                ):
        expected_ids = set()

        vulns = vulnerability_factory.create_batch(
            5, workspace=second_workspace, severity='high')
        vulns += vulnerability_web_factory.create_batch(
            5, workspace=second_workspace, severity='high')

        medium_vulns = vulnerability_factory.create_batch(
            5, workspace=second_workspace, severity='medium')
        medium_vulns_web = vulnerability_web_factory.create_batch(
            5, workspace=second_workspace, severity='medium')
        session.add_all(vulns)
        session.add_all(medium_vulns + medium_vulns_web)
        session.commit()
        expected_ids.update(vuln.id for vuln in medium_vulns)
        expected_ids.update(vuln.id for vuln in medium_vulns_web)

        res = test_client.get(urljoin(self.url(
            workspace=second_workspace), f'?severity={medium_name}'))
        assert res.status_code == 200
        for vuln in res.json['data']:
            assert vuln['severity'] == 'med'
        assert {vuln['_id'] for vuln in res.json['data']} == expected_ids

    def test_filter_by_invalid_severity_fails(self, test_client):
        res = test_client.get(urljoin(self.url(), '?severity=131231'))
        assert res.status_code == 400
        assert b'Invalid severity type' in res.data

    @pytest.mark.usefixtures('mock_envelope_list')
    def test_filter_by_invalid_severity(self, test_client):
        res = test_client.get(urljoin(self.url(), '?severity=invalid'))
        assert res.status_code == 400

    @pytest.mark.usefixtures('mock_envelope_list')
    def test_filter_by_method(self, test_client, session, second_workspace,
                              vulnerability_factory,
                              vulnerability_web_factory):

        # Vulns that shouldn't be shown
        vuln_second_workspace = vulnerability_factory.create_batch(5, workspace=second_workspace)
        more_vuln_second_workspace = vulnerability_web_factory.create_batch(5, workspace=second_workspace,
                                                                            method='POSTT')

        # Vulns that must be shown
        expected_vulns = vulnerability_web_factory.create_batch(
            5, workspace=second_workspace, method='POST')

        session.add_all(vuln_second_workspace)
        session.add_all(more_vuln_second_workspace)
        session.add_all(expected_vulns)
        session.commit()
        expected_ids = {vuln.id for vuln in expected_vulns}

        # This shouldn't show any vulns with POSTT method
        res = test_client.get(urljoin(self.url(
            workspace=second_workspace), '?method=POST'))
        assert res.status_code == 200
        assert {vuln['_id'] for vuln in res.json['data']} == expected_ids, "This may fail because no presence of " \
                                                                           "filter_alchemy branch"

        # This shouldn't show any vulns since by default method filter is
        # an exact match, not a like statement
        res = test_client.get(urljoin(self.url(
            workspace=second_workspace), '?method=%25POST%25'))
        assert res.status_code == 200
        assert len(res.json['data']) == 0

    @pytest.mark.usefixtures('mock_envelope_list')
    def test_filter_by_website(self, test_client, session,
                               second_workspace,
                               vulnerability_factory,
                               vulnerability_web_factory,
                               ):

        # Vulns that shouldn't be shown
        second_workspace_vulns = vulnerability_factory.create_batch(5, workspace=second_workspace)
        second_workspace_more_vulns = vulnerability_web_factory.create_batch(
            5, workspace=second_workspace, website='other.com')

        # Vulns that must be shown
        expected_vulns = vulnerability_web_factory.create_batch(
            5, workspace=second_workspace, website='faradaysec.com')
        session.add_all(second_workspace_vulns)
        session.add_all(second_workspace_more_vulns)
        session.add_all(expected_vulns)
        session.commit()
        expected_ids = {vuln.id for vuln in expected_vulns}

        res = test_client.get(urljoin(self.url(
            workspace=second_workspace), '?website=faradaysec.com'))
        assert res.status_code == 200

        for vuln in res.json['data']:
            assert vuln['website'] == 'faradaysec.com'
        assert {vuln['_id'] for vuln in res.json['data']} == expected_ids

    @pytest.mark.usefixtures('mock_envelope_list')
    def test_filter_by_target(self, test_client, session, host_factory,
                              service_factory, vulnerability_factory,
                              vulnerability_web_factory):

        # Change setting
        test_client.patch('/v3/settings/query_limits', data={"vuln_query_limit": 0})

        host = host_factory.create(workspace=self.workspace,
                                   ip='9.9.9.9')
        expected_ids = set()

        host_vulns = vulnerability_factory.create_batch(
            10, workspace=self.workspace, host=host, service=None)
        session.flush()
        expected_ids.update(v.id for v in host_vulns)

        for service in service_factory.create_batch(10,
                                                    workspace=self.workspace,
                                                    host=host):
            service_vuln = vulnerability_factory.create(
                workspace=self.workspace, service=service, host=None)
            web_vuln = vulnerability_web_factory.create(
                workspace=self.workspace, service=service)
            session.flush()
            expected_ids.add(service_vuln.id)
            expected_ids.add(web_vuln.id)

        res = test_client.get(urljoin(self.url(), '?target=9.9.9.9'))
        assert res.status_code == 200
        for vuln in res.json['data']:
            assert vuln['target'] == '9.9.9.9'
        assert {vuln['_id'] for vuln in res.json['data']} == expected_ids

    @pytest.mark.usefixtures('ignore_nplusone')
    @pytest.mark.parametrize('filter_params', [
        {
            'test_name': 'filter_by_target',
            'filter_field_name': 'target',
            'filter_operations': [
                {
                    'filter_operation': 'eq',
                    'filter_value': '"192.168.0.1"',
                    'res_status_code': 200,
                    'count': 10
                }
            ],
            'order_operations': ORDER,
            'group_operations': GROUP,
        },
        {
            'test_name': 'filter_by_target_host_ip',  # Habria que sacar esto ya que esta por target :|
            'filter_field_name': 'target',
            'filter_operations': [
                {
                    'filter_operation': 'eq',
                    'filter_value': '"192.168.0.1"',
                    'res_status_code': 200,
                    'count': 10
                }
            ],
            'order_operations': ORDER,
            'group_operations': GROUP,
        },
        {
            'test_name': 'test_filter_restless_by_service_port',
            'filter_field_name': 'service',
            'filter_operations': [
                {
                    'filter_operation': 'has',
                    'filter_value': '{"name": "port", "op": "eq", "val": "8956"}',
                    'res_status_code': 200,
                    'count': 8
                }
            ],
            'order_operations': ORDER,
            'group_operations': GROUP,
        },
        {
            'test_name': 'test_filter_restless_by_service_name',
            'filter_field_name': 'service',
            'filter_operations': [
                {
                    'filter_operation': 'has',
                    'filter_value': '{"name": "name", "op": "eq", "val": "ssh"}',
                    'res_status_code': 200,
                    'count': 1
                }
            ],
            'order_operations': ORDER,
            'group_operations': GROUP,
        },
        {
            'test_name': 'filter_by_name',
            'filter_field_name': 'name',
            'filter_operations': [
                {
                    'filter_operation': 'eq',
                    'filter_value': '"test_vuln1"',
                    'res_status_code': 200,
                    'count': 1
                },
                {
                    'filter_operation': 'like',
                    'filter_value': '"test_vuln%"',
                    'res_status_code': 200,
                    'count': 2
                },
                {
                    'filter_operation': 'ilike',
                    'filter_value': '"%TEST_VULN%"',
                    'res_status_code': 200,
                    'count': 2
                }
            ],
            'order_operations': ORDER,
            'group_operations': GROUP,
        },
        {
            'test_name': 'filter_by_severity',
            'filter_field_name': 'severity',
            'filter_operations': [
                {
                    'filter_operation': 'eq',
                    'filter_value': '"high"',
                    'res_status_code': 200,
                    'count': 1
                },
                {
                    'filter_operation': 'eq',
                    'filter_value': '"medium"',
                    'res_status_code': 200,
                    'count': 8
                },
                {
                    'filter_operation': 'eq',
                    'filter_value': '"informational"',
                    'res_status_code': 200,
                    'count': 10
                }
            ],
            'order_operations': ORDER,
            'group_operations': GROUP,
        },
        {
            'test_name': 'filter_by_status',
            'filter_field_name': 'status',
            'filter_operations': [
                {
                    'filter_operation': 'eq',
                    'filter_value': '"open"',
                    'res_status_code': 200,
                    'count': 0
                },
                {
                    'filter_operation': 'eq',
                    'filter_value': '"closed"',
                    'res_status_code': 200,
                    'count': 11
                },
                {
                    'filter_operation': 'eq',
                    'filter_value': '"re-opened"',
                    'res_status_code': 200,
                    'count': 1
                },
                {
                    'filter_operation': 'eq',
                    'filter_value': '"risk-accepted"',
                    'res_status_code': 200,
                    'count': 8
                },
            ],
            'order_operations': ORDER,
            'group_operations': GROUP,
        },

    ])
    def test_filter_restless_react_confirmed(self, test_client, session, workspace, host_factory, vulnerability_web_factory, vulnerability_factory, service_factory, filter_params):

        Vulnerability.query.delete()
        host = host_factory.create(workspace=workspace, ip="192.168.0.2")
        host_vulns = vulnerability_factory.create_batch(
            1, severity="high", name="test_vuln1", status="closed", workspace=self.workspace, host=host, service=None)

        host2 = host_factory.create(workspace=workspace, ip="192.168.0.1")
        host_vulns2 = vulnerability_factory.create_batch(
            10, severity="informational", workspace=self.workspace, host=host2, status="closed", service=None)

        service = service_factory.create(port=9098, name="ssh", workspace=self.workspace)
        vulns = vulnerability_factory.create_batch(
            1, name="test_vuln2", severity="low", workspace=self.workspace, status="re-opened", service=service, host=None)

        service = service_factory.create(port=8956, name="443", workspace=self.workspace)

        vulns_web = vulnerability_web_factory.create_batch(
            8, workspace=self.workspace, host=None, service=service, status="risk-accepted", severity='medium')

        session.commit()
        for operation in filter_params['filter_operations']:

            # With no order by
            qparams = f'filter?q={{"filters":[' \
                      f'{{"name": "{filter_params["filter_field_name"]}", ' \
                      f'"op":"{operation["filter_operation"]}",' \
                      f'"val": {operation["filter_value"]} }}]}}'

            res = test_client.get(join(self.url(), qparams))

            assert res.status_code == operation['res_status_code']
            assert len(res.json['vulnerabilities']) == operation['count']

            for order_ops in filter_params['order_operations']:
                orderparams = '"order_by": ['
                separator = ""
                for order in order_ops:
                    orderparams = f'{orderparams}{separator}{{"field": "{order["field"]}", "direction": "{order["direction"]}"}}'
                    separator = ','
                orderparams = f'{orderparams}]'

                qparams = f'filter?q={{"filters":[' \
                          f'{{"name": "{filter_params["filter_field_name"]}", ' \
                          f'"op":"{operation["filter_operation"]}",' \
                          f'"val": {operation["filter_value"]} }}], {orderparams} }}'
                res = test_client.get(join(self.url(), qparams))

                assert res.status_code == operation['res_status_code']
                assert len(res.json['vulnerabilities']) == operation['count']

            for group_ops in filter_params['group_operations']:
                groupparams = '"group_by": ['
                separator = ""
                for group in group_ops:
                    groupparams = f'{groupparams}{separator}{{"field": "{group["field"]}"}}'
                    separator = ','
                groupparams = f'{groupparams}]'

                qparams = f'filter?q={{"filters":[' \
                          f'{{"name": "{filter_params["filter_field_name"]}", ' \
                          f'"op":"{operation["filter_operation"]}",' \
                          f'"val": {operation["filter_value"]} }}], {groupparams} }}'
                res = test_client.get(join(self.url(), qparams))

                assert res.status_code == 200

    @pytest.mark.usefixtures('mock_envelope_list')
    def test_sort_by_method(self, session, test_client, second_workspace,
                            vulnerability_factory, vulnerability_web_factory):
        vulns = vulnerability_factory.create_batch(
            10, workspace=second_workspace
        )
        vulns += vulnerability_web_factory.create_batch(
            10, workspace=second_workspace, method=None
        )
        session.add_all(vulns)
        session.commit()
        for method in ('afjbeidcgh'):
            vulnerability_web_factory.create(workspace=second_workspace,
                                             method=method)

        session.commit()
        res = test_client.get(self.url(workspace=second_workspace)
                              + '?sort=method&sort_dir=asc')
        assert res.status_code == 200, res.data
        assert len(res.json['data']) == 30
        assert ''.join(v['method'] for v in res.json['data']
                       if v['method']) == 'abcdefghij'

        res = test_client.get(self.url(workspace=second_workspace)
                              + '?sort=method&sort_dir=desc')
        assert res.status_code == 200, res.data
        assert len(res.json['data']) == 30
        assert ''.join(v['method'] for v in res.json['data']
                       if v['method']) == 'abcdefghij'[::-1]

    def test_create_vuln_with_evidence(self, host_with_hostnames, test_client,
                                       session):
        session.commit()  # flush host_with_hostnames
        attachments = [
            (TEST_DATA_PATH / 'faraday.png').open('rb'),
            (TEST_DATA_PATH / 'test.html').open('rb')
        ]
        raw_data = _create_post_data_vulnerability(
            name='New vulns',
            vuln_type='Vulnerability',
            parent_id=host_with_hostnames.id,
            parent_type='Host',
            refs=[],
            policyviolations=[],
            attachments=attachments,
        )
        ws = host_with_hostnames.workspace
        vuln_count_previous = session.query(Vulnerability).count()
        res = test_client.post(self.url(workspace=ws), data=raw_data)

        assert res.status_code == 201
        assert len(res.json['_attachments']) == 2
        assert vuln_count_previous + 1 == session.query(Vulnerability).count()
        [fileobj.close() for fileobj in attachments]

    @pytest.mark.parametrize('cve_list', [
        {
            'cve': {'data': ['cve-2017-0002', 'CVE-2017-0012', 'CVE-2017-0012'], 'count': 2}
        },
        {
            'cve': {'data': [], 'count': 0}
        },
        {
            'cve': {'data': ['cve-2017-0003', 'CVE-2017-0012', 'CVE-2017-0012'], 'count': 2}
        },
        {
            'cve': {'data': ['asdf-2017-0003', 'CVE-2017-0012', 'CVE-2017-0013'], 'count': 2}
        },
        {
            'cve': {'data': ['CVE-2017-0003, CVE-2017-0012', 'CVE-2017-0013'], 'count': 3}
        },
    ])
    def test_create_vuln_with_cve(self, cve_list, host_with_hostnames, test_client, session):
        session.commit()  # flush host_with_hostnames
        raw_data = _create_post_data_vulnerability(
            name='New vulns',
            vuln_type='Vulnerability',
            parent_id=host_with_hostnames.id,
            parent_type='Host',
            refs=[],
            cve=cve_list['cve']['data'],
            policyviolations=[]
        )
        ws = host_with_hostnames.workspace
        vuln_count_previous = session.query(Vulnerability).count()
        res = test_client.post(self.url(workspace=ws), data=raw_data)
        assert res.status_code == 201
        assert session.query(CVE).count() == cve_list['cve']['count']
        assert vuln_count_previous + 1 == session.query(Vulnerability).count()

    @pytest.mark.usefixtures("ignore_nplusone")
    def test_filter_vulns_not_contains_cve(self, test_client, session, host, vulnerability_factory,
                                           vulnerability_web_factory):
        VulnerabilityGeneric.query.delete()
        session.commit()

        cve1 = CVE(name="CVE-2014-0160")
        session.add(cve1)

        cve2 = CVE(name="CVE-2014-0161")
        session.add(cve2)

        session.commit()

        vuln = vulnerability_factory.create(name="first_cve", host=host, workspace=self.workspace)
        vuln.cve = [cve1.name]
        session.add(vuln)

        vuln = vulnerability_factory.create(name="with_both_cve", host=host, workspace=self.workspace)
        vuln.cve = [cve1.name, cve2.name]
        session.add(vuln)

        vuln_web = vulnerability_web_factory.create(name="second_cve", host=host, workspace=self.workspace)
        vuln_web.cve = [cve2.name]
        session.add(vuln_web)

        vuln_web = vulnerability_web_factory.create(name="with_no_cve", host=host, workspace=self.workspace)
        session.add(vuln_web)
        session.commit()

        data = {
            'q': '{"filters":[{"name":"cve_instances","op":"not_any","val":{"name":"name","op":"eq","val":"CVE-2014-0160"}}]}'
        }
        res = test_client.get(f'/v3/ws/{self.workspace.name}/vulns/filter', query_string=data)

        assert res.status_code == 200
        assert len(res.json['vulnerabilities']) == 2
        assert 'first_cve' not in res.json['vulnerabilities'][0]['value']['name']
        assert 'first_cve' not in res.json['vulnerabilities'][1]['value']['name']

    # TODO: is this repeated?
    def test_patch_vuln_with_cve_list(self, host_with_hostnames, test_client, session):
        session.commit()  # flush host_with_hostnames
        raw_data = _create_post_data_vulnerability(
            name='New vulns',
            vuln_type='Vulnerability',
            parent_id=host_with_hostnames.id,
            parent_type='Host',
            refs=[],
            cve=['CVE-2017-0002', 'CVE-2017-0012', 'CVE-2017-0012'],
            policyviolations=[]
        )
        ws = host_with_hostnames.workspace
        res = test_client.post(self.url(workspace=ws), data=raw_data)
        assert res.status_code == 201

        new_cve_list = ['CVE-2017-0001']
        res = test_client.patch(f'{self.url(res.json["_id"], workspace=ws)}', data={'cve': new_cve_list})
        assert res.status_code == 200
        assert set(res.json['cve']) == set(new_cve_list)

    def test_create_vuln_and_get_cve_list(self, host_with_hostnames, test_client, session):
        session.commit()  # flush host_with_hostnames
        raw_data = _create_post_data_vulnerability(
            name='New vulns',
            vuln_type='Vulnerability',
            parent_id=host_with_hostnames.id,
            parent_type='Host',
            refs=[],
            cve=['CVE-2017-0002', 'CVE-2017-0012', 'CVE-2017-0012'],
            policyviolations=[]
        )
        ws = host_with_hostnames.workspace
        res = test_client.post(self.url(workspace=ws), data=raw_data)
        assert res.status_code == 201
        assert len(res.json['cve']) == 2

    def test_create_vuln_with_malformed_cve_list(self, host_with_hostnames, test_client, session):
        session.commit()  # flush host_with_hostnames
        raw_data = _create_post_data_vulnerability(
            name='New vulns',
            vuln_type='Vulnerability',
            parent_id=host_with_hostnames.id,
            parent_type='Host',
            refs=[],
            cve=['CVE-2017-0002', 'CVE-2017-0X12', 'CVE-2017-0012'],
            policyviolations=[]
        )
        ws = host_with_hostnames.workspace
        res = test_client.post(self.url(workspace=ws), data=raw_data)
        assert res.status_code == 201
        assert len(res.json['cve']) == 2
        assert set(res.json['cve']) == {'CVE-2017-0002', 'CVE-2017-0012'}

    def test_create_vuln_with_policyviolations(self, host_with_hostnames, test_client, session):
        session.commit()  # flush host_with_hostnames
        raw_data = _create_post_data_vulnerability(
            name='New vulns',
            vuln_type='Vulnerability',
            parent_id=host_with_hostnames.id,
            parent_type='Host',
            refs=[],
            policyviolations=['PCI DSS Credir card not encrypted',
                              'PCI DSS Credir card not encrypted'],
        )
        ws = host_with_hostnames.workspace
        vuln_count_previous = session.query(Vulnerability).count()
        res = test_client.post(self.url(workspace=ws), data=raw_data)
        assert res.status_code == 201
        assert session.query(PolicyViolation).count() == 1
        assert vuln_count_previous + 1 == session.query(Vulnerability).count()

    @pytest.mark.parametrize('cvss', [
        {
            'version': 'cvss2',
            'vector': 'AV:L/AC:M/Au:N/C:P/I:P/A:C',
            'base_score': 5.9,
            'impact_score': 8.5,
            'exploitability_score': 3.4,
            'temporal_score': None,
            'environmental_score': None,
        },
        {
            'version': 'cvss3',
            'vector': 'CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:C/C:H/I:H/A:H',
            'base_score': 8.0,
            'temporal_score': 8.0,
            'impact_score': 6.1,
            'exploitability_score': 1.3,
            'environmental_score': 8.1,  # There is a difference between first.org and nvd. Nvd result is 8.0
        },
        {
            'version': 'cvss3',
            'vector': 'CVSS:3.1/AV:P/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:L',
            'base_score': 3.7,
            'temporal_score': 3.7,
            'environmental_score': 3.7,
            'impact_score': 2.8,
            'exploitability_score': 0.7,
        },
        {
            'version': 'cvss3',
            'vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N',
            'base_score': 0.0,
            'temporal_score': 0.0,
            'environmental_score': 0.0,
            'impact_score': 0.0,
            'exploitability_score': 3.9,
        },
        {
            'version': 'cvss3',
            'vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/E:U/RL:T/RC:C/CR:H/IR:M/AR:M/MAV:A/MAC:H/MPR:L/MUI:R/MS:U/MC:X/MI:L/MA:H',
            'base_score': 0.0,
            'temporal_score': 0.0,
            'environmental_score': 4.5,
            'impact_score': 0.0,
            'exploitability_score': 3.9  # 3.7 ,
        },
        {
            'version': 'cvss3',
            'vector': 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:L/E:U/RL:T/RC:C/CR:H/IR:M/AR:M/MAV:A/MAC:H/MPR:L/MUI:R/MS:U/MC:X/MI:L/MA:H',
            'base_score': 8.7,
            'temporal_score': 7.7,
            'environmental_score': 6.0,
            'impact_score': 6.0,
            'exploitability_score': 2.1,  # 2.5
        },
        {
            'version': 'cvss3',
            'vector': 'CVSS:3.1/AV:A/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:H/E:U/RL:T/RC:C/CR:L/IR:H/AR:M/MAV:N/MAC:L/MPR:L/MUI:R/MS:U/MC:X/MI:L/MA:N',
            'base_score': 5.6,
            'temporal_score': 4.9,
            'environmental_score': 4.2,
            'impact_score': 4.8,
            'exploitability_score': 0.9,
        },
        {
            'version': 'cvss3',
            'vector': 'CVSS:3.1/AV:A/AC:H/PR:H/UI:R/S:U/C:H/I:H/A:H/E:H/RL:W/RC:R',
            'base_score': 6.3,
            'temporal_score': 5.9,
            'environmental_score': 5.9,
            'impact_score': 5.9,
            'exploitability_score': 0.4,
        },
        {
            'version': 'cvss4',
            'vector': 'CVSS:4.0/AV:A/AC:L/AT:P/PR:L/UI:A/VC:L/VI:H/VA:L/SC:L/SI:H/SA:L',
            'base_score': 5.9
        }
    ])
    def test_create_vuln_with_cvss_scores(self, host_with_hostnames, test_client, session, cvss):
        session.commit()  # flush host_with_hostnames
        cvss2 = {}
        cvss3 = {}
        cvss4 = {}
        if cvss['version'] == 'cvss2':
            cvss2 = {'vector_string': cvss['vector']}
        elif cvss['version'] == 'cvss3':
            cvss3 = {'vector_string': cvss['vector']}
        else:
            cvss4 = {'vector_string': cvss['vector']}

        raw_data = _create_post_data_vulnerability(
            name='New vulns',
            vuln_type='Vulnerability',
            parent_id=host_with_hostnames.id,
            parent_type='Host',
            policyviolations=[],
            refs=[],
            cvss2=cvss2,
            cvss3=cvss3,
            cvss4=cvss4,
        )
        ws = host_with_hostnames.workspace
        res = test_client.post(self.url(workspace=ws), data=raw_data)
        assert res.status_code == 201

        assert res.json[cvss['version']] is not None
        if cvss['version'] == 'cvss4':
            assert res.json[cvss['version']]['base_score'] == cvss['base_score']
        else:
            assert res.json[cvss['version']]['base_score'] == cvss['base_score']
            assert res.json[cvss['version']]['temporal_score'] == cvss['temporal_score']
            assert res.json[cvss['version']]['environmental_score'] == cvss['environmental_score']
            assert res.json[cvss['version']]['impact_score'] == cvss['impact_score']
            assert res.json[cvss['version']]['exploitability_score'] == cvss['exploitability_score']
        if cvss3:
            vuln = VulnerabilityGeneric.query.with_entities(VulnerabilityGeneric.cvss3_scope)\
                .filter(VulnerabilityGeneric.id == res.json['obj_id']).first()
            assert vuln is not None
            assert vuln.cvss3_scope == CVSS3(cvss3['vector_string']).get_value_description('S').lower()

    def test_create_vuln_with_cvss_only_mandatory(self, host_with_hostnames, test_client, session):
        session.commit()  # flush host_with_hostnames
        cvss2 = {'vector_string': 'AV:L/AC:L/Au:M/C:N/I:P/A:C'}
        cvss3 = {'vector_string': 'CVSS:3.0/S:C/C:H/I:H/A:N/AV:P/AC:H/PR:H/UI:R'}
        cvss4 = {'vector_string': 'CVSS:4.0/AV:A/AC:H/AT:P/PR:L/UI:A/VC:L/VI:H/VA:L/SC:H/SI:L/SA:H'}
        raw_data = _create_post_data_vulnerability(
            name='New vulns',
            vuln_type='Vulnerability',
            parent_id=host_with_hostnames.id,
            parent_type='Host',
            policyviolations=[],
            refs=[],
            cvss2=cvss2,
            cvss3=cvss3,
            cvss4=cvss4,
        )
        ws = host_with_hostnames.workspace
        res = test_client.post(self.url(workspace=ws), data=raw_data)
        assert res.status_code == 201

        assert res.json['cvss2'] is not None
        assert res.json['cvss2']['base_score'] == 5.0
        assert res.json['cvss2']['base_severity'] == 'medium'
        assert res.json['cvss2']['temporal_severity'] is None
        assert res.json['cvss2']['temporal_score'] is None
        assert res.json['cvss2']['environmental_score'] is None
        assert res.json['cvss2']['environmental_severity'] is None
        assert res.json['cvss2']['access_vector'] == 'local'
        assert res.json['cvss2']['access_complexity'] == 'low'
        assert res.json['cvss2']['authentication'] == 'multiple'
        assert res.json['cvss2']['confidentiality_impact'] == 'none'
        assert res.json['cvss2']['integrity_impact'] == 'partial'
        assert res.json['cvss2']['availability_impact'] == 'complete'
        assert res.json['cvss2']['exploitability'] is None
        assert res.json['cvss2']['remediation_level'] is None
        assert res.json['cvss2']['report_confidence'] is None
        assert res.json['cvss2']['collateral_damage_potential'] is None
        assert res.json['cvss2']['target_distribution'] is None
        assert res.json['cvss2']['confidentiality_requirement'] is None
        assert res.json['cvss2']['integrity_requirement'] is None
        assert res.json['cvss2']['availability_requirement'] is None

        assert res.json['cvss3'] is not None
        assert res.json['cvss3']['base_score'] == 6.5
        assert res.json['cvss3']['temporal_score'] == 6.5
        assert res.json['cvss3']['environmental_score'] == 6.5
        assert res.json['cvss3']['attack_vector'] == 'physical'
        assert res.json['cvss3']['attack_complexity'] == 'high'
        assert res.json['cvss3']['privileges_required'] == 'high'
        assert res.json['cvss3']['user_interaction'] == 'required'
        assert res.json['cvss3']['confidentiality_impact'] == 'high'
        assert res.json['cvss3']['integrity_impact'] == 'high'
        assert res.json['cvss3']['availability_impact'] == 'none'
        assert res.json['cvss3']['scope'] == 'changed'
        assert res.json['cvss3']['exploit_code_maturity'] is None
        assert res.json['cvss3']['remediation_level'] is None
        assert res.json['cvss3']['report_confidence'] is None
        assert res.json['cvss3']['confidentiality_requirement'] is None
        assert res.json['cvss3']['integrity_requirement'] is None
        assert res.json['cvss3']['availability_requirement'] is None
        assert res.json['cvss3']['modified_attack_vector'] is None
        assert res.json['cvss3']['modified_attack_complexity'] is None
        assert res.json['cvss3']['modified_privileges_required'] is None
        assert res.json['cvss3']['modified_user_interaction'] is None
        assert res.json['cvss3']['modified_scope'] is None
        assert res.json['cvss3']['modified_confidentiality_impact'] is None
        assert res.json['cvss3']['modified_integrity_impact'] is None
        assert res.json['cvss3']['modified_availability_impact'] is None

        assert res.json['cvss4'] is not None
        assert res.json['cvss4']['base_score'] == 6.0
        assert res.json['cvss4']['base_severity'] == 'medium'
        assert res.json['cvss4']['attack_vector'] == 'adjacent'
        assert res.json['cvss4']['attack_complexity'] == 'high'
        assert res.json['cvss4']['attack_requirements'] == 'present'
        assert res.json['cvss4']['privileges_required'] == 'low'
        assert res.json['cvss4']['user_interaction'] == 'active'
        assert res.json['cvss4']['vulnerable_system_confidentiality_impact'] == 'low'
        assert res.json['cvss4']['vulnerable_system_integrity_impact'] == 'high'
        assert res.json['cvss4']['vulnerable_system_availability_impact'] == 'low'
        assert res.json['cvss4']['subsequent_system_confidentiality_impact'] == 'high'
        assert res.json['cvss4']['subsequent_system_integrity_impact'] == 'low'
        assert res.json['cvss4']['subsequent_system_availability_impact'] == 'high'
        assert res.json['cvss4']['safety'] is None
        assert res.json['cvss4']['automatable'] is None
        assert res.json['cvss4']['recovery'] is None
        assert res.json['cvss4']['value_density'] is None
        assert res.json['cvss4']['vulnerability_response_effort'] is None
        assert res.json['cvss4']['provider_urgency'] is None
        assert res.json['cvss4']['modified_attack_vector'] is None
        assert res.json['cvss4']['modified_attack_complexity'] is None
        assert res.json['cvss4']['modified_attack_requirements'] is None
        assert res.json['cvss4']['modified_privileges_required'] is None
        assert res.json['cvss4']['modified_user_interaction'] is None
        assert res.json['cvss4']['modified_vulnerable_system_confidentiality_impact'] is None
        assert res.json['cvss4']['modified_subsequent_system_confidentiality_impact'] is None
        assert res.json['cvss4']['modified_vulnerable_system_integrity_impact'] is None
        assert res.json['cvss4']['modified_subsequent_system_integrity_impact'] is None
        assert res.json['cvss4']['modified_vulnerable_system_availability_impact'] is None
        assert res.json['cvss4']['modified_subsequent_system_availability_impact'] is None
        assert res.json['cvss4']['confidentiality_requirement'] is None
        assert res.json['cvss4']['integrity_requirement'] is None
        assert res.json['cvss4']['availability_requirement'] is None
        assert res.json['cvss4']['exploit_maturity'] is None

    def test_create_vuln_with_cvss(self, host_with_hostnames, test_client, session):
        session.commit()  # flush host_with_hostnames
        cvss2 = {'vector_string': 'AV:L/AC:L/Au:M/C:N/I:P/A:C/E:U/RL:W/RC:ND/CDP:L/TD:H/CR:ND/IR:ND'}
        cvss3 = {'vector_string': 'CVSS:3.0/S:C/C:H/I:H/A:N/AV:P/AC:H/PR:H/UI:R/E:H/RL:O/RC:R/CR:H/IR:X/AR:X/MAC:H/MPR:X/MUI:X/MC:L/MA:X'}
        cvss4 = {'vector_string': 'CVSS:4.0/AV:N/AC:H/AT:P/PR:L/UI:A/VC:L/VI:H/VA:L/SC:H/SI:L/SA:H/E:A/CR:L/IR:M/AR:H/MAV:A/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:L/MVA:H/MSC:L/MSI:S/MSA:N/S:P/AU:N/R:U/V:C/RE:M/U:Green'}

        raw_data = _create_post_data_vulnerability(
            name='New vulns',
            vuln_type='Vulnerability',
            parent_id=host_with_hostnames.id,
            parent_type='Host',
            policyviolations=[],
            refs=[],
            cvss2=cvss2,
            cvss3=cvss3,
            cvss4=cvss4,
        )
        ws = host_with_hostnames.workspace
        res = test_client.post(self.url(workspace=ws), data=raw_data)
        assert res.status_code == 201
        assert res.json['cvss2'] is not None
        assert res.json['cvss2']['base_score'] == 5.0
        assert res.json['cvss2']['temporal_score'] == 4.0
        assert res.json['cvss2']['environmental_score'] == 4.6
        assert res.json['cvss2']['access_vector'] == 'local'
        assert res.json['cvss2']['access_complexity'] == 'low'
        assert res.json['cvss2']['authentication'] == 'multiple'
        assert res.json['cvss2']['confidentiality_impact'] == 'none'
        assert res.json['cvss2']['integrity_impact'] == 'partial'
        assert res.json['cvss2']['availability_impact'] == 'complete'
        assert res.json['cvss2']['exploitability'] == 'unproven'
        assert res.json['cvss2']['remediation_level'] == 'workaround'
        assert res.json['cvss2']['report_confidence'] is None
        assert res.json['cvss2']['collateral_damage_potential'] == 'low'
        assert res.json['cvss2']['target_distribution'] == 'high'
        assert res.json['cvss2']['confidentiality_requirement'] is None
        assert res.json['cvss2']['integrity_requirement'] is None
        assert res.json['cvss2']['availability_requirement'] is None

        assert res.json['cvss3'] is not None
        assert res.json['cvss3']['base_score'] == 6.5
        assert res.json['cvss3']['temporal_score'] == 6.0
        assert res.json['cvss3']['environmental_score'] == 5.3
        assert res.json['cvss3']['attack_vector'] == 'physical'
        assert res.json['cvss3']['attack_complexity'] == 'high'
        assert res.json['cvss3']['privileges_required'] == 'high'
        assert res.json['cvss3']['user_interaction'] == 'required'
        assert res.json['cvss3']['confidentiality_impact'] == 'high'
        assert res.json['cvss3']['integrity_impact'] == 'high'
        assert res.json['cvss3']['availability_impact'] == 'none'
        assert res.json['cvss3']['exploit_code_maturity'] == 'high'
        assert res.json['cvss3']['remediation_level'] == 'official fix'
        assert res.json['cvss3']['report_confidence'] == 'reasonable'
        assert res.json['cvss3']['confidentiality_requirement'] == 'high'
        assert res.json['cvss3']['integrity_requirement'] is None
        assert res.json['cvss3']['availability_requirement'] is None
        assert res.json['cvss3']['modified_attack_vector'] is None
        assert res.json['cvss3']['modified_attack_complexity'] == 'high'
        assert res.json['cvss3']['modified_privileges_required'] == 'high'
        assert res.json['cvss3']['modified_user_interaction'] == 'required'
        assert res.json['cvss3']['modified_scope'] is None
        assert res.json['cvss3']['modified_confidentiality_impact'] == 'low'
        assert res.json['cvss3']['modified_integrity_impact'] is None
        assert res.json['cvss3']['modified_availability_impact'] == 'none'

        assert res.json['cvss4'] is not None
        assert res.json['cvss4']['base_score'] == 6.9
        assert res.json['cvss4']['base_severity'] == 'medium'
        assert res.json['cvss4']['attack_vector'] == 'network'
        assert res.json['cvss4']['attack_complexity'] == 'high'
        assert res.json['cvss4']['attack_requirements'] == 'present'
        assert res.json['cvss4']['privileges_required'] == 'low'
        assert res.json['cvss4']['user_interaction'] == 'active'
        assert res.json['cvss4']['vulnerable_system_confidentiality_impact'] == 'low'
        assert res.json['cvss4']['vulnerable_system_integrity_impact'] == 'high'
        assert res.json['cvss4']['vulnerable_system_availability_impact'] == 'low'
        assert res.json['cvss4']['subsequent_system_confidentiality_impact'] == 'high'
        assert res.json['cvss4']['subsequent_system_integrity_impact'] == 'low'
        assert res.json['cvss4']['subsequent_system_availability_impact'] == 'high'
        assert res.json['cvss4']['safety'] == 'present'
        assert res.json['cvss4']['automatable'] == 'no'
        assert res.json['cvss4']['recovery'] == 'user'
        assert res.json['cvss4']['value_density'] == 'concentrated'
        assert res.json['cvss4']['vulnerability_response_effort'] == 'moderate'
        assert res.json['cvss4']['provider_urgency'] == 'green'
        assert res.json['cvss4']['modified_attack_vector'] == 'adjacent'
        assert res.json['cvss4']['modified_attack_complexity'] == 'high'
        assert res.json['cvss4']['modified_attack_requirements'] == 'present'
        assert res.json['cvss4']['modified_privileges_required'] == 'high'
        assert res.json['cvss4']['modified_user_interaction'] == 'active'
        assert res.json['cvss4']['modified_vulnerable_system_confidentiality_impact'] == 'high'
        assert res.json['cvss4']['modified_subsequent_system_confidentiality_impact'] == 'low'
        assert res.json['cvss4']['modified_vulnerable_system_integrity_impact'] == 'low'
        assert res.json['cvss4']['modified_subsequent_system_integrity_impact'] == 'safety'
        assert res.json['cvss4']['modified_vulnerable_system_availability_impact'] == 'high'
        assert res.json['cvss4']['modified_subsequent_system_availability_impact'] == 'negligible'
        assert res.json['cvss4']['confidentiality_requirement'] == 'low'
        assert res.json['cvss4']['integrity_requirement'] == 'medium'
        assert res.json['cvss4']['availability_requirement'] == 'high'
        assert res.json['cvss4']['exploit_maturity'] == 'attacked'

    def test_create_vuln_with_empty_cvss(self, host_with_hostnames, test_client, session):
        session.commit()  # flush host_with_hostnames
        cvss2 = {'vector_string': 'AV:L/AC:L/Au:M/C:N/I:P/A:C/E:U/RL:W/RC:ND/CDP:L/TD:H/CR:ND/IR:ND'}
        cvss3 = {'vector_string': 'CVSS:3.0/S:C/C:H/I:H/A:N/AV:P/AC:H/PR:H/UI:R/E:H/RL:O/RC:R/CR:H/IR:X/AR:X/MAC:H/MPR:X/MUI:X/MC:L/MA:X'}
        cvss4 = {'vector_string': 'CVSS:4.0/AV:A/AC:H/AT:P/PR:L/UI:P/VC:L/VI:H/VA:L/SC:L/SI:H/SA:L'}
        raw_data = _create_post_data_vulnerability(
            name='New vulns',
            vuln_type='Vulnerability',
            parent_id=host_with_hostnames.id,
            parent_type='Host',
            policyviolations=[],
            refs=[],
            cvss2=cvss2,
            cvss3=cvss3,
            cvss4=cvss4,
        )
        ws = host_with_hostnames.workspace
        res = test_client.post(self.url(workspace=ws), data=raw_data)
        assert res.status_code == 201
        vuln = session.query(VulnerabilityGeneric).filter(VulnerabilityGeneric.id == res.json['_id']).first()
        assert vuln.cvss2_vector_string == cvss2['vector_string']
        assert vuln.cvss3_vector_string == cvss3['vector_string']
        assert vuln.cvss4_vector_string == cvss4['vector_string']
        vuln.cvss2_vector_string = ''
        vuln.cvss3_vector_string = ''
        vuln.cvss4_vector_string = ''
        assert vuln.cvss2_vector_string is None
        assert vuln.cvss2_base_score is None
        assert vuln.cvss2_temporal_score is None
        assert vuln.cvss2_environmental_score is None

        assert vuln.cvss3_vector_string is None
        assert vuln.cvss3_base_score is None
        assert vuln.cvss3_temporal_score is None
        assert vuln.cvss3_environmental_score is None

        assert vuln.cvss4_vector_string is None
        assert vuln.cvss4_base_score is None

    def test_create_vuln_with_cvss_malformed(self, host_with_hostnames, test_client, session):
        """
        this will create vuln but cvss will have only the malformed vector string
        """
        session.commit()  # flush host_with_hostnames
        cvss2 = {'vector_string': 'AV:L/AC:L/Au:M/C:N/I:P/A:J'}
        cvss3 = {'vector_string': 'CVSS:3.0/S:C/C:H/I:H/A:N/AV:P'}
        cvss4 = {'vector_string': 'CVSS:4.0/VA:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/PU:N/PA:N/PI:N/SA:U'}
        raw_data = _create_post_data_vulnerability(
            name='New vulns',
            vuln_type='Vulnerability',
            parent_id=host_with_hostnames.id,
            parent_type='Host',
            policyviolations=[],
            refs=[],
            cvss2=cvss2,
            cvss3=cvss3,
            cvss4=cvss4,
        )
        ws = host_with_hostnames.workspace
        res = test_client.post(self.url(workspace=ws), data=raw_data)
        assert res.status_code == 201
        assert res.json['cvss2']['vector_string'] == cvss2['vector_string']
        assert res.json['cvss3']['vector_string'] == cvss3['vector_string']
        assert res.json['cvss4']['vector_string'] == cvss4['vector_string']

    def test_create_vuln_imapct_verification(self, host_with_hostnames, test_client, session):
        session.commit()  # flush host_with_hostnames
        raw_data = _create_post_data_vulnerability(
            name='New vulns',
            vuln_type='Vulnerability',
            parent_id=host_with_hostnames.id,
            parent_type='Host',
            refs=[],
            policyviolations=[],
            impact={
                'accountability': True,
                'availability': True,
                'confidentiality': True,
                'integrity': True
            }
        )
        ws = host_with_hostnames.workspace
        vuln_count_previous = session.query(Vulnerability).count()
        res = test_client.post(self.url(workspace=ws), data=raw_data)
        assert res.status_code == 201
        assert vuln_count_previous + 1 == session.query(Vulnerability).count()
        assert res.json['name'] == 'New vulns'
        assert res.json['impact'] == {'accountability': True,
                                      'availability': True,
                                      'confidentiality': True,
                                      'integrity': True}

    def test_handles_invalid_impact(self, host_with_hostnames, test_client,
                                    session):
        session.commit()  # flush host_with_hostnames
        raw_data = _create_post_data_vulnerability(
            name='New vulns',
            vuln_type='Vulnerability',
            parent_id=host_with_hostnames.id,
            parent_type='Host',
            refs=[],
            policyviolations=[],
            impact={
                'accountability': True,
                'integrity': 'aaaa',
                'invalid': None,
            }
        )
        ws = host_with_hostnames.workspace
        vuln_count_previous = session.query(Vulnerability).count()
        res = test_client.post(self.url(workspace=ws), data=raw_data)
        assert res.status_code == 400

    def test_create_vuln_with_invalid_type(self,
                                           host_with_hostnames,
                                           test_client,
                                           session):
        session.commit()  # flush host_with_hostnames
        raw_data = _create_post_data_vulnerability(
            name='New vulns',
            vuln_type='VulnerabilitySarasa',
            parent_id=host_with_hostnames.id,
            parent_type='Host',
            refs=[],
            policyviolations=[]
        )
        ws = host_with_hostnames.workspace
        vuln_count_previous = session.query(Vulnerability).count()
        res = test_client.post(
            self.url(workspace=ws),
            data=raw_data,
        )
        assert res.status_code == 400
        assert vuln_count_previous == session.query(Vulnerability).count()
        assert res.json['message'] == 'Invalid vulnerability type.'

    def test_create_vuln_without_type(self, host_with_hostnames, test_client, session):
        """
        This one should only check basic vuln properties
        :param host_with_hostnames:
        :param test_client:
        :param session:
        :return:
        """
        session.commit()  # flush host_with_hostnames
        raw_data = _create_post_data_vulnerability(
            name='New vulns',
            vuln_type='a',
            parent_id=host_with_hostnames.id,
            parent_type='Host',
            refs=[],
            policyviolations=[],
            description='helloworld',
            severity='low',
        )
        raw_data.pop("type")
        ws = host_with_hostnames.workspace
        vuln_count_previous = session.query(Vulnerability).count()
        res = test_client.post(self.url(workspace=ws), data=raw_data)
        assert res.status_code == 400
        assert vuln_count_previous == session.query(Vulnerability).count()
        assert res.json['message'] == 'Type is required.'

    def test_create_vuln_with_invalid_severity(self,
                                               host_with_hostnames,
                                               test_client, session):
        session.commit()  # flush host_with_hostnames
        raw_data = _create_post_data_vulnerability(
            name='New vulns',
            vuln_type='Vulnerability',
            parent_id=host_with_hostnames.id,
            parent_type='Host',
            refs=[],
            policyviolations=[],
            severity="invalid",
        )
        ws = host_with_hostnames.workspace
        vuln_count_previous = session.query(Vulnerability).count()
        res = test_client.post(self.url(workspace=ws), data=raw_data)
        assert res.status_code == 400
        assert vuln_count_previous == session.query(Vulnerability).count()
        assert b'Invalid severity type.' in res.data

    def test_modify_parent(self, test_client, session, workspace):
        host = HostFactory.create(ip='127.0.0.1', workspace=workspace)
        session.add(host)
        session.commit()
        vulnerability = VulnerabilityFactory.create(
            name='test',
            host=host,
            service=None,
            workspace=workspace,
            severity='low'
        )
        session.add(vulnerability)
        session.commit()

        assert vulnerability.host_id == host.id

        new_host = HostFactory(ip="192.168.10.1", workspace=workspace)
        session.add(new_host)
        session.commit()

        data = {
            "parent": new_host.id,
            "parent_type": "Host"
        }
        res = test_client.patch(f'{self.url(workspace=workspace)}/{vulnerability.id}', data=data)
        assert res.status_code == 200
        assert res.json['parent'] == new_host.id

    def test_modify_parent_with_no_parent_type_or_parent(self, test_client, session, workspace):
        host = HostFactory.create(ip='127.0.0.1', workspace=workspace)
        session.add(host)
        session.commit()

        service = ServiceFactory.create(name="ssh", workspace=workspace)
        session.add(service)
        session.commit()

        vulnerability = VulnerabilityFactory.create(
            name='test',
            host=host,
            service=None,
            workspace=workspace,
            severity='low'
        )
        session.add(vulnerability)
        session.commit()

        assert vulnerability.host_id == host.id

        new_host = HostFactory(ip="192.168.10.1", workspace=workspace)
        session.add(new_host)
        session.commit()

        data = {
            "parent": new_host.id,
        }
        res = test_client.patch(f'{self.url(workspace=workspace)}/{vulnerability.id}', data=data)
        assert res.status_code == 400

        data = {
            "parent_type": "Service",
        }
        res = test_client.patch(f'{self.url(workspace=workspace)}/{vulnerability.id}', data=data)
        assert res.status_code == 400

    def test_modify_web_vuln_parent_with_host_parent_type(self, test_client, session, workspace):
        service = ServiceFactory.create(name="ssh", workspace=workspace)
        session.add(service)
        session.commit()
        vulnerability = VulnerabilityWebFactory.create(
            name='test',
            host=None,
            service=service,
            workspace=workspace,
            severity='low'
        )
        session.add(vulnerability)
        session.commit()

        assert vulnerability.service_id == service.id

        new_host = HostFactory(ip="192.168.10.1", workspace=workspace)
        session.add(new_host)
        session.commit()

        data = {
            "parent": new_host.id,
            "parent_type": "Host"
        }
        res = test_client.patch(f'{self.url(workspace=workspace)}/{vulnerability.id}', data=data)
        assert res.status_code == 400
        assert vulnerability.parent.id == service.id

    def test_modify_vulnerability_parent_from_host_parent_to_service_parent(self, test_client, session, workspace):
        host = HostFactory.create(ip='127.0.0.1', workspace=workspace)
        session.add(host)
        session.commit()

        vulnerability = VulnerabilityFactory.create(
            name='test',
            host=host,
            service=None,
            workspace=workspace,
            severity='low'
        )
        session.add(vulnerability)
        session.commit()
        assert vulnerability.host_id == host.id

        service = ServiceFactory.create(name="ssh2", workspace=workspace)
        session.add(service)
        session.commit()
        web_vulnerability = VulnerabilityWebFactory.create(
            name='test',
            host=None,
            service=service,
            workspace=workspace,
            severity='low'
        )
        session.add(web_vulnerability)
        session.commit()
        assert web_vulnerability.service_id == service.id

        new_service = ServiceFactory.create(name="ssh1", workspace=workspace)
        session.add(new_service)
        session.commit()

        data = {
            "parent": new_service.id,
            "parent_type": "Service"
        }
        res = test_client.patch(f'{self.url(workspace=workspace)}/{vulnerability.id}', data=data)
        assert res.status_code == 200
        assert res.json['parent'] == new_service.id
        assert res.json['parent_type'] == "Service"

        res = test_client.patch(f'{self.url(workspace=workspace)}/{web_vulnerability.id}', data=data)
        assert res.status_code == 200
        assert res.json['parent'] == new_service.id
        assert res.json['parent_type'] == "Service"

    def test_create_vuln_with_invalid_ease_of_resolution(self,
                                                         host_with_hostnames,
                                                         test_client,
                                                         session):
        session.commit()  # flush host_with_hostnames
        raw_data = _create_post_data_vulnerability(
            name='New vulns',
            vuln_type='Vulnerability',
            parent_id=host_with_hostnames.id,
            parent_type='Host',
            refs=[],
            policyviolations=[],
            easeofresolution='frutafrutafruta'
        )
        ws = host_with_hostnames.workspace
        vuln_count_previous = session.query(Vulnerability).count()
        res = test_client.post(self.url(workspace=ws), data=raw_data)
        assert res.status_code == 400
        assert vuln_count_previous == session.query(Vulnerability).count()
        assert list(res.json['messages']['json'].keys()) == ['easeofresolution']
        assert 'Must be one of' in res.json['messages']['json']['easeofresolution'][0]

    def test_create_vuln_with_null_ease_of_resolution(self,
                                                      host_with_hostnames,
                                                      test_client,
                                                      session):
        session.commit()  # flush host_with_hostnames
        raw_data = _create_post_data_vulnerability(
            name='New vulns',
            vuln_type='Vulnerability',
            parent_id=host_with_hostnames.id,
            parent_type='Host',
            refs=[],
            policyviolations=[],
            easeofresolution=None,
        )
        ws = host_with_hostnames.workspace
        res = test_client.post(self.url(workspace=ws),
                               data=raw_data)
        assert res.status_code == 201, (res.status_code, res.data)
        created_vuln = Vulnerability.query.get(res.json['_id'])
        assert created_vuln.ease_of_resolution is None

    def test_count_order_by_incorrect_keyword(self, test_client, session):
        for i, vuln in enumerate(self.objects[:3]):
            vuln.confirmed = True
            # Set critical severity to first vuln, high to the others
            if i == 0:
                vuln.severity = 'critical'
            else:
                vuln.severity = 'high'

            session.add(vuln)
            session.commit()

        # Desc
        res = test_client.get(
            join(self.url(), "count?confirmed=1&group_by=severity&order=sc"
                 ))
        assert res.status_code == 400

        # Asc
        res = test_client.get(join(self.url(), "count?confirmed=1&group_by=severity&order=name,asc"))
        assert res.status_code == 400

    def test_count_order_by(self, test_client, session):
        for i, vuln in enumerate(self.objects[:3]):
            vuln.confirmed = True
            # Set critical severity to first vuln, high to the others
            if i == 0:
                vuln.severity = 'critical'
            else:
                vuln.severity = 'high'

            session.add(vuln)
            session.commit()

        # Desc
        res = test_client.get(
            join(self.url(), "count?confirmed=1&group_by=severity&order=desc"
                 ))
        assert res.status_code == 200
        assert res.json['total_count'] == 3
        assert sorted(res.json['groups'], key=lambda i: (i['name'], i['count'], i['severity'])) == sorted([
            {"name": "high", "severity": "high", "count": 2},
            {"name": "critical", "severity": "critical", "count": 1},
        ], key=lambda i: (i['name'], i['count'], i['severity']))

        # Asc
        res = test_client.get(
            join(self.url(), "count?confirmed=1&group_by=severity&order=asc"))
        assert res.status_code == 200
        assert res.json['total_count'] == 3
        assert sorted(res.json['groups'], key=lambda i: (i['name'], i['count'], i['severity']), reverse=True) == sorted(
            [
                {"name": "critical", "severity": "critical", "count": 1},
                {"name": "high", "severity": "high", "count": 2},
            ], key=lambda i: (i['name'], i['count'], i['severity']), reverse=True)

    def test_count_group_by_incorrect_vuln_column(self, test_client, session):
        for i, vuln in enumerate(self.objects[:3]):
            vuln.confirmed = True
            # Set critical severity to first vuln, high to the others
            if i == 0:
                vuln.severity = 'critical'
            else:
                vuln.severity = 'high'

            session.add(vuln)
            session.commit()

        res = test_client.get(join(self.url(), "count?confirmed=1&group_by=username"))
        assert res.status_code == 400

        res = test_client.get(join(self.url(), "count?confirmed=1&group_by="))
        assert res.status_code == 400

    def test_count_confirmed(self, test_client, session):
        for i, vuln in enumerate(self.objects[:3]):
            vuln.confirmed = True

            # Set critical severity to first vuln, high to the others
            if i == 0:
                vuln.severity = 'critical'
            else:
                vuln.severity = 'high'

            session.add(vuln)
            session.commit()

        res = test_client.get(join(self.url(), 'count?confirmed=1&group_by=severity'))
        assert res.status_code == 200
        assert res.json['total_count'] == 3
        assert sorted(res.json['groups'], key=lambda i: (i['count'], i['name'], i['severity'])) == sorted([
            {"name": "high", "severity": "high", "count": 2},
            {"name": "critical", "severity": "critical", "count": 1},
        ], key=lambda i: (i['count'], i['name'], i['severity']))

    def test_count_severity_map(self, test_client, second_workspace, session):
        VulnerabilityGeneric.query.delete()
        session.commit()
        vulns = self.factory.create_batch(4, severity='informational',
                                          workspace=second_workspace)
        vulns += self.factory.create_batch(3, severity='medium',
                                           workspace=second_workspace)
        vulns += self.factory.create_batch(2, severity='low',
                                           workspace=second_workspace)
        session.add_all(vulns)
        session.commit()

        res = test_client.get(
            join(self.url(workspace=second_workspace), 'count?group_by=severity'
                 ))
        assert res.status_code == 200
        assert res.json['total_count'] == 9
        assert sorted(res.json['groups'], key=lambda i: (i['count'], i['name'], i['severity'])) == sorted([
            {"name": "med", "severity": "med", "count": 3},
            {"name": "low", "severity": "low", "count": 2},
            {"name": "info", "severity": "info", "count": 4},
        ], key=lambda i: (i['count'], i['name'], i['severity']))

    def test_count_multiworkspace_one_workspace(self, test_client, session):
        for i, vuln in enumerate(self.objects):
            vuln.confirmed = True
            # Set critical severity to first vuln, high to the others
            if i == 0:
                vuln.severity = 'critical'
            else:
                vuln.severity = 'high'

            session.add(vuln)
            session.commit()

        res = test_client.get(
            join(
                self.url(),
                f'count_multi_workspace?workspaces={self.workspace.name}&confirmed=1&group_by=severity&order=desc'
            )
        )

        assert res.status_code == 200
        assert len(res.json['groups']) == 1
        assert res.json['total_count'] == 5

    def test_count_multiworkspace_two_public_workspaces(self, test_client, session, second_workspace):
        vulns = self.factory.create_batch(1, severity='informational',
                                          workspace=second_workspace)
        vulns += self.factory.create_batch(3, severity='medium',
                                           workspace=second_workspace)
        vulns += self.factory.create_batch(1, severity='low',
                                           workspace=second_workspace)
        session.add_all(vulns)
        session.commit()

        for i, vuln in enumerate(self.objects):
            vuln.confirmed = True
            # Set critical severity to first vuln, high to the others
            if i == 0:
                vuln.severity = 'critical'
            else:
                vuln.severity = 'high'

            session.add(vuln)
        session.commit()

        res = test_client.get(
            join(
                self.url(),
                f'count_multi_workspace?workspaces={self.workspace.name},'
                f'{second_workspace.name}&confirmed=1&group_by=severity&order=desc'
            )
        )

        assert res.status_code == 200
        assert len(res.json['groups']) == 2
        assert res.json['total_count'] == 10

    def test_count_multiworkspace_no_workspace_param(self, test_client):
        res = test_client.get(
            join(self.url(), 'count_multi_workspace?confirmed=1&group_by=severity&order=desc'
                 ))
        assert res.status_code == 400

    def test_count_multiworkspace_no_groupby_param(self, test_client):
        res = test_client.get(
            join(self.url(), f'count_multi_workspace?workspaces={self.workspace.name}&confirmed=1&order=desc'
                 ))
        assert res.status_code == 400

    def test_count_multiworkspace_nonexistent_ws(self, test_client):
        res = test_client.get(
            join(
                self.url(),
                f'count_multi_workspace?workspaces=asdf,{self.workspace.name}&confirmed=1&group_by=severity&order=desc'
            )
        )
        assert res.status_code == 404

    @pytest.mark.usefixtures('mock_envelope_list')
    def test_target(self, test_client, session, second_workspace,
                    host_factory, service_factory,
                    vulnerability_factory, vulnerability_web_factory):
        host_factory.create_batch(5, workspace=second_workspace)
        service_factory.create_batch(5, workspace=second_workspace)
        host = host_factory.create(workspace=second_workspace)
        service = service_factory.create(host=host,
                                         workspace=second_workspace)
        vulns = [
            vulnerability_factory.create(host=host, service=None,
                                         workspace=second_workspace),
            vulnerability_factory.create(service=service, host=None,
                                         workspace=second_workspace),
            vulnerability_web_factory.create(service=service,
                                             workspace=second_workspace),
        ]

        session.commit()
        res = test_client.get(self.url(workspace=second_workspace))
        assert res.status_code == 200
        for v in res.json['data']:
            assert v['target'] == host.ip

    @pytest.mark.usefixtures('mock_envelope_list')
    def test_os(self, test_client, session, second_workspace,
                host_factory, service_factory,
                vulnerability_factory, vulnerability_web_factory):
        host_factory.create_batch(5, workspace=second_workspace)
        service_factory.create_batch(5, workspace=second_workspace)
        host = host_factory.create(workspace=second_workspace)
        service = service_factory.create(host=host,
                                         workspace=second_workspace)
        vulns = [
            vulnerability_factory.create(host=host, service=None,
                                         workspace=second_workspace),
            vulnerability_factory.create(service=service, host=None,
                                         workspace=second_workspace),
            vulnerability_web_factory.create(service=service,
                                             workspace=second_workspace),
        ]

        session.commit()
        res = test_client.get(self.url(workspace=second_workspace))
        assert res.status_code == 200
        for v in res.json['data']:
            assert v['host_os'] == host.os

    @pytest.mark.usefixtures('mock_envelope_list')
    def test_filter_by_command_id(self, test_client, session,
                                  second_workspace,
                                  workspace,
                                  vulnerability_factory,
                                  vulnerability_web_factory,
                                  ):
        expected_ids = set()
        web_expected_ids = set()
        host = HostFactory.create(workspace=second_workspace)
        service = ServiceFactory.create(workspace=second_workspace)

        command = EmptyCommandFactory.create(workspace=second_workspace)
        web_command = EmptyCommandFactory.create(workspace=second_workspace)
        high_vulns = vulnerability_factory.create_batch(
            5, workspace=second_workspace, severity='high', host=host, service=None)
        high_vulns_web = vulnerability_web_factory.create_batch(
            5, workspace=second_workspace, severity='high', service=service)
        session.commit()
        CommandObjectFactory.create(
            command=command,
            object_type='host',
            object_id=host.id,
            workspace=second_workspace
        )
        CommandObjectFactory.create(
            command=web_command,
            object_type='service',
            object_id=service.id,
            workspace=second_workspace
        )
        for high_vuln in high_vulns:
            CommandObjectFactory.create(
                command=command,
                object_type='vulnerability',
                object_id=high_vuln.id,
                workspace=second_workspace
            )
        for high_vuln_web in high_vulns_web:
            CommandObjectFactory.create(
                command=web_command,
                object_type='vulnerability',
                object_id=high_vuln_web.id,
                workspace=second_workspace
            )

        session.commit()

        expected_ids.update(vuln.id for vuln in high_vulns)
        web_expected_ids.update(vuln.id for vuln in high_vulns_web)

        res = test_client.get(urljoin(self.url(
            workspace=second_workspace), f'?command_id={command.id}'))
        assert res.status_code == 200
        for vuln in res.json['data']:
            command_object = CommandObject.query.filter_by(
                object_id=vuln['_id'],
                object_type='vulnerability',
                workspace=second_workspace,
            ).first()
            vuln['metadata']['command_id'] == command_object.command.id
        assert {vuln['_id'] for vuln in res.json['data']} == expected_ids

        # Check for web vulns
        res = test_client.get(urljoin(self.url(
            workspace=second_workspace), f'?command_id={web_command.id}'))
        assert res.status_code == 200
        for vuln in res.json['data']:
            command_object = CommandObject.query.filter_by(
                object_id=vuln['_id'],
                object_type='vulnerability',
                workspace=second_workspace,
            ).first()
            vuln['metadata']['command_id'] == command_object.command.id
        assert {vuln['_id'] for vuln in res.json['data']} == web_expected_ids

        # Check for cross-workspace bugs
        res = test_client.get(urljoin(self.url(
            workspace=workspace), f'?command_id={web_command.id}'))
        assert res.status_code == 200
        assert len(res.json['data']) == 0

    def test_vulnerability_metadata(self, session, test_client, workspace):
        owner = UserFactory.create()
        service = ServiceFactory.create(workspace=workspace)
        command = EmptyCommandFactory.create(id=5555, workspace=workspace)
        update_command = EmptyCommandFactory.create(workspace=workspace)

        vuln = VulnerabilityWebFactory.create(
            service=service,
            creator=owner,
            workspace=workspace,
        )
        session.flush()
        CommandObjectFactory.create(
            command=command,
            object_type='vulnerability',
            object_id=vuln.id,
            workspace=workspace
        )

        CommandObjectFactory.create(
            command=update_command,
            object_type='vulnerability',
            object_id=vuln.id,
            workspace=workspace
        )
        session.commit()

        res = test_client.get(self.url())
        assert res.status_code == 200
        from_json_vuln = list(filter(lambda raw_vuln: raw_vuln['id'] == vuln.id,
                                     res.json['vulnerabilities']))
        assert 'metadata' in from_json_vuln[0]['value']
        expected_metadata = {
            'command_id': command.id,
            'create_time': pytz.UTC.localize(vuln.create_date).isoformat(),
            'creator': command.tool,
            'owner': owner.username,
            'update_action': 0,
            'update_controller_action': '',
            'update_time': pytz.UTC.localize(vuln.update_date).isoformat(),
            'update_user': None
        }
        assert expected_metadata == from_json_vuln[0]['value']['metadata']

    @pytest.mark.parametrize("parent_type, parent_factory", [
        ("Host", HostFactory),
        ("Service", ServiceFactory),
    ], ids=["with host parent", "with service parent"])
    def test_create_with_parent_of_other_workspace(
            self, parent_type, parent_factory, test_client, session,
            second_workspace):
        parent = parent_factory.create(workspace=second_workspace)
        session.commit()
        assert parent.workspace_id != self.workspace.id
        data = _create_post_data_vulnerability(
            name='New vulns',
            vuln_type='Vulnerability',
            parent_id=parent.id,
            parent_type=parent_type,
            refs=[],
            policyviolations=[],
            description='helloworld',
            severity='low',
        )
        res = test_client.post(self.url(), data=data)
        assert res.status_code == 400
        assert b'Parent id not found' in res.data

    @pytest.mark.parametrize("parent_type, parent_factory", [
        ("Host", HostFactory),
        ("Service", ServiceFactory),
    ], ids=["with host parent", "with service parent"])
    def test_update_with_parent_of_other_workspace(
            self, parent_type, parent_factory, test_client, session,
            second_workspace, credential_factory):
        parent = parent_factory.create(workspace=second_workspace)
        session.add(parent)
        session.commit()
        assert parent.workspace_id != self.workspace.id
        data = self._create_put_data(
            name='New name',
            desc='New desc',
            status='closed',
            parent=parent.id,
            parent_type=parent_type,
            refs=[{'name': 'ref1', 'type': 'patch'}],
            policy_violations=['pv0']
        )
        res = test_client.put(self.url(self.first_object), data=data)
        assert res.status_code == 400
        assert b'Parent id not found' in res.data

    def test_create_vuln_multiple_times_returns_conflict(self, host_with_hostnames, test_client, session):
        """
        This one should only check basic vuln properties
        :param host_with_hostnames:
        :param test_client:
        :param session:
        :return:
        """
        session.commit()  # flush host_with_hostnames
        raw_data = _create_post_data_vulnerability(
            name='New vulns',
            vuln_type='Vulnerability',
            parent_id=host_with_hostnames.id,
            parent_type='Host',
            refs=[],
            policyviolations=[],
            description='helloworld',
            severity='low',
        )
        ws = host_with_hostnames.workspace
        res = test_client.post(self.url(workspace=ws), data=raw_data)
        assert res.status_code == 201
        res = test_client.post(self.url(workspace=ws), data=raw_data)
        assert res.status_code == 409

    def test_create_webvuln_multiple_times_returns_conflict(self, host_with_hostnames, test_client, session):
        """
        This one should only check basic vuln properties
        :param host_with_hostnames:
        :param test_client:
        :param session:
        :return:
        """
        service = ServiceFactory.create(workspace=self.workspace)
        session.commit()  # flush host_with_hostnames
        raw_data = _create_post_data_vulnerability(
            name='New vulnsweb',
            vuln_type='VulnerabilityWeb',
            parent_id=service.id,
            parent_type='Service',
            refs=[],
            policyviolations=[],
            description='helloworld',
            severity='low',
        )
        ws = host_with_hostnames.workspace
        res = test_client.post(self.url(workspace=ws), data=raw_data)
        assert res.status_code == 201
        res = test_client.post(self.url(workspace=ws), data=raw_data)
        assert res.status_code == 409

    def test_create_similar_vuln_service_and_vuln_web_conflict_succeed(
            self, service, vulnerability_factory, vulnerability_web_factory,
            session, test_client, workspace):
        service_vuln = vulnerability_factory.create(
            service=service, host=None, workspace=workspace,
            name="test conflict", description="test"
        )
        session.commit()
        old_count = VulnerabilityGeneric.query.count()
        raw_data = _create_post_data_vulnerability(
            name='test conflict',
            description='test',
            vuln_type='Vulnerability',
            parent_id=service.id,
            parent_type='Service',
            refs=[],
            policyviolations=[],
            severity='low',
        )
        raw_data['type'] = 'VulnerabilityWeb'
        res = test_client.post(self.url(), data=raw_data)
        assert res.status_code == 201
        assert VulnerabilityGeneric.query.count() == old_count + 1

    def test_update_conflict(self, host, vulnerability_factory, session,
                             test_client):
        vulnerability_factory.create(
            workspace=self.workspace, host=host, service=None,
            name="x", description="x")
        target_vuln = vulnerability_factory.create(
            workspace=self.workspace, host=host, service=None,
            name="y", description="y")
        session.commit()
        raw_data = self._create_put_data(
            'x',
            'x',
            'open',
            host.id,
            'Host',
        )
        res = test_client.put(self.url(obj=target_vuln), data=raw_data)
        assert res.status_code == 409, res.json

    def test_create_and_update_webvuln(self, host_with_hostnames, test_client, session):
        """
            This reproduces a bug found. after creating an object with a
            command, the update caused an integrity error within the same
            command scope.
        """
        command = CommandFactory.create(workspace=self.workspace)
        service = ServiceFactory.create(workspace=self.workspace)
        session.commit()  # flush host_with_hostnames
        raw_data = _create_post_data_vulnerability(
            name='New vulnsweb',
            vuln_type='VulnerabilityWeb',
            parent_id=service.id,
            parent_type='Service',
            refs=[],
            policyviolations=[],
            description='helloworld',
            severity='low',
        )
        ws_name = host_with_hostnames.workspace.name
        res = test_client.post(
            urljoin(self.url(workspace=host_with_hostnames.workspace), f'?command_id={command.id}'),
            data=raw_data
        )
        assert res.status_code == 201
        raw_data = _create_post_data_vulnerability(
            name='Update vulnsweb',
            vuln_type='VulnerabilityWeb',
            parent_id=service.id,
            parent_type='Service',
            refs=[],
            policyviolations=[],
            description='Update helloworld',
            severity='high',
        )
        res = test_client.put(
            join(
                self.url(workspace=host_with_hostnames.workspace), f'{res.json["_id"]}?command_id={command.id}'
            ),
            data=raw_data
        )
        assert res.status_code == 200

    def test_create_vuln_from_command(self, test_client, session):
        command = EmptyCommandFactory.create(workspace=self.workspace)
        service = ServiceFactory.create(workspace=self.workspace)
        session.commit()
        assert len(command.command_objects) == 0
        url = urljoin(self.url(workspace=command.workspace), f"?{urlencode({'command_id': command.id})}")
        raw_data = _create_post_data_vulnerability(
            name='Update vulnsweb',
            vuln_type='VulnerabilityWeb',
            parent_id=service.id,
            parent_type='Service',
            refs=[],
            policyviolations=[],
            description='helloworld',
            severity='high',
        )
        res = test_client.post(url, data=raw_data)

        assert res.status_code == 201
        assert len(command.command_objects) == 1
        cmd_obj = command.command_objects[0]
        assert cmd_obj.object_type == 'vulnerability'
        assert cmd_obj.object_id == res.json['_id']
        assert res.json['metadata']['creator'] == command.tool

    def test_with_invalid_id_returns_400(self, session, test_client):
        """
            Bug found on hackaton.
        """
        session.commit()  # flush host_with_hostnames
        raw_data = _create_post_data_vulnerability(
            name='New vulns',
            vuln_type='Vulnerability',
            parent_id='',
            parent_type='Host',
            refs=[],
            policyviolations=[],
            description='helloworld',
            severity='low',
        )
        res = test_client.post(self.url(), data=raw_data)
        assert res.status_code == 400

    def test_vuln_created_without_command_has_webui_in_metadata(self, test_client, session):
        host = HostFactory.create(workspace=self.workspace)
        session.commit()  # flush host_with_hostnames
        raw_data = _create_post_data_vulnerability(
            name='New vulns',
            vuln_type='Vulnerability',
            parent_id=host.id,
            parent_type='Host',
            refs=[],
            policyviolations=[],
            description='helloworld',
            severity='low',
        )
        res = test_client.post(self.url(), data=raw_data)
        assert res.status_code == 201
        assert res.json['metadata']['creator'] == 'Web UI'

    def test_invalid_host_id_error_message(self, test_client):
        """
            This test reporduces a bug when the parent_id is a string it returned
            the error message "Invalid Parent Type"
        """
        raw_data = {
            'confirmed': False,
            'data': None,
            'desc': 'pepe',
            'description': 'pepe',
            'metadata': {
                'command_id': '',
                'create_time': 1518627247.194113,
                'creator': '',
                'owner': '',
                'update_action': 0,
                'update_controller_action': 'No model controller call',
                'update_time': 1518627247.194114,
                'update_user': ''},
            'name': 'vuln1',
            'owned': False,
            'owner': '',
            'parent': '358302',
            'parent_type': 'Host',
            'policyviolations': [],
            'refs': [],
            'resolution': '',
            'severity': 'critical',
            'status': 'open',
            'type': 'Vulnerability'
        }

        res = test_client.post(self.url(), data=raw_data)
        assert res.status_code == 400
        assert res.json == {'messages': {'json': {'_schema': ['Parent id not found: 358302']}}}

    def test_after_deleting_vuln_ref_and_policies_remains(self, session, test_client):
        vuln = VulnerabilityFactory.create(workspace=self.workspace)
        ref1 = ReferenceFactory.create(workspace=self.workspace)
        pv1 = PolicyViolationFactory.create(workspace=self.workspace)
        vuln.reference_instances.add(ref1)
        vuln.policy_violation_instances.add(pv1)
        session.add(vuln)
        session.commit()

        assert Reference.query.count() == 1
        assert PolicyViolation.query.count() == 1
        assert Vulnerability.query.count() == 6

        res = test_client.delete(self.url(vuln))

        assert res.status_code == 204

        assert Reference.query.count() == 1
        assert PolicyViolation.query.count() == 1
        assert Vulnerability.query.count() == 5

    def test_search_by_id(self, session, test_client):
        vuln = VulnerabilityFactory.create()
        vuln2 = VulnerabilityFactory.create(workspace=vuln.workspace)
        session.add(vuln)
        session.add(vuln2)
        session.commit()
        res = test_client.get(self.url(workspace=vuln.workspace) + f'?id={vuln.id}')
        assert res.json['count'] == 1
        assert res.json['vulnerabilities'][0]['value']['name'] == vuln.name

    def test_search_by_hostnames_service_case(self, session, test_client):
        workspace = WorkspaceFactory.create()
        vuln2 = VulnerabilityFactory.create(workspace=workspace)
        host = HostFactory.create(workspace=workspace)
        hostname = HostnameFactory.create(workspace=workspace, name='test.com', host=host)
        host.hostnames.append(hostname)
        service = ServiceFactory.create(workspace=workspace, host=host)
        vuln = VulnerabilityFactory.create(service=service, host=None, workspace=workspace)
        session.add(vuln)
        session.add(vuln2)
        session.add(service)
        session.add(hostname)
        session.commit()
        url = urljoin(self.url(workspace=workspace), f'?hostnames={hostname.name}')
        res = test_client.get(url)

        assert res.status_code == 200
        assert res.json['count'] == 1
        assert res.json['vulnerabilities'][0]['value']['name'] == vuln.name

    def test_search_by_hostnames_host_case(self, session, test_client):
        workspace = WorkspaceFactory.create()
        vuln2 = VulnerabilityFactory.create(workspace=workspace)
        host = HostFactory.create(workspace=workspace)
        hostname = HostnameFactory.create(workspace=workspace, name='test.com', host=host)
        host.hostnames.append(hostname)
        vuln = VulnerabilityFactory.create(host=host, service=None, workspace=workspace)
        session.add(vuln)
        session.add(vuln2)
        session.add(host)
        session.add(hostname)
        session.commit()
        url = urljoin(self.url(workspace=workspace), f'?hostnames={hostname.name}')
        res = test_client.get(url)
        assert res.status_code == 200
        assert res.json['count'] == 1
        assert res.json['vulnerabilities'][0]['value']['name'] == vuln.name

    # TODO el siguiente test no funciona, nos preocupamos por arreglarlo?
    @pytest.mark.skip()
    def test_hostnames_comma_separated(self, test_client, session):
        # Create Host A with hostname HA
        hostnameA = HostnameFactory.create(workspace=self.workspace)
        hostnameA.host.workspace = hostnameA.workspace
        # Create Host B with hostname HB
        hostnameB = HostnameFactory.create(workspace=hostnameA.workspace)
        hostnameB.host.workspace = hostnameA.workspace
        # Create Vuln with Host A
        vuln = VulnerabilityFactory.create(host=hostnameA.host, workspace=hostnameA.workspace)
        # Create Vuln with Host B
        vuln2 = VulnerabilityFactory.create(host=hostnameB.host, workspace=hostnameA.workspace)
        session.add(hostnameA)
        session.add(hostnameB)
        session.add(vuln)
        session.add(vuln2)
        session.commit()

        # Search with hosnames=HA,HB
        res = test_client.get(urljoin(self.url(workspace=vuln.workspace), f'?hostname={hostnameA},{hostnameB}'))
        assert res.status_code == 200
        assert res.json['count'] == 2

    def test_missing_policy_violation_case(self, test_client, session):
        """
            bug found when a json was missing the policyviolations key
        """
        host = HostFactory.create(workspace=self.workspace)
        session.commit()
        data = {
            'name': 'Test Alert policy_violations',
            'severity': 'informational',
            'creator': 'Zap',
            'parent_type': 'Host',
            'parent': host.id,
            'type': 'Vulnerability',
        }
        res = test_client.post(self.url(), data=data)
        assert res.status_code == 201

    def test_missing_references_case(self, test_client, session):
        """
            bug found when a json was missing the policyviolations key
        """
        host = HostFactory.create(workspace=self.workspace)
        session.commit()
        data = {
            'name': 'Test Alert policy_violations',
            'severity': 'informational',
            'creator': 'Zap',
            'parent_type': 'Host',
            'parent': host.id,
            'type': 'Vulnerability',
        }
        res = test_client.post(self.url(), data=data)
        assert res.status_code == 201

    def test_add_attachment_to_vuln(self, test_client, session, csrf_token,
                                    host_with_hostnames):
        ws = WorkspaceFactory.create(name='abc')
        session.add(ws)
        vuln = VulnerabilityFactory.create(workspace=ws)
        session.add(vuln)
        session.commit()
        file_contents = b'my file contents'
        data = {
            'file': (BytesIO(file_contents), 'borrar.txt'),
            'csrf_token': csrf_token
        }
        headers = {'Content-type': 'multipart/form-data'}

        res = test_client.post(
            f'/v3/ws/abc/vulns/{vuln.id}/attachment',
            data=data, headers=headers, use_json_data=False)

        assert res.status_code == 200

        file_id = session.query(Vulnerability).filter_by(id=vuln.id).first().evidence[0].content['file_id']
        depot = DepotManager.get()
        assert file_contents == depot.get(file_id).read()

    def test_add_attachment_to_vuln_fails_readonly(self, test_client, session, host_with_hostnames):
        ws = WorkspaceFactory.create(name='abc')
        session.add(ws)
        vuln = VulnerabilityFactory.create(workspace=ws)
        session.add(vuln)
        session.commit()
        file_contents = b'my file contents'
        data = {
            'file': (BytesIO(file_contents), 'borrar.txt')
        }
        headers = {'Content-type': 'multipart/form-data'}

        ws.readonly = True
        session.commit()

        res = test_client.post(
            f'/v3/ws/abc/vulns/{vuln.id}/attachment',
            data=data, headers=headers, use_json_data=False)
        assert res.status_code == 403
        query_test = session.query(Vulnerability).filter_by(id=vuln.id).first().evidence
        assert query_test == []

    def test_delete_attachment_from_vuln(self, test_client, session, host_with_hostnames):
        session.commit()  # flush host_with_hostnames
        ws_name = host_with_hostnames.workspace.name
        attachment = NamedTemporaryFile()
        file_content = b'test file'
        attachment.write(file_content)
        attachment.seek(0)
        vuln = _create_post_data_vulnerability(
            name='Testing vuln',
            vuln_type='Vulnerability',
            parent_id=host_with_hostnames.id,
            parent_type='Host',
            refs=[],
            policyviolations=[],
            attachments=[attachment]
        )
        res = test_client.post(f'/v3/ws/{ws_name}/vulns', data=vuln)
        assert res.status_code == 201

        filename = attachment.name.split('/')[-1]
        vuln_id = res.json['_id']
        res = test_client.delete(
            f'/v3/ws/{ws_name}/vulns/{vuln_id}/attachment/{filename}'
        )
        assert res.status_code == 200

        query_test = session.query(Vulnerability).filter_by(id=vuln_id).first().evidence
        assert query_test == []

    def test_delete_attachment_from_vuln_fails_readonly(self, test_client, session, host_with_hostnames):
        session.commit()  # flush host_with_hostnames
        ws_name = host_with_hostnames.workspace.name
        attachment = NamedTemporaryFile()
        file_content = b'test file'
        attachment.write(file_content)
        attachment.seek(0)
        vuln = _create_post_data_vulnerability(
            name='Testing vuln',
            vuln_type='Vulnerability',
            parent_id=host_with_hostnames.id,
            parent_type='Host',
            refs=[],
            policyviolations=[],
            attachments=[attachment]
        )
        res = test_client.post(f'/v3/ws/{ws_name}/vulns', data=vuln)
        assert res.status_code == 201

        self.workspace.readonly = True
        session.commit()

        filename = attachment.name.split('/')[-1]
        vuln_id = res.json['_id']
        res = test_client.delete(
            f'/v3/ws/{ws_name}/vulns/{vuln_id}/attachment/{filename}'
        )
        assert res.status_code == 403

        query_test = session.query(Vulnerability).filter_by(id=vuln_id).first().evidence
        assert len(query_test) == 1
        assert query_test[0].filename == filename

    def test_invalid_vuln_filters(self, test_client, session, workspace):
        data = {
            "q": {"filters": [{"name": "severity", "op": "eq", "val": "medium"}]}
        }
        res = test_client.get(f'/v3/ws/{workspace.name}/vulns/filter', query_string=data)
        assert res.status_code == 400

    def test_vuln_filter_exception(self, test_client, workspace, session):
        vuln = VulnerabilityFactory.create(workspace=workspace, severity="medium")
        session.add(vuln)
        session.commit()
        data = {
            'q': '{"filters":[{"name":"severity","op":"eq","val":"medium"}]}'
        }
        res = test_client.get(f'/v3/ws/{workspace.name}/vulns/filter', query_string=data)
        assert res.status_code == 200
        assert res.json['count'] == 1

    def test_vuln_restless_group_same_creator(self, test_client, session):
        workspace = WorkspaceFactory.create()
        creator = UserFactory.create()
        vuln = VulnerabilityFactory.create(
            workspace=workspace,
            severity="medium",
            creator=creator,
        )
        vuln2 = VulnerabilityFactory.create(
            workspace=workspace,
            severity="medium",
            creator=creator,
        )
        session.add(vuln)
        session.add(vuln2)
        session.commit()
        data = {
            'q': '{"group_by":[{"field":"creator_id"}]}'
        }
        res = test_client.get(f'/v3/ws/{workspace.name}/vulns/filter', query_string=data)
        assert res.status_code == 200
        assert res.json['count'] == 1  # all vulns created by the same creator
        expected = [{'count': 2, 'creator_id': creator.id}]
        assert [vuln['value'] for vuln in res.json['vulnerabilities']] == expected

    def test_vuln_group_by_severity_does_not_duplicate_groups(self, test_client, session):
        workspace = WorkspaceFactory.create()
        creator = UserFactory.create()
        vuln = VulnerabilityFactory.create_batch(size=10,
                                                 workspace=workspace,
                                                 severity="critical",
                                                 creator=creator,
                                                 )
        vuln2 = VulnerabilityWebFactory.create_batch(size=10,
                                                     workspace=workspace,
                                                     severity="critical",
                                                     creator=creator,
                                                     )
        session.add_all(vuln)
        session.add_all(vuln2)
        session.commit()
        data = {
            'q': '{"group_by":[{"field":"severity"}]}'
        }
        res = test_client.get(f'/v3/ws/{workspace.name}/vulns/filter', query_string=data)
        assert res.status_code == 200, res.json
        assert res.json['count'] == 1, res.json  # all vulns created by the same creator
        expected = {
            'count': 1,
            'vulnerabilities': [
                {'id': 0, 'key': 0, 'value': {'count': 20, 'severity': 'critical'}}
            ]
        }
        assert res.json == expected, res.json

    def test_vuln_group_by_multiple_fields(self, test_client, session):
        workspace = WorkspaceFactory.create()
        creator = UserFactory.create()
        vuln = VulnerabilityFactory.create_batch(size=10,
                                                 name='name 1',
                                                 workspace=workspace,
                                                 severity="critical",
                                                 creator=creator,
                                                 )
        vuln2 = VulnerabilityWebFactory.create_batch(size=10,
                                                     name='name 2',
                                                     workspace=workspace,
                                                     severity="critical",
                                                     creator=creator,
                                                     )
        session.add_all(vuln)
        session.add_all(vuln2)
        session.commit()
        data = {
            'q': '{"group_by":[{"field":"severity"}, {"field": "name"}]}'
        }
        res = test_client.get(f'/v3/ws/{workspace.name}/vulns/filter', query_string=data)
        assert res.status_code == 200, res.json
        assert res.json['count'] == 2, res.json  # all vulns created by the same creator
        expected = {'vulnerabilities': [
            {'id': 0, 'key': 0, 'value': {'count': 10, 'severity': 'critical', 'name': 'name 1'}},
            {'id': 1, 'key': 1, 'value': {'count': 10, 'severity': 'critical', 'name': 'name 2'}}], 'count': 2}

        assert res.json == expected, res.json

    @pytest.mark.parametrize('col_name', [
        'severity',
        'name',
        'status',
        'description',
    ])
    def test_vuln_group_by_all_columns(self, col_name, test_client, session):
        workspace = WorkspaceFactory.create()
        creator = UserFactory.create()
        vuln = VulnerabilityFactory.create_batch(size=10,
                                                 workspace=workspace,
                                                 severity="critical",
                                                 creator=creator,
                                                 )
        vuln2 = VulnerabilityWebFactory.create_batch(size=10,
                                                     workspace=workspace,
                                                     severity="critical",
                                                     creator=creator,
                                                     )
        session.add_all(vuln)
        session.add_all(vuln2)
        session.commit()
        data = {
            'q': json.dumps({"group_by": [{"field": col_name}]})
        }
        res = test_client.get(f'/v3/ws/{workspace.name}/vulns/filter', query_string=data)
        assert res.status_code == 200, res.json

    def test_vuln_restless_group_same_name_description(self, test_client, session):
        workspace = WorkspaceFactory.create()
        creator = UserFactory.create()
        vuln = VulnerabilityFactory.create(
            name="test",
            description="test",
            workspace=workspace,
            severity="medium",
            creator=creator,
        )
        vuln2 = VulnerabilityFactory.create(
            name="test",
            description="test",
            workspace=workspace,
            severity="medium",
            creator=creator,
        )
        vuln3 = VulnerabilityFactory.create(
            name="test2",
            description="test",
            workspace=workspace,
            severity="medium",
            creator=creator,
        )
        session.add(vuln)
        session.add(vuln2)
        session.add(vuln3)
        session.commit()
        data = {
            'q': '{"group_by":[{"field":"name"}, {"field":"description"}]}'
        }
        res = test_client.get(f'/v3/ws/{workspace.name}/vulns/filter', query_string=data)
        assert res.status_code == 200
        assert res.json['count'] == 2
        expected = [{'count': 2, 'name': 'test', 'description': 'test'},
                    {'count': 1, 'name': 'test2', 'description': 'test'}]
        assert [vuln['value'] for vuln in res.json['vulnerabilities']] == expected

    @pytest.mark.skip(reason="Not working. the relation field host__vulnerability_high_generic_count is a function which needs to join Host. From react confirmed that they don't use this field. The cost benefit does not worth it, imho")
    def test_vuln_restless_sort_by_(self, test_client, session):
        workspace = WorkspaceFactory.create()
        host = HostFactory.create(workspace=workspace)
        host2 = HostFactory.create(workspace=workspace)
        creator = UserFactory.create()
        vuln = VulnerabilityFactory.create(
            name="test",
            description="test",
            workspace=workspace,
            severity="critical",
            creator=creator,
            service=None,
            host=host,
        )
        vuln2 = VulnerabilityFactory.create(
            name="test 2",
            description="test",
            workspace=workspace,
            severity="critical",
            creator=creator,
            service=None,
            host=host,
        )
        vuln3 = VulnerabilityFactory.create(
            name="test 3",
            description="test",
            workspace=workspace,
            severity="low",
            creator=creator,
            service=None,
            host=host,
        )
        vulns = VulnerabilityFactory.create_batch(
            10,
            workspace=workspace,
            service=None,
            severity="medium",
            host=host2,
        )
        session.add(vuln)
        session.add(vuln2)
        session.add(vuln3)
        session.add_all(vulns)
        session.commit()
        query = {"order_by": [
            {"field": "host__vulnerability_critical_generic_count", "direction": "desc"},
            {"field": "host__vulnerability_high_generic_count", "direction": "desc"},
            {"field": "host__vulnerability_medium_generic_count", "direction": "desc"},
        ],
            "filters": [{"or": [
                {"name": "severity", "op": "==", "val": "critical"},
                {"name": "severity", "op": "==", "val": "high"},
                {"name": "severity", "op": "==", "val": "medium"},
            ]}]
        }

        data = {
            'q': json.dumps(query)
        }
        res = test_client.get(f'/v3/ws/{workspace.name}/vulns/filter', query_string=data)
        assert res.status_code == 200
        assert res.json['count'] == 12
        expected_order = ['critical', 'critical', 'med', 'med', 'med', 'med', 'med', 'med', 'med', 'med', 'med', 'med']
        assert expected_order == [vuln['value']['severity'] for vuln in res.json['vulnerabilities']]

    @pytest.mark.usefixtures('ignore_nplusone')
    def test_vuln_filter_by_creator_username(self, session, workspace, test_client):
        vuln = VulnerabilityWebFactory.create(workspace=workspace, severity="medium")
        session.add(vuln)
        session.commit()
        data = {
            'q': json.dumps({"filters": [{"name": "creator", "op": "eq", "val": vuln.creator.username}]})
        }
        res = test_client.get(f'/v3/ws/{workspace.name}/vulns/filter', query_string=data)
        assert res.status_code == 200

    def test_vuln_web_filter_exception(self, test_client, workspace, session):
        vuln = VulnerabilityWebFactory.create(workspace=workspace, severity="medium")
        session.add(vuln)
        session.commit()
        data = {
            'q': '{"filters":[{"name":"severity","op":"eq","val":"medium"}]}'
        }
        res = test_client.get(f'/v3/ws/{workspace.name}/vulns/filter', query_string=data)
        assert res.status_code == 200
        assert res.json['count'] == 1

    def test_add_vuln_without_parent_id(self, test_client):
        raw_data = _create_post_data_vulnerability(
            name='New vulns',
            vuln_type='Vulnerability',
            parent_id=0,
            parent_type="Host",
            refs=[],
            policyviolations=[],
        )
        res = test_client.post(self.url(), data=raw_data)
        assert res.status_code == 400

    def test_add_vuln_with_unknown_parent_type(self, test_client, session, host_with_hostnames):
        session.commit()
        raw_data = _create_post_data_vulnerability(
            name='New vulns',
            vuln_type='Vulnerability',
            parent_id=host_with_hostnames.id,
            parent_type="invalid_host",
            refs=[],
            policyviolations=[],
        )
        res = test_client.post(self.url(), data=raw_data)
        assert res.json['messages']['json']['_schema'][0] == 'Unknown parent type'

    def test_add_empty_attachment(self, test_client, session, workspace, csrf_token):
        vuln = VulnerabilityFactory.create(workspace=workspace)
        session.add(vuln)
        session.commit()

        res = test_client.post(
            f'/v3/ws/{workspace.name}/vulns/{vuln.id}/attachment',
            data={'csrf_token': csrf_token},
            headers={'Content-Type': 'multipart/form-data'},
            use_json_data=False)
        assert res.status_code == 400

    def test_get_attachment_with_invalid_workspace_and_vuln(self, test_client):
        res = test_client.get(
            "/v3/ws/invalid_ws/vulns/invalid_vuln/attachment/random_name"
        )
        assert res.status_code == 404

    def test_delete_attachment_with_invalid_workspace_and_vuln(self, test_client):
        res = test_client.delete(
            "/v3/ws/invalid_ws/vulns/invalid_vuln/attachment/random_name"
        )
        # assert res.status_code == 404  # Should check why should return 404 and not 405
        assert res.status_code == 405

    def test_delete_invalid_attachment(self, test_client, workspace, session):
        vuln = VulnerabilityFactory.create(workspace=workspace)
        session.add(vuln)
        session.commit()
        res = test_client.delete(
            f"/v3/ws/{workspace.name}/vulns/{vuln.id}/attachment/random_name"
        )
        assert res.status_code == 404

    def test_export_vuln_csv_empty_workspace(self, test_client, session):
        ws = WorkspaceFactory(name='abc')
        res = test_client.get(f'/v3/ws/{ws.name}/vulns/export_csv')
        expected_headers = [
            "confirmed", "id", "date", "name", "severity", "service",
            "target", "desc", "status", "hostnames", "comments", "owner",
            "os", "resolution", "refs", "easeofresolution", "web_vulnerability",
            "data", "website", "path", "status_code", "request", "response", "method",
            "params", "pname", "query", "cve", 'cvss2_vector_string', 'cvss2_base_score',
            'cvss3_vector_string', 'cvss3_base_score', 'cvss4_vector_string', 'cvss4_base_score', 'cwe', "policyviolations", "external_id",
            "impact_confidentiality", "impact_integrity", "impact_availability", "impact_accountability",
            "update_date", "host_id", "host_description", "mac",
            "host_owned", "host_creator_id", "host_date", "host_update_date",
            "service_id", "service_name", "service_description", "service_owned",
            "port", "protocol", "summary", "version", "service_status",
            "service_creator_id", "service_date", "service_update_date", "service_parent_id"
        ]
        assert res.status_code == 200
        assert expected_headers == res.data.decode('utf-8').strip('\r\n').split(',')

    def test_export_vuln_csv_filters_confirmed_using_filters_query(self, test_client, session):
        workspace = WorkspaceFactory.create()
        confirmed_vulns = VulnerabilityFactory.create(confirmed=True, workspace=workspace)
        session.add(confirmed_vulns)
        session.commit()
        res = test_client.get(
            join(
                self.url(workspace=workspace),
                'export_csv?q={"filters":[{"name":"confirmed","op":"==","val":"true"}]}'
            )
        )
        assert res.status_code == 200
        assert self._verify_csv(res.data, confirmed=True)

    @pytest.mark.usefixtures('ignore_nplusone')
    def test_export_vuln_csv_unicode_bug(self, test_client, session):
        workspace = WorkspaceFactory.create()
        desc = 'Latin-1 Supplement \xa1 \xa2 \xa3 \xa4 \xa5 \xa6 \xa7 \xa8'
        confirmed_vulns = VulnerabilityFactory.create(
            confirmed=True,
            description=desc,
            workspace=workspace)
        session.add(confirmed_vulns)
        session.commit()
        res = test_client.get(join(self.url(workspace=workspace), 'export_csv'))
        assert res.status_code == 200
        assert self._verify_csv(res.data, confirmed=True)

    @pytest.mark.usefixtures('ignore_nplusone')
    def test_export_vuln_csv_filters_confirmed_using_filters_query_severity(self, test_client, session):
        workspace = WorkspaceFactory.create()
        confirmed_vulns = VulnerabilityFactory.create(confirmed=True, severity='critical', workspace=workspace)
        session.add(confirmed_vulns)
        session.commit()
        res = test_client.get(
            join(
                self.url(workspace=workspace),
                'export_csv?q={"filters":[{"name":"severity","op":"==","val":"critical"}]}'
            )
        )
        assert res.status_code == 200
        assert self._verify_csv(res.data, confirmed=True, severity='critical')

    @pytest.mark.usefixtures('ignore_nplusone')
    def test_export_vulns_confirmed(self, session, test_client):
        self.first_object.confirmed = True
        session.add(self.first_object)
        session.commit()
        res = test_client.get(
            join(self.url(), 'export_csv?confirmed=true')
        )
        assert res.status_code == 200
        self._verify_csv(res.data, confirmed=True)

    @pytest.mark.usefixtures('ignore_nplusone')
    def test_export_vulns_check_update_time(self, session, test_client):
        workspace = WorkspaceFactory.create()
        host = HostFactory.create(workspace=workspace)
        session.add(host)
        service = ServiceFactory.create(workspace=workspace, host=host)
        session.add(service)
        vuln = VulnerabilityFactory.create(workspace=workspace, host=host)
        vuln.service = service
        session.add(vuln)
        session.commit()

        host.owned = True
        service.owned = True
        vuln.confirmed = True
        session.add(host)
        session.add(service)
        session.add(vuln)
        session.commit()

        res = test_client.get(f'/v3/ws/{workspace.name}/vulns/export_csv')
        assert res.status_code == 200

        csv_data = csv.DictReader(StringIO(res.data.decode('utf-8')), delimiter=',')

        for index, line in enumerate(csv_data):
            create_date = parser.parse(line['date'])
            update_date = parser.parse(line['update_date'])
            assert create_date < update_date

            create_date = parser.parse(line['host_date'])
            update_date = parser.parse(line['host_update_date'])
            assert create_date < update_date

            create_date = parser.parse(line['service_date'])
            update_date = parser.parse(line['service_update_date'])
            assert create_date < update_date

    @pytest.mark.usefixtures('ignore_nplusone')
    def test_export_vulns_csv_with_custom_fields(self, session, test_client):

        custom_field_schema = CustomFieldsSchemaFactory(
            field_name='cvss',
            field_type='str',
            field_display_name='CVSS',
            table_name='vulnerability'
        )
        session.add(custom_field_schema)
        session.commit()
        for vuln in self.objects:
            vuln.custom_fields = {"cvss": "9"}

        # lets add a non "schema" custom field called invalid, this should not be shown on the csv
        self.first_object.custom_fields = {"cvss": "9", "invalid": "not shown"}
        # another case witt custom fields as None
        vuln = VulnerabilityFactory.create()
        vuln.custom_fields = None
        session.add(vuln)
        session.commit()

        res = test_client.get(join(self.url(), 'export_csv'))
        assert self._verify_csv(res.data)

    def _verify_csv(self, raw_csv_data, confirmed=False, severity=None):
        custom_fields = [custom_field.field_name for custom_field in CustomFieldsSchema.query.all()]
        vuln_headers = [
            "confirmed", "id", "date", "name", "severity", "service",
            "target", "desc", "status", "hostnames", "comments", "owner",
            "os", "resolution", "refs", "easeofresolution", "web_vulnerability",
            "data", "website", "path", "status_code", "request", "response", "method",
            "params", "pname", "query", "policyviolations", "external_id", "impact_confidentiality",
            "impact_integrity", "impact_availability", "impact_accountability", "update_date"
        ]
        host_and_service_headers = [
            "host_id", "host_description", "mac",
            "host_owned", "host_creator_id", "host_date", "host_update_date",
            "service_id", "service_name", "service_description", "service_owned",
            "port", "protocol", "summary", "version", "service_status",
            "service_creator_id", "service_date", "service_update_date", "service_parent_id"
        ]

        csv_data = csv.DictReader(StringIO(raw_csv_data.decode('utf-8')), delimiter=',')
        for index, line in enumerate(csv_data):
            # test vulns
            vuln = Vulnerability.query.filter_by(id=line['id'], confirmed=confirmed)
            if severity:
                vuln.filter_by(severity=severity)

            vuln = vuln.first()
            if vuln.name != line['name']:
                return False
            # test custom fields
            for c_index, custom_field in enumerate(custom_fields):
                if vuln.custom_fields and vuln.custom_fields.get(custom_field, "") != line['cf_' + custom_field]:
                    return False

            # test hosts
            host = Host.query.filter(Host.id == line['host_id']).first()
            if host:
                if host.ip != line['target']:
                    return False

            # test services
            service = None
            if line['service_id']:
                service = Service.query.filter(Service.id == line['service_id']).first()
                if service:
                    if service.summary != line['summary']:
                        return False

        return True

    @pytest.mark.usefixtures('ignore_nplusone')
    def test_update_vuln_cant_change_tool(self, test_client, session):
        host = HostFactory.create(workspace=self.workspace)
        tool = "tool_name"
        updated_tool = "new_tool"
        vuln = VulnerabilityFactory.create(workspace=self.workspace, host_id=host.id, tool=tool)
        session.add(vuln)
        session.commit()  # flush host_with_hostnames
        raw_data = self._create_put_data(
            'Updated vuln Name',
            'Updated vuln',
            'open',
            host.id,
            'Host',
        )
        raw_data.update({'tool': updated_tool})
        res = test_client.put(self.url(obj=vuln, workspace=self.workspace), data=raw_data)
        assert res.status_code == 200
        assert res.json['tool'] == tool

    def test_patch_with_attachments(self, test_client, session, workspace):
        vuln = VulnerabilityFactory.create(workspace=workspace)
        session.add(vuln)
        session.commit()
        png_file = Path(__file__).parent / 'data' / 'faraday.png'

        with open(png_file, 'rb') as file_obj:
            new_file = FaradayUploadedFile(file_obj.read())

        new_attach = File(object_type='vulnerability', object_id=vuln.id, name='Faraday', filename='faraday.png',
                          content=new_file)
        session.add(new_attach)
        session.commit()

        res = test_client.patch(f'{self.url(vuln, workspace=workspace)}', data={})
        assert res.status_code == 200
        res = test_client.get(f'{self.url(vuln, workspace=workspace)}/attachment')
        assert res.status_code == 200
        assert new_attach.filename in res.json
        assert 'image/png' in res.json[new_attach.filename]['content_type']

    @pytest.mark.usefixtures('ignore_nplusone')
    def test_bulk_update_vuln_cant_change_tool_type_or_attachments(self, test_client, session):
        host = HostFactory.create(workspace=self.workspace)
        tool = "tool_name"
        updated_tool = "new_tool"
        vuln = VulnerabilityFactory.create(workspace=self.workspace, host_id=host.id, tool=tool)
        session.add(vuln)
        session.commit()  # flush host_with_hostnames
        type = "Vulnerability" if "web" in vuln.type.lower() else "Vulnerability"
        # flush host_with_hostnames
        attachment = NamedTemporaryFile()
        file_content = b'test file'
        attachment.write(file_content)
        attachment.seek(0)
        attachment_data = self._create_put_data(
            'Updated with attachment',
            'Updated vuln',
            'open',
            host.id,
            'Host',
            attachments=[attachment]
        )["_attachments"]
        raw_data = {'ids': [vuln.id], 'tool': updated_tool, "type": type, "_attachments": attachment_data}
        res = test_client.patch(self.url(), data=raw_data)
        assert res.status_code == 200
        assert res.json['updated'] == 0

    def test_export_csv_from_filters_endpoint(self, test_client, session, workspace):
        vuln = VulnerabilityFactory.create(workspace=workspace)
        session.add(vuln)
        session.commit()
        res = test_client.get(f'/v3/ws/{workspace.name}/vulns/filter?export_csv=true')

        assert res.status_code == 200
        assert self._verify_csv(res.data)

    def test_export_csv_with_filters(self, test_client, session):
        ws = WorkspaceFactory(name="abc")
        vuln_critical = VulnerabilityFactory.create(workspace=ws, severity="critical")
        vuln_info = VulnerabilityFactory.create(workspace=ws, severity="informational")
        session.add(vuln_critical)
        session.add(vuln_info)
        session.commit()
        url = (f'/v3/ws/{ws.name}/vulns/filter?'
               'q={"filters":[{"name":"severity","op":"==","val":"critical"}]}&export_csv=false')

        res = test_client.get(url)

        # Response should contain a CSV with only the vulns filtered, in this case with the critical vuln
        assert res.status_code == 200
        assert res.json["count"] == 1
        assert self._verify_csv(res.data)

    def test_export_csv_with_false_argument(self, test_client, session):
        ws = WorkspaceFactory(name="abc")
        vuln_high = VulnerabilityFactory.create(workspace=ws, severity="high")
        vuln_low = VulnerabilityFactory.create(workspace=ws, severity="low")
        session.add(vuln_high)
        session.add(vuln_low)
        session.commit()
        url = (f'/v3/ws/{ws.name}/vulns/filter?'
               'q={"filters":[{"name":"severity","op":"==","val":"high"}]}&export_csv=false')

        res = test_client.get(url)

        # Response should contain only the vulns filtered, in this case only the vuln with high severity
        assert res.status_code == 200
        assert res.json["count"] == 1
        assert res.json["vulnerabilities"][0]["value"]["severity"] == "high"

    def test_export_csv_with_empty_workspace(self, test_client, session):
        ws = WorkspaceFactory(name='abc')
        res = test_client.get(f'/v3/ws/{ws.name}/vulns/filter?export_csv=true')
        expected_headers = [
            "confirmed", "id", "date", "name", "severity", "service",
            "target", "desc", "status", "hostnames", "comments", "owner",
            "os", "resolution", "refs", "easeofresolution", "web_vulnerability",
            "data", "website", "path", "status_code", "request", "response", "method",
            "params", "pname", "query", "cve", 'cvss2_vector_string', 'cvss2_base_score',
            'cvss3_vector_string', 'cvss3_base_score', 'cvss4_vector_string', 'cvss4_base_score',
            'cwe', "policyviolations", "external_id",
            "impact_confidentiality", "impact_integrity", "impact_availability", "impact_accountability",
            "update_date", "host_id", "host_description", "mac",
            "host_owned", "host_creator_id", "host_date", "host_update_date",
            "service_id", "service_name", "service_description", "service_owned",
            "port", "protocol", "summary", "version", "service_status",
            "service_creator_id", "service_date", "service_update_date", "service_parent_id"
        ]
        assert res.status_code == 200
        assert expected_headers == res.data.decode('utf-8').strip('\r\n').split(',')

    @pytest.mark.usefixtures('ignore_nplusone')
    def test_export_csv_unicode_bug(self, test_client, session):
        workspace = WorkspaceFactory.create()
        desc = 'Latin-1 Supplement \xa1 \xa2 \xa3 \xa4 \xa5 \xa6 \xa7 \xa8'
        confirmed_vulns = VulnerabilityFactory.create(
            confirmed=True,
            description=desc,
            workspace=workspace)
        session.add(confirmed_vulns)
        session.commit()
        res = test_client.get(f'/v3/ws/{workspace.name}/vulns/filter?export_csv=true')
        assert res.status_code == 200
        assert self._verify_csv(res.data, confirmed=True)

    @pytest.mark.usefixtures('ignore_nplusone')
    def test_export_csv_check_update_time(self, session, test_client):
        workspace = WorkspaceFactory.create()
        host = HostFactory.create(workspace=workspace)
        session.add(host)
        service = ServiceFactory.create(workspace=workspace, host=host)
        session.add(service)
        vuln = VulnerabilityFactory.create(workspace=workspace, host=host)
        vuln.service = service
        session.add(vuln)
        session.commit()

        host.owned = True
        service.owned = True
        vuln.confirmed = True
        session.add(host)
        session.add(service)
        session.add(vuln)
        session.commit()

        res = test_client.get(f'/v3/ws/{workspace.name}/vulns/filter?export_csv=true')
        assert res.status_code == 200

        csv_data = csv.DictReader(StringIO(res.data.decode('utf-8')), delimiter=',')

        for index, line in enumerate(csv_data):
            create_date = parser.parse(line['date'])
            update_date = parser.parse(line['update_date'])
            assert create_date < update_date

            create_date = parser.parse(line['host_date'])
            update_date = parser.parse(line['host_update_date'])
            assert create_date < update_date

            create_date = parser.parse(line['service_date'])
            update_date = parser.parse(line['service_update_date'])
            assert create_date < update_date

    @pytest.mark.usefixtures('ignore_nplusone')
    def test_export_csv_with_custom_fields(self, session, test_client, workspace):

        custom_field_schema = CustomFieldsSchemaFactory(
            field_name='cvss',
            field_type='str',
            field_display_name='CVSS',
            table_name='vulnerability'
        )
        session.add(custom_field_schema)
        session.commit()
        for vuln in self.objects:
            vuln.custom_fields = {"cvss": "9"}

        # lets add a non "schema" custom field called invalid, this should not be shown on the csv
        self.first_object.custom_fields = {"cvss": "9", "invalid": "not shown"}
        # another case witt custom fields as None
        vuln = VulnerabilityFactory.create(workspace=workspace)
        vuln.custom_fields = None
        session.add(vuln)
        session.commit()

        res = test_client.get(f'/v3/ws/{workspace.name}/vulns/filter?export_csv=true')

        assert res.status_code == 200
        assert self._verify_csv(res.data)

    def test_patch_vulnerability_credentials(self, test_client, session, workspace):
        """Test patching a vulnerability to add credentials"""
        # Create a vulnerability
        vuln = VulnerabilityFactory.create(workspace=workspace)
        session.add(vuln)

        # Create credentials
        cred1 = CredentialFactory.create(workspace=workspace)
        cred2 = CredentialFactory.create(workspace=workspace)
        session.add(cred1)
        session.add(cred2)
        session.commit()

        # Patch the vulnerability to add credentials
        patch_data = {
            'credentials': [cred1.id, cred2.id]
        }

        res = test_client.patch(
            f'/v3/ws/{workspace.name}/vulns/{vuln.id}',
            data=patch_data
        )

        assert res.status_code == 200

        # Verify credentials were added
        updated_vuln = session.query(VulnerabilityGeneric).get(vuln.id)
        credential_ids = [c.id for c in updated_vuln.credentials]
        assert len(credential_ids) == 2
        assert cred1.id in credential_ids
        assert cred2.id in credential_ids

        # Check if the vulnerability is in the credentials
        assert vuln in cred1.vulnerabilities
        assert vuln in cred2.vulnerabilities


@pytest.mark.usefixtures('logged_user')
class TestCustomFieldVulnerability(ReadWriteAPITests):
    model = Vulnerability
    factory = factories.VulnerabilityFactory
    api_endpoint = 'vulns'
    view_class = VulnerabilityWorkspacedView
    patchable_fields = ['name']

    def test_create_vuln_with_custom_fields_shown(self, test_client, second_workspace, session):
        host = HostFactory.create(workspace=self.workspace)
        custom_field_schema = CustomFieldsSchemaFactory(
            field_name='cvss',
            field_type='str',
            field_display_name='CVSS',
            table_name='vulnerability'
        )
        session.add(host)
        session.add(custom_field_schema)
        session.commit()
        data = {
            'name': 'Test Alert policy_violations',
            'severity': 'informational',
            'creator': 'Zap',
            'parent_type': 'Host',
            'parent': host.id,
            'type': 'Vulnerability',
            'custom_fields': {
                'cvss': '321321',
            }
        }
        res = test_client.post(self.url(), data=data)

        assert res.status_code == 201
        assert res.json['custom_fields']['cvss'] == '321321'

    def test_create_vuln_with_custom_fields_using_field_display_name_continues_with_warning(self, test_client,
                                                                                            second_workspace, session,
                                                                                            caplog):
        host = HostFactory.create(workspace=self.workspace)
        custom_field_schema = CustomFieldsSchemaFactory(
            field_name='cvss',
            field_type='str',
            field_display_name='CVSS',
            table_name='vulnerability'
        )
        session.add(host)
        session.add(custom_field_schema)
        session.commit()
        data = {
            'name': 'Test Alert policy_violations',
            'severity': 'informational',
            'creator': 'Zap',
            'parent_type': 'Host',
            'parent': host.id,
            'type': 'Vulnerability',
            'custom_fields': {
                'CVSS': '321321',  # here we use the field_name and not the display_name
            }
        }
        res = test_client.post(self.url(), data=data)

        assert res.status_code == 201
        assert "Invalid custom field" in caplog.text

    def test_create_vuln_with_custom_fields_list(self, test_client, second_workspace, session):
        host = HostFactory.create(workspace=self.workspace)
        custom_field_schema = CustomFieldsSchemaFactory(
            field_name='changes',
            field_type='list',
            field_display_name='Changes',
            table_name='vulnerability'
        )
        session.add(host)
        session.add(custom_field_schema)
        session.commit()
        data = {
            'name': 'Test Alert policy_violations',
            'severity': 'informational',
            'creator': 'Zap',
            'parent_type': 'Host',
            'parent': host.id,
            'type': 'Vulnerability',
            'custom_fields': {
                'changes': ['1', '2', '3'],
            }
        }
        res = test_client.post(self.url(), data=data)

        assert res.status_code == 201
        assert res.json['custom_fields']['changes'] == ['1', '2', '3']

    def test_create_vuln_with_custom_fields_with_invalid_type_fails(self, test_client, second_workspace, session):
        host = HostFactory.create(workspace=self.workspace)
        custom_field_schema = CustomFieldsSchemaFactory(
            field_name='cvss',
            field_type='int',
            field_display_name='CVSS',
            table_name='vulnerability'
        )
        session.add(host)
        session.add(custom_field_schema)
        session.commit()
        data = {
            'name': 'Test Alert policy_violations',
            'severity': 'informational',
            'creator': 'Zap',
            'parent_type': 'Host',
            'parent': host.id,
            'type': 'Vulnerability',
            'custom_fields': {
                'cvss': 'pepe',
            }
        }
        res = test_client.post(self.url(), data=data)

        assert res.status_code == 400

    def test_bulk_update_custom_attributes(self, test_client, session):
        host = HostFactory.create(workspace=self.workspace)
        custom_field_schema = CustomFieldsSchemaFactory(
            field_name='string',
            field_type='str',
            field_display_name='string',
            table_name='vulnerability'
        )
        custom_field_schema2 = CustomFieldsSchemaFactory(
            field_name='int',
            field_type='int',
            field_display_name='int',
            table_name='vulnerability'
        )
        custom_field_schema3 = CustomFieldsSchemaFactory(
            field_name='string2',
            field_type='str',
            field_display_name='string2',
            table_name='vulnerability'
        )
        session.add(host)
        session.add(custom_field_schema)
        session.add(custom_field_schema2)
        session.add(custom_field_schema3)
        session.commit()
        vuln1 = VulnerabilityFactory.create(workspace=self.workspace)
        vuln2 = VulnerabilityFactory.create(workspace=self.workspace)
        vuln3 = VulnerabilityFactory.create(workspace=self.workspace)
        vuln1.custom_fields = {}
        vuln2.custom_fields = {}
        vuln3.custom_fields = {}
        session.add(vuln1)
        session.add(vuln2)
        session.add(vuln3)

        vuln_id_1 = vuln1.id
        vuln_id_2 = vuln2.id
        vuln_id_3 = vuln3.id

        # Bulk update: Add a custom attribute to both vulnerabilities

        bulk_update_data = {
            "ids": [vuln_id_1, vuln_id_2],
            "custom_fields": {"string": "test"}
        }

        res_update = test_client.patch(self.url(workspace=self.workspace), data=bulk_update_data)

        assert res_update.status_code == 200

        vuln_1 = Vulnerability.query.get(vuln_id_1)
        vuln_2 = Vulnerability.query.get(vuln_id_2)

        assert vuln_1.custom_fields['string'] == "test"
        assert vuln_2.custom_fields['string'] == "test"

        # Bulk update: Add another custom attribute to both vulnerabilities

        bulk_update_data = {
            "ids": [vuln_id_1, vuln_id_2],
            "custom_fields": {"int": 10000}
        }

        res_update = test_client.patch(self.url(workspace=self.workspace), data=bulk_update_data)

        assert res_update.status_code == 200

        vuln_1 = Vulnerability.query.get(vuln_id_1)
        vuln_2 = Vulnerability.query.get(vuln_id_2)

        custom_fields = {"string": "test", "int": 10000}

        assert vuln_1.custom_fields == custom_fields
        assert vuln_2.custom_fields == custom_fields

        # Bulk update: Update an existing custom attribute in both vulnerabilities

        bulk_update_data = {
            "ids": [vuln_id_1, vuln_id_2],
            "custom_fields": {"string": "test2"}
        }

        res_update = test_client.patch(self.url(workspace=self.workspace), data=bulk_update_data)

        assert res_update.status_code == 200

        vuln_1 = Vulnerability.query.get(vuln_id_1)
        vuln_2 = Vulnerability.query.get(vuln_id_2)

        custom_fields = {"string": "test2", "int": 10000}

        assert vuln_1.custom_fields == custom_fields
        assert vuln_2.custom_fields == custom_fields

        # Bulk update: Add a custom attribute to two of three vulnerabilities

        bulk_update_data = {
            "ids": [vuln_id_1, vuln_id_3],
            "custom_fields": {"string2": "string2"}
        }

        res_update = test_client.patch(self.url(workspace=self.workspace), data=bulk_update_data)

        assert res_update.status_code == 200

        vuln_1 = Vulnerability.query.get(vuln_id_1)
        vuln_2 = Vulnerability.query.get(vuln_id_2)
        vuln_3 = Vulnerability.query.get(vuln_id_3)

        assert "string2" not in vuln_2.custom_fields.keys()
        assert vuln_2.custom_fields == custom_fields
        assert vuln_3.custom_fields == {"string2": "string2"}
        assert vuln_1.custom_fields == {"string2": "string2", "string": "test2", "int": 10000}

    def test_bulk_update_create_command(self, test_client, session):
        ws = WorkspaceFactory(name='abc')
        vuln1 = VulnerabilityFactory.create(workspace=ws)
        vuln2 = VulnerabilityFactory.create(workspace=ws)
        session.add(vuln1)
        session.add(vuln2)
        session.commit()
        update_data = {
            "ids": [vuln1.id, vuln2.id],
            "desc": "UPDATED",
            "description": "UPDATED"
        }
        res = test_client.patch(f'/v3/ws/{ws.name}/vulns', data=update_data)
        assert res.status_code == 200

        _command = session.query(Command).filter(Command.command == "bulk_update").first()
        assert _command

    def test_create_vuln_with_invalid_custom_fields_continues_with_warning(self, test_client, second_workspace, session,
                                                                           caplog):
        host = HostFactory.create(workspace=self.workspace)
        session.add(host)
        session.commit()
        data = {
            'name': 'Test Alert policy_violations',
            'severity': 'informational',
            'creator': 'Zap',
            'parent_type': 'Host',
            'parent': host.id,
            'type': 'Vulnerability',
            'custom_fields': {
                'CVSS': '321321',
            }
        }
        res = test_client.post(self.url(), data=data)

        assert res.status_code == 201
        assert "Invalid custom field" in caplog.text

    def test_create_create_vuln_web_with_host_as_parent_fails(
            self, host, session, test_client):
        session.commit()  # flush host_with_hostnames
        raw_data = _create_post_data_vulnerability(
            name='Empty desc',
            vuln_type='VulnerabilityWeb',
            parent_id=host.id,
            parent_type='Host',
            refs=[],
            policyviolations=[],
            description='',
            severity='low',
        )
        res = test_client.post(self.url(), data=raw_data)
        assert res.status_code == 400

    def test_create_create_vuln_web_with_host_as_parent_fails_using_service_id(
            self, host, session, test_client):
        service = ServiceFactory.create(workspace=host.workspace)
        session.commit()  # flush host_with_hostnames
        raw_data = _create_post_data_vulnerability(
            name='Empty desc',
            vuln_type='VulnerabilityWeb',
            parent_id=host.id,
            parent_type='Host',
            service_id=service.id,
            refs=[],
            policyviolations=[],
            description='',
            severity='low',
        )
        res = test_client.post(self.url(), data=raw_data)
        assert res.status_code == 400

    @pytest.mark.usefixtures('ignore_nplusone')
    def test_bulk_delete_vuln_id(self, host_with_hostnames, test_client, session):
        """
        This one should only check basic vuln properties
        :param host_with_hostnames:
        :param test_client:
        :param session:
        :return:
        """
        session.commit()  # flush host_with_hostnames
        raw_data_vuln_1 = _create_post_data_vulnerability(
            name='New vuln 1',
            vuln_type='Vulnerability',
            parent_id=host_with_hostnames.id,
            parent_type='Host',
            refs=[],
            policyviolations=[],
            description='helloworld 1',
            severity='low',
        )
        raw_data_vuln_2 = _create_post_data_vulnerability(
            name='New vuln 2',
            vuln_type='Vulnerability',
            parent_id=host_with_hostnames.id,
            parent_type='Host',
            refs=[],
            policyviolations=[],
            description='helloworld 2',
            severity='low',
        )
        ws_name = host_with_hostnames.workspace.name
        vuln_count_previous = session.query(Vulnerability).count()
        res_1 = test_client.post(f'/v3/ws/{ws_name}/vulns', data=raw_data_vuln_1)
        res_2 = test_client.post(f'/v3/ws/{ws_name}/vulns', data=raw_data_vuln_2)
        vuln_1_id = int(res_1.json['obj_id'])
        vuln_2_id = int(res_2.json['obj_id'])
        vulns_to_delete = [vuln_1_id, vuln_2_id]
        request_data = {'ids': vulns_to_delete}
        delete_response = test_client.delete(f'/v3/ws/{ws_name}/vulns', data=request_data)
        vuln_count_after = session.query(Vulnerability).count()
        deleted_vulns = delete_response.json['deleted']
        assert delete_response.status_code == 200
        assert vuln_count_previous == vuln_count_after
        assert deleted_vulns == len(vulns_to_delete)

    @pytest.mark.usefixtures('ignore_nplusone')
    @pytest.mark.skip(reason="To be reimplemented")
    def test_bulk_delete_vuln_severity(self, host_with_hostnames, test_client, session):
        """
        This one should only check basic vuln properties
        :param host_with_hostnames:
        :param test_client:
        :param session:
        :return:
        """
        session.commit()  # flush host_with_hostnames
        raw_data_vuln_1 = _create_post_data_vulnerability(
            name='New vuln 1',
            vuln_type='Vulnerability',
            parent_id=host_with_hostnames.id,
            parent_type='Host',
            refs=[],
            policyviolations=[],
            description='helloworld 1',
            severity='low',
        )
        raw_data_vuln_2 = _create_post_data_vulnerability(
            name='New vuln 2',
            vuln_type='Vulnerability',
            parent_id=host_with_hostnames.id,
            parent_type='Host',
            refs=[],
            policyviolations=[],
            description='helloworld 2',
            severity='low',
        )
        ws_name = host_with_hostnames.workspace.name
        vuln_count_previous = session.query(Vulnerability).count()
        res_1 = test_client.post(f'/v3/ws/{ws_name}/vulns', data=raw_data_vuln_1)
        res_2 = test_client.post(f'/v3/ws/{ws_name}/vulns', data=raw_data_vuln_2)
        vuln_1_id = res_1.json['obj_id']
        vuln_2_id = res_2.json['obj_id']
        vulns_to_delete = [vuln_1_id, vuln_2_id]
        request_data = {'severities': ['low']}
        delete_response = test_client.delete(f'/v3/ws/{ws_name}/vulns/bulk_delete', data=request_data)
        vuln_count_after = session.query(Vulnerability).count()
        deleted_vulns = delete_response.json['deleted_vulns']
        assert delete_response.status_code == 200
        assert vuln_count_previous == vuln_count_after
        assert deleted_vulns == len(vulns_to_delete)

    def test_create_vuln_with_tool(self, host_with_hostnames, test_client, session):
        """
        This one should only check basic vuln properties
        :param host_with_hostnames:
        :param test_client:
        :param session:
        :return:
        """
        session.commit()  # flush host_with_hostnames
        tool_name = "tool_name"
        raw_data = _create_post_data_vulnerability(
            name='New vulns',
            vuln_type='Vulnerability',
            parent_id=host_with_hostnames.id,
            parent_type='Host',
            refs=[],
            policyviolations=[],
            description='helloworld',
            severity='low',
            tool=tool_name
        )
        ws = host_with_hostnames.workspace
        vuln_count_previous = session.query(Vulnerability).count()
        res = test_client.post(self.url(workspace=ws), data=raw_data)
        assert res.status_code == 201
        assert vuln_count_previous + 1 == session.query(Vulnerability).count()
        assert res.json['tool'] == tool_name

    def test_create_vuln_without_tool(self, host_with_hostnames, test_client, session):
        """
        This one should only check basic vuln properties
        :param host_with_hostnames:
        :param test_client:
        :param session:
        :return:
        """
        session.commit()  # flush host_with_hostnames
        raw_data = _create_post_data_vulnerability(
            name='New vulns',
            vuln_type='Vulnerability',
            parent_id=host_with_hostnames.id,
            parent_type='Host',
            refs=[],
            policyviolations=[],
            description='helloworld',
            severity='low',
        )
        ws = host_with_hostnames.workspace
        vuln_count_previous = session.query(Vulnerability).count()
        res = test_client.post(self.url(workspace=ws), data=raw_data)
        assert res.status_code == 201
        assert vuln_count_previous + 1 == session.query(Vulnerability).count()
        assert res.json['tool'] == "Web UI"

    def test_create_vuln_from_command_with_tool(self, test_client, session):
        command = EmptyCommandFactory.create(workspace=self.workspace)
        service = ServiceFactory.create(workspace=self.workspace)
        session.commit()
        tool = "tool_name"
        url = self.url(workspace=command.workspace) + '?' + urlencode({'command_id': command.id})
        raw_data = _create_post_data_vulnerability(
            name='Update vulnsweb',
            vuln_type='VulnerabilityWeb',
            parent_id=service.id,
            parent_type='Service',
            refs=[],
            policyviolations=[],
            description='helloworld',
            severity='high',
            tool=tool
        )
        res = test_client.post(url, data=raw_data)
        assert res.status_code == 201
        assert len(command.command_objects) == 1
        cmd_obj = command.command_objects[0]
        assert cmd_obj.object_type == 'vulnerability'
        assert cmd_obj.object_id == res.json['_id']
        assert res.json['tool'] == tool

    def test_create_vuln_from_command_without_tool(self, test_client, session):
        command = EmptyCommandFactory.create(workspace=self.workspace)
        service = ServiceFactory.create(workspace=self.workspace)
        session.commit()
        url = self.url(workspace=command.workspace) + '?' + urlencode({'command_id': command.id})
        raw_data = _create_post_data_vulnerability(
            name='Update vulnsweb',
            vuln_type='VulnerabilityWeb',
            parent_id=service.id,
            parent_type='Service',
            refs=[],
            policyviolations=[],
            description='helloworld',
            severity='high',
        )
        res = test_client.post(url, data=raw_data)
        assert res.status_code == 201
        assert len(command.command_objects) == 1
        cmd_obj = command.command_objects[0]
        assert cmd_obj.object_type == 'vulnerability'
        assert cmd_obj.object_id == res.json['_id']
        assert res.json['tool'] == command.tool

    def test_custom_field_cvss(self, session, test_client):
        add_text_field = CustomFieldsSchemaFactory.create(
            table_name='vulnerability',
            field_name='cvss',
            field_type='text',
            field_display_name='CVSS',
        )
        session.add(add_text_field)
        session.commit()

    # @pytest.mark.usefixtures('ignore_nplusone')
    def test_bulk_delete_by_severity(self, test_client):
        all_objs = self.model.query.all()
        for obj in all_objs[0:2]:
            obj.severity = 'low'  # Factory just use "critical" or "high"

        data = {"severities": ["low"]}
        res = test_client.delete(self.url(), data=data)
        assert res.status_code == 200
        assert all([was_deleted(obj) for obj in all_objs[0:2]])
        assert res.json['deleted'] == 2
        assert all([not was_deleted(obj) for obj in all_objs[2:]])
        assert self.model.query.count() == 3

    def test_bulk_delete_by_severity_invalid_severity(self, test_client):
        all_objs = self.model.query.all()
        for obj in all_objs[0:2]:
            obj.severity = 'low'  # Factory just use "critical" or "high"

        data = {"severities": ["sarasa"]}
        res = test_client.delete(self.url(), data=data)
        assert res.status_code == 400


@pytest.mark.usefixtures('logged_user')
class TestVulnerabilitySearch:

    @pytest.mark.skip_sql_dialect('sqlite')
    def test_search_by_hostname_vulns(self, test_client, session):
        workspace = WorkspaceFactory.create()
        host = HostFactory.create(workspace=workspace)
        host.hostnames.append(HostnameFactory.create(name='pepe', workspace=workspace))
        vuln = VulnerabilityFactory.create(host=host, service=None, workspace=workspace)
        session.add(vuln)
        session.add(host)
        session.commit()

        query_filter = {"filters":
                            [{"name": "hostnames", "op": "eq", "val": "pepe"}]
                        }
        res = test_client.get(
            f'/v3/ws/{workspace.name}/vulns/filter?q={json.dumps(query_filter)}'
        )
        assert res.status_code == 200
        assert res.json['count'] == 1
        assert res.json['vulnerabilities'][0]['id'] == vuln.id

    @pytest.mark.skip_sql_dialect('sqlite')
    def test_search_by_hostname_vulns_with_service(self, test_client, session):
        workspace = WorkspaceFactory.create()
        host = HostFactory.create(workspace=workspace)
        host.hostnames.append(HostnameFactory.create(name='pepe', workspace=workspace))
        service = ServiceFactory.create(host=host, workspace=workspace)
        vuln = VulnerabilityFactory.create(host=None, service=service, workspace=workspace)
        session.add(vuln)
        session.add(host)
        session.commit()

        query_filter = {"filters":
                            [{"name": "hostnames", "op": "eq", "val": "pepe"}]
                        }
        res = test_client.get(
            f'/v3/ws/{workspace.name}/vulns?q={json.dumps(query_filter)}'
        )
        assert res.status_code == 200
        assert res.json['count'] == 1
        assert res.json['vulnerabilities'][0]['id'] == vuln.id

    @pytest.mark.skip_sql_dialect('sqlite')
    @pytest.mark.usefixtures('ignore_nplusone')
    def test_search_hostname_web_vulns(self, test_client, session):
        workspace = WorkspaceFactory.create()
        host = HostFactory.create(workspace=workspace)
        host.hostnames.append(HostnameFactory.create(name='pepe', workspace=workspace))
        service = ServiceFactory.create(host=host, workspace=workspace)
        vuln = VulnerabilityWebFactory.create(service=service, workspace=workspace)
        session.add(vuln)
        session.add(host)
        session.commit()

        query_filter = {"filters":
                            [{"name": "hostnames", "op": "eq", "val": "pepe"}]
                        }
        res = test_client.get(
            f'/v3/ws/{workspace.name}/vulns/filter?q={json.dumps(query_filter)}'
        )
        assert res.status_code == 200
        assert res.json['count'] == 1
        assert res.json['vulnerabilities'][0]['id'] == vuln.id

    def test_search_empty_filters(self, workspace, test_client, session):
        query_filter = {"filters":
                            []
                        }
        res = test_client.get(
            f'/v3/ws/{workspace.name}/vulns/filter?q={json.dumps(query_filter)}'
        )
        assert res.status_code == 200
        assert res.json['count'] == 0

    def test_search_code_attribute_bug(self, workspace, test_client, session):
        query_filter = {"filters":
                            [{"name": "code", "op": "eq", "val": "test"}]
                        }
        res = test_client.get(
            f'/v3/ws/{workspace.name}/vulns/filter?q={json.dumps(query_filter)}'
        )

        assert res.status_code == 400, res.json

    @pytest.mark.skip_sql_dialect('sqlite')
    def test_search_by_hostname_multiple_logic(self, test_client, session):
        workspace = WorkspaceFactory.create()
        host = HostFactory.create(workspace=workspace)
        host.hostnames.append(HostnameFactory.create(name='pepe', workspace=workspace))
        vuln = VulnerabilityFactory.create(host=host, service=None, workspace=workspace)
        session.add(vuln)
        session.add(host)
        session.commit()

        query_filter = {"filters": [
            {"and": [{"name": "hostnames", "op": "eq", "val": "pepe"}]}
        ]}
        res = test_client.get(
            f'/v3/ws/{workspace.name}/vulns/filter?q={json.dumps(query_filter)}'
        )
        assert res.status_code == 200
        assert res.json['count'] == 1
        assert res.json['vulnerabilities'][0]['id'] == vuln.id

    @pytest.mark.skip_sql_dialect('sqlite')
    @pytest.mark.usefixtures('ignore_nplusone')
    def test_search_filter_offset_and_limit_mixed_vulns_type_bug(self, test_client, session):
        workspace = WorkspaceFactory.create()
        host = HostFactory.create(workspace=workspace)
        vulns = VulnerabilityFactory.create_batch(10,
                                                  workspace=workspace,
                                                  severity='high'
                                                  )
        session.add_all(vulns)
        web_vulns = VulnerabilityWebFactory.create_batch(10,
                                                         workspace=workspace,
                                                         severity='high'
                                                         )
        session.add_all(web_vulns)
        session.add(host)
        session.commit()
        paginated_vulns = set()
        expected_vulns = set([vuln.id for vuln in vulns] + [vuln.id for vuln in web_vulns])
        for offset in range(0, 2):
            query_filter = {
                "filters": [{"name": "severity", "op": "eq", "val": "high"}],
                "limit": 10,
                "offset": offset * 10,
            }
            res = test_client.get(
                f'/v3/ws/{workspace.name}/vulns/filter?q={json.dumps(query_filter)}'
            )
            assert res.status_code == 200
            assert res.json['count'] == 20, query_filter
            assert len(res.json['vulnerabilities']) == 10
            for vuln in res.json['vulnerabilities']:
                paginated_vulns.add(vuln['id'])
        assert expected_vulns == paginated_vulns

    @pytest.mark.skip_sql_dialect('sqlite')
    @pytest.mark.usefixtures('ignore_nplusone')
    def test_search_filter_offset_and_limit_page_size_10(self, test_client, session):
        workspace = WorkspaceFactory.create()
        host = HostFactory.create(workspace=workspace)
        vulns = VulnerabilityWebFactory.create_batch(100,
                                                     workspace=workspace,
                                                     severity='high'
                                                     )
        session.add_all(vulns)
        session.add(host)
        session.commit()
        paginated_vulns = set()
        expected_vulns = {vuln.id for vuln in vulns}
        for offset in range(0, 10):
            query_filter = {
                "filters": [{"name": "severity", "op": "eq", "val": "high"}],
                "limit": 10,
                "offset": 10 * offset,
            }
            res = test_client.get(
                f'/v3/ws/{workspace.name}/vulns/filter?q={json.dumps(query_filter)}'
            )
            assert res.status_code == 200
            assert res.json['count'] == 100
            for vuln in res.json['vulnerabilities']:
                paginated_vulns.add(vuln['id'])
        assert expected_vulns == paginated_vulns

    @pytest.mark.skip_sql_dialect('sqlite')
    @pytest.mark.usefixtures('ignore_nplusone')
    def test_search_filter_offset_and_limit(self, test_client, session):
        workspace = WorkspaceFactory.create()
        host = HostFactory.create(workspace=workspace)
        vulns = VulnerabilityWebFactory.create_batch(10,
                                                     workspace=workspace,
                                                     severity='high'
                                                     )
        session.add_all(vulns)
        vulns = VulnerabilityFactory.create_batch(10,
                                                  workspace=workspace,
                                                  severity='low'
                                                  )
        session.add_all(vulns)
        med_vulns = VulnerabilityFactory.create_batch(10,
                                                      workspace=workspace,
                                                      severity='medium'
                                                      )
        session.add_all(med_vulns)
        session.add(host)
        session.commit()
        paginated_vulns = set()
        expected_vulns = {vuln.id for vuln in med_vulns}
        for offset in range(0, 10):
            query_filter = {
                "filters": [{"name": "severity", "op": "eq", "val": "medium"}],
                "limit": "1",
                "offset": offset,
            }
            res = test_client.get(
                f'/v3/ws/{workspace.name}/vulns/filter?q={json.dumps(query_filter)}'
            )
            assert res.status_code == 200
            assert res.json['count'] == 10
            paginated_vulns.add(res.json['vulnerabilities'][0]['id'])

        assert expected_vulns == paginated_vulns

    def test_vuln_get_limit(self, test_client, session):

        # Change setting
        test_client.patch('/v3/settings/query_limits', data={"vuln_query_limit": 25})

        workspace = WorkspaceFactory.create()
        host = HostFactory.create(workspace=workspace)
        vulns = VulnerabilityWebFactory.create_batch(50,
                                                     workspace=workspace,
                                                     severity='high'
                                                     )
        session.add_all(vulns)
        session.add(host)
        session.commit()

        res = test_client.get(f'/v3/ws/{workspace.name}/vulns')

        assert res.status_code == 200
        assert res.json['count'] == 50
        assert len(res.json['vulnerabilities']) == 25

    @pytest.mark.parametrize("limit", [
        ["5", 5],
        [None, 25],
        ["100", 25]
    ])
    def test_vuln_filter_limit(self, test_client, session, limit):

        # Change setting
        test_client.patch('/v3/settings/query_limits', data={"vuln_query_limit": 25})

        workspace = WorkspaceFactory.create()
        host = HostFactory.create(workspace=workspace)
        vulns = VulnerabilityWebFactory.create_batch(50,
                                                     workspace=workspace,
                                                     severity='high'
                                                     )
        session.add_all(vulns)
        session.add(host)
        session.commit()

        if limit[0] is None:
            query_filter = {}
        else:
            query_filter = {
                "filters": [],
                "limit": limit[0],
                "offset": "1",
            }
        res = test_client.get(
            f'/v3/ws/{workspace.name}/vulns/filter?q={json.dumps(query_filter)}'
        )
        assert res.status_code == 200
        assert res.json['count'] == 50
        assert len(res.json['vulnerabilities']) == limit[1]

    @pytest.mark.skip_sql_dialect('sqlite')
    @pytest.mark.usefixtures('ignore_nplusone')
    @pytest.mark.skip(reason="We need a better solution for searching in the model.")
    def test_search_by_host_os_with_vulnerability_web_bug(self, test_client, session):
        """
            When searching by the host os an error was raised when a vuln web exists in the ws
        """
        workspace = WorkspaceFactory.create()
        host = HostFactory.create(workspace=workspace, os='Linux')
        service = ServiceFactory.create(host=host, workspace=workspace)
        vuln = VulnerabilityFactory.create(
            service=service,
            confirmed=True,
            workspace=workspace,
        )
        host2 = HostFactory.create(workspace=workspace, os='OS/2')
        vuln2 = VulnerabilityFactory.create(
            confirmed=True,
            host=host2,
            service=None,
            workspace=workspace,
        )
        session.add(vuln)
        session.add(vuln2)
        session.add(host)
        session.commit()

        query_filter = {"filters": [
            {"name": "host__os", "op": "has", "val": "Linux"}
        ]}
        res = test_client.get(
            f'/v3/ws/{workspace.name}/vulns/filter?q={json.dumps(query_filter)}'
        )
        assert res.status_code == 200
        assert res.json['count'] == 1
        assert res.json['vulnerabilities'][0]['id'] == vuln.id

    @pytest.mark.skip_sql_dialect('sqlite')
    @pytest.mark.usefixtures('ignore_nplusone')
    def test_search_by_date_equals(self, test_client, session):
        """
            When searching by the host os an error was raised when a vuln web exists in the ws
        """
        workspace = WorkspaceFactory.create()
        service = ServiceFactory.create(workspace=workspace)
        vuln = VulnerabilityWebFactory.create(
            service=service,
            confirmed=True,
            workspace=workspace,
            create_date=datetime.datetime(2020, 7, 8)
        )
        vuln2 = VulnerabilityFactory.create(
            confirmed=True,
            service=None,
            workspace=workspace,
            create_date=datetime.datetime(2020, 7, 8, 13, 59, 59)
        )
        vuln3 = VulnerabilityFactory.create(
            confirmed=True,
            service=None,
            workspace=workspace,
            create_date=datetime.datetime(2020, 7, 8, 23, 59, 59)
        )
        vuln4 = VulnerabilityFactory.create(
            confirmed=True,
            service=None,
            workspace=workspace,
            create_date=datetime.datetime(2019, 7, 8, 23, 59, 59)
        )
        session.add(vuln)
        session.add(vuln2)
        session.add(vuln3)
        session.add(vuln4)
        session.commit()

        query_filter = {"filters": [
            {"name": "create_date", "op": "eq", "val": vuln.create_date.strftime("%Y-%m-%d")}
        ]}
        res = test_client.get(
            f'/v3/ws/{workspace.name}/vulns/filter?q={json.dumps(query_filter)}'
        )
        assert res.status_code == 200
        assert res.json['count'] == 3

    @pytest.mark.skip_sql_dialect('sqlite')
    def test_search_by_date_equals_invalid_date(self, test_client, session):
        """
            When searching by the host os an error was raised when a vuln web exists in the ws
        """
        workspace = WorkspaceFactory.create()
        query_filter = {"filters": [
            {"name": "create_date", "op": "eq", "val": "30/01/2020"}
        ]}
        res = test_client.get(
            f'/v3/ws/{workspace.name}/vulns/filter?q={json.dumps(query_filter)}'
        )
        assert res.status_code == 400

    @pytest.mark.skip_sql_dialect('sqlite')
    def test_search_hypothesis_test_found_case(self, test_client, session, workspace):
        query_filter = {'filters': [{'name': 'host_id', 'op': 'not_in',
                                     'val': '\U0010a1a7\U00093553\U000eb46a\x1e\x10\r\x18%\U0005ddfa0\x05\U000fdeba\x08\x04絮'}]}
        res = test_client.get(
            f'/v3/ws/{workspace.name}/vulns/filter?q={json.dumps(query_filter)}'
        )
        assert res.status_code == 400

    @pytest.mark.skip_sql_dialect('sqlite')
    def test_search_hypothesis_test_found_case_2(self, test_client, session, workspace):
        query_filter = {'filters': [{'name': 'host__os', 'op': 'ilike', 'val': -1915870387}]}
        res = test_client.get(
            f'/v3/ws/{workspace.name}/vulns/filter?q={json.dumps(query_filter)}'
        )
        assert res.status_code == 400

    @pytest.mark.skip_sql_dialect('sqlite')
    @pytest.mark.parametrize('query_filter', [
        {'filters': [{'name': 'workspace_id', 'op': '==', 'val': ''}]},
        {'filters': [{'name': 'type', 'op': '==', 'val': -24286}]},
        {'filters': [{'name': 'risk', 'op': 'ilike', 'val': -881419975}]},
    ])
    def test_search_hypothesis_test_found_case_3(self, query_filter, test_client, session, workspace):
        res = test_client.get(
            f'/v3/ws/{workspace.name}/vulns/filter?q={json.dumps(query_filter)}'
        )
        assert res.status_code == 400

    @pytest.mark.skip_sql_dialect('sqlite')
    @pytest.mark.parametrize('query_filter', [
        {'filters': [{'name': 'workspace_id', 'op': 'in', 'val': 56}]},
        {'filters': [{'name': 'creator', 'op': 'in', 'val': 56}]},
        {'filters': [{'name': 'creator_id', 'op': 'not_in', 'val': 0}]}
    ])
    def test_search_hypothesis_test_found_case_4(self, query_filter, test_client, session, workspace):
        res = test_client.get(
            f'/v3/ws/{workspace.name}/vulns/filter?q={json.dumps(query_filter)}'
        )
        assert res.status_code == 400

    @pytest.mark.skip_sql_dialect('sqlite')
    @pytest.mark.parametrize('query_filter', [
        {'filters': [{'name': 'creator', 'op': 'geq', 'val': 27576}, {'name': 'name', 'op': 'eq', 'val': None}]},
        {'filters': [{'name': 'impact_confidentiality', 'op': 'ge', 'val': 0}]},
        {'filters': [{'name': 'creator', 'op': 'eq', 'val': -22}]}
    ])
    def test_search_hypothesis_test_found_case_5(self, query_filter, test_client, session, workspace):
        res = test_client.get(
            f'/v3/ws/{workspace.name}/vulns/filter?q={json.dumps(query_filter)}'
        )
        assert res.status_code == 400

    @pytest.mark.skip_sql_dialect('sqlite')
    def test_search_hypothesis_test_found_case_6(self, test_client, session, workspace):
        query_filter = {'filters': [{'name': 'resolution', 'op': '==', 'val': ''}]}
        res = test_client.get(
            f'/v3/ws/{workspace.name}/vulns/filter?q={json.dumps(query_filter)}'
        )
        assert res.status_code == 200

    @pytest.mark.skip_sql_dialect('sqlite')
    def test_search_hypothesis_test_found_case_7(self, test_client, session, workspace):
        query_filter = {'filters': [
            {'name': 'name', 'op': '>', 'val': '\U0004e755\U0007a789\U000e02d1\U000b3d32\x10\U000ad0e2,\x05\x1a'},
            {'name': 'creator', 'op': 'eq', 'val': 21883}]}
        res = test_client.get(
            f'/v3/ws/{workspace.name}/vulns/filter?q={json.dumps(query_filter)}'
        )
        assert res.status_code == 400

    @pytest.mark.skip_sql_dialect('sqlite')
    @pytest.mark.parametrize('query_filter', [
        {'filters': [{'name': 'id', 'op': '>', 'val': 3}]},
        {'filters': [{'name': 'create_date', 'op': '>', 'val': '2020-10-10'}]}
    ])
    def test_search_hypothesis_test_found_case_7_valid(self, query_filter, test_client, session, workspace):
        res = test_client.get(
            f'/v3/ws/{workspace.name}/vulns/filter?q={json.dumps(query_filter)}'
        )
        assert res.status_code == 200

    @pytest.mark.skip_sql_dialect('sqlite')
    def test_search_hypothesis_test_found_case_8(self, test_client, session, workspace):
        query_filter = {'filters': [{'name': 'hostnames', 'op': '==', 'val': ''}]}
        res = test_client.get(
            f'/v3/ws/{workspace.name}/vulns/filter?q={json.dumps(query_filter)}'
        )
        assert res.status_code == 200

    @pytest.mark.skip_sql_dialect('sqlite')
    def test_search_hypothesis_test_found_case_9(self, test_client, session, workspace):
        query_filter = {'filters': [{'name': 'issuetracker', 'op': 'not_equal_to',
                                     'val': '0\x00\U00034383$\x13-\U000375fb\U0007add2\x01\x01\U0010c23a'}]}

        res = test_client.get(
            f'/v3/ws/{workspace.name}/vulns/filter?q={json.dumps(query_filter)}'
        )
        assert res.status_code == 400

    @pytest.mark.skip_sql_dialect('sqlite')
    def test_search_hypothesis_test_found_case_10(self, test_client, session, workspace):
        query_filter = {'filters': [{'name': 'impact_integrity', 'op': 'neq', 'val': 0}]}

        res = test_client.get(
            f'/v3/ws/{workspace.name}/vulns/filter?q={json.dumps(query_filter)}'
        )
        assert res.status_code == 400

    @pytest.mark.skip_sql_dialect('sqlite')
    def test_search_hypothesis_test_found_case_11(self, test_client, session, workspace):
        query_filter = {'filters': [{'name': 'host_id', 'op': 'like', 'val': '0'}]}

        res = test_client.get(
            f'/v3/ws/{workspace.name}/vulns/filter?q={json.dumps(query_filter)}'
        )
        assert res.status_code == 400

    # TODO: Add new tests for custom_fields filters
    @pytest.mark.skip
    def test_search_hypothesis_test_found_case_12(self, test_client, session, workspace):
        query_filter = {'filters': [{'name': 'custom_fields', 'op': 'like', 'val': ''}]}

        res = test_client.get(
            f'/v3/ws/{workspace.name}/vulns/filter?q={json.dumps(query_filter)}'
        )
        assert res.status_code == 400

    @pytest.mark.skip_sql_dialect('sqlite')
    def test_search_hypothesis_test_found_case_13(self, test_client, session, workspace):
        query_filter = {'filters': [{'name': 'impact_accountability', 'op': 'ilike', 'val': '0'}]}

        res = test_client.get(
            f'/v3/ws/{workspace.name}/vulns/filter?q={json.dumps(query_filter)}'
        )
        assert res.status_code == 400

    @pytest.mark.usefixtures('ignore_nplusone')
    def test_filter_count(self, test_client, session, workspace):
        vulns_web = VulnerabilityWebFactory.create_batch(10, workspace=workspace, severity='high')
        vulns = VulnerabilityFactory.create_batch(10, workspace=workspace, severity='high')
        another_workspace = WorkspaceFactory.create()
        more_vulns = VulnerabilityFactory.create_batch(10, workspace=another_workspace, severity='high')
        session.add_all(more_vulns)
        session.add_all(vulns_web)
        session.add_all(vulns)
        session.commit()
        query_filter = {'filters': [{'name': 'severity', 'op': 'eq', 'val': 'high'}]}

        res = test_client.get(
            f'/v3/ws/{workspace.name}/vulns/filter?q={json.dumps(query_filter)}'
        )
        assert res.status_code == 200
        assert res.json['count'] == 20

    @pytest.mark.usefixtures('ignore_nplusone')
    def test_filter_group_and_sort(self, test_client, session, workspace):
        vulns_web = VulnerabilityWebFactory.create_batch(10, workspace=workspace, severity='high')
        vulns = VulnerabilityFactory.create_batch(10, workspace=workspace, severity='high')
        another_workspace = WorkspaceFactory.create()
        more_vulns = VulnerabilityFactory.create_batch(10, workspace=another_workspace, severity='high')
        session.add_all(more_vulns)
        session.add_all(vulns_web)
        session.add_all(vulns)
        session.commit()
        query_filter = {
            "group_by":
                [{"field": "severity"}],
            "order_by":
                [{"field": "name", "direction": "asc"}]
        }

        res = test_client.get(
            f'/v3/ws/{workspace.name}/vulns/filter?q={json.dumps(query_filter)}'
        )
        assert res.status_code == 400

    def test_filter_order_by_without_filters_fix_500_error(self, test_client, session, workspace):
        query_filter = {
            "order_by":
                [{"field": "cve_instances__name", "direction": "desc"}],
            "limit": 10,
            "offset": 0
        }

        res = test_client.get(
            f'/v3/ws/{workspace.name}/vulns/filter?q={json.dumps(query_filter)}'
        )
        assert res.status_code == 200

    @pytest.mark.skip_sql_dialect('sqlite')
    @pytest.mark.parametrize("sort_order", [
        {"direction": "asc", "expected": ['a', 'A', 'b', 'B']},
        {"direction": "desc", "expected": ['B', 'b', 'A', 'a']}
    ])
    def test_filter_order_by_name_directions(self, sort_order, test_client, session, workspace):
        vuln_1 = VulnerabilityWebFactory.create(name='a', workspace=workspace, severity='high')
        vuln_2 = VulnerabilityWebFactory.create(name='b', workspace=workspace, severity='high')
        vuln_3 = VulnerabilityWebFactory.create(name='A', workspace=workspace, severity='high')
        vuln_4 = VulnerabilityWebFactory.create(name='B', workspace=workspace, severity='high')

        session.add_all([vuln_1, vuln_2, vuln_3, vuln_4])
        session.commit()
        query_filter = {
            "order_by":
                [{"field": "name", "direction": sort_order["direction"]}],
            "limit": 10,
            "offset": 0
        }

        res = test_client.get(
            f'/v3/ws/{workspace.name}/vulns/filter?q={json.dumps(query_filter)}'
        )
        assert res.status_code == 200
        expected_order = sort_order["expected"]

        assert expected_order == [vuln['value']['name'] for vuln in res.json['vulnerabilities']]

    @pytest.mark.skip_sql_dialect('sqlite')
    def test_filter_order_by_severity(self, test_client, session, workspace):
        vuln_4 = VulnerabilityWebFactory.create(name='B', workspace=workspace, severity='low')
        vuln_1 = VulnerabilityWebFactory.create(name='a', workspace=workspace, severity='critical')
        vuln_3 = VulnerabilityWebFactory.create(name='A', workspace=workspace, severity='medium')
        vuln_2 = VulnerabilityWebFactory.create(name='b', workspace=workspace, severity='high')

        session.add_all([vuln_1, vuln_2, vuln_3, vuln_4])
        session.commit()
        query_filter = {
            "order_by":
                [{"field": "severity", "direction": "desc"}],
            "limit": 10,
            "offset": 0
        }

        res = test_client.get(
            f'/v3/ws/{workspace.name}/vulns/filter?q={json.dumps(query_filter)}'
        )
        assert res.status_code == 200
        expected_order = ['critical', 'high', 'med', 'low']

        assert expected_order == [vuln['value']['severity'] for vuln in res.json['vulnerabilities']]

        query_filter = {
            "order_by":
                [{"field": "severity", "direction": "asc"}],
            "limit": 10,
            "offset": 0
        }

        res = test_client.get(
            f'/v3/ws/{workspace.name}/vulns/filter?q={json.dumps(query_filter)}'
        )
        assert res.status_code == 200
        expected_order = ['low', 'med', 'high', 'critical']

        assert expected_order == [vuln['value']['severity'] for vuln in res.json['vulnerabilities']]

    def test_filter_by_creator_command_id(self,
                                          test_client,
                                          session,
                                          workspace,
                                          command_object_factory,
                                          empty_command_factory):

        command = empty_command_factory.create(workspace=workspace,
                                               tool="metasploit")
        session.commit()
        vulns_web = VulnerabilityWebFactory.create_batch(10, workspace=workspace, severity='high')
        vulns = VulnerabilityFactory.create_batch(100, workspace=workspace, severity='high')
        another_workspace = WorkspaceFactory.create()
        more_vulns = VulnerabilityFactory.create_batch(10, workspace=another_workspace, severity='high')
        session.add_all(more_vulns)
        session.add_all(vulns_web)
        session.add_all(vulns)
        session.commit()
        for vuln in vulns:
            command_object_factory.create(command=command,
                                          object_type='vulnerability',
                                          object_id=vuln.id,
                                          workspace=workspace)
        session.commit()

        query_filter = {
            "filters": [{"and": [
                {"name": "creator_command_id", "op": "==", "val": command.id}]
            }],
            "offset": 0,
            "limit": 40
        }

        res = test_client.get(
            f'/v3/ws/{workspace.name}/vulns/filter?q={json.dumps(query_filter)}'
        )
        assert res.status_code == 200
        assert res.json['count'] == 100

    def test_add_evidence_with_description(self, test_client, session, workspace, csrf_token):
        vuln = VulnerabilityFactory.create(workspace=workspace)
        session.add(vuln)
        session.commit()

        file_contents = b'Testing attachment with description'
        data = {
            'file': (BytesIO(file_contents), 'testing_description.txt'),
            'csrf_token': csrf_token,
            'description': 'Attachment description'
        }

        res = test_client.post(
            f'/v3/ws/{workspace.name}/vulns/{vuln.id}/attachment',
            data=data,
            use_json_data=False
        )
        assert res.status_code == 200

        # Get vulnerability created
        res = test_client.get(f'/v3/ws/{workspace.name}/vulns/{vuln.id}/attachment')
        assert res.status_code == 200
        attachments_json = res.json

        attachment = attachments_json['testing_description.txt']

        assert attachment['description'] == 'Attachment description'

    def test_patch_attachment_description(self, test_client, session, workspace, csrf_token):
        vuln = VulnerabilityFactory.create(workspace=workspace)
        session.add(vuln)
        session.commit()

        file_contents = b'Testing attachment with description'
        data = {
            'file': (BytesIO(file_contents), 'testing_description.txt'),
            'csrf_token': csrf_token,
            'description': 'Attachment description'
        }

        res = test_client.post(
            f'/v3/ws/{workspace.name}/vulns/{vuln.id}/attachment',
            data=data,
            use_json_data=False
        )
        assert res.status_code == 200

        patch_data = {'description': 'Updated attachment description'}
        res = test_client.patch(
            f'/v3/ws/{workspace.name}/vulns/{vuln.id}/attachment/testing_description.txt',
            json=patch_data,
        )

        assert res.status_code == 200

        updated_attachment = session.query(File).filter_by(
            object_type='vulnerability',
            object_id=vuln.id,
            filename='testing_description.txt'
        ).one()
        assert updated_attachment.description == 'Updated attachment description'

    def test_patch_attachment_description_bad_body(self, test_client, session, workspace, csrf_token):
        vuln = VulnerabilityFactory.create(workspace=workspace)
        session.add(vuln)
        session.commit()

        file_contents = b'Testing attachment with description'
        data = {
            'file': (BytesIO(file_contents), 'testing_description.txt'),
            'csrf_token': csrf_token,
            'description': 'Attachment description'
        }

        res = test_client.post(
            f'/v3/ws/{workspace.name}/vulns/{vuln.id}/attachment',
            data=data,
            use_json_data=False
        )
        assert res.status_code == 200

        patch_data = {'descriptions': 'Updated attachment description'}
        res = test_client.patch(
            f'/v3/ws/{workspace.name}/vulns/{vuln.id}/attachment/testing_description.txt',
            json=patch_data,
        )

        assert res.status_code == 400


def test_type_filter(workspace, session,
                     vulnerability_factory,
                     vulnerability_web_factory):
    filter_ = VulnerabilityWorkspacedFilterSet().filters['type']
    std_vulns = vulnerability_factory.create_batch(10, workspace=workspace)
    web_vulns = vulnerability_web_factory.create_batch(10, workspace=workspace)
    session.add_all(std_vulns)
    session.add_all(web_vulns)
    session.commit()

    std_filter = filter_.filter(VulnerabilityGeneric.query,
                                VulnerabilityGeneric,
                                'type',
                                'Vulnerability'
                                )
    assert {v.id for v in std_filter} == {v.id for v in std_vulns}

    web_filter = filter_.filter(VulnerabilityGeneric.query,
                                VulnerabilityGeneric,
                                'type',
                                'VulnerabilityWeb'
                                )
    assert {v.id for v in web_filter} == {v.id for v in web_vulns}


def test_creator_filter(workspace, session,
                        empty_command_factory, command_object_factory,
                        vulnerability_factory, vulnerability_web_factory):
    filter_ = VulnerabilityWorkspacedFilterSet().filters['creator']
    std_vulns = vulnerability_factory.create_batch(10,
                                                   workspace=workspace)[:5]
    session.add(workspace)
    web_vulns = vulnerability_web_factory.create_batch(10,
                                                       workspace=workspace)[:5]
    command = empty_command_factory.create(workspace=workspace,
                                           tool="metasploit")

    vulns = std_vulns + web_vulns
    session.add(command)
    session.add_all(vulns)
    session.commit()
    for vuln in vulns:
        command_object_factory.create(command=command,
                                      object_type='vulnerability',
                                      object_id=vuln.id,
                                      workspace=workspace)
    session.commit()

    filtered = filter_.filter(VulnerabilityGeneric.query,
                              VulnerabilityGeneric,
                              'creator',
                              'metasp')
    assert {v.id for v in filtered} == {v.id for v in vulns}


def test_service_filter(workspace, session, host, service_factory,
                        vulnerability_factory, vulnerability_web_factory):
    filter_ = VulnerabilityWorkspacedFilterSet().filters['service']

    vulnerability_factory.create_batch(5, host=host, service=None,
                                       workspace=workspace)
    other_service = service_factory.create(name='ftp', workspace=workspace)
    vulnerability_factory.create_batch(10, host=None, service=other_service,
                                       workspace=workspace)
    vulnerability_web_factory.create_batch(10, service=other_service,
                                           workspace=workspace)

    service = service_factory.create(name='http', workspace=workspace)
    vulns = []
    vulns = vulnerability_factory.create_batch(10, host=None, service=service,
                                               workspace=workspace)
    vulns += vulnerability_web_factory.create_batch(10, service=service,
                                                    workspace=workspace)
    session.commit()

    filtered = filter_.filter(VulnerabilityGeneric.query,
                              VulnerabilityGeneric,
                              'service',
                              'http')
    assert all(v.service and v.service.name == 'http'
               for v in filtered)
    assert {v.id for v in filtered} == {v.id for v in vulns}


def test_name_filter(workspace, session, host, vulnerability_factory):
    """Test case insensitivity and partial match detection"""
    filter_ = VulnerabilityWorkspacedFilterSet().filters['name']
    vulnerability_factory.create_batch(5, host=host, workspace=workspace)
    expected_vulns = vulnerability_factory.create_batch(
        5, host=host, workspace=workspace, name="Old OpenSSL version")
    session.add_all(expected_vulns)
    session.add(workspace)
    session.commit()
    filtered = filter_.filter(VulnerabilityGeneric.query,
                              VulnerabilityGeneric,
                              'name',
                              'openssl')
    assert {v.id for v in filtered} == {v.id for v in expected_vulns}


def vulnerability_json(parent_id, parent_type, vuln=None):
    vuln_dict = {
        'metadata': st.fixed_dictionaries({
            'update_time': st.floats(),
            'update_user': st.one_of(st.none(), st.text()),
            'update_action': st.integers(),
            'creator': st.text(),
            'create_time': st.floats(),
            'update_controller_action': st.text(),
            'owner': st.one_of(st.none(), st.text())}),
        'obj_id': st.integers(),
        'owner': st.one_of(st.none(), st.text()),
        'parent': st.sampled_from([parent_id]),
        'parent_type': st.sampled_from([parent_type]),
        'type': st.one_of(
            st.sampled_from([
                "Vulnerability", "Invalid", None]),
            st.text()
        ),
        'ws': st.one_of(st.none(), st.text()),
        'confirmed': st.booleans(),
        'data': st.one_of(st.none(), st.text()),
        'desc': st.one_of(st.none(), st.text()),
        'easeofresolution': st.sampled_from(['trivial',
                                             'simple',
                                             'moderate',
                                             'difficult',
                                             'infeasible']),
        'impact': st.fixed_dictionaries({'accountability': st.booleans(), 'availability': st.booleans(),
                                         'confidentiality': st.booleans(),
                                         'integrity': st.booleans()}),
        'name': st.one_of(st.none(), st.text()),
        'owned': st.booleans(),
        'policyviolations': st.lists(st.one_of(st.none(), st.text())),
        'refs': st.lists(st.one_of(st.none(), st.text())),
        'resolution': st.one_of(st.none(), st.text()),
        'severity': st.sampled_from(['critical',
                                     'high',
                                     'med',
                                     'medium',
                                     'low',
                                     'informational',
                                     'unclassified']),
        'status': st.sampled_from(['open',
                                   'closed',
                                   're-opened',
                                   'risk-accepted']),
        '_attachments': st.fixed_dictionaries({}),
        'description': st.one_of(st.none(), st.text()),
        'protocol': st.one_of(st.none(), st.text()),
        'version': st.one_of(st.none(), st.text())}
    if vuln:
        vuln_dict.update({
            '_id': st.integers(min_value=vuln.id, max_value=vuln.id),
            'id': st.integers(min_value=vuln.id, max_value=vuln.id)
        })
    return st.fixed_dictionaries(vuln_dict)


@pytest.mark.usefixtures('logged_user')
@pytest.mark.hypothesis
def test_hypothesis(host_with_hostnames, test_client, session):
    vuln = VulnerabilityFactory.create(workspace=host_with_hostnames.workspace)
    session.add(vuln)
    session.commit()
    VulnerabilityData = vulnerability_json(host_with_hostnames.id, 'Host')
    VulnerabilityDataWithId = vulnerability_json(host_with_hostnames.id, 'Host', vuln)

    @given(VulnerabilityData)
    def send_api_create_request(raw_data):
        ws_name = host_with_hostnames.workspace.name
        res = test_client.post(f'/v3/ws/{ws_name}/vulns/',
                               data=raw_data)
        assert res.status_code in [201, 400, 409]

    @given(VulnerabilityData)
    def send_api_create_request_v3(raw_data):
        ws_name = host_with_hostnames.workspace.name
        res = test_client.post(f'/v3/ws/{ws_name}/vulns/',
                               data=raw_data)
        assert res.status_code in [201, 400, 409]

    @given(VulnerabilityDataWithId)
    def send_api_update_request(raw_data):
        ws_name = host_with_hostnames.workspace.name
        res = test_client.put(f"/v3/ws/{ws_name}/vulns/{raw_data['_id']}",
                              data=raw_data)
        assert res.status_code in [200, 400, 409, 405]

    @given(VulnerabilityDataWithId)
    def send_api_update_request_v3(raw_data):
        ws_name = host_with_hostnames.workspace.name
        res = test_client.put(f"/v3/ws/{ws_name}/vulns/{raw_data['_id']}",
                              data=raw_data)
        assert res.status_code in [200, 400, 409, 405]

    send_api_create_request()
    send_api_update_request()
    send_api_create_request_v3()
    send_api_update_request_v3()


def filter_json():
    return st.fixed_dictionaries({
        'filters': st.lists(
            st.fixed_dictionaries({
                'name': st.sampled_from(
                    [col.name for col in VulnerabilityWeb.__table__.columns]
                ),
                'op': st.sampled_from([
                    'is_null', 'is_not_null',
                    '==', 'eq', 'equals',
                    'equal_to', '!=', 'ne', 'neq',
                    'not_equal_to', 'does_not_equal',
                    '>', 'gt', '<', 'lt',
                    '>=', 'ge', 'gte', 'geq',
                    '<=', 'le', 'lte', 'leq', 'ilike',
                    'like', 'in', 'not_in', 'has', 'any',
                ]),
                'val': st.one_of(st.text(), st.none(), st.integers())
            })
        )
    })


@pytest.mark.usefixtures('logged_user')
@pytest.mark.hypothesis
@pytest.mark.usefixtures('ignore_nplusone')
def test_filter_hypothesis(host_with_hostnames, test_client, session):
    vuln = VulnerabilityFactory.create(workspace=host_with_hostnames.workspace)
    vulns_web = VulnerabilityWebFactory.create_batch(10, workspace=host_with_hostnames.workspace)
    vulns = VulnerabilityWebFactory.create_batch(10, workspace=host_with_hostnames.workspace)
    session.add(vuln)
    session.add_all(vulns)
    session.add_all(vulns_web)
    session.commit()
    FilterData = filter_json()

    @given(FilterData)
    @settings(deadline=None)
    def send_api_filter_request(raw_filter):
        ws_name = host_with_hostnames.workspace.name
        encoded_filter = urllib.parse.quote(json.dumps(raw_filter))
        res = test_client.get(f'/v3/ws/{ws_name}/vulns/filter?q={encoded_filter}')
        if res.status_code not in [200, 400]:
            print(json.dumps(raw_filter))

        assert res.status_code in [200, 400]

    @given(FilterData)
    @settings(deadline=None)
    def send_api_filter_request_v3(raw_filter):
        ws_name = host_with_hostnames.workspace.name
        encoded_filter = urllib.parse.quote(json.dumps(raw_filter))
        res = test_client.get(f'/v3/ws/{ws_name}/vulns/filter?q={encoded_filter}')
        if res.status_code not in [200, 400]:
            print(json.dumps(raw_filter))

        assert res.status_code in [200, 400]

    send_api_filter_request()
    send_api_filter_request_v3()


def test_model_converter():
    """Test that string fields are translated to NullToBlankString
    fields"""
    # Generic test. Think twice if you want to delete this
    field = VulnerabilitySchema().fields['data']
    assert isinstance(field, NullToBlankString)
    assert field.allow_none
