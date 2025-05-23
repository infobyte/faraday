'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
import operator
from io import BytesIO
from posixpath import join

import pytz

from urllib.parse import urlencode, urljoin
from random import choice
from hypothesis import given, strategies as st

import pytest

from tests.test_api_workspaced_base import ReadWriteAPITests
from faraday.server.models import db, WorkspaceSummaryReport
from faraday.server.api.modules.workspace_summary_report import WorkspaceSummaryReportView
from tests.factories import (
    WorkspaceSummaryReportFactory,
    EmptyCommandFactory,
    WorkspaceFactory,
)

HOSTS_COUNT = 5
SERVICE_COUNT = [10, 5]  # 10 services to the first host, 5 to the second


class TestWorkspaceSummaryReportAPI(ReadWriteAPITests):
    model = WorkspaceSummaryReport
    factory = WorkspaceSummaryReportFactory
    api_endpoint = 'workspace_summary_report'
    unique_fields = ['ip']
    view_class = WorkspaceSummaryReportView

#     @pytest.mark.usefixtures("mock_envelope_list")
#     def test_sort_by_description(self, test_client, session):
#         for host in Host.query.all():
#             # I don't want to test case sensitive sorting
#             host.description = host.description.lower()
#         session.commit()
#         expected_ids = [host.id for host in
#                         sorted(Host.query.all(),
#                                key=operator.attrgetter('description'))]
#         res = test_client.get(urljoin(self.url(), '?sort=description&sort_dir=asc'))
#         assert res.status_code == 200
#         assert [host['_id'] for host in res.json['data']] == expected_ids
#
#         expected_ids.reverse()  # In place list reverse
#         res = test_client.get(urljoin(self.url(), '?sort=description&sort_dir=desc'))
#         assert res.status_code == 200
#         assert [host['_id'] for host in res.json['data']] == expected_ids
#
#     @pytest.mark.usefixtures("mock_envelope_list")
#     def test_sort_by_services(self, test_client, session, second_workspace,
#                               host_factory, service_factory):
#         expected_ids = []
#         for i in range(10):
#             host = host_factory.create(workspace=second_workspace)
#             service_factory.create_batch(
#                 i, host=host, workspace=second_workspace, status='open')
#             session.flush()
#             expected_ids.append(host.id)
#         session.commit()
#         res = test_client.get(urljoin(self.url(workspace=second_workspace),
#                                       '?sort=services&sort_dir=asc'))
#         assert res.status_code == 200
#         assert [h['_id'] for h in res.json['data']] == expected_ids
#
#     @pytest.mark.usefixtures("mock_envelope_list")
#     def test_sort_by_update_time(self, test_client, session, second_workspace,
#                                  host_factory):
#         """
#         This test doesn't test only the hosts view, but all the ones that
#         expose a object with metadata.
#         Think twice if you are thinking in removing it
#         """
#         expected = host_factory.create_batch(10, workspace=second_workspace)
#         session.commit()
#         for i in range(len(expected)):
#             if i % 2 == 0:  # Only update some hosts
#                 host = expected.pop(0)
#                 host.description = 'i was updated'
#                 session.add(host)
#                 session.commit()
#                 expected.append(host)  # Put it on the end
#         res = test_client.get(urljoin(self.url(workspace=second_workspace),
#                                '?sort=metadata.update_time&sort_dir=asc'))
#         assert res.status_code == 200, res.data
#         assert [h['_id'] for h in res.json['data']] == [h.id for h in expected]
#
#     def test_create_a_host_twice_returns_conflict(self, test_client):
#         res = test_client.post(self.url(), data={
#             "ip": "127.0.0.1",
#             "description": "aaaaa",
#         })
#         assert res.status_code == 201
#         assert Host.query.count() == HOSTS_COUNT + 1
#         host_id = res.json['id']
#         host = Host.query.get(host_id)
#         assert host.ip == "127.0.0.1"
#         assert host.description == "aaaaa"
#         assert host.os == ''
#         assert host.workspace == self.workspace
#         res = test_client.post(self.url(), data={
#             "ip": "127.0.0.1",
#             "description": "aaaaa",
#         })
#         assert res.status_code == 409
#         assert res.json['object']['_id'] == host_id
#
#     def test_create_host_from_command(self, test_client, session):
#         command = EmptyCommandFactory.create()
#         session.commit()
#         assert len(command.command_objects) == 0
#         url = urljoin(self.url(workspace=command.workspace), '?' + urlencode({'command_id': command.id}))
#
#         res = test_client.post(url, data={
#             "ip": "127.0.0.1",
#             "description": "aaaaa",
#         })
#
#         assert res.status_code == 201
#         assert len(command.command_objects) == 1
#         cmd_obj = command.command_objects[0]
#         assert cmd_obj.object_type == 'host'
#         assert cmd_obj.object_id == res.json['id']
#
#     def test_create_host_cant_assign_command_from_another_workspace(self, test_client, session):
#         command = EmptyCommandFactory.create()
#         new_workspace = WorkspaceFactory.create()
#         session.commit()
#         assert len(command.command_objects) == 0
#         url = urljoin(self.url(workspace=new_workspace), '?' + urlencode({'command_id': command.id}))
#
#         res = test_client.post(url, data={
#             "ip": "127.0.0.1",
#             "description": "aaaaa",
#         })
#
#         assert res.status_code == 400
#         assert res.json == {'message': 'Command not found.'}
#         assert len(command.command_objects) == 0
#
#     def test_service_summaries(self, test_client, session, service_factory):
#         service_factory.create(name='http', protocol='tcp', port=80,
#                                host=self.first_object, status='open',
#                                version='nginx',
#                                workspace=self.workspace)
#         service_factory.create(name='https', protocol='tcp', port=443,
#                                host=self.first_object, status='open',
#                                version=None,
#                                workspace=self.workspace)
#         service_factory.create(name='dns', protocol='udp', port=5353,
#                                host=self.first_object, status='open',
#                                version=None,
#                                workspace=self.workspace)
#         service_factory.create(name='smtp', protocol='tcp', port=25,
#                                host=self.first_object, status='filtered',
#                                version=None,
#                                workspace=self.workspace)
#         service_factory.create(name='dns', protocol='udp', port=53,
#                                host=self.first_object, status='open',
#                                version=None,
#                                workspace=self.workspace)
#         service_factory.create(name='other', protocol='udp', port=1234,
#                                host=self.first_object, status='closed',
#                                version=None,
#                                workspace=self.workspace)
#         session.commit()
#         res = test_client.get(self.url(self.first_object))
#         assert res.status_code == 200
#         service_summaries = res.json['service_summaries']
#         assert service_summaries == [
#             '(80/tcp) http (nginx)',
#             '(443/tcp) https',
#             '(53/udp) dns',
#             '(5353/udp) dns',
#         ]
#
#     def test_delete_host_with_blank_ip(self, session, test_client):
#         """
#             Bug found while deleting data from workspaces.
#             If we don't allow blank in name we should delete this test.
#         """
#         host = self.factory.create(ip='')
#         session.add(host)
#         session.commit()
#
#         res = test_client.delete(self.url(host, workspace=host.workspace))
#         assert res.status_code == 204
#
#     def test_update_hostname(self, session, test_client):
#         host = HostFactory.create()
#         session.add(host)
#         session.commit()
#         data = {
#             "description": "",
#             "default_gateway": "",
#             "ip": "127.0.0.1",
#             "owned": False,
#             "name": "127.0.0.1",
#             "mac": "",
#             "hostnames": ["dasdas"],
#             "owner": "faraday",
#             "os": "Unknown",
#         }
#
#         res = test_client.put(self.url(host, workspace=host.workspace), data=data)
#         assert res.status_code == 200
#
#         assert session.query(Hostname).filter_by(host=host).count() == 1
#         assert session.query(Hostname).all()[0].name == 'dasdas'
#
#     @pytest.mark.skip  # TODO unskip
#     def test_hosts_ordered_by_vulns_severity(self, session, test_client, service_factory,
#                                              vulnerability_factory, vulnerability_web_factory):
#         ws = WorkspaceFactory.create()
#         session.add(ws)
#         hosts_list = []
#         for i in range(0, 10):
#             host = HostFactory.create(workspace=ws)
#             session.add(host)
#             service = service_factory.create(workspace=ws, host=host)
#             session.add(service)
#             hosts_list.append(host)
#         session.commit()
#
#         severities = ['critical', 'high', 'medium', 'low', 'informational', 'unclassified']
#         # Vulns counter by severity in host
#         vulns_by_severity = {host.id: [0, 0, 0, 0, 0, 0] for host in hosts_list}
#
#         for host in hosts_list:
#             # Each host has 10 vulns
#             for i in range(0, 10):
#                 vuln_web = choice([True, False])
#                 severity = choice(severities)
#
#                 if vuln_web:
#                     vuln = vulnerability_web_factory.create(
#                         workspace=ws, service=host.services[0], severity=severity
#                     )
#                 else:
#                     vuln = vulnerability_factory.create(
#                         host=None, service=host.services[0],
#                         workspace=host.workspace, severity=severity
#                     )
#                 session.add(vuln)
#
#                 # Increase 1 to number of vulns by severity in the host
#                 vulns_by_severity[host.id][severities.index(severity)] += 1
#         session.commit()
#
#         # Sort vulns_by_severity by number of vulns by severity in every host
#         sorted_hosts = sorted(
#             vulns_by_severity.items(),
#             key=lambda host: [vuln_count for vuln_count in host[1]],
#             reverse=True
#         )
#
#         res = test_client.get(self.url(workspace=ws))
#         assert res.status_code == 200
#
#         response_hosts = res.json['rows']
#         for host in response_hosts:
#             # sorted_hosts and response_hosts have the same order so the index
#             # of host in sorted_host is the same as the
#             # index of host in response_hosts
#             index_in_sorted_host = [host_tuple[0] for host_tuple in sorted_hosts].index(host['id'])
#             index_in_response_hosts = response_hosts.index(host)
#
#             assert index_in_sorted_host == index_in_response_hosts
#
#     def test_hosts_order_without_vulns(self, session, test_client):
#         # If a host has no vulns, it should be ordered by IP in ascending order
#         ws = WorkspaceFactory.create()
#         session.add(ws)
#         hosts_ids = []
#         for i in range(0, 10):
#             host = HostFactory.create(workspace=ws, ip=f'127.0.0.{i}')
#             session.add(host)
#             session.commit()
#             hosts_ids.append(host.id)
#
#         res = test_client.get(self.url(workspace=ws))
#         assert res.status_code == 200
#
#         response_hosts = res.json['rows']
#         for host in response_hosts:
#             # hosts_ids and response_hosts have the same order so the index
#             # of host in hosts_ids is the same as the
#             # index of host in response_hosts
#             index_in_hosts_ids = hosts_ids.index(host['id'])
#             index_in_response_hosts = response_hosts.index(host)
#
#             assert index_in_hosts_ids == index_in_response_hosts
#
#     @pytest.mark.usefixtures('ignore_nplusone')
#     def test_bulk_update_host_with_hostnames(self, test_client, session,
#                                         host_with_hostnames):
#         session.commit()
#         data = {
#             "ids": [host_with_hostnames.id, self.first_object.id],
#             "hostnames": ["other.com", "test.com"],
#         }
#         res = test_client.patch(self.url(), data=data)
#         assert res.status_code == 200
#         assert res.json["updated"] == 2
#         expected = {"other.com", "test.com"}
#         assert {hn.name for hn in host_with_hostnames.hostnames} == expected
#         assert {hn.name for hn in self.first_object.hostnames} == expected
#
#     @pytest.mark.usefixtures('ignore_nplusone')
#     def test_bulk_update_host_without_hostnames(self, test_client, session,
#                                                 host_with_hostnames):
#         session.commit()
#         expected = {hn.name for hn in host_with_hostnames.hostnames}
#         data = {
#             "ids": [host_with_hostnames.id],
#             "os": "NotAnOS"
#         }
#         res = test_client.patch(self.url(), data=data)
#         assert res.status_code == 200
#         assert res.json["updated"] == 1
#         assert {hn.name for hn in host_with_hostnames.hostnames} == expected
#
#     def test_add_tags_with_filter_for_host(self, test_client, session, workspace, logged_user, host_factory):
#         """
#         This one should create 3 hosts with one tag
#         remove the tag from 2 host and add another_tag
#         using set_tag wiht hosts ids
#         """
#         host1, host2, host3 = host_factory.create_batch(3, workspace=workspace)
#         host1.tags = ["test"]
#         host2.tags = ["test"]
#         host3.tags = []
#         session.add(host1)
#         session.add(host2)
#         session.add(host3)
#         session.commit()
#         body = {
#             "tags_to_remove": ["test"],
#             "tags_to_add": ["another_tag"],
#         }
#         filters_reopened_vulns = f'{{"filters": [{{"name": "id", "op": ">", "val": "{host1.id}"}}]}}'
#         test_client.post(
#             f'/v3/ws/{workspace.name}/hosts/set_tags?q={filters_reopened_vulns}',
#             data=body,
#         )
#         host1After = Host.query.filter(Host.id == host1.id).first()
#         assert len(host1After.tags) == 1
#         assert "test" in host1After.tags
#         host2After = Host.query.filter(Host.id == host2.id).first()
#         assert len(host2After.tags) == 1
#         assert "another_tag" in host2After.tags
#         host3After = Host.query.filter(Host.id == host3.id).first()
#         assert len(host3After.tags) == 1
#         assert "another_tag" in host3After.tags
#
#
# def host_json():
#     return st.fixed_dictionaries(
#         {
#             "metadata":
#                 st.fixed_dictionaries({
#                     "update_time": st.floats(),
#                     "update_user": st.one_of(st.none(), st.text()),
#                     "update_action": st.integers(),
#                     "creator": st.text(),
#                     "create_time": st.integers(),
#                     "update_controller_action": st.text(),
#                     "owner": st.one_of(st.none(), st.text()),
#                     "command_id": st.one_of(st.none(), st.text(), st.integers()), }),
#             "name": st.one_of(st.none(), st.text()),
#             "ip": st.one_of(st.none(), st.text()),
#             "_rev": st.one_of(st.none(), st.text()),
#             "description": st.one_of(st.none(), st.text()),
#             "default_gateway": st.one_of(st.none(), st.text()),
#             "owned": st.booleans(),
#             "services": st.one_of(st.none(), st.integers()),
#             "hostnames": st.lists(st.text()),
#             "vulns": st.one_of(st.none(), st.integers()),
#             "owner": st.one_of(st.none(), st.text()),
#             "_id": st.one_of(st.none(), st.integers()),
#             "os": st.one_of(st.none(), st.text()),
#             "id": st.one_of(st.none(), st.integers()),
#             "icon": st.one_of(st.none(), st.text())}
#     )
#
#
# @pytest.mark.usefixtures('logged_user')
# @pytest.mark.hypothesis
# def test_hypothesis(host_with_hostnames, test_client, session):
#     session.commit()
#     HostData = host_json()
#
#     @given(HostData)
#     def send_api_request(raw_data):
#         ws_name = host_with_hostnames.workspace.name
#         res = test_client.post(f'/v3/ws/{ws_name}/vulns',
#                                data=raw_data)
#         assert res.status_code in [201, 400, 409]
#
#     send_api_request()
