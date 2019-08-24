import pytest

from faraday.searcher.api import Api
from faraday.searcher.searcher import Searcher, MailNotification
from faraday.searcher.sqlapi import SqlApi
from faraday.server.models import Service, Host
from faraday.server.models import Vulnerability, CommandObject
from tests.factories import VulnerabilityTemplateFactory, ServiceFactory, \
    HostFactory, CustomFieldsSchemaFactory
from tests.factories import WorkspaceFactory, VulnerabilityFactory


def check_command(vuln, session):
    command_obj_rel = session.query(CommandObject).filter_by(object_type='vulnerability', object_id=vuln.id).first()
    assert command_obj_rel is not None
    assert command_obj_rel.command.tool == 'Searcher'
    count = session.query(CommandObject).filter_by(object_type='vulnerability', object_id=vuln.id).count()
    assert count == 1


@pytest.mark.usefixtures('logged_user')
class TestSearcherRules():
    @pytest.mark.parametrize("api", [
        lambda workspace, test_client, session: Api(workspace.name, test_client, session, username='test',
                                                    password='test', base=''),
        lambda workspace, test_client, session: SqlApi(workspace.name, test_client, session),
    ])
    @pytest.mark.usefixtures('ignore_nplusone')
    def test_searcher_update_rules(self, api, session, test_client):
        workspace = WorkspaceFactory.create()
        vuln = VulnerabilityFactory.create(workspace=workspace, severity='low')
        session.add(workspace)
        session.add(vuln)
        session.commit()
        assert vuln.severity == 'low'

        searcher = Searcher(api(workspace, test_client, session))

        rules = [{
            'id': 'CHANGE_SEVERITY',
            'model': 'Vulnerability',
            'object': "severity=low",
            'actions': ["--UPDATE:severity=med"]
        }]

        searcher.process(rules)
        vulns_count = session.query(Vulnerability).filter_by(workspace=workspace).count()
        assert vulns_count == 1
        vuln = session.query(Vulnerability).filter_by(workspace=workspace).first()
        assert vuln.severity == 'medium'
        check_command(vuln, session)

    @pytest.mark.parametrize("api", [
        lambda workspace, test_client, session: Api(workspace.name, test_client, session, username='test',
                                                    password='test', base=''),
        lambda workspace, test_client, session: SqlApi(workspace.name, test_client, session),
    ])
    @pytest.mark.usefixtures('ignore_nplusone')
    def test_searcher_delete_rules(self, api, session, test_client):
        workspace = WorkspaceFactory.create()
        vuln = VulnerabilityFactory.create(workspace=workspace, severity='low')
        session.add(workspace)
        session.add(vuln)
        session.commit()

        searcher = Searcher(api(workspace, test_client, session))

        rules = [{
            'id': 'DELETE_LOW',
            'model': 'Vulnerability',
            'object': "severity=low",
            'actions': ["--DELETE:"]
        }]

        searcher.process(rules)
        vulns_count = session.query(Vulnerability).filter_by(workspace=workspace).count()
        assert vulns_count == 0

    @pytest.mark.parametrize("api", [
        lambda workspace, test_client, session: Api(workspace.name, test_client, session, username='test',
                                                    password='test', base=''),
        lambda workspace, test_client, session: SqlApi(workspace.name, test_client, session),
    ])
    @pytest.mark.usefixtures('ignore_nplusone')
    @pytest.mark.skip("No available in community")
    def test_searcher_rules_tag_vulns_low(self, api, session, test_client):
        workspace = WorkspaceFactory.create()
        vuln = VulnerabilityFactory.create(workspace=workspace, severity='low')
        session.add(workspace)
        session.add(vuln)
        session.commit()

        searcher = Searcher(api(workspace, test_client, session))

        rules = [{
            'id': 'DELETE_LOW',
            'model': 'Vulnerability',
            'object': "severity=low",
            'actions': ["--UPDATE:tags=TEST"]
        }]

        searcher.process(rules)
        vulns_count = session.query(Vulnerability).filter_by(workspace=workspace).count()
        assert vulns_count == 1
        vuln = session.query(Vulnerability).filter_by(workspace=workspace, id=vuln.id).first()
        assert list(vuln.tags) == ["TEST"]
        check_command(vuln, session)

    @pytest.mark.parametrize("api", [
        lambda workspace, test_client, session: Api(workspace.name, test_client, session, username='test',
                                                    password='test', base=''),
        lambda workspace, test_client, session: SqlApi(workspace.name, test_client, session),
    ])
    @pytest.mark.usefixtures('ignore_nplusone')
    def test_confirm_vuln(self, api, session, test_client):
        workspace = WorkspaceFactory.create()
        vuln = VulnerabilityFactory.create(workspace=workspace, severity='low', confirmed=False)
        session.add(workspace)
        session.add(vuln)
        session.commit()

        assert vuln.confirmed is False

        searcher = Searcher(api(workspace, test_client, session))
        rules = [{
            'id': 'CONFIRM_VULN',
            'model': 'Vulnerability',
            'object': "severity=low",
            'actions': ["--UPDATE:confirmed=True"]
        }]

        searcher.process(rules)
        vulns_count = session.query(Vulnerability).filter_by(workspace=workspace).count()
        assert vulns_count == 1
        vuln = session.query(Vulnerability).filter_by(workspace=workspace).first()
        assert vuln.confirmed is True

    @pytest.mark.parametrize("api", [
        lambda workspace, test_client, session: Api(workspace.name, test_client, session, username='test',
                                                    password='test', base=''),
        lambda workspace, test_client, session: SqlApi(workspace.name, test_client, session),
    ])
    @pytest.mark.usefixtures('ignore_nplusone')
    def test_apply_template_by_id(self, api, session, test_client):
        workspace = WorkspaceFactory.create()
        template = VulnerabilityTemplateFactory.create()
        vuln = VulnerabilityFactory.create(workspace=workspace, severity='low', confirmed=False)
        session.add(workspace)
        session.add(vuln)
        session.add(template)
        session.commit()

        template_name = template.name
        template_id = template.id
        searcher = Searcher(api(workspace, test_client, session))
        rules = [{
            'id': 'APPLY_TEMPLATE',
            'model': 'Vulnerability',
            'object': "severity=low",
            'actions': ["--UPDATE:template={}".format(template_id)]
        }]

        searcher.process(rules)
        vulns_count = session.query(Vulnerability).filter_by(workspace=workspace).count()
        assert vulns_count == 1
        vuln = session.query(Vulnerability).filter_by(workspace=workspace).first()
        assert vuln.name == template_name

    @pytest.mark.parametrize("api", [
        lambda workspace, test_client, session: Api(workspace.name, test_client, session, username='test',
                                                    password='test', base=''),
        lambda workspace, test_client, session: SqlApi(workspace.name, test_client, session),
    ])
    @pytest.mark.usefixtures('ignore_nplusone')
    # TO FIX
    def test_remove_duplicated_by_name(self, api, session, test_client):
        workspace = WorkspaceFactory.create()
        host = HostFactory.create(workspace=workspace)
        vuln = VulnerabilityFactory.create(workspace=workspace, severity='low',
                                           name='Duplicated Vuln',
                                           host=host, service=None)
        duplicated_vuln = VulnerabilityFactory.create(workspace=workspace, severity='low',
                                                      name='Duplicated Vuln 2',
                                                      host=host, service=None)
        session.add(workspace)
        session.add(vuln)
        session.add(duplicated_vuln)
        session.add(host)
        session.commit()

        searcher = Searcher(api(workspace, test_client, session))
        rules = [{
            'id': 'REMOVE_DUPLICATED_VULNS',
            'model': 'Vulnerability',
            'fields': ['name'],
            'object': "severity=low --old",  # Without --old param Searcher deletes  all duplicated objects
            'actions': ["--DELETE:"]
        }]

        vulns_count = session.query(Vulnerability).filter_by(workspace=workspace).count()
        assert vulns_count == 2

        searcher.process(rules)

        vulns_count = session.query(Vulnerability).filter_by(workspace=workspace).count()
        assert vulns_count == 1

    @pytest.mark.parametrize("api", [
        lambda workspace, test_client, session: Api(workspace.name, test_client, session, username='test',
                                                    password='test', base=''),
        lambda workspace, test_client, session: SqlApi(workspace.name, test_client, session),
    ])
    @pytest.mark.usefixtures('ignore_nplusone')
    def test_mail_notification(self, api, session, test_client):
        workspace = WorkspaceFactory.create()
        vuln = VulnerabilityFactory.create(workspace=workspace, severity='low')
        session.add(workspace)
        session.add(vuln)
        session.commit()

        mail_notification = MailNotification(
            'test@test.com',
            'testpass',
            'smtp.gmail.com',
            587
        )
        searcher = Searcher(api(workspace, test_client, session), mail_notificacion=mail_notification)
        rules = [{
            'id': 'SEND_MAIL',
            'model': 'Vulnerability',
            'object': "severity=low",
            'actions': ["--ALERT:test2@test.com"]
        }]

        searcher.process(rules)

        assert searcher.mail_notificacion == mail_notification

    def test_add_ref_to_duplicated_vuln(self, session, test_client):
        workspace = WorkspaceFactory.create()
        host = HostFactory.create(workspace=workspace)
        vuln = VulnerabilityFactory.create(workspace=workspace, severity='low',
                                           name='Duplicated Vuln',
                                           host=host, service=None)
        duplicated_vuln = VulnerabilityFactory.create(workspace=workspace, severity='low',
                                                      name='Duplicated Vuln 2',
                                                      host=host, service=None)
        session.add(workspace)
        session.add(vuln)
        session.add(duplicated_vuln)
        session.add(host)
        session.commit()

        first_vuln_id = vuln.id

        api = Api(test_client, workspace.name, username='test', password='test', base='')
        searcher = Searcher(api)
        rules = [{
            'id': 'ADD_REFS_DUPLICATED_VULNS',
            'model': 'Vulnerability',
            'fields': ['name'],
            'object': "severity=low --old",  # Without --old param Searcher deletes  all duplicated objects
            'conditions': ['severity=low'],
            'actions': ["--UPDATE:refs=REF_TEST"]
        }]

        vulns_count = session.query(Vulnerability).filter_by(workspace=workspace).count()
        assert vulns_count == 2

        searcher.process(rules)

        vuln1 = session.query(Vulnerability).get(first_vuln_id)
        assert len(vuln1.references) > 0
        assert list(vuln1.references)[0] == 'REF_TEST'

    @pytest.mark.parametrize("api", [
        lambda workspace, test_client, session: Api(workspace.name, test_client, session, username='test',
                                                    password='test', base=''),
        lambda workspace, test_client, session: SqlApi(workspace.name, test_client, session),
    ])
    @pytest.mark.usefixtures('ignore_nplusone')
    def test_update_severity_inside_one_host(self, api, session, test_client):
        workspace = WorkspaceFactory.create()
        host = HostFactory.create(workspace=workspace)
        vuln1 = VulnerabilityFactory.create(workspace=workspace, severity='low',
                                            host=host, service=None)
        vuln2 = VulnerabilityFactory.create(workspace=workspace, severity='low',
                                            host=host, service=None)
        session.add(workspace)
        session.add(vuln1)
        session.add(vuln2)
        session.add(host)
        session.commit()

        parent_id = host.id
        first_vuln_id = vuln1.id
        second_vuln_id = vuln2.id

        assert vuln1.severity == 'low'
        assert vuln2.severity == 'low'
        assert vuln1.parent.id == parent_id
        assert vuln2.parent.id == parent_id

        searcher = Searcher(api(workspace, test_client, session))
        rules = [{
            'id': 'CHANGE_SEVERITY_INSIDE_HOST',
            'model': 'Vulnerability',
            'parent': parent_id,
            'object': "severity=low",  # Without --old param Searcher deletes  all duplicated objects
            'conditions': ['severity=low'],
            'actions': ["--UPDATE:severity=info"]
        }]

        searcher.process(rules)

        vuln1 = session.query(Vulnerability).get(first_vuln_id)
        vuln2 = session.query(Vulnerability).get(second_vuln_id)

        assert vuln1.severity == 'informational'
        assert vuln2.severity == 'informational'

    @pytest.mark.parametrize("api", [
        lambda workspace, test_client, session: Api(workspace.name, test_client, session, username='test',
                                                    password='test', base=''),
        lambda workspace, test_client, session: SqlApi(workspace.name, test_client, session),
    ])
    @pytest.mark.usefixtures('ignore_nplusone')
    # TO FIX
    def test_delete_vulns_with_dynamic_values(self, api, session, test_client):
        workspace = WorkspaceFactory.create()
        vuln1 = VulnerabilityFactory.create(workspace=workspace, name="TEST1")
        vuln2 = VulnerabilityFactory.create(workspace=workspace, name="TEST2")
        session.add(workspace)
        session.add(vuln1)
        session.add(vuln2)
        session.commit()

        searcher = Searcher(api(workspace, test_client, session))
        rules = [{
            'id': 'DELETE_VULN_{{name}}',
            'model': 'Vulnerability',
            'object': "regex=^{{name}}",
            'actions': ["--DELETE:"],
            'values': [{'name': 'TEST1'}, {'name': 'TEST2'}]
        }]

        vulns_count = session.query(Vulnerability).filter_by(workspace=workspace).count()
        assert vulns_count == 2

        searcher.process(rules)

        vulns_count = session.query(Vulnerability).filter_by(workspace=workspace).count()
        assert vulns_count == 0

    @pytest.mark.parametrize("api", [
        lambda workspace, test_client, session: Api(workspace.name, test_client, session, username='test',
                                                    password='test', base=''),
        lambda workspace, test_client, session: SqlApi(workspace.name, test_client, session),
    ])
    @pytest.mark.usefixtures('ignore_nplusone')
    # TO FIX
    def test_update_custom_field(self, api, session, test_client):
        workspace = WorkspaceFactory.create()
        custom_field = CustomFieldsSchemaFactory.create(
            table_name='vulnerability',
            field_name='cfield',
            field_type='str',
            field_order=1,
            field_display_name='CField',
        )
        vuln = VulnerabilityFactory.create(workspace=workspace, severity='low', confirmed=True)
        vuln.custom_fields = {'cfield': 'test'}
        session.add(workspace)
        session.add(custom_field)
        session.add(vuln)
        session.commit()

        searcher = Searcher(api(workspace, test_client, session))

        rules = [{
            'id': 'CHANGE_CUSTOM_FIELD',
            'model': 'Vulnerability',
            'object': "severity=low",
            'conditions': ['confirmed=True'],
            'actions': ["--UPDATE:cfield=CUSTOM_FIELD_UPDATED"]
        }]

        searcher.process(rules)

        vulns_count = session.query(Vulnerability).filter_by(workspace=workspace).count()
        assert vulns_count == 1
        vuln = session.query(Vulnerability).filter_by(workspace=workspace).first()
        assert vuln.custom_fields['cfield'] == 'CUSTOM_FIELD_UPDATED'
        check_command(vuln, session)

    @pytest.mark.parametrize("api", [
        lambda workspace, test_client, session: Api(workspace.name, test_client, session, username='test',
                                                    password='test', base=''),
        lambda workspace, test_client, session: SqlApi(workspace.name, test_client, session),
    ])
    @pytest.mark.usefixtures('ignore_nplusone')
    def test_delete_services(self, api, session, test_client):
        workspace = WorkspaceFactory.create()
        service = ServiceFactory.create(workspace=workspace, name="http")
        session.add(workspace)
        session.add(service)
        session.commit()

        searcher = Searcher(api(workspace, test_client, session))
        rules = [{
            'id': 'DELETE_SERVICE',
            'model': 'Service',
            'object': "name=http",
            'actions': ["--DELETE:"]
        }]

        service_count = session.query(Service).filter_by(workspace=workspace).count()
        assert service_count == 1

        searcher.process(rules)

        service_count = session.query(Service).filter_by(workspace=workspace).count()
        assert service_count == 0

    @pytest.mark.parametrize("api", [
        lambda workspace, test_client, session: Api(workspace.name, test_client, session, username='test',
                                                    password='test', base=''),
        lambda workspace, test_client, session: SqlApi(workspace.name, test_client, session),
    ])
    @pytest.mark.usefixtures('ignore_nplusone')
    def test_delete_host(self, api, session, test_client):
        workspace = WorkspaceFactory.create()
        host = HostFactory.create(workspace=workspace, ip="10.25.86.39")
        session.add(workspace)
        session.add(host)
        session.commit()

        searcher = Searcher(api(workspace, test_client, session))
        rules = [{
            'id': 'DELETE_HOST',
            'model': 'Host',
            'object': "ip=10.25.86.39",
            'actions': ["--DELETE:"]
        }]

        host_count = session.query(Host).filter_by(workspace=workspace).count()
        assert host_count == 1

        searcher.process(rules)

        host_count = session.query(Host).filter_by(workspace=workspace).count()
        assert host_count == 0

    @pytest.mark.parametrize("api", [
        lambda workspace, test_client, session: Api(workspace.name, test_client, session, username='test',
                                                    password='test', base=''),
        lambda workspace, test_client, session: SqlApi(workspace.name, test_client, session),
    ])
    @pytest.mark.usefixtures('ignore_nplusone')
    def test_update_services(self, api, session, test_client):
        workspace = WorkspaceFactory.create()
        service = ServiceFactory.create(workspace=workspace, name="http", owned=False)
        session.add(workspace)
        session.add(service)
        session.commit()

        assert service.owned is False

        searcher = Searcher(api(workspace, test_client, session))
        rules = [{
            'id': 'UPDATE_SERVICE',
            'model': 'Service',
            'object': "name=http",
            'actions': ["--UPDATE:owned=True"]
        }]

        searcher.process(rules)

        service = session.query(Service).filter_by(workspace=workspace).first()
        assert service.owned is True

    @pytest.mark.parametrize("api", [
        lambda workspace, test_client, session: Api(workspace.name, test_client, session, username='test',
                                                    password='test', base=''),
        lambda workspace, test_client, session: SqlApi(workspace.name, test_client, session),
    ])
    @pytest.mark.usefixtures('ignore_nplusone')
    def test_update_host(self, api, session, test_client):
        workspace = WorkspaceFactory.create()
        host = HostFactory.create(workspace=workspace, ip="10.25.86.39", owned=False)
        session.add(workspace)
        session.add(host)
        session.commit()

        assert host.owned is False

        searcher = Searcher(api(workspace, test_client, session))
        rules = [{
            'id': 'UPDATE_HOST',
            'model': 'Host',
            'object': "ip=10.25.86.39",
            'actions': ["--UPDATE:owned=True"]
        }]

        searcher.process(rules)

        host = session.query(Host).filter_by(workspace=workspace).first()
        assert host.owned is True
