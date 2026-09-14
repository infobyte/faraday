import pytest

from tests.factories import CustomFieldsSchemaFactory, VulnerabilityFactory, WorkspaceFactory
from tests.test_api_non_workspaced_base import ReadWriteAPITests, BulkDeleteTestsMixin

from faraday.server.api.modules.custom_fields import CustomFieldsSchemaView
from faraday.server.models import (
    CustomFieldsSchema,
    Vulnerability,
)


@pytest.mark.usefixtures('logged_user')
class TestVulnerabilityCustomFields(ReadWriteAPITests, BulkDeleteTestsMixin):
    model = CustomFieldsSchema
    factory = CustomFieldsSchemaFactory
    api_endpoint = 'custom_fields_schema'
    # unique_fields = ['ip']
    # update_fields = ['ip', 'description', 'os']
    view_class = CustomFieldsSchemaView
    patchable_fields = ['field_display_name']

    def test_custom_fields_data(self, session, test_client):
        add_text_field = CustomFieldsSchemaFactory.create(
            table_name='vulnerability',
            field_name='cvss',
            field_type='text',
            field_order=1,
            field_display_name='CVSS',
        )
        session.add(add_text_field)
        session.commit()

        res = test_client.get(self.url())
        assert res.status_code == 200
        assert {'table_name': 'vulnerability', 'id': add_text_field.id, 'field_type': 'text',
                'field_name': 'cvss', 'field_display_name': 'CVSS', 'field_metadata': None,
                'field_order': 1} in res.json

    def test_custom_fields_field_name_cant_be_changed(self, session, test_client):
        add_text_field = CustomFieldsSchemaFactory.create(
            table_name='vulnerability',
            field_name='cvss',
            field_type='str',
            field_order=1,
            field_display_name='CVSS',
        )
        session.add(add_text_field)
        session.commit()

        data = {
            'field_name': 'cvss 2',
            'field_type': 'int',
            'table_name': 'sarasa',
            'field_display_name': 'CVSS new',
            'field_order': 1
        }
        res = test_client.put(self.url(add_text_field.id), data=data)
        assert res.status_code == 200

        custom_field_obj = session.query(CustomFieldsSchema).filter_by(id=add_text_field.id).first()
        assert custom_field_obj.field_name == 'cvss'
        assert custom_field_obj.table_name == 'vulnerability'
        assert custom_field_obj.field_type == 'str'
        assert custom_field_obj.field_display_name == 'CVSS new'

    def test_delete_clears_custom_field_values_from_vulns(self, session, test_client):
        """Deleting a CA must wipe its values from all vulnerabilities (issue #6369)."""
        workspace = WorkspaceFactory.create()
        cf = CustomFieldsSchemaFactory.create(
            table_name='vulnerability',
            field_name='prueba',
            field_type='str',
            field_order=1,
            field_display_name='Prueba',
        )
        vuln = VulnerabilityFactory.create(workspace=workspace, custom_fields={'prueba': 'hola'})
        session.add_all([workspace, cf, vuln])
        session.commit()

        res = test_client.delete(self.url(cf.id))
        assert res.status_code == 204

        session.expire(vuln)
        updated_vuln = session.query(Vulnerability).filter_by(id=vuln.id).one()
        assert 'prueba' not in (updated_vuln.custom_fields or {})

    def test_bulk_delete_clears_custom_field_values_from_vulns(self, session, test_client):
        """Bulk-deleting CAs must wipe their values from all vulnerabilities (issue #6369)."""
        workspace = WorkspaceFactory.create()
        cf = CustomFieldsSchemaFactory.create(
            table_name='vulnerability',
            field_name='prueba',
            field_type='str',
            field_order=1,
            field_display_name='Prueba',
        )
        vuln = VulnerabilityFactory.create(workspace=workspace, custom_fields={'prueba': 'hola'})
        session.add_all([workspace, cf, vuln])
        session.commit()

        res = test_client.delete(self.url(), json={'ids': [cf.id]})
        assert res.status_code == 200

        session.expire(vuln)
        updated_vuln = session.query(Vulnerability).filter_by(id=vuln.id).one()
        assert 'prueba' not in (updated_vuln.custom_fields or {})

    def test_add_custom_fields_with_metadata(self, session, test_client):
        add_choice_field = CustomFieldsSchemaFactory.create(
            table_name='vulnerability',
            field_name='gender',
            field_type='choice',
            field_metadata=['Male', 'Female'],
            field_order=1,
            field_display_name='Gender',
        )

        session.add(add_choice_field)
        session.commit()

        res = test_client.get(self.url())
        assert res.status_code == 200
        assert {'table_name': 'vulnerability', 'id': add_choice_field.id, 'field_type': 'choice',
                'field_name': 'gender', 'field_display_name': 'Gender', 'field_metadata': "['Male', 'Female']",
                'field_order': 1} in res.json

