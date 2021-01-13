
import pytest

from tests.factories import CustomFieldsSchemaFactory
from tests.test_api_non_workspaced_base import ReadWriteAPITests

from faraday.server.api.modules.custom_fields import CustomFieldsSchemaView
from faraday.server.models import (
    CustomFieldsSchema
)

@pytest.mark.usefixtures('logged_user')
class TestVulnerabilityCustomFields(ReadWriteAPITests):
    model = CustomFieldsSchema
    factory = CustomFieldsSchemaFactory
    api_endpoint = 'custom_fields_schema'
    #unique_fields = ['ip']
    #update_fields = ['ip', 'description', 'os']
    view_class = CustomFieldsSchemaView

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

        res = test_client.get(self.url()) # '/v2/custom_fields_schema/')
        assert res.status_code == 200
        assert {u'table_name': u'vulnerability', u'id': add_text_field.id, u'field_type': u'text', u'field_name': u'cvss', u'field_display_name': u'CVSS', u'field_metadata': None, u'field_order': 1} in res.json

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
            u'field_name': u'cvss 2',
            u'field_type': 'int',
            u'table_name': 'sarasa',
            u'field_display_name': u'CVSS new',
            u'field_order': 1
        }
        res = test_client.put(self.url(add_text_field.id), data=data)
        assert res.status_code == 200

        custom_field_obj = session.query(CustomFieldsSchema).filter_by(id=add_text_field.id).first()
        assert custom_field_obj.field_name == 'cvss'
        assert custom_field_obj.table_name == 'vulnerability'
        assert custom_field_obj.field_type == 'str'
        assert custom_field_obj.field_display_name == 'CVSS new'

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

        res = test_client.get(self.url())  # '/v2/custom_fields_schema/')
        assert res.status_code == 200
        assert {u'table_name': u'vulnerability', u'id': add_choice_field.id, u'field_type': u'choice',
                u'field_name': u'gender', u'field_display_name': u'Gender', u'field_metadata': ['Male', 'Female'],
                u'field_order': 1} in res.json
