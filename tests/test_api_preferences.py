import pytest

from tests.test_api_non_workspaced_base import GenericAPITest
from tests.factories import UserFactory
from faraday.server.models import User
from faraday.server.api.modules.preferences import PreferencesView
from tests.utils.url import v2_to_v3


pytest.fixture('logged_user')
class TestPreferences(GenericAPITest):
    model = User
    factory = UserFactory
    api_endpoint = 'preferences'
    view_class = PreferencesView

    def test_add_preference(self, test_client):
        preferences = {'field1': 1, 'field2': 'str1'}
        data = {'preferences': preferences}
        response = test_client.post(self.url(), data=data)

        assert response.status_code == 200

        response = test_client.get(self.url())

        assert response.status_code == 200
        assert response.json['preferences'] == preferences

    def test_list_preferences_from_session(self, test_client):
        preferences = {'field1': 1, 'field2': 'str1'}
        data = {'preferences': preferences}
        response = test_client.post(self.url(), data=data)

        assert response.status_code == 200

        response = test_client.get('/session')

        assert response.status_code == 200
        assert response.json['preferences'] == preferences


    def test_add_invalid_preference(self, test_client):
        preferences = {'field1': 1, 'field2': 'str1'}
        data = {'p': preferences}
        response = test_client.post(self.url(), data=data)

        assert response.status_code == 400


class TestPreferencesV3(TestPreferences):
    def url(self, obj=None):
        return v2_to_v3(super().url(obj))
