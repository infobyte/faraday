import os
import pytest


@pytest.mark.usefixtures('logged_user')
class TestAPIInfoEndpoint:

    def test_api_info(self, test_client):
        current_dir = os.path.dirname(os.path.realpath(__file__))
        # this is a bug on the info api!
        # we require faraday to be a package since we can't import
        # from base path when our current working dir is test_cases.
        if 'test_cases' in current_dir:
            faraday_base = os.path.join(current_dir, '..')
            os.chdir(faraday_base)

        response = test_client.get('v2/info')
        assert response.status_code == 200
        assert response.json['Faraday Server'] == 'Running'
        # to avoid side effects
        os.chdir(current_dir)