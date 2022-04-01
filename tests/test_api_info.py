'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

import pytest


class TestAPIInfoEndpoint:

    def test_api_info_public(self, test_client):
        response = test_client.get('v3/info')
        assert response.status_code == 200
        assert response.json['Faraday Server'] == 'Running'

    @pytest.mark.usefixtures('logged_user')
    def test_api_info(self, test_client):
        response = test_client.get('v3/info')
        assert response.status_code == 200
        assert response.json['Faraday Server'] == 'Running'

    def test_api_config_public(self, test_client, session):
        from faraday import __version__
        response = test_client.get('config')
        assert response.status_code == 200
        assert __version__ in response.json['ver']

    @pytest.mark.usefixtures('logged_user')
    def test_get_config(self, test_client):
        from faraday import __version__
        res = test_client.get('/config')
        assert res.status_code == 200
        assert __version__ in res.json['ver']
