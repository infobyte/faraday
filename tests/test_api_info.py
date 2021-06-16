'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

import pytest


@pytest.mark.usefixtures('logged_user')
class TestAPIInfoEndpoint:

    def test_api_info(self, test_client):
        response = test_client.get('v3/info')
        assert response.status_code == 200
        assert response.json['Faraday Server'] == 'Running'

    def test_get_config(self, test_client):
        res = test_client.get('/config')
        assert res.status_code == 200
        assert res.json['lic_db'] == 'faraday_licenses'
