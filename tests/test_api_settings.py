"""
Faraday Penetration Test IDE
Copyright (C) 2019  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
"""
from __future__ import absolute_import

import pytest
from unittest import mock

from faraday.settings.reports import ReportsSettings


@mock.patch("faraday.settings.reports.ReportsSettings.must_restart_threads", False)
@pytest.mark.usefixtures('logged_user')
class TestServerConfig:
    def test_update_server_config(self, test_client):
        new_config = {"ignore_info_severity": True, 'custom_plugins_folder': ''}
        response = test_client.patch("/v3/settings/reports", json=new_config)
        assert response.status_code == 200
        assert ReportsSettings.settings.ignore_info_severity == new_config["ignore_info_severity"]

    def test_get_valid_settings(self, test_client):
        response = test_client.get("/v3/settings/reports")
        assert response.status_code == 200
        assert "ignore_info_severity" in response.json
        assert "custom_plugins_folder" in response.json

    def test_get_invalid_settings(self, test_client):
        response = test_client.get("/v3/settings/invalid")
        assert response.status_code == 404

    def test_update_settings_with_empty_json(self, test_client):
        response = test_client.patch("/v3/settings/reports", json={})
        assert response.status_code == 400
        assert "messages" in response.json

    def test_update_settings_with_invalid_value(self, test_client):
        data = {
            "INVALID_VALUE": "",
            "ignore_info_severity": True
        }
        response = test_client.patch("/v3/settings/reports", json=data)
        assert response.status_code == 400
        assert "messages" in response.json

    def test_update_settings_with_valid_value(self, test_client):
        response = test_client.get("/v3/settings/reports")
        assert response.status_code == 200
        actual_value = response.json['ignore_info_severity']
        data = {'ignore_info_severity': not actual_value, 'custom_plugins_folder': response.json['custom_plugins_folder']}
        response = test_client.patch("/v3/settings/reports", json=data)
        assert response.status_code == 200
        assert response.json["ignore_info_severity"] != actual_value
