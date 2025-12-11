'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
"""Tests for many API endpoints that do not depend on workspace_name"""
import datetime
import pytest

from tests import factories
from tests.test_api_non_workspaced_base import ReadOnlyAPITests
from faraday.server.models import (
    Command
)
from faraday.server.api.modules.global_commands import GlobalCommandView


# Note: because of a bug with pytest, I can't simply mark TestListGlobalCommandView
# with @pytest.mark.skip. I had to made it inherit from object instad of
# ReadOnlyAPITests, and to manually skip the extra tests inside the class.
# See https://docs.pytest.org/en/latest/skipping.html#skip-all-test-functions-of-a-class-or-module
# and https://github.com/pytest-dev/pytest/issues/568 for more information

@pytest.mark.usefixtures('logged_user')
class TestListGlobalCommandView(ReadOnlyAPITests):
    model = Command
    factory = factories.CommandFactory
    api_endpoint = 'global_commands'
    view_class = GlobalCommandView
    patchable_fields = ["ip"]

    @pytest.mark.usefixtures('ignore_nplusone')
    def test_list_retrieves_all_items_from(self, test_client, session):
        OBJECT_COUNT = 5
        res = test_client.get(self.url())
        assert res.status_code == 200
        assert len(res.json['commands']) == OBJECT_COUNT

    @pytest.mark.usefixtures('ignore_nplusone')
    def test_backwards_compatibility_list(self, test_client, second_workspace, session):
        self.factory.create(workspace=second_workspace)
        session.commit()
        res = test_client.get(self.url())
        assert res.status_code == 200
        assert 'commands' in res.json
        for command in res.json['commands']:
            assert {'id', 'key', 'value'} == set(command.keys())
            object_properties = [
                '_id',
                'command',
                'duration',
                'hostname',
                'ip',
                'itime',
                'params',
                'user',
                'workspace',
                'tool',
                'import_source',
                'creator',
                'metadata',
                'tasks'
            ]
            assert set(object_properties) == set(command['value'].keys())

    @pytest.mark.usefixtures('ignore_nplusone')
    def test_sub_second_command_returns_correct_duration_value(self, test_client):
        command = self.factory(
            start_date=datetime.datetime(2017, 11, 14, 12, 29, 21, 248433),
            end_date=datetime.datetime(2017, 11, 14, 12, 29, 21, 690839)
        )
        res = test_client.get(self.url())
        assert res.status_code == 200
        assert res.json['commands'][-1]['value']['duration'] == 0.442406

    @pytest.mark.usefixtures('ignore_nplusone')
    def test_more_than_one_second_command_returns_correct_duration_value(self, test_client):
        command = self.factory(
            start_date=datetime.datetime(2017, 11, 14, 12, 29, 20, 248433),
            end_date=datetime.datetime(2017, 11, 14, 12, 29, 21, 690839)
        )
        res = test_client.get(self.url())
        assert res.status_code == 200
        assert res.json['commands'][-1]['value']['duration'] == 1.442406

    @pytest.mark.usefixtures('ignore_nplusone')
    def test_more_than_one_minute_command_returns_correct_duration_value(self, test_client):
        command = self.factory(
            start_date=datetime.datetime(2017, 11, 14, 12, 28, 20, 248433),
            end_date=datetime.datetime(2017, 11, 14, 12, 29, 21, 690839)
        )
        res = test_client.get(self.url())
        assert res.status_code == 200
        assert res.json['commands'][-1]['value']['duration'] == 61.442406

    @pytest.mark.usefixtures('ignore_nplusone')
    def test_less_than_one_day_none_end_date_command_returns_msg(self, test_client):
        command = self.factory(
            start_date=datetime.datetime.now(),
            end_date=None
        )
        res = test_client.get(self.url())
        assert res.status_code == 200
        assert res.json['commands'][0]['value']['duration'].lower() == "in progress"
