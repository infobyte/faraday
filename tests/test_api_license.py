# -*- coding: utf8 -*-
'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

"""Tests for many API endpoints that do not depend on workspace_name"""

import pytest
import pytz
from hypothesis import given, strategies as st

from tests import factories
from tests.test_api_non_workspaced_base import (
    ReadWriteAPITests,
    API_PREFIX,
    BulkUpdateTestsMixin,
    BulkDeleteTestsMixin
)
from faraday.server.models import (
    License,
)
from faraday.server.api.modules.licenses import LicenseView
from tests.factories import LicenseFactory


class LicenseEnvelopedView(LicenseView):
    """A custom view to test that enveloping on generic views work ok"""
    route_base = "test_envelope_list"

    def _envelope_list(self, objects, pagination_metadata=None):
        return {"object_list": objects}


class TestLicensesAPI(ReadWriteAPITests, BulkUpdateTestsMixin, BulkDeleteTestsMixin):
    model = License
    factory = factories.LicenseFactory
    api_endpoint = 'licenses'
    view_class = LicenseView
    patchable_fields = ["product"]

    # @pytest.mark.skip(reason="Not a license actually test")
    def test_envelope_list(self, test_client, app):
        LicenseEnvelopedView.register(app)
        original_res = test_client.get(self.url())
        assert original_res.status_code == 200
        new_res = test_client.get(API_PREFIX + 'test_envelope_list')
        assert new_res.status_code == 200

        assert new_res.json == {"object_list": original_res.json}

    def test_license_note_was_missing(self, test_client, session):
        notes = 'A great note. License'
        lic = LicenseFactory.create(notes=notes)
        session.commit()
        res = test_client.get(self.url(obj=lic))
        assert res.status_code == 200
        assert res.json['notes'] == 'A great note. License'


def license_json():
    return st.fixed_dictionaries(
        {
            "lictype": st.one_of(st.none(), st.text()),
            "metadata": st.fixed_dictionaries({
                "update_time": st.floats(),
                "update_user": st.one_of(st.none(), st.text()),
                "update_action": st.integers(),
                "creator": st.one_of(st.none(), st.text()),
                "create_time": st.floats(),
                "update_controller_action": st.one_of(st.none(), st.text()),
                "owner": st.one_of(st.none(), st.text())}),
            "notes": st.one_of(st.none(), st.text()),
            "product": st.one_of(st.none(), st.text()),
            "start": st.datetimes(),
            "end": st.datetimes(),
            "type": st.one_of(st.none(), st.text())
        })


@pytest.mark.usefixtures('logged_user')
@pytest.mark.hypothesis
def test_hypothesis_license(test_client, session):
    session.commit()
    LicenseData = license_json()

    @given(LicenseData)
    def send_api_request(raw_data):
        raw_data['start'] = pytz.UTC.localize(raw_data['start']).isoformat()
        raw_data['end'] = pytz.UTC.localize(raw_data['end']).isoformat()
        res = test_client.post('v3/licenses/', data=raw_data)
        assert res.status_code in [201, 400, 409]

    send_api_request()
