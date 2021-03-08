# -*- coding: utf8 -*-
'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
from random import randrange

import pytest

from tests.factories import SearchFilterFactory, UserFactory
from tests.test_api_non_workspaced_base import ReadWriteAPITests, PatchableTestsMixin
from tests.test_api_agent import logout
from tests.conftest import login_as
from faraday.server.models import SearchFilter

from faraday.server.api.modules.search_filter import SearchFilterView
from tests.utils.url import v2_to_v3


@pytest.mark.usefixtures('logged_user')
class TestSearchFilterAPI(ReadWriteAPITests):
    model = SearchFilter
    factory = SearchFilterFactory
    api_endpoint = 'searchfilter'
    view_class = SearchFilterView
    patchable_fields = ['name']

    pytest.fixture(autouse=True)

    def test_list_retrieves_all_items_from(self, test_client, logged_user):
        for searchfilter in SearchFilter.query.all():
            searchfilter.creator = logged_user
        super(TestSearchFilterAPI, self).test_list_retrieves_all_items_from(test_client, logged_user)

    def test_list_retrieves_all_items_from_logger_user(self, test_client, session, logged_user):
        user_filter = SearchFilterFactory.create(creator=logged_user)
        session.add(user_filter)
        session.commit()
        res = test_client.get(self.url())
        assert res.status_code == 200
        if 'rows' in res.json:
            assert len(res.json['rows']) == 1
        else:
            assert len(res.json) == 1

    def test_retrieve_one_object(self, test_client, logged_user):
        self.first_object.creator = logged_user
        super(TestSearchFilterAPI, self).test_retrieve_one_object(test_client, logged_user)

    def test_retrieve_one_object_from_logged_user(self, test_client, session, logged_user):

        filters = []
        for n in range(5):
            user_filter = SearchFilterFactory.create(creator=logged_user)
            session.add(user_filter)
            filters.append(user_filter)

        session.commit()

        print(self.url(filters[randrange(5)]))
        res = test_client.get(self.url(filters[randrange(5)]))
        assert res.status_code == 200
        assert isinstance(res.json, dict)

    def test_retrieve_filter_from_another_user(self, test_client, session, logged_user):
        user_filter = SearchFilterFactory.create(creator=logged_user)
        another_user = UserFactory.create()
        session.add(user_filter)
        session.add(another_user)
        session.commit()

        logout(test_client, [302])
        login_as(test_client, another_user)

        res = test_client.get(self.url(user_filter))
        assert res.status_code == 404

    def test_retrieve_filter_list_is_empty_from_another_user(self, test_client, session, logged_user):
        user_filter = SearchFilterFactory.create(creator=logged_user)
        another_user = UserFactory.create()
        session.add(user_filter)
        session.add(another_user)
        session.commit()

        logout(test_client, [302])
        login_as(test_client, another_user)

        res = test_client.get(self.url())
        assert res.status_code == 200
        assert res.json == []

    def test_delete_filter_from_another_user(self, test_client, session, logged_user):
        user_filter = SearchFilterFactory.create(creator=logged_user)
        another_user = UserFactory.create()
        session.add(user_filter)
        session.add(another_user)
        session.commit()

        logout(test_client, [302])
        login_as(test_client, another_user)

        res = test_client.delete(self.url(user_filter))
        assert res.status_code == 404

    @pytest.mark.parametrize("method", ["PUT"])
    def test_update_an_object(self, test_client, logged_user, method):
        self.first_object.creator = logged_user
        super(TestSearchFilterAPI, self).test_update_an_object(test_client, logged_user, method)

    def test_update_an_object_fails_with_empty_dict(self, test_client, logged_user):
        self.first_object.creator = logged_user
        super(TestSearchFilterAPI, self).test_update_an_object_fails_with_empty_dict(test_client, logged_user)

    def test_delete(self, test_client, logged_user):
        self.first_object.creator = logged_user
        super(TestSearchFilterAPI, self).test_delete(test_client, logged_user)


@pytest.mark.usefixtures('logged_user')
class TestSearchFilterAPIV3(TestSearchFilterAPI, PatchableTestsMixin):
    def url(self, obj=None):
        return v2_to_v3(super(TestSearchFilterAPIV3, self).url(obj))

    @pytest.mark.parametrize("method", ["PUT", "PATCH"])
    def test_update_an_object(self, test_client, logged_user, method):
        super(TestSearchFilterAPIV3, self).test_update_an_object(test_client, logged_user, method)

    def test_patch_update_an_object_does_not_fail_with_partial_data(self, test_client, logged_user):
        self.first_object.creator = logged_user
        super(TestSearchFilterAPIV3, self).test_update_an_object_fails_with_empty_dict(test_client, logged_user)
