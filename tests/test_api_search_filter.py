'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
from random import randrange

import pytest

from tests.factories import SearchFilterFactory, UserFactory
from tests.test_api_non_workspaced_base import (
    ReadWriteAPITests,
    BulkUpdateTestsMixin,
    BulkDeleteTestsMixin
)
from tests.test_api_agent import logout
from tests.conftest import login_as
from faraday.server.models import SearchFilter

from faraday.server.api.modules.search_filter import SearchFilterView


@pytest.mark.usefixtures('logged_user')
class TestSearchFilterAPI(ReadWriteAPITests, BulkUpdateTestsMixin, BulkDeleteTestsMixin):
    model = SearchFilter
    factory = SearchFilterFactory
    api_endpoint = 'searchfilter'
    view_class = SearchFilterView
    patchable_fields = ['name']

    pytest.fixture(autouse=True)

    def test_bulk_update_an_object(self, test_client, session, logged_user):
        all_objs = self.model.query.all()
        all_objs_id = [obj.__getattribute__(self.view_class.lookup_field) for obj in self.model.query.all()]
        all_objs, all_objs_id = all_objs[:-1], all_objs_id[:-1]
        for obj in all_objs:
            obj.creator_id = logged_user.id
        session.commit()

        data = self.factory.build_dict()
        data = BulkUpdateTestsMixin.control_data(self, data)

        res = test_client.patch(self.url(), data={})
        assert res.status_code == 400
        data["ids"] = all_objs_id
        res = test_client.patch(self.url(), data=data)

        assert res.status_code == 200, (res.status_code, res.json)
        assert self.model.query.count() == 5
        assert res.json['updated'] == len(all_objs)
        for obj in self.model.query.all():
            if getattr(obj, self.view_class.lookup_field) not in all_objs_id:
                assert any(
                    [
                        data[updated_field] != getattr(obj, updated_field)
                        for updated_field in data if updated_field != 'ids'
                    ]
                )
            else:
                assert all(
                    [
                        data[updated_field] == getattr(obj, updated_field)
                        for updated_field in data if updated_field != 'ids'
                    ]
                )

    def test_bulk_update_invalid_ids(self, test_client, session, logged_user):
        data = self.factory.build_dict()
        data = BulkUpdateTestsMixin.control_data(self, data)
        data['ids'] = [-1, 'test']
        res = test_client.patch(self.url(), data=data)
        assert res.status_code == 200
        assert res.json['updated'] == 0

        self.first_object.creator_id = logged_user.id
        session.commit()
        data['ids'] = [-1, 'test', self.first_object.__getattribute__(self.view_class.lookup_field)]
        res = test_client.patch(self.url(), data=data)
        assert res.status_code == 200
        assert res.json['updated'] == 1

    def test_list_retrieves_all_items_from(self, test_client, logged_user):
        for searchfilter in SearchFilter.query.all():
            searchfilter.creator = logged_user
        super().test_list_retrieves_all_items_from(test_client, logged_user)

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
        super().test_retrieve_one_object(test_client, logged_user)

    def test_retrieve_one_object_from_logged_user(self, test_client, session, logged_user):

        filters = []
        for n in range(5):
            user_filter = SearchFilterFactory.create(creator=logged_user)
            session.add(user_filter)
            filters.append(user_filter)

        session.commit()

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

    @pytest.mark.parametrize("method", ["PUT", "PATCH"])
    def test_update_an_object(self, test_client, logged_user, method):
        self.first_object.creator = logged_user
        super().test_update_an_object(test_client, logged_user, method)

    def test_update_an_object_fails_with_empty_dict(self, test_client, logged_user):
        self.first_object.creator = logged_user
        super().test_update_an_object_fails_with_empty_dict(test_client, logged_user)

    def test_delete(self, test_client, logged_user):
        self.first_object.creator = logged_user
        super().test_delete(test_client, logged_user)

    def test_patch_update_an_object_does_not_fail_with_partial_data(self, test_client, logged_user):
        self.first_object.creator = logged_user
        super().test_patch_update_an_object_does_not_fail_with_partial_data(test_client, logged_user)

    @pytest.mark.usefixtures('ignore_nplusone')
    def test_bulk_delete(self, test_client, logged_user):
        for obj in self.model.query.all():
            obj.creator = logged_user
        super().test_bulk_delete(test_client)
