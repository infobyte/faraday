#-*- coding: utf8 -*-
'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
from builtins import str

"""Generic tests for APIs NOT prefixed with a workspace_name"""

import pytest
from sqlalchemy.orm.util import was_deleted

API_PREFIX = '/v2/'
OBJECT_COUNT = 5


def v3_url(test_suite, obj=None, root_api=False, **kwargs):
    ## TODO v3 just in PATCH with no / in the end. Remove after all v3 released
    if root_api:
        url: str = test_suite.url(**kwargs)
    else:
        if obj is None:
            obj = test_suite.first_object
        url: str = test_suite.url(obj, **kwargs)

    if url[-1] == "/":
        url = url[:-1]
    return url.replace("v2", "v3")

@pytest.mark.usefixtures('logged_user')
class GenericAPITest:

    model = None
    factory = None
    api_endpoint = None
    lookup_field = 'id'
    unique_fields = []
    update_fields = []

    @pytest.fixture(autouse=True)
    def load_many_objects(self, database, session):
        objects = self.factory.create_batch(OBJECT_COUNT)
        self.first_object = objects[0]
        session.commit()
        assert self.model.query.count() == OBJECT_COUNT
        return objects

    @pytest.fixture
    def object_instance(self, session):
        """An object instance saved in the database"""
        obj = self.factory.create()
        session.commit()
        return obj

    def url(self, obj=None):
        url = API_PREFIX + self.api_endpoint + '/'
        if obj is not None:
            id_ = str(getattr(obj, self.lookup_field)) if isinstance(
                obj, self.model) else str(obj)
            url += id_ + u'/'
        return url


@pytest.mark.usefixtures('logged_user')
class ListTestsMixin:

    def test_list_retrieves_all_items_from(self, test_client, logged_user):
        res = test_client.get(self.url())
        assert res.status_code == 200
        if 'rows' in res.json:
            assert len(res.json['rows']) == OBJECT_COUNT
        else:
            assert len(res.json) == OBJECT_COUNT


@pytest.mark.usefixtures('logged_user')
class RetrieveTestsMixin:

    def test_retrieve_one_object(self, test_client, logged_user):
        res = test_client.get(self.url(self.first_object))
        assert res.status_code == 200
        assert isinstance(res.json, dict)

    @pytest.mark.parametrize('object_id', [123456789, -1, 'xxx', u'áá'])
    def test_404_when_retrieving_unexistent_object(self, test_client,
                                                   object_id):
        url = self.url(object_id)
        res = test_client.get(url)
        assert res.status_code == 404


class CreateTestsMixin:

    def test_create_succeeds(self, test_client):
        res = test_client.post(self.url(),
                               data=self.factory.build_dict())
        assert res.status_code == 201, (res.status_code, res.json)
        assert self.model.query.count() == OBJECT_COUNT + 1
        object_id = res.json['id']
        self.model.query.get(object_id)

    def test_create_fails_with_empty_dict(self, test_client):
        res = test_client.post(self.url(), data={})
        assert res.status_code == 400, (res.status_code, res.json)

    def test_create_fails_with_existing(self, session, test_client):
        for unique_field in self.unique_fields:
            data = self.factory.build_dict()
            data[unique_field] = getattr(self.first_object, unique_field)
            res = test_client.post(self.url(), data=data)
            assert res.status_code == 400
            assert self.model.query.count() == OBJECT_COUNT


@pytest.mark.usefixtures('logged_user')
class UpdateTestsMixin:

    @pytest.mark.parametrize("method", ["PUT", "PATCH"])
    def test_update_an_object(self, test_client, logged_user, method):
        data = self.factory.build_dict()
        if method == "PUT":
            res = test_client.put(self.url(self.first_object),
                                  data=data)
        elif method == "PATCH":
            res = test_client.patch(v3_url(self),
                                    data=data)
        assert res.status_code == 200, (res.status_code, res.json)
        assert self.model.query.count() == OBJECT_COUNT
        for updated_field in self.update_fields:
            assert res.json[updated_field] == getattr(self.first_object,
                                                        updated_field)

    @pytest.mark.parametrize("method", ["PUT", "PATCH"])
    def test_update_fails_with_existing(self, test_client, session, method):
        for unique_field in self.unique_fields:
            data = self.factory.build_dict()
            data[unique_field] = getattr(self.objects[1], unique_field)
            if method == "PUT":
                res = test_client.put(self.url(self.first_object),
                                      data=data)
            elif method == "PATCH":
                res = test_client.patch(v3_url(self),
                                        data=data)
            assert res.status_code == 400
            assert self.model.query.count() == OBJECT_COUNT

    def test_update_an_object_fails_with_empty_dict(self, test_client, logged_user):
        """To do this the user should use a PATCH request"""
        res = test_client.put(self.url(self.first_object), data={})
        assert res.status_code == 400, (res.status_code, res.json)

    def test_patch_update_an_object_does_not_fail_with_partial_data(self, test_client, logged_user):
        """To do this the user should use a PATCH request"""
        res = test_client.patch(v3_url(self), data={})
        assert res.status_code == 200, (res.status_code, res.json)


@pytest.mark.usefixtures('logged_user')
class DeleteTestsMixin:

    def test_delete(self, test_client, logged_user):
        res = test_client.delete(self.url(self.first_object))
        assert res.status_code == 204  # No content
        assert was_deleted(self.first_object)
        assert self.model.query.count() == OBJECT_COUNT - 1

    @pytest.mark.parametrize('object_id', [12300, -1, 'xxx', u'áá'])
    def test_delete_non_existent_raises_404(self, test_client,
                                            object_id):
        res = test_client.delete(self.url(object_id))
        assert res.status_code == 404  # No content
        assert self.model.query.count() == OBJECT_COUNT

    @pytest.mark.usefixtures('ignore_nplusone')
    def test_bulk_delete(self, test_client):

        all_objs = self.model.query.all()
        all_objs_id = [obj.__getattribute__(self.view_class.lookup_field) for obj in self.model.query.all()]

        data = {"ids": all_objs_id}
        res = test_client.delete(v3_url(self, root_api=True), data=data)
        assert res.status_code == 204  # No content
        for obj in all_objs:
            assert was_deleted(obj)
        assert self.model.query.count() == 0



class ReadWriteTestsMixin(ListTestsMixin,
                          RetrieveTestsMixin,
                          CreateTestsMixin,
                          UpdateTestsMixin,
                          DeleteTestsMixin,
                          ):
    pass


class ReadWriteAPITests(ReadWriteTestsMixin,
                        GenericAPITest):
    pass


class ReadOnlyAPITests(ListTestsMixin,
                       RetrieveTestsMixin,
                       GenericAPITest):
    pass
