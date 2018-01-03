#-*- coding: utf8 -*-

"""Generic tests for APIs prefixed with a workspace_name"""

import pytest
from sqlalchemy.orm.util import was_deleted
from server.models import db, Workspace, Credential
from test_api_pagination import PaginationTestsMixin as \
    OriginalPaginationTestsMixin

API_PREFIX = '/v2/ws/'
OBJECT_COUNT = 5


@pytest.mark.usefixtures('logged_user')
class GenericAPITest:

    model = None
    factory = None
    api_endpoint = None
    pk_field = 'id'
    unique_fields = []
    update_fields = []

    @pytest.fixture(autouse=True)
    def load_workspace_with_objects(self, database, session, workspace):
        self.objects = self.factory.create_batch(
            OBJECT_COUNT, workspace=workspace)
        self.first_object = self.objects[0]
        session.commit()
        assert workspace.id is not None
        self.workspace = workspace
        return workspace

    @pytest.fixture
    def object_instance(self, session, workspace):
        """An object instance with the correct workspace assigned,
        saved in the database"""
        obj = self.factory.create(workspace=workspace)
        session.commit()
        return obj

    def url(self, obj=None, workspace=None):
        workspace = workspace or self.workspace
        url = API_PREFIX + workspace.name + '/' + self.api_endpoint + '/'
        if obj is not None:
            id_ = unicode(obj.id) if isinstance(
                obj, self.model) else unicode(obj)
            url += id_ + u'/'
        return url


class ListTestsMixin:
    view_class = None  # Must be overriden

    @pytest.fixture
    def mock_envelope_list(self, monkeypatch):
        assert self.view_class is not None, 'You must define view_class ' \
            'in order to use ListTestsMixin or PaginationTestsMixin'
        def _envelope_list(self, objects, pagination_metadata=None):
            return {"data": objects}
        monkeypatch.setattr(self.view_class, '_envelope_list', _envelope_list)

    @pytest.mark.usefixtures('mock_envelope_list')
    def test_list_retrieves_all_items_from_workspace(self, test_client,
                                                     second_workspace,
                                                     session):
        self.factory.create(workspace=second_workspace)
        session.commit()
        res = test_client.get(self.url())
        assert res.status_code == 200
        assert len(res.json['data']) == OBJECT_COUNT


class RetrieveTestsMixin:

    def test_retrieve_one_object(self, test_client):
        res = test_client.get(self.url(self.first_object))
        assert res.status_code == 200
        assert isinstance(res.json, dict)

    def test_retrieve_fails_object_of_other_workspcae(self,
                                                      test_client,
                                                      session,
                                                      second_workspace):
        res = test_client.get(self.url(self.first_object, second_workspace))
        assert res.status_code == 404

    @pytest.mark.parametrize('object_id', [123, -1, 'xxx', u'áá'])
    def test_404_when_retrieving_unexistent_object(self, test_client,
                                                   object_id):
        url = self.url(object_id)
        res = test_client.get(url)
        assert res.status_code == 404


class CreateTestsMixin:

    def test_create_succeeds(self, test_client):
        data = self.factory.build_dict(workspace=self.workspace)
        res = test_client.post(self.url(),
                               data=data)
        assert res.status_code == 201, (res.status_code, res.data)
        assert self.model.query.count() == OBJECT_COUNT + 1
        object_id = res.json['id']
        obj = self.model.query.get(object_id)
        assert obj.workspace == self.workspace

    def test_create_fails_with_empty_dict(self, test_client):
        res = test_client.post(self.url(), data={})
        assert res.status_code == 400

    def test_create_fails_with_existing(self, session, test_client):
        for unique_field in self.unique_fields:
            data = self.factory.build_dict()
            data[unique_field] = getattr(self.first_object, unique_field)
            res = test_client.post(self.url(), data=data)
            assert res.status_code == 409
            assert self.model.query.count() == OBJECT_COUNT

    def test_create_with_existing_in_other_workspace(self, test_client,
                                                     session,
                                                     second_workspace):
        if not self.unique_fields:
            return
        unique_field = self.unique_fields[0]
        other_object = self.factory.create(workspace=second_workspace)
        session.commit()

        data = self.factory.build_dict()
        data[unique_field] = getattr(other_object, unique_field)
        res = test_client.post(self.url(), data=data)
        assert res.status_code == 201
        # It should create two hosts, one for each workspace
        assert self.model.query.count() == OBJECT_COUNT + 2


class UpdateTestsMixin:

    def test_update_an_object(self, test_client):
        data = self.factory.build_dict(workspace=self.workspace)
        res = test_client.put(self.url(self.first_object),
                              data=data)
        assert res.status_code == 200
        assert self.model.query.count() == OBJECT_COUNT
        for updated_field in self.update_fields:
            assert res.json[updated_field] == getattr(self.first_object,
                                                      updated_field)

    def test_update_fails_with_existing(self, test_client, session):
        for unique_field in self.unique_fields:
            data = self.factory.build_dict()
            data[unique_field] = getattr(self.objects[1], unique_field)
            res = test_client.put(self.url(self.first_object), data=data)
            assert res.status_code == 409
            assert self.model.query.count() == OBJECT_COUNT

    def test_update_an_object_fails_with_empty_dict(self, test_client):
        """To do this the user should use a PATCH request"""
        res = test_client.put(self.url(self.first_object), data={})
        assert res.status_code == 400

    def test_update_cant_change_id(self, test_client):
        raw_json = self.factory.build_dict(workspace=self.workspace)
        expected_id = self.first_object.id
        raw_json['id'] = 100000
        res = test_client.put(self.url(self.first_object),
                              data=raw_json)
        assert res.status_code == 200
        assert res.json['id'] == expected_id



class DeleteTestsMixin:

    def test_delete(self, test_client):
        res = test_client.delete(self.url(self.first_object))
        assert res.status_code == 204  # No content
        assert was_deleted(self.first_object)
        assert self.model.query.count() == OBJECT_COUNT - 1

    def test_delete_from_other_workspace_fails(self, test_client,
                                                    second_workspace):
        res = test_client.delete(self.url(self.first_object,
                                          workspace=second_workspace))
        assert res.status_code == 404  # No content
        assert not was_deleted(self.first_object)
        assert self.model.query.count() == OBJECT_COUNT


class PaginationTestsMixin(OriginalPaginationTestsMixin):
    def create_many_objects(self, session, n):
        objects = self.factory.create_batch(n, workspace=self.workspace)
        session.commit()
        return objects


class ReadWriteTestsMixin(ListTestsMixin,
                          RetrieveTestsMixin,
                          CreateTestsMixin,
                          UpdateTestsMixin,
                          DeleteTestsMixin):
    pass


class ReadWriteAPITests(ReadWriteTestsMixin,
                        GenericAPITest):
    pass


class ReadOnlyAPITests(ListTestsMixin,
                       RetrieveTestsMixin,
                       GenericAPITest):
    pass
