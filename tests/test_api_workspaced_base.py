#-*- coding: utf8 -*-
'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
from builtins import str
from posixpath import join as urljoin


"""Generic tests for APIs prefixed with a workspace_name"""

import pytest
from sqlalchemy.orm.util import was_deleted
from faraday.server.models import db
from tests.test_api_pagination import PaginationTestsMixin as \
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
        session.add_all(self.objects)
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
            id_ = str(obj.id) if isinstance(
                obj, self.model) else str(obj)
            url += id_ + u'/'
        return url


class ListTestsMixin:
    view_class = None  # Must be overriden

    @pytest.fixture
    def mock_envelope_list(self, monkeypatch):
        assert self.view_class is not None, 'You must define view_class ' \
            'in order to use ListTestsMixin or PaginationTestsMixin'

        def _envelope_list(_, objects, pagination_metadata=None):
            return {"data": objects}
        monkeypatch.setattr(self.view_class, '_envelope_list', _envelope_list)

    @pytest.mark.usefixtures('mock_envelope_list')
    def test_list_retrieves_all_items_from_workspace(self, test_client,
                                                     second_workspace,
                                                     session):
        obj = self.factory.create(workspace=second_workspace)
        session.add(obj)
        session.commit()
        res = test_client.get(self.url())
        assert res.status_code == 200
        assert len(res.json['data']) == OBJECT_COUNT

    def test_can_list_readonly(self, test_client, session):
        self.workspace.readonly = True
        session.commit()
        res = test_client.get(self.url())
        assert res.status_code == 200

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

    @pytest.mark.parametrize('object_id', [123456789, -1, 'xxx', u'áá'])
    def test_404_when_retrieving_unexistent_object(self, test_client,
                                                   object_id):
        url = self.url(object_id)
        res = test_client.get(url)
        assert res.status_code == 404


class CreateTestsMixin:

    def test_create_succeeds(self, test_client):
        data = self.factory.build_dict(workspace=self.workspace)
        count = self.model.query.count()
        res = test_client.post(self.url(),
                               data=data)
        assert res.status_code == 201, (res.status_code, res.data)
        assert self.model.query.count() == count + 1
        object_id = res.json.get('id') or res.json['_id']
        obj = self.model.query.get(object_id)
        assert obj.workspace == self.workspace

    def test_create_fails_readonly(self, test_client):
        self.workspace.readonly = True
        db.session.commit()
        data = self.factory.build_dict(workspace=self.workspace)
        count = self.model.query.count()
        res = test_client.post(self.url(),
                               data=data)
        db.session.commit()
        assert res.status_code == 403
        assert self.model.query.count() == count


    def test_create_inactive_fails(self, test_client):
        self.workspace.deactivate()
        db.session.commit()
        data = self.factory.build_dict(workspace=self.workspace)
        count = self.model.query.count()
        res = test_client.post(self.url(),
                               data=data)
        assert res.status_code == 403, (res.status_code, res.data)
        assert self.model.query.count() == count

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

    def control_cant_change_data(self, data: dict) -> dict:
        return data

    @pytest.mark.parametrize("method", ["PUT"])
    def test_update_an_object(self, test_client, method):
        data = self.factory.build_dict(workspace=self.workspace)
        data = self.control_cant_change_data(data)
        count = self.model.query.count()
        if method == "PUT":
            res = test_client.put(self.url(self.first_object),
                                  data=data)
        elif method == "PATCH":
            data = PatchableTestsMixin.control_data(self, data)
            res = test_client.patch(self.url(self.first_object), data=data)
        assert res.status_code == 200
        assert self.model.query.count() == count
        for updated_field in self.update_fields:
            assert res.json[updated_field] == getattr(self.first_object,
                                                      updated_field)

    @pytest.mark.parametrize("method", ["PUT"])
    def test_update_an_object_readonly_fails(self, test_client, method):
        self.workspace.readonly = True
        db.session.commit()
        for unique_field in self.unique_fields:
            data = self.factory.build_dict()
            old_field = getattr(self.objects[0], unique_field)
            old_id = getattr(self.objects[0], 'id')
            if method == "PUT":
                res = test_client.put(self.url(self.first_object), data=data)
            elif method == "PATCH":
                res = test_client.patch(self.url(self.first_object), data=data)
            db.session.commit()
            assert res.status_code == 403
            assert self.model.query.count() == OBJECT_COUNT
            assert old_field == getattr(self.model.query.filter(self.model.id == old_id).one(), unique_field)

    @pytest.mark.parametrize("method", ["PUT"])
    def test_update_inactive_fails(self, test_client, method):
        self.workspace.deactivate()
        db.session.commit()
        data = self.factory.build_dict(workspace=self.workspace)
        count = self.model.query.count()
        if method == "PUT":
            res = test_client.put(self.url(self.first_object),
                                  data=data)
        elif method == "PATCH":
            res = test_client.patch(self.url(self.first_object),
                                    data=data)
        assert res.status_code == 403
        assert self.model.query.count() == count

    @pytest.mark.parametrize("method", ["PUT"])
    def test_update_fails_with_existing(self, test_client, session, method):
        for unique_field in self.unique_fields:
            unique_field_value = getattr(self.objects[1], unique_field)
            if method == "PUT":
                data = self.factory.build_dict()
                data[unique_field] = unique_field_value
                res = test_client.put(self.url(self.first_object), data=data)
            elif method == "PATCH":
                res = test_client.patch(self.url(self.first_object), data={unique_field: unique_field_value})
            assert res.status_code == 409
            assert self.model.query.count() == OBJECT_COUNT

    def test_update_an_object_fails_with_empty_dict(self, test_client):
        """To do this the user should use a PATCH request"""
        res = test_client.put(self.url(self.first_object), data={})
        assert res.status_code == 400

    @pytest.mark.parametrize("method", ["PUT"])
    def test_update_cant_change_id(self, test_client, method):
        raw_json = self.factory.build_dict(workspace=self.workspace)
        raw_json = self.control_cant_change_data(raw_json)
        expected_id = self.first_object.id
        raw_json['id'] = 100000
        if method == "PUT":
            res = test_client.put(self.url(self.first_object),
                                  data=raw_json)
        if method == "PATCH":
            res = test_client.patch(self.url(self.first_object),
                                    data=raw_json)
        assert res.status_code == 200, (res.status_code, res.data)
        object_id = res.json.get('id') or res.json['_id']
        assert object_id == expected_id


class PatchableTestsMixin(UpdateTestsMixin):

    @staticmethod
    def control_data(test_suite, data: dict) -> dict:
        return {key: value for (key, value) in data.items() if key in test_suite.patchable_fields}

    @pytest.mark.parametrize("method", ["PUT", "PATCH"])
    def test_update_an_object(self, test_client, method):
        super(PatchableTestsMixin, self).test_update_an_object(test_client, method)

    @pytest.mark.parametrize("method", ["PUT", "PATCH"])
    def test_update_an_object_readonly_fails(self, test_client, method):
        super(PatchableTestsMixin, self).test_update_an_object_readonly_fails(test_client, method)

    @pytest.mark.parametrize("method", ["PUT", "PATCH"])
    def test_update_inactive_fails(self, test_client, method):
        super(PatchableTestsMixin, self).test_update_inactive_fails(test_client, method)

    @pytest.mark.parametrize("method", ["PUT", "PATCH"])
    def test_update_fails_with_existing(self, test_client, session, method):
        super(PatchableTestsMixin, self).test_update_fails_with_existing(test_client, session, method)

    def test_update_an_object_fails_with_empty_dict(self, test_client):
        """To do this the user should use a PATCH request"""
        res = test_client.patch(self.url(self.first_object), data={})
        assert res.status_code == 200, (res.status_code, res.json)

    @pytest.mark.parametrize("method", ["PUT", "PATCH"])
    def test_update_cant_change_id(self, test_client, method):
        super(PatchableTestsMixin, self).test_update_cant_change_id(test_client, method)

class CountTestsMixin:
    def test_count(self, test_client, session, user_factory):

        factory_kwargs = {}
        for extra_filter in self.view_class.count_extra_filters:
            field = extra_filter.left.name
            value = extra_filter.right.effective_value
            setattr(self.first_object, field, value)
            factory_kwargs[field] = value

        session.add(self.factory.create(creator=self.first_object.creator,
                                  workspace=self.first_object.workspace,
                                  **factory_kwargs))

        session.commit()

        if self.view_class.route_prefix.startswith("/v2"):
            res = test_client.get(urljoin(self.url(), "count/?group_by=creator_id"))
        else:
            res = test_client.get(urljoin(self.url(), "count?group_by=creator_id"))

        assert res.status_code == 200, res.json
        res = res.get_json()

        creators = []
        grouped = 0
        for obj in res['groups']:
            if obj['count'] == 2:
                grouped += 1
            creators.append(obj['creator_id'])

        assert grouped == 1, (res)
        assert creators == sorted(creators)

    def test_count_descending(self, test_client, session, user_factory):

        factory_kwargs = {}
        for extra_filter in self.view_class.count_extra_filters:
            field = extra_filter.left.name
            value = extra_filter.right.effective_value
            setattr(self.first_object, field, value)
            factory_kwargs[field] = value

        session.add(self.factory.create(creator=self.first_object.creator,
                                        workspace=self.first_object.workspace,
                                        **factory_kwargs))

        session.commit()

        if self.view_class.route_prefix.startswith("/v2"):
            res = test_client.get(urljoin(self.url(), "count/?group_by=creator_id&order=desc"))
        else:
            res = test_client.get(urljoin(self.url(), "count?group_by=creator_id&order=desc"))

        assert res.status_code == 200, res.json
        res = res.get_json()

        creators = []
        grouped = 0
        for obj in res['groups']:
            if obj['count'] == 2:
                grouped += 1
            creators.append(obj['creator_id'])

        assert grouped == 1, res
        assert creators == sorted(creators, reverse=True)



class DeleteTestsMixin:

    def test_delete(self, test_client):
        res = test_client.delete(self.url(self.first_object))
        assert res.status_code == 204  # No content
        assert was_deleted(self.first_object)
        assert self.model.query.count() == OBJECT_COUNT - 1

    def test_delete_readonly_fails(self, test_client, session):
        self.workspace.readonly = True
        session.commit()
        res = test_client.delete(self.url(self.first_object))
        assert res.status_code == 403  # No content
        assert not was_deleted(self.first_object)
        assert self.model.query.count() == OBJECT_COUNT

    def test_delete_inactive_fails(self, test_client):
        self.workspace.deactivate()
        db.session.commit()
        res = test_client.delete(self.url(self.first_object))
        assert res.status_code == 403
        assert not was_deleted(self.first_object)
        assert self.model.query.count() == OBJECT_COUNT

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
                          CountTestsMixin,
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


class ReadOnlyMultiWorkspacedAPITests(ListTestsMixin,
                                      RetrieveTestsMixin,
                                      GenericAPITest):

    @pytest.fixture(autouse=True)
    def load_workspace_with_objects(self, database, session, workspace):
        self.objects = self.factory.create_batch(
            OBJECT_COUNT, workspaces=[workspace])
        self.first_object = self.objects[0]
        session.add_all(self.objects)
        session.commit()
        assert workspace.id is not None
        self.workspace = workspace
        return workspace

    @pytest.mark.usefixtures('mock_envelope_list')
    def test_list_retrieves_all_items_from_workspace(self, test_client,
                                                     second_workspace,
                                                     session):
        obj = self.factory.create(workspaces=[second_workspace])
        session.add(obj)
        session.commit()
        res = test_client.get(self.url())
        assert res.status_code == 200
        assert len(res.json['data']) == OBJECT_COUNT

class ReadWriteMultiWorkspacedAPITests(ReadOnlyMultiWorkspacedAPITests,
                                       ReadWriteTestsMixin):
    pass
