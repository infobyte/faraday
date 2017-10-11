#-*- coding: utf8 -*-

"""Generic test mixins for APIs with pagination enabled when listing"""

import pytest
from urllib import urlencode

def with_0_and_n_objects(n=10):
    return pytest.mark.parametrize('object_count', [0, n])

class PaginationTestsMixin:
    view_class = None  # Must be overriden

    @pytest.fixture
    def delete_previously_created_objects(self, session):
        for obj in self.objects:
            session.delete(obj)
        session.commit()

    @pytest.fixture
    def custom_envelope(self, monkeypatch):
        def _envelope_list(self, objects, pagination_metadata=None):
            return {"data": objects}
        monkeypatch.setattr(self.view_class, '_envelope_list', _envelope_list)

    @pytest.fixture
    def pagination_test_logic(self, delete_previously_created_objects,
                              custom_envelope):
        # Load this two fixtures
        pass

    def create_many_objects(self, session, n):
        objects = self.factory.create_batch(n)
        session.commit()
        return objects

    def page_url(self, page_number=None, per_page=None):
        parameters = {}
        if page_number is not None:
            parameters[
                self.view_class.page_number_parameter_name] = page_number
        if per_page is not None:
            parameters[self.view_class.per_page_parameter_name] = per_page
        return self.url() + '?' + urlencode(parameters)

    @pytest.mark.parametrize("page_number", [None, 1, 2])
    @pytest.mark.usefixtures('pagination_test_logic')
    @pytest.mark.pagination
    def test_returns_all_with_no_per_page(self, test_client, session,
                                          page_number):
        self.create_many_objects(session, 100)
        res = test_client.get(self.page_url(page_number,
                                            per_page=None))
        assert res.status_code == 200
        assert len(res.json['data']) == 100

    @pytest.mark.skip("TODO: Fix for sqlite and postgres")
    @with_0_and_n_objects()
    @pytest.mark.usefixtures('pagination_test_logic')
    @pytest.mark.pagination
    def test_does_not_allow_negative_per_page(self, session, test_client,
                                              object_count):
        self.create_many_objects(session, object_count)
        res = test_client.get(self.page_url(1, -1))
        assert res.status_code == 404

    @pytest.mark.skip("TODO: Fix for sqlite and postgres")
    @with_0_and_n_objects()
    @pytest.mark.usefixtures('pagination_test_logic')
    @pytest.mark.pagination
    def test_does_not_allow_negative_page_number(self, session, test_client,
                                                 object_count):
        self.create_many_objects(session, object_count)
        res = test_client.get(self.page_url(-1, 10))
        assert res.status_code == 200
        assert res.json == {u'data': []}

    @pytest.mark.usefixtures('pagination_test_logic')
    @pytest.mark.pagination
    def test_pages_have_different_elements(self, session, test_client):
        """Test correct page size, correct IDs and that there are
        no duplicate items in different pages"""
        ids = {getattr(obj, self.pk_field)
               for obj in self.create_many_objects(session, 95)}
        for page_number in range(1, 11):
            res = test_client.get(self.page_url(page_number, 10))
            assert res.status_code == 200
            new_ids = {obj.get(self.pk_field) for obj in res.json['data']}
            assert len(new_ids) == (5 if page_number == 10 else 10)
            assert new_ids.issubset(ids)
            ids.difference_update(new_ids)  # Remove the new ids
        assert not ids

    @pytest.mark.usefixtures('pagination_test_logic')
    @pytest.mark.pagination
    def test_404_on_page_with_no_elements(self, session, test_client):
        self.create_many_objects(session, 5)
        res = test_client.get(self.page_url(2, 5))
        assert res.status_code == 200
        assert res.json == {u'data': []}

    @pytest.mark.usefixtures('pagination_test_logic')
    @pytest.mark.pagination
    def test_succeed_on_first_page_with_no_elements(self, test_client):
        res = test_client.get(self.page_url(1, 5))
        assert res.status_code == 200
        assert len(res.json['data']) == 0
